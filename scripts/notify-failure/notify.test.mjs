import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { stripLog, parseAdvisories, pickFailedSteps, buildMessage, escapeMrkdwn } from './notify.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'notify.mjs');
const SCA = 'SCA gate (prod tier)';

const ts = (line, n = 0) => `2026-10-13T02:0${n}:11.1234567Z ${line}`;
const withTs = (lines) => lines.map((l, i) => ts(l, i % 10)).join('\n');

// Real shapes, modelled on scripts/security/audit-gate.mjs. In a job log the
// runner rewrites `::error::` to `##[error]` and prefixes every line with an ISO
// timestamp; a raw stderr paste keeps `::error::`.
const PNPM_LOG = withTs([
  'Security SCA gate — tier=prod, scope=production deps, date=2026-10-13',
  'pnpm audit (prod): critical=0 high=3 moderate=1 low=0',
  '',
  'Suppressed (still valid):',
  '  - high GHSA-old1-old1-old1 left-pad — Old accepted thing',
  '  (prod cut: these are accepted only until their expiry — keep the list short.)',
  '',
  '##[error]3 un-suppressed HIGH/CRITICAL advisory(ies) in shipped dependencies:',
  '  - HIGH GHSA-aaaa-bbbb-cccc undici — Undici resource exhaustion',
  '      fix: upgrade to >=6.21.1 · https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
  '  - CRITICAL GHSA-dddd-eeee-ffff proxy-addr — Spoofed — header trust',
  '      fix: upgrade to a patched version · https://github.com/advisories/GHSA-dddd-eeee-ffff',
  '  - HIGH GHSA-gggg-hhhh-iiii @scope/pkg — Prototype pollution',
  '      fix: upgrade to 2.0.8 · https://github.com/advisories/GHSA-gggg-hhhh-iiii',
  '',
  'Add a reviewed entry to security-ignore.yml to accept, or upgrade the dependency.',
  '##[error]Process completed with exit code 1.',
]);

// viorant-cli: npm audit. `vulnerable:` continuation instead of `fix:`, and the
// id falls back to `a.id` (an npm advisory number) when there is no GHSA.
const CLI_LOG = withTs([
  'npm audit (prod): critical=0 high=3',
  '##[error]3 un-suppressed HIGH/CRITICAL advisory(ies) in shipped dependencies:',
  '  - HIGH GHSA-1111-2222-3333 ws — ws DoS',
  '      vulnerable: >=8.0.0 <8.17.1 · upgrade ws to 8.17.1 · https://github.com/advisories/GHSA-1111-2222-3333',
  '  - HIGH 1105444 tar — tar arbitrary file write',
  '      vulnerable: <6.2.1 · a fix is available (`npm audit fix`) · https://github.com/advisories/1105444',
  '  - CRITICAL GHSA-4444-5555-6666 ink-thing — Remote code execution',
  '      vulnerable: * · no fix available yet · https://github.com/advisories/GHSA-4444-5555-6666',
  '',
  'Add a reviewed entry to security-ignore.yml to accept, or upgrade the dependency.',
]);

const EXPIRED_LOG = withTs([
  '##[error]Suppression for npm GHSA-zzzz-zzzz-zzzz expired 2026-10-01 (approver adi) — re-review or renew it.',
  '',
  '1 suppression(s) expired as of 2026-10-13. Failing.',
]);

const base = {
  repo: 'viorant/viorant-hub',
  runUrl: 'https://github.com/viorant/viorant-hub/actions/runs/999',
  scaStepName: SCA,
};

const text = (msg) => msg.blocks.map((b) => b.text.text).join('\n');

test('stripLog removes the leading timestamp and ANSI escapes', () => {
  const raw = '2026-10-13T02:01:11.1234567Z \u001b[31;1m  - HIGH GHSA-x mod — t\u001b[0m';
  assert.equal(stripLog(raw), '  - HIGH GHSA-x mod — t');
  assert.equal(stripLog(`${ts('a')}\n${ts('b')}`), 'a\nb');
});

test('AC2: pnpm gate log — every advisory returned, length equals declared', () => {
  const r = parseAdvisories(PNPM_LOG);
  assert.equal(r.declared, 3);
  assert.equal(r.advisories.length, 3);
  assert.deepEqual(
    r.advisories.map((a) => [a.severity, a.id, a.module]),
    [
      ['HIGH', 'GHSA-aaaa-bbbb-cccc', 'undici'],
      ['CRITICAL', 'GHSA-dddd-eeee-ffff', 'proxy-addr'],
      ['HIGH', 'GHSA-gggg-hhhh-iiii', '@scope/pkg'],
    ],
  );
  assert.equal(r.advisories[1].title, 'Spoofed — header trust');
});

test('AC2: cli gate log — vulnerable: continuation lines and a non-GHSA id', () => {
  const r = parseAdvisories(CLI_LOG);
  assert.equal(r.declared, 3);
  assert.equal(r.advisories.length, 3);
  assert.deepEqual(
    r.advisories.map((a) => [a.severity, a.id, a.module]),
    [
      ['HIGH', 'GHSA-1111-2222-3333', 'ws'],
      ['HIGH', '1105444', 'tar'],
      ['CRITICAL', 'GHSA-4444-5555-6666', 'ink-thing'],
    ],
  );
});

test('the header parses as ##[error] and as ::error::, with or without timestamps', () => {
  const body = [
    '  - HIGH GHSA-aaaa-bbbb-cccc undici — Undici thing',
    '      fix: upgrade to 1 · https://x',
  ];
  const forms = [
    withTs(['##[error]1 un-suppressed HIGH/CRITICAL advisory(ies) in shipped dependencies:', ...body]),
    withTs(['::error::1 un-suppressed HIGH/CRITICAL advisory(ies) in shipped dependencies:', ...body]),
    ['::error::1 un-suppressed HIGH/CRITICAL advisory(ies) in shipped dependencies:', ...body].join('\n'),
  ];
  for (const log of forms) {
    const r = parseAdvisories(log);
    assert.equal(r.declared, 1, log);
    assert.equal(r.advisories.length, 1, log);
    assert.equal(r.advisories[0].id, 'GHSA-aaaa-bbbb-cccc');
  }
});

test('the parser stops at the trailer and ignores the lowercase Suppressed block', () => {
  const log = `${PNPM_LOG}\n${ts('  - HIGH GHSA-late-late-late after — must not be collected')}`;
  const r = parseAdvisories(log);
  assert.equal(r.advisories.length, 3);
  assert.ok(!r.advisories.some((a) => a.id === 'GHSA-old1-old1-old1'));
  assert.ok(!r.advisories.some((a) => a.id === 'GHSA-late-late-late'));
});

test('expired-suppression log: no header, no advisories, no throw', () => {
  assert.deepEqual(parseAdvisories(EXPIRED_LOG), { declared: null, advisories: [] });
  assert.deepEqual(parseAdvisories(''), { declared: null, advisories: [] });
  assert.deepEqual(parseAdvisories(undefined), { declared: null, advisories: [] });
});

test('expired-suppression log: the message still names the step and has no advisories line', () => {
  const msg = buildMessage({
    ...base,
    failed: [{ job: 'deep', step: SCA, log: EXPIRED_LOG }],
  });
  const t = text(msg);
  assert.match(t, /SCA gate \(prod tier\)/);
  assert.doesNotMatch(t, /GHSA|advisor/i);
});

test('count mismatch (header says 3, 2 parsed) renders "3 advisories, 2 listed"', () => {
  const log = PNPM_LOG.split('\n')
    .filter((l) => !l.includes('GHSA-gggg') && !l.includes('2.0.8'))
    .join('\n');
  const t = text(buildMessage({ ...base, failed: [{ job: 'deep', step: SCA, log }] }));
  assert.match(t, /3 advisories, 2 listed/);
  assert.match(t, /GHSA-aaaa-bbbb-cccc/);
});

test('pickFailedSteps: first failed step per failed job, ignoring cancelled and skipped', () => {
  const jobs = {
    jobs: [
      {
        id: 1,
        name: 'deep',
        conclusion: 'failure',
        steps: [
          { name: 'Checkout', conclusion: 'success' },
          { name: 'Setup', conclusion: 'skipped' },
          { name: SCA, conclusion: 'failure' },
          { name: 'Gitleaks', conclusion: 'failure' },
          { name: 'Upload', conclusion: 'cancelled' },
        ],
      },
      { id: 2, name: 'lint', conclusion: 'success', steps: [{ name: 'Lint', conclusion: 'success' }] },
      {
        id: 3,
        name: 'only-cancelled',
        conclusion: 'cancelled',
        steps: [{ name: 'Test', conclusion: 'cancelled' }],
      },
    ],
  };
  assert.deepEqual(pickFailedSteps(jobs), [{ jobId: 1, job: 'deep', step: SCA }]);
});

test('pickFailedSteps skips its own job and returns [] when nothing failed', () => {
  const jobs = {
    jobs: [
      { id: 7, name: 'notify / notify', steps: [{ name: 'Gate', conclusion: 'failure' }] },
      { id: 8, name: 'ok', steps: [{ name: 'a', conclusion: 'success' }] },
    ],
  };
  assert.deepEqual(pickFailedSteps(jobs, 7), []);
  assert.deepEqual(pickFailedSteps({ jobs: [] }), []);
  assert.deepEqual(pickFailedSteps({}), []);
});

test('AC1: a non-SCA failure names repo, step, job and run link — and no advisories line', () => {
  const msg = buildMessage({ ...base, failed: [{ job: 'deep', step: 'Gitleaks (secret scan)' }] });
  const t = text(msg);
  assert.match(t, /viorant-hub/);
  assert.match(t, /Gitleaks \(secret scan\)/);
  assert.match(t, /deep/);
  assert.match(t, /<https:\/\/github\.com\/viorant\/viorant-hub\/actions\/runs\/999\|/);
  assert.doesNotMatch(t, /GHSA|advisor/i);
  assert.match(msg.text, /viorant-hub/);
  assert.match(msg.text, /Gitleaks \(secret scan\)/);
  assert.doesNotMatch(msg.text, /<https?:/);
});

test('AC2: the SCA step failing lists "SEV ID module" per advisory', () => {
  const t = text(buildMessage({ ...base, failed: [{ job: 'deep', step: SCA, log: PNPM_LOG }] }));
  assert.match(t, /HIGH GHSA-aaaa-bbbb-cccc undici/);
  assert.match(t, /CRITICAL GHSA-dddd-eeee-ffff proxy-addr/);
  assert.match(t, /HIGH GHSA-gggg-hhhh-iiii @scope\/pkg/);
  assert.doesNotMatch(t, /listed/);
});

test('AC2: the SCA step name is overridable', () => {
  const step = 'SCA gate (HIGH/CRITICAL in shipped deps + expired suppressions)';
  const t = text(
    buildMessage({ ...base, scaStepName: step, failed: [{ job: 'scan', step, log: CLI_LOG }] }),
  );
  assert.match(t, /HIGH 1105444 tar/);
});

test('AC3: no failed step gives null', () => {
  assert.equal(buildMessage({ ...base, failed: [] }), null);
});

test('jobs unavailable (failed === null) still posts a generic line naming the run', () => {
  const msg = buildMessage({ ...base, failed: null });
  assert.match(text(msg), /viorant-hub/);
  assert.match(text(msg), /actions\/runs\/999/);
});

test('mrkdwn is escaped in step names, job names and advisory modules', () => {
  assert.equal(escapeMrkdwn('a<b>&c'), 'a&lt;b&gt;&amp;c');
  const t = text(
    buildMessage({
      ...base,
      failed: [{ job: 'j<1>', step: 'Step <script> & co' }],
    }),
  );
  assert.match(t, /Step &lt;script&gt; &amp; co/);
  assert.match(t, /j&lt;1&gt;/);
  assert.ok(!t.toLowerCase().includes('<script'), 'raw angle bracket leaked into mrkdwn');

  const log = withTs([
    '##[error]1 un-suppressed HIGH/CRITICAL advisory(ies) in shipped dependencies:',
    '  - HIGH GHSA-aaaa-bbbb-cccc evil<mod> — title',
  ]);
  const t2 = text(buildMessage({ ...base, failed: [{ job: 'd', step: SCA, log }] }));
  assert.match(t2, /evil&lt;mod&gt;/);
});

test('more than 10 advisories are capped with "+K more"', () => {
  const lines = ['##[error]13 un-suppressed HIGH/CRITICAL advisory(ies) in shipped dependencies:'];
  for (let i = 1; i <= 13; i++) {
    lines.push(`  - HIGH GHSA-${String(i).padStart(4, '0')}-xxxx-xxxx pkg${i} — t${i}`);
    lines.push('      fix: upgrade to 1 · https://x');
  }
  const t = text(buildMessage({ ...base, failed: [{ job: 'd', step: SCA, log: withTs(lines) }] }));
  assert.match(t, /pkg10\b/);
  assert.doesNotMatch(t, /pkg11\b/);
  assert.match(t, /\+3 more/);
});

// --- main() ------------------------------------------------------------------

function run(env, args = []) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SCRIPT, ...args], {
      env: { PATH: process.env.PATH, ...env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

test('AC4: SLACK_WEBHOOK unset — a loud ::warning:: and exit 0', async () => {
  const r = await run({ REPO: 'viorant/viorant-hub', RUN_ID: '1', RUN_URL: 'https://x/runs/1' });
  assert.equal(r.code, 0);
  assert.match(r.stderr, /::warning::notify-failure: SLACK_ENG_WEBHOOK absent — nothing posted/);
});

async function withSlack(status, fn) {
  const received = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      received.push(JSON.parse(body));
      res.statusCode = status;
      res.end(status === 200 ? 'ok' : 'nope');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    return await fn(`http://127.0.0.1:${server.address().port}/hook`, received);
  } finally {
    server.close();
  }
}

function fixtureDir(jobs, logs = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'notify-failure-'));
  if (jobs) writeFileSync(join(dir, 'jobs.json'), JSON.stringify(jobs));
  for (const [id, log] of Object.entries(logs)) writeFileSync(join(dir, `${id}.log`), log);
  return dir;
}

const failedJobs = {
  jobs: [{ id: 42, name: 'deep', steps: [{ name: SCA, conclusion: 'failure' }] }],
};

test('main posts the advisories line for a failed SCA step', async () => {
  const dir = fixtureDir(failedJobs, { 42: PNPM_LOG });
  await withSlack(200, async (url, received) => {
    const r = await run({
      SLACK_WEBHOOK: url,
      REPO: 'viorant/viorant-hub',
      RUN_URL: 'https://github.com/viorant/viorant-hub/actions/runs/5',
      JOBS_FILE: join(dir, 'jobs.json'),
      LOG_DIR: dir,
    });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(received.length, 1);
    assert.match(text(received[0]), /CRITICAL GHSA-dddd-eeee-ffff proxy-addr/);
  });
});

test('main posts nothing when no step failed (AC3)', async () => {
  const dir = fixtureDir({ jobs: [{ id: 1, name: 'a', steps: [{ name: 's', conclusion: 'success' }] }] });
  await withSlack(200, async (url, received) => {
    const r = await run({
      SLACK_WEBHOOK: url,
      REPO: 'viorant/viorant-hub',
      RUN_URL: 'https://x/runs/5',
      JOBS_FILE: join(dir, 'jobs.json'),
      LOG_DIR: dir,
    });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(received.length, 0);
  });
});

test('main falls back to a generic line when the jobs file is missing', async () => {
  await withSlack(200, async (url, received) => {
    const r = await run({
      SLACK_WEBHOOK: url,
      REPO: 'viorant/viorant-hub',
      RUN_URL: 'https://x/runs/5',
      JOBS_FILE: '/nonexistent/jobs.json',
    });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(received.length, 1);
    assert.match(text(received[0]), /viorant-hub/);
  });
});

test('a Slack error is a warning and exit 0, but exit 1 with --strict', async () => {
  const dir = fixtureDir(failedJobs);
  await withSlack(500, async (url) => {
    const env = {
      SLACK_WEBHOOK: url,
      REPO: 'viorant/viorant-hub',
      RUN_URL: 'https://x/runs/5',
      JOBS_FILE: join(dir, 'jobs.json'),
    };
    const soft = await run(env);
    assert.equal(soft.code, 0);
    assert.match(soft.stderr, /::warning::notify-failure: Slack POST failed 500/);
    const strict = await run(env, ['--strict']);
    assert.equal(strict.code, 1);
    assert.match(strict.stderr, /::error::notify-failure: Slack POST failed 500/);
  });
});
