#!/usr/bin/env node
// Failed-run → Slack notification. Zero-dependency (Node 22 global fetch).
//
// Called by .github/workflows/notify-failure.yml after a caller's job failed. It
// posts one line to #engineering: repo, failing step, job, run link. When the
// failing step is the SCA gate it adds the advisories the gate printed, so the
// message says what to upgrade without anyone opening the run.
//
// Env:
//   SLACK_WEBHOOK   Slack incoming webhook URL                        (required)
//   REPO            owner/name                                        (required)
//   RUN_URL         link to the failed run                            (required)
//   JOBS_FILE       the `actions/runs/<id>/jobs` payload, saved by the gate step
//                   (absent/unreadable → a generic line naming the run)
//   LOG_DIR         directory holding `<jobId>.log` for the SCA step's job
//   SCA_STEP_NAME   the step whose log is parsed   (default `SCA gate (prod tier)`)
//   SELF_JOB_ID     the notify job's own id, never reported            (optional)
//
// Exit 0 unless --strict is passed. A Slack hiccup must never read as a broken
// build: this runs after the failure it reports and gates nothing.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const DEFAULT_SCA_STEP = 'SCA gate (prod tier)';
const ADVISORY_CAP = 10;

// Slack parses `<url|label>` as a link and bare `&` as an entity start, so a step
// or module name carrying either would break or forge the links around it.
export function escapeMrkdwn(text) {
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Job logs prefix every line with an ISO timestamp (and sometimes a BOM on the
// first) and may carry ANSI colour.
export function stripLog(text) {
  return String(text ?? '')
    .replace(/\u001b\[[0-9;]*[A-Za-z]/g, '')
    .split('\n')
    .map((line) => line.replace(/\r$/, '').replace(/^﻿?\d{4}-\d\d-\d\dT[\d:.]+Z ?/, ''))
    .join('\n');
}

// scripts/security/audit-gate.mjs prints, on stderr:
//   ::error::N un-suppressed HIGH/CRITICAL advisory(ies) in shipped dependencies:
//     - SEV ID module — title
//         fix: upgrade to … · <url>              (pnpm gates)
//         vulnerable: <range> · <fix> · <url>    (viorant-cli)
//
//   Add a reviewed entry to security-ignore.yml to accept, or upgrade the dependency.
// A runner rewrites `::error::` to `##[error]` in the job log; both are accepted.
// Every indented continuation line is skipped rather than allow-listed, so a gate
// that words its second line differently still parses. The parse ends at the first
// line that is neither blank, a bullet nor indented (the trailer).
const HEADER = /(?:##\[error\]|::error::)\s*(\d+) un-suppressed HIGH\/CRITICAL advisory\(ies\) in shipped dependencies:/;
const BULLET = /^\s{1,3}-\s+([A-Z]+)\s+(\S+)\s+(\S+)(?:\s+—\s+(.*))?$/;
const CONTINUATION = /^\s{4,}\S/;

export function parseAdvisories(logText) {
  const lines = stripLog(logText).split('\n');
  const start = lines.findIndex((l) => HEADER.test(l));
  if (start === -1) return { declared: null, advisories: [] };

  const declared = Number(lines[start].match(HEADER)[1]);
  const advisories = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim() === '' || CONTINUATION.test(line)) continue;
    const m = line.match(BULLET);
    if (!m) break;
    advisories.push({ severity: m[1], id: m[2], module: m[3], title: m[4] ?? '' });
  }
  return { declared, advisories };
}

// The first failed step of each failed job. Cancelled and skipped steps are what
// a failure leaves behind, not the cause.
export function pickFailedSteps(jobs, selfJobId) {
  const out = [];
  for (const job of jobs?.jobs ?? []) {
    if (selfJobId != null && String(job.id) === String(selfJobId)) continue;
    const step = (job.steps ?? []).find((s) => s.conclusion === 'failure');
    if (step) out.push({ jobId: job.id, job: job.name, step: step.name });
  }
  return out;
}

function advisoriesLine({ declared, advisories }) {
  if (declared === null) return null;
  const shown = advisories
    .slice(0, ADVISORY_CAP)
    .map((a) => `${escapeMrkdwn(a.severity)} ${escapeMrkdwn(a.id)} ${escapeMrkdwn(a.module)}`);
  const more = advisories.length - ADVISORY_CAP;
  if (more > 0) shown.push(`+${more} more`);
  // A count that disagrees with the list means the gate's wording drifted from
  // this parser. Say so rather than present a partial list as the whole.
  const count =
    declared === advisories.length
      ? `${declared} ${declared === 1 ? 'advisory' : 'advisories'}`
      : `${declared} advisories, ${advisories.length} listed`;
  return shown.length ? `${count}: ${shown.join(', ')}` : count;
}

// ctx.failed: [{ job, step, log? }] — `null` means the jobs API was unavailable,
// so the failure is known (the caller's `if: failure()`) but not where. `[]`
// means nothing failed, which posts nothing.
export function buildMessage(ctx) {
  const { repo, runUrl, failed } = ctx;
  const scaStep = ctx.scaStepName || DEFAULT_SCA_STEP;
  const shortRepo = String(repo).split('/').pop();
  const link = `<${runUrl}|run>`;
  const lead = `🔴 *CI failed* · \`${escapeMrkdwn(shortRepo)}\``;

  if (failed === null || failed === undefined) {
    return {
      text: `CI failed — ${shortRepo}: ${runUrl}`,
      blocks: [{ type: 'section', text: { type: 'mrkdwn', text: `${lead} · ${link}` } }],
    };
  }
  if (failed.length === 0) return null;

  const lines = [];
  for (const f of failed) {
    lines.push(`${lead} · *${escapeMrkdwn(f.step)}* in \`${escapeMrkdwn(f.job)}\` · ${link}`);
    if (f.step === scaStep) {
      const adv = advisoriesLine(parseAdvisories(f.log));
      if (adv) lines.push(adv);
    }
  }
  return {
    text: `CI failed — ${shortRepo}: ${failed.map((f) => `${f.step} (${f.job})`).join('; ')}`,
    blocks: [{ type: 'section', text: { type: 'mrkdwn', text: lines.join('\n') } }],
  };
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

function readText(path) {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
}

async function main() {
  const strict = process.argv.includes('--strict');
  const env = process.env;
  const warn = (msg) => {
    console.error(`::${strict ? 'error' : 'warning'}::${msg}`);
    process.exit(strict ? 1 : 0);
  };

  // Loud but never a failure, even under --strict: a repo without the secret is a
  // wiring gap to fix, not a reason to turn a red run into two.
  if (!env.SLACK_WEBHOOK) {
    console.error('::warning::notify-failure: SLACK_ENG_WEBHOOK absent — nothing posted');
    process.exit(0);
  }
  const missing = ['REPO', 'RUN_URL'].filter((k) => !env[k]);
  if (missing.length) warn(`notify-failure: missing env ${missing.join(', ')} — nothing posted.`);

  const jobs = env.JOBS_FILE ? readJson(env.JOBS_FILE) : null;
  const failed = jobs
    ? pickFailedSteps(jobs, env.SELF_JOB_ID).map((f) => ({
        ...f,
        log: env.LOG_DIR ? readText(join(env.LOG_DIR, `${f.jobId}.log`)) : undefined,
      }))
    : null;

  const payload = buildMessage({
    repo: env.REPO,
    runUrl: env.RUN_URL,
    scaStepName: env.SCA_STEP_NAME,
    failed,
  });
  if (!payload) {
    console.log('notify-failure: no failed step — nothing posted');
    return;
  }

  const res = await fetch(env.SLACK_WEBHOOK, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) warn(`notify-failure: Slack POST failed ${res.status} ${await res.text().catch(() => '')}`);
  console.log(`notify-failure: posted failure for ${env.REPO}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`::warning::notify-failure: ${err.message}`);
    process.exit(process.argv.includes('--strict') ? 1 : 0);
  });
}
