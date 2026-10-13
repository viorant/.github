# Notify on failure

Posts one line to `#engineering` when a run failed:

| When | Message |
| --- | --- |
| A caller's run failed at a step other than the SCA gate | 🔴 **CI failed** · `repo` · **step** in `job` · run link |
| It failed at the **SCA gate** | the same line, then `N advisories: HIGH GHSA-… module, …` |
| Nothing failed | nothing |

The advisories line is the point: a red nightly SCA gate used to go unannounced
for days (VIOR-1422), and once announced it should say what to upgrade without
anyone opening the run. It carries `SEV ID module` for each advisory, capped at
10 with `+K more`. Titles and fix hints stay in the run.

## Wiring a repo up

Add a final job to the caller's workflow (`daily.yml`, `security-scan.yml`, …):

```yaml
  notify:
    needs: deep              # every job whose failure should be announced
    if: failure()
    permissions:
      contents: read
      actions: read
    uses: viorant/.github/.github/workflows/notify-failure.yml@main
    secrets: inherit
```

If the SCA step is not named `SCA gate (prod tier)` (the `security-scan.yml`
callers name it `SCA gate (HIGH/CRITICAL in shipped deps + expired
suppressions)`), pass it:

```yaml
    with:
      sca-step-name: 'SCA gate (HIGH/CRITICAL in shipped deps + expired suppressions)'
```

Requirements:

- **The caller job must grant `actions: read`.** A called workflow cannot raise
  its permissions above the caller's, and `daily.yml` sets a top-level
  `contents: read`, so this has to be on the `notify` job itself. Without it the
  jobs lookup fails, the run warns, and Slack gets a generic line that links the
  run but names no step.
- `if: failure()` is the first line of defence. The workflow checks the run's
  jobs again and posts nothing when no step failed, so a stray `always()` is
  harmless.
- `SLACK_ENG_WEBHOOK` must be visible to the repo (`secrets: inherit`). If it is
  not, the run logs `::warning::notify-failure: SLACK_ENG_WEBHOOK absent —
  nothing posted` and exits 0. It never fails, even with `--strict`. This is
  **not** `SLACK_RELEASE_WEBHOOK`; there is no fallback between them.

This workflow is not a required status check and cannot gate a merge.

## How the advisories are found

The gate step lists the run's jobs (`actions/runs/<id>/jobs`) and takes each
failed job's **first** step with conclusion `failure`. Cancelled and skipped steps
are what a failure leaves behind, not its cause. For a job whose failing step is
the SCA gate, it downloads that job's log. `notify.mjs` then parses the
header and bullets that `scripts/security/audit-gate.mjs` prints on stderr:

```
##[error]3 un-suppressed HIGH/CRITICAL advisory(ies) in shipped dependencies:
  - HIGH GHSA-aaaa-bbbb-cccc undici — Undici resource exhaustion
      fix: upgrade to >=6.21.1 · https://github.com/advisories/GHSA-aaaa-bbbb-cccc
```

Design and limits:

- The runner rewrites the gate's `::error::` to `##[error]` and prefixes each
  line with a timestamp. Both header forms are accepted, and timestamps and ANSI
  are stripped first.
- Every **indented** continuation line is skipped, so the pnpm gates' `fix:`
  line and the CLI's `vulnerable: <range> · <fix> · <url>` line both work with
  no allow-list. The CLI's id can be a non-GHSA number; any `\S+` id is taken.
- The parse stops at the first line that is not blank, a bullet or indented, which
  is the `Add a reviewed entry to security-ignore.yml…` trailer. The `Suppressed
  (still valid):` block is printed to stdout *before* the header, in lowercase, so
  it is never collected.
- The header carries a count. If it disagrees with the number of bullets parsed,
  the line reads `3 advisories, 2 listed`, so wording drift degrades visibly
  instead of passing a partial list off as complete.
- An **expired suppression** fails the same step but prints no header. The line
  names the step and has no advisories line.
- A log that cannot be fetched is a warning, and the line posts without
  advisories.

The parser is fixture-tested against the gate's source, not a captured live log.
The real proof is a forced failure on the first caller.

## Tests

```sh
node --test 'scripts/notify-failure/*.test.mjs'
```

`notify.mjs` exports `stripLog` / `parseAdvisories` / `pickFailedSteps` /
`buildMessage` / `escapeMrkdwn` as pure functions; only `main()` touches the
network. `main()` is tested against a local HTTP server. `ci.yml` also
shellchecks the workflow's gate script and asserts its contract (`workflow_call`
shape, the optional secret, `actions: read`), since `node --test` has no
zero-dependency YAML parser.
