# agent-runlog

Wrap any command and save a concise, safety-aware run log for agents.

AI agents do a lot of work through shell commands, test runs, linters, build scripts, and sub-agent CLIs. When something goes wrong, the transcript is usually messy and the useful evidence is buried. `agent-runlog` gives every run a small audit trail: command, duration, exit code, output tails, git state, and simple risk/loop/failure signals.

```bash
npx @builtbyecho/agent-runlog -- npm test
```

## What it writes

By default, logs go to `.agent-runs/<timestamp>/`:

- `report.md` — human/agent readable summary
- `handoff.md` — compact paste-ready summary for another agent, a PR comment, or CI step summary
- `run.json` — structured report for automation
- `stdout.log` — stdout, redacted by default
- `stderr.log` — stderr, redacted by default

When run inside a git repository, the report includes the branch, compact status, diffstat, and changed paths after the command. That makes it easier to answer “what did this test/build/script touch?” from the handoff alone.

## Install

```bash
npm install -g @builtbyecho/agent-runlog
```

Or run without installing:

```bash
npx @builtbyecho/agent-runlog -- npm test
```

## Usage

```bash
agent-runlog [options] -- <command> [args...]
```

Options:

- `--out DIR` / `-o` — output directory. Default: `.agent-runs/<timestamp>`.
- `--cwd DIR` — working directory for the command.
- `--quiet` / `-q` — do not mirror child output to terminal.
- `--json` — print the final report JSON to stdout.
- `--timeout N` — stop hung commands after a duration like `30s`, `5m`, or `1h`.
- `--fail-on high|medium|low` — fail the wrapper if findings include that severity or higher.
- `--handoff FILE` — also write the compact handoff summary to a specific file.
- `--github-summary` — append the compact handoff to `$GITHUB_STEP_SUMMARY`.
- `--no-redact` — store raw stdout/stderr instead of redacted logs.

Examples:

```bash
agent-runlog -- npm test
agent-runlog -o .agent-runs/lint -- npm run lint
agent-runlog --json -- node scripts/migrate.js > run.json
agent-runlog --timeout 5m -- npm test
agent-runlog --fail-on high -- npm test
agent-runlog --handoff /tmp/test-handoff.md -- npm test
GITHUB_STEP_SUMMARY="$GITHUB_STEP_SUMMARY" agent-runlog --github-summary -- npm test
agent-runlog --no-redact -- node scripts/debug-local.js
```

## Why this exists

Agent observability tools are getting powerful, but sometimes you need the boring local primitive: wrap a command, capture the evidence, and make it easy for the next agent or human to see what happened.

This is useful for:

- coding agents running tests/builds
- CI repros
- long-running CLI tasks
- sub-agent harnesses
- debugging repeated failure loops

## Timeout guard

Agents sometimes get stuck behind watch modes, stalled network calls, or tests that never settle. Add `--timeout` to turn those hangs into useful evidence instead of an endless wait:

```bash
agent-runlog --timeout 10m -- npm test
```

When the timeout is hit, `agent-runlog` sends `SIGTERM`, records `timedOut: true` and `timeoutMs` in `run.json`, marks the run as failed, and adds a timeout finding to `report.md`.

## Finding gates

Sometimes a command exits successfully while still printing something that should block sharing or merging: a leaked token, repeated failure loop, or error text hidden in a long transcript.

Use `--fail-on` to turn findings into a CI-style gate:

```bash
agent-runlog --fail-on high -- npm test
agent-runlog --fail-on medium -- npm run build
```

The wrapped command's original `exitCode` is still preserved in `run.json`. If the gate is violated, the `agent-runlog` process exits `1`, records `policy.violated: true`, and marks the report status as failed so CI and agents can treat it as blocking evidence.

## Agent handoffs

Every run now includes `handoff.md`, a shorter summary designed for the next agent or human who needs the result without reading a full transcript. It includes:

- the command, status, duration, and working directory
- links to the generated evidence files
- the top findings
- git state before/after the run, including changed paths after the run
- a suggested next step

Use `--handoff FILE` when you want a stable summary path outside `.agent-runs/`, for example:

```bash
agent-runlog --handoff .agent-runs/latest-handoff.md -- npm test
```

In GitHub Actions, `--github-summary` appends the same compact summary to the job summary:

```yaml
- name: Test with run evidence
  run: npx @builtbyecho/agent-runlog --github-summary -- npm test
```

## Redaction by default

Agent logs often accidentally capture API keys, bearer tokens, private keys, or `.env`-style assignments. `agent-runlog` now redacts obvious secret-looking values before writing `stdout.log`, `stderr.log`, `run.json`, and `report.md`. The original byte counts are still recorded, and the report includes redaction counts by type.

If you explicitly need raw logs for a local-only debugging session, pass `--no-redact`. Be careful before sharing those logs with another agent or human.

## What it detects

`agent-runlog` currently flags:

- repeated output lines that may indicate loops
- non-zero exits
- error/failure language
- obvious secret-looking output patterns
- very long runs

It is not a full secret scanner or observability platform. It is a tiny portable run ledger.

## Library API

```js
import { runLogged } from '@builtbyecho/agent-runlog';

const { report, outDir } = await runLogged('npm', ['test'], { timeoutMs: 5 * 60 * 1000 });

// Fail the wrapper when high-severity findings are detected:
await runLogged('npm', ['test'], { failOnSeverity: 'high' });

// Preserve raw logs only when you really need them:
await runLogged('node', ['debug.js'], { redact: false });
console.log(report.analysis.summary, outDir);
```

## License

MIT

## Agent Skill

This package includes an OpenClaw/Claude-style skill at `skills/agent-runlog` that teaches agents when and how to wrap commands with `agent-runlog` for redacted run evidence and handoffs.

## Package Names

`@builtbyecho/agent-runlog` is the canonical package. The older unscoped `agent-runlog` package remains on npm as a compatibility package for historical installs.
