# agent-runlog

Wrap any command and save a concise, safety-aware run log for agents.

AI agents do a lot of work through shell commands, test runs, linters, build scripts, and sub-agent CLIs. When something goes wrong, the transcript is usually messy and the useful evidence is buried. `agent-runlog` gives every run a small audit trail: command, duration, exit code, output tails, git state, and simple risk/loop/failure signals.

```bash
npx agent-runlog -- npm test
```

## What it writes

By default, logs go to `.agent-runs/<timestamp>/`:

- `report.md` — human/agent readable summary
- `run.json` — structured report for automation
- `stdout.log` — stdout, redacted by default
- `stderr.log` — stderr, redacted by default

## Install

```bash
npm install -g agent-runlog
```

Or run without installing:

```bash
npx agent-runlog -- npm test
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
- `--no-redact` — store raw stdout/stderr instead of redacted logs.

Examples:

```bash
agent-runlog -- npm test
agent-runlog -o .agent-runs/lint -- npm run lint
agent-runlog --json -- node scripts/migrate.js > run.json
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
import { runLogged } from 'agent-runlog';

const { report, outDir } = await runLogged('npm', ['test']);

// Preserve raw logs only when you really need them:
await runLogged('node', ['debug.js'], { redact: false });
console.log(report.analysis.summary, outDir);
```

## License

MIT

## Agent Skill

This package includes an OpenClaw/Claude-style skill at `skills/agent-runlog` that teaches agents when and how to wrap commands with `agent-runlog` for redacted run evidence and handoffs.
