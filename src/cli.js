#!/usr/bin/env node
import { runLogged, writeHandoffFiles } from './index.js';

function parse(argv) {
  const args = { outDir: undefined, cwd: process.cwd(), quiet: false, printJson: false, redact: true, timeoutMs: undefined, failOnSeverity: undefined, handoffFile: undefined, githubSummary: false, command: [] };
  let i = 0;
  for (; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') { args.command = argv.slice(i + 1); break; }
    if (arg === '--help' || arg === '-h') args.help = true;
    else if (arg === '--out' || arg === '-o') args.outDir = argv[++i];
    else if (arg === '--cwd') args.cwd = argv[++i];
    else if (arg === '--quiet' || arg === '-q') args.quiet = true;
    else if (arg === '--json') args.printJson = true;
    else if (arg === '--timeout') args.timeoutMs = parseDuration(argv[++i]);
    else if (arg === '--fail-on') args.failOnSeverity = parseSeverity(argv[++i]);
    else if (arg === '--handoff') args.handoffFile = argv[++i];
    else if (arg === '--github-summary') args.githubSummary = true;
    else if (arg === '--no-redact') args.redact = false;
    else if (!arg.startsWith('-')) { args.command = argv.slice(i); break; }
    else throw new Error(`Unknown option: ${arg}`);
  }
  return args;
}

function parseDuration(value) {
  if (!value) throw new Error('Missing value for --timeout');
  const match = String(value).trim().match(/^(\d+(?:\.\d+)?)(ms|s|m|h)?$/i);
  if (!match) throw new Error(`Invalid timeout duration: ${value}`);
  const amount = Number(match[1]);
  const unit = (match[2] || 'ms').toLowerCase();
  const multiplier = unit === 'h' ? 3600000 : unit === 'm' ? 60000 : unit === 's' ? 1000 : 1;
  return Math.round(amount * multiplier);
}

function parseSeverity(value) {
  if (!value) throw new Error('Missing value for --fail-on');
  const normalized = String(value).toLowerCase();
  if (!['high', 'medium', 'low'].includes(normalized)) {
    throw new Error(`Invalid --fail-on severity: ${value}. Use high, medium, or low.`);
  }
  return normalized;
}

function help() {
  return `agent-runlog — wrap any command and save a concise agent run audit log

Usage:
  agent-runlog [options] -- <command> [args...]
  agent-runlog [options] <command> [args...]

Options:
  -o, --out DIR     Output directory (default: .agent-runs/<timestamp>)
      --cwd DIR     Working directory for command (default: current directory)
  -q, --quiet       Do not mirror child output to terminal
      --json        Print the run report JSON to stdout after completion
      --timeout N   Stop the command after a duration (e.g. 30s, 5m, 1h)
      --fail-on S   Fail wrapper if findings include severity S or higher
                    S must be high, medium, or low
      --handoff F   Also write a compact handoff summary to file F
      --github-summary
                    Append the compact handoff to $GITHUB_STEP_SUMMARY
      --no-redact   Store raw stdout/stderr logs instead of redacted logs
  -h, --help        Show help

Examples:
  agent-runlog -- npm test
  agent-runlog -o .agent-runs/lint -- npm run lint
  agent-runlog --json -- node scripts/task.js > run.json
  agent-runlog --timeout 5m -- npm test
  agent-runlog --fail-on high -- npm test
  agent-runlog --handoff /tmp/test-handoff.md -- npm test
`;
}

try {
  const args = parse(process.argv.slice(2));
  if (args.help) {
    console.log(help());
    process.exit(0);
  }
  if (!args.command.length) throw new Error('Missing command. Use -- before the command if needed.');
  const [cmd, ...cmdArgs] = args.command;
  const { report, outDir } = await runLogged(cmd, cmdArgs, { cwd: args.cwd, outDir: args.outDir, quiet: args.quiet || args.printJson, redact: args.redact, timeoutMs: args.timeoutMs, failOnSeverity: args.failOnSeverity });
  if (args.handoffFile || args.githubSummary) {
    const githubSummaryFile = args.githubSummary ? process.env.GITHUB_STEP_SUMMARY : undefined;
    if (args.githubSummary && !githubSummaryFile) throw new Error('--github-summary requires GITHUB_STEP_SUMMARY to be set');
    writeHandoffFiles(report, outDir, { handoffFile: args.handoffFile, githubSummaryFile });
  }
  if (args.printJson) console.log(JSON.stringify({ outDir, ...report }, null, 2));
  else console.error(`\nagent-runlog: wrote ${outDir}/report.md`);
  process.exit(report.policy?.violated ? 1 : report.exitCode ?? 0);
} catch (error) {
  console.error(`agent-runlog: ${error.message}`);
  process.exit(1);
}
