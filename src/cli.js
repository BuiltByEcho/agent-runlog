#!/usr/bin/env node
import { runLogged } from './index.js';

function parse(argv) {
  const args = { outDir: undefined, cwd: process.cwd(), quiet: false, printJson: false, command: [] };
  let i = 0;
  for (; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') { args.command = argv.slice(i + 1); break; }
    if (arg === '--help' || arg === '-h') args.help = true;
    else if (arg === '--out' || arg === '-o') args.outDir = argv[++i];
    else if (arg === '--cwd') args.cwd = argv[++i];
    else if (arg === '--quiet' || arg === '-q') args.quiet = true;
    else if (arg === '--json') args.printJson = true;
    else if (!arg.startsWith('-')) { args.command = argv.slice(i); break; }
    else throw new Error(`Unknown option: ${arg}`);
  }
  return args;
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
  -h, --help        Show help

Examples:
  agent-runlog -- npm test
  agent-runlog -o .agent-runs/lint -- npm run lint
  agent-runlog --json -- node scripts/task.js > run.json
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
  const { report, outDir } = await runLogged(cmd, cmdArgs, { cwd: args.cwd, outDir: args.outDir, quiet: args.quiet || args.printJson });
  if (args.printJson) console.log(JSON.stringify({ outDir, ...report }, null, 2));
  else console.error(`\nagent-runlog: wrote ${outDir}/report.md`);
  process.exit(report.exitCode ?? 0);
} catch (error) {
  console.error(`agent-runlog: ${error.message}`);
  process.exit(1);
}
