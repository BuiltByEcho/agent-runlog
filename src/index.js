import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

const SECRET_PATTERNS = [
  [/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, 'GitHub token'],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/g, 'OpenAI-style API key'],
  [/\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g, 'Slack token'],
  [/-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, 'private key block'],
  [/\b[A-Za-z0-9_]*(?:SECRET|TOKEN|API_KEY|PRIVATE_KEY|PASSWORD)[A-Za-z0-9_]*\s*=\s*['\"][^'\"]{8,}['\"]/gi, 'secret-looking assignment']
];

export async function runLogged(command, args = [], options = {}) {
  const cwd = resolve(options.cwd || process.cwd());
  const startedAt = new Date();
  const runId = options.runId || timestampId(startedAt);
  const outDir = resolve(cwd, options.outDir || join('.agent-runs', runId));
  mkdirSync(outDir, { recursive: true });

  const before = gitSnapshot(cwd);
  const stdoutChunks = [];
  const stderrChunks = [];
  const child = spawn(command, args, {
    cwd,
    env: process.env,
    shell: options.shell ?? process.platform === 'win32'
  });

  child.stdout?.on('data', chunk => {
    stdoutChunks.push(chunk);
    if (!options.quiet) process.stdout.write(chunk);
  });
  child.stderr?.on('data', chunk => {
    stderrChunks.push(chunk);
    if (!options.quiet) process.stderr.write(chunk);
  });

  const exit = await new Promise(resolveExit => {
    child.on('error', error => resolveExit({ code: 127, signal: null, error: error.message }));
    child.on('close', (code, signal) => resolveExit({ code, signal, error: null }));
  });

  const endedAt = new Date();
  const stdout = Buffer.concat(stdoutChunks).toString('utf8');
  const stderr = Buffer.concat(stderrChunks).toString('utf8');
  const after = gitSnapshot(cwd);
  const output = `${stdout}\n${stderr}`;
  const analysis = analyzeOutput(output, exit.code, endedAt - startedAt);
  const report = {
    runId,
    command: [command, ...args],
    cwd,
    startedAt: startedAt.toISOString(),
    endedAt: endedAt.toISOString(),
    durationMs: endedAt - startedAt,
    exitCode: exit.code,
    signal: exit.signal,
    spawnError: exit.error,
    git: { before, after },
    output: {
      stdoutBytes: Buffer.byteLength(stdout),
      stderrBytes: Buffer.byteLength(stderr),
      stdoutTail: tail(stdout, 80),
      stderrTail: tail(stderr, 80)
    },
    analysis
  };

  writeFileSync(join(outDir, 'stdout.log'), stdout);
  writeFileSync(join(outDir, 'stderr.log'), stderr);
  writeFileSync(join(outDir, 'run.json'), JSON.stringify(report, null, 2));
  writeFileSync(join(outDir, 'report.md'), formatMarkdown(report));

  return { report, outDir };
}

export function analyzeOutput(text, exitCode = 0, durationMs = 0) {
  const findings = [];
  const lines = text.split(/\r?\n/).filter(Boolean);
  const repeated = repeatedLines(lines);
  for (const item of repeated.slice(0, 5)) {
    findings.push({ severity: item.count >= 10 ? 'medium' : 'low', type: 'repetition', message: `Repeated line ${item.count}x: ${item.line.slice(0, 140)}` });
  }
  for (const [pattern, label] of SECRET_PATTERNS) {
    if (pattern.test(text)) findings.push({ severity: 'high', type: 'secret', message: `Output contains ${label}` });
    pattern.lastIndex = 0;
  }
  if (exitCode !== 0) findings.push({ severity: 'medium', type: 'exit', message: `Command exited non-zero (${exitCode})` });
  if (/\b(error|failed|exception|traceback|panic)\b/i.test(text)) findings.push({ severity: exitCode ? 'medium' : 'low', type: 'error-text', message: 'Output contains error/failure language' });
  if (durationMs > 10 * 60 * 1000) findings.push({ severity: 'low', type: 'duration', message: 'Run lasted over 10 minutes' });
  return {
    status: exitCode === 0 ? 'success' : 'failed',
    findings,
    summary: summarize(lines, exitCode, findings)
  };
}

export function formatMarkdown(report) {
  const cmd = report.command.map(shellQuote).join(' ');
  const lines = [];
  lines.push(`# Agent Runlog: ${report.runId}`);
  lines.push('');
  lines.push(`- Command: \`${cmd}\``);
  lines.push(`- CWD: \`${report.cwd}\``);
  lines.push(`- Status: **${report.analysis.status}** (exit ${report.exitCode})`);
  lines.push(`- Duration: ${formatDuration(report.durationMs)}`);
  lines.push(`- Started: ${report.startedAt}`);
  lines.push('');
  lines.push('## Summary');
  lines.push(report.analysis.summary);
  lines.push('');
  lines.push('## Findings');
  if (report.analysis.findings.length) {
    for (const f of report.analysis.findings) lines.push(`- [${f.severity}] ${f.type}: ${f.message}`);
  } else {
    lines.push('- No obvious risk/loop/failure signals detected.');
  }
  lines.push('');
  lines.push('## Git state');
  lines.push(`- Before: ${report.git.before.branch || 'no git'} / ${report.git.before.status || 'unknown'}`);
  lines.push(`- After: ${report.git.after.branch || 'no git'} / ${report.git.after.status || 'unknown'}`);
  if (report.git.after.diffStat) lines.push(`- Diffstat after run: ${report.git.after.diffStat}`);
  lines.push('');
  lines.push('## Output tails');
  lines.push('### stdout');
  lines.push('```text');
  lines.push(report.output.stdoutTail || '(empty)');
  lines.push('```');
  lines.push('');
  lines.push('### stderr');
  lines.push('```text');
  lines.push(report.output.stderrTail || '(empty)');
  lines.push('```');
  lines.push('');
  return lines.join('\n');
}

function gitSnapshot(cwd) {
  if (!existsSync(join(cwd, '.git'))) return { branch: '', status: 'not a git repo', diffStat: '' };
  return {
    branch: git(cwd, ['branch', '--show-current']),
    status: git(cwd, ['status', '--short']) || 'clean',
    diffStat: git(cwd, ['diff', '--stat'])
  };
}

function git(cwd, args) {
  try { return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return ''; }
}

function repeatedLines(lines) {
  const counts = new Map();
  for (const raw of lines) {
    const line = raw.trim();
    if (line.length < 8) continue;
    counts.set(line, (counts.get(line) || 0) + 1);
  }
  return [...counts.entries()].filter(([, count]) => count >= 3).map(([line, count]) => ({ line, count })).sort((a, b) => b.count - a.count);
}

function summarize(lines, exitCode, findings) {
  const parts = [];
  parts.push(exitCode === 0 ? 'Command completed successfully.' : `Command failed with exit code ${exitCode}.`);
  parts.push(`Captured ${lines.length} non-empty output line(s).`);
  const high = findings.filter(f => f.severity === 'high').length;
  const medium = findings.filter(f => f.severity === 'medium').length;
  if (high || medium) parts.push(`Detected ${high} high and ${medium} medium severity finding(s).`);
  else parts.push('No high/medium severity findings detected.');
  return parts.join(' ');
}

function tail(text, maxLines) {
  return text.split(/\r?\n/).slice(-maxLines).join('\n').trim();
}

function timestampId(date) {
  return date.toISOString().replace(/[:.]/g, '-');
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  const s = Math.round(ms / 100) / 10;
  return `${s}s`;
}

function shellQuote(value) {
  if (/^[A-Za-z0-9_./:=@-]+$/.test(value)) return value;
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}
