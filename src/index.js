import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

const SECRET_PATTERNS = [
  [/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, 'GitHub token'],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/g, 'OpenAI-style API key'],
  [/\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g, 'Slack token'],
  [/-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, 'private key block'],
  [/\b[A-Za-z0-9_]*(?:SECRET|TOKEN|API_KEY|PRIVATE_KEY|PASSWORD)[A-Za-z0-9_]*\s*=\s*(?:['\"][^'\"]{8,}['\"]|\\['\"][^'\"]{8,}\\['\"]|[^\s&;]{8,})/gi, 'secret-looking assignment'],
  [/\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*\b/g, 'Bearer token']
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
  const redact = options.redact !== false;
  const stdoutRedaction = redact ? redactSecrets(stdout) : { text: stdout, redactions: [] };
  const stderrRedaction = redact ? redactSecrets(stderr) : { text: stderr, redactions: [] };
  const stdoutForLogs = stdoutRedaction.text;
  const stderrForLogs = stderrRedaction.text;
  const commandRedactions = redact ? [command, ...args].map(value => redactSecrets(String(value))) : [];
  const redactionStats = redact ? mergeRedactions(stdoutRedaction.redactions, stderrRedaction.redactions, ...commandRedactions.map(item => item.redactions)) : [];
  const commandForReport = redact ? commandRedactions.map(item => item.text) : [command, ...args];
  const report = {
    runId,
    command: commandForReport,
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
      storedRedacted: redact,
      redactions: redactionStats,
      stdoutTail: tail(stdoutForLogs, 80),
      stderrTail: tail(stderrForLogs, 80)
    },
    analysis
  };

  writeFileSync(join(outDir, 'stdout.log'), stdoutForLogs);
  writeFileSync(join(outDir, 'stderr.log'), stderrForLogs);
  writeFileSync(join(outDir, 'run.json'), JSON.stringify(report, null, 2));
  writeFileSync(join(outDir, 'report.md'), formatMarkdown(report));

  return { report, outDir };
}

export function redactSecrets(text) {
  const redactions = [];
  let redacted = text;
  for (const [pattern, label] of SECRET_PATTERNS) {
    let count = 0;
    redacted = redacted.replace(pattern, () => {
      count += 1;
      return `[REDACTED: ${label}]`;
    });
    pattern.lastIndex = 0;
    if (count) redactions.push({ label, count });
  }
  return { text: redacted, redactions };
}

export function analyzeOutput(text, exitCode = 0, durationMs = 0) {
  const findings = [];
  const safeText = redactSecrets(text).text;
  const lines = safeText.split(/\r?\n/).filter(Boolean);
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
  lines.push(`- Stored logs redacted: ${report.output.storedRedacted ? 'yes' : 'no'}`);
  lines.push('');
  lines.push('## Summary');
  lines.push(report.analysis.summary);
  lines.push('');
  if (report.output.redactions?.length) {
    lines.push('');
    lines.push('## Redactions');
    for (const item of report.output.redactions) lines.push(`- ${item.label}: ${item.count}`);
  }
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

function mergeRedactions(...groups) {
  const totals = new Map();
  for (const group of groups) {
    for (const item of group) totals.set(item.label, (totals.get(item.label) || 0) + item.count);
  }
  return [...totals.entries()].map(([label, count]) => ({ label, count }));
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
