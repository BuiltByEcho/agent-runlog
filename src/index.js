import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
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

const SEVERITY_RANK = { low: 1, medium: 2, high: 3 };

export async function runLogged(command, args = [], options = {}) {
  const cwd = resolve(options.cwd || process.cwd());
  const startedAt = new Date();
  const runId = options.runId || timestampId(startedAt);
  const outDir = resolve(cwd, options.outDir || join('.agent-runs', runId));
  mkdirSync(outDir, { recursive: true });

  const before = gitSnapshot(cwd);
  const stdoutChunks = [];
  const stderrChunks = [];
  const timeoutMs = normalizeTimeoutMs(options.timeoutMs);
  let timedOut = false;
  let timeoutHandle;
  let forceKillHandle;
  const child = spawn(command, args, {
    cwd,
    env: process.env,
    shell: options.shell ?? process.platform === 'win32'
  });

  if (timeoutMs) {
    timeoutHandle = setTimeout(() => {
      timedOut = true;
      child.kill(options.timeoutSignal || 'SIGTERM');
      forceKillHandle = setTimeout(() => child.kill('SIGKILL'), options.timeoutKillAfterMs || 5000);
    }, timeoutMs);
  }

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
  if (timeoutHandle) clearTimeout(timeoutHandle);
  if (forceKillHandle) clearTimeout(forceKillHandle);

  const endedAt = new Date();
  const stdout = Buffer.concat(stdoutChunks).toString('utf8');
  const stderr = Buffer.concat(stderrChunks).toString('utf8');
  const after = gitSnapshot(cwd);
  const output = `${stdout}\n${stderr}`;
  const analysis = analyzeOutput(output, exit.code, endedAt - startedAt, { timedOut, timeoutMs });
  const policy = evaluatePolicy(analysis.findings, options.failOnSeverity);
  if (policy.violated && analysis.status === 'success') analysis.status = 'failed';
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
    timedOut,
    timeoutMs: timeoutMs || null,
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
    analysis,
    policy
  };

  writeFileSync(join(outDir, 'stdout.log'), stdoutForLogs);
  writeFileSync(join(outDir, 'stderr.log'), stderrForLogs);
  writeFileSync(join(outDir, 'run.json'), JSON.stringify(report, null, 2));
  writeFileSync(join(outDir, 'report.md'), formatMarkdown(report));
  writeFileSync(join(outDir, 'handoff.md'), formatHandoffMarkdown(report, outDir));

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

export function analyzeOutput(text, exitCode = 0, durationMs = 0, options = {}) {
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
  if (options.timedOut) findings.push({ severity: 'medium', type: 'timeout', message: `Command exceeded timeout (${formatDuration(options.timeoutMs || durationMs)})` });
  if (exitCode !== 0 && exitCode !== null) findings.push({ severity: 'medium', type: 'exit', message: `Command exited non-zero (${exitCode})` });
  if (/\b(error|failed|exception|traceback|panic)\b/i.test(text)) findings.push({ severity: exitCode || options.timedOut ? 'medium' : 'low', type: 'error-text', message: 'Output contains error/failure language' });
  if (durationMs > 10 * 60 * 1000) findings.push({ severity: 'low', type: 'duration', message: 'Run lasted over 10 minutes' });
  return {
    status: exitCode === 0 && !options.timedOut ? 'success' : 'failed',
    findings,
    summary: summarize(lines, exitCode, findings, options)
  };
}

export function evaluatePolicy(findings = [], failOnSeverity) {
  if (!failOnSeverity) return { failOnSeverity: null, violated: false, matchedFindings: [] };
  const normalized = String(failOnSeverity).toLowerCase();
  const threshold = SEVERITY_RANK[normalized];
  if (!threshold) throw new Error(`Invalid failOnSeverity: ${failOnSeverity}`);
  const matchedFindings = findings.filter(finding => SEVERITY_RANK[finding.severity] >= threshold);
  return {
    failOnSeverity: normalized,
    violated: matchedFindings.length > 0,
    matchedFindings: matchedFindings.map(finding => ({
      severity: finding.severity,
      type: finding.type,
      message: finding.message
    }))
  };
}

export function formatMarkdown(report) {
  const cmd = report.command.map(shellQuote).join(' ');
  const lines = [];
  lines.push(`# Agent Runlog: ${report.runId}`);
  lines.push('');
  lines.push(`- Command: \`${cmd}\``);
  lines.push(`- CWD: \`${report.cwd}\``);
  const exitLabel = report.exitCode === null ? `signal ${report.signal || 'unknown'}` : `exit ${report.exitCode}`;
  lines.push(`- Status: **${report.analysis.status}** (${exitLabel})`);
  lines.push(`- Duration: ${formatDuration(report.durationMs)}`);
  if (report.timeoutMs) lines.push(`- Timeout: ${formatDuration(report.timeoutMs)}${report.timedOut ? ' (hit)' : ''}`);
  if (report.policy?.failOnSeverity) lines.push(`- Finding gate: ${report.policy.failOnSeverity}${report.policy.violated ? ' (violated)' : ' (passed)'}`);
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
  if (report.policy?.violated) {
    lines.push('## Finding gate');
    lines.push(`The \`${report.policy.failOnSeverity}\` gate was violated by ${report.policy.matchedFindings.length} finding(s).`);
    lines.push('');
  }
  lines.push('## Git state');
  lines.push(`- Before: ${report.git.before.branch || 'no git'} / ${report.git.before.status || 'unknown'}`);
  lines.push(`- After: ${report.git.after.branch || 'no git'} / ${report.git.after.status || 'unknown'}`);
  if (report.git.after.diffStat) lines.push(`- Diffstat after run: ${summarizeDiffStat(report.git.after.diffStat)}`);
  if (report.git.after.changedFiles?.length) {
    lines.push('- Changed files after run:');
    for (const file of report.git.after.changedFiles.slice(0, 20)) lines.push(`  - ${file.path} (${file.status})`);
    if (report.git.after.changedFiles.length > 20) lines.push(`  - ... ${report.git.after.changedFiles.length - 20} more`);
  }
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

export function formatHandoffMarkdown(report, outDir = '') {
  const cmd = report.command.map(shellQuote).join(' ');
  const exitLabel = report.exitCode === null ? `signal ${report.signal || 'unknown'}` : `exit ${report.exitCode}`;
  const findings = report.analysis.findings.slice(0, 5);
  const lines = [];
  lines.push(`## Agent Run Handoff: ${report.analysis.status}`);
  lines.push('');
  lines.push(`- Command: \`${cmd}\``);
  lines.push(`- Result: ${report.analysis.status} (${exitLabel}, ${formatDuration(report.durationMs)})`);
  if (report.timedOut) lines.push(`- Timeout: hit after ${formatDuration(report.timeoutMs || report.durationMs)}`);
  if (report.policy?.failOnSeverity) lines.push(`- Finding gate: ${report.policy.failOnSeverity}${report.policy.violated ? ' (violated)' : ' (passed)'}`);
  lines.push(`- CWD: \`${report.cwd}\``);
  if (outDir) {
    lines.push(`- Evidence: \`${outDir}/report.md\`, \`${outDir}/run.json\`, \`${outDir}/stdout.log\`, \`${outDir}/stderr.log\``);
  }
  lines.push('');
  lines.push('### Summary');
  lines.push(report.analysis.summary);
  lines.push('');
  lines.push('### Findings');
  if (findings.length) {
    for (const finding of findings) lines.push(`- [${finding.severity}] ${finding.type}: ${finding.message}`);
    if (report.analysis.findings.length > findings.length) lines.push(`- ${report.analysis.findings.length - findings.length} more finding(s) in the full report.`);
  } else {
    lines.push('- No obvious risk/loop/failure signals detected.');
  }
  lines.push('');
  lines.push('### Git');
  lines.push(`- Before: ${report.git.before.branch || 'no git'} / ${summarizeGitStatus(report.git.before.status)}`);
  lines.push(`- After: ${report.git.after.branch || 'no git'} / ${summarizeGitStatus(report.git.after.status)}`);
  if (report.git.after.diffStat) lines.push(`- Diffstat after run: ${summarizeDiffStat(report.git.after.diffStat)}`);
  if (report.git.after.changedFiles?.length) lines.push(`- Changed files after run: ${summarizeChangedFiles(report.git.after.changedFiles)}`);
  lines.push('');
  lines.push('### Next');
  if (report.analysis.status === 'success') {
    lines.push('- Treat this run as passing evidence for the current change.');
  } else if (report.policy?.violated) {
    lines.push('- Inspect the policy-matching findings before treating this run as safe to share or merge.');
  } else if (report.timedOut) {
    lines.push('- Inspect the output tails, then rerun with a longer timeout or disable watch/interactive mode.');
  } else {
    lines.push('- Inspect the output tails and fix the highest-severity finding before rerunning.');
  }
  lines.push('');
  return lines.join('\n');
}

export function writeHandoffFiles(report, outDir, options = {}) {
  const markdown = formatHandoffMarkdown(report, outDir);
  if (options.handoffFile) writeFileSync(resolve(report.cwd, options.handoffFile), markdown);
  if (options.githubSummaryFile) appendFileSync(resolve(report.cwd, options.githubSummaryFile), `${markdown}\n`);
  return markdown;
}

function gitSnapshot(cwd) {
  if (!existsSync(join(cwd, '.git'))) return { branch: '', status: 'not a git repo', diffStat: '', changedFiles: [] };
  const status = git(cwd, ['status', '--short']) || 'clean';
  return {
    branch: git(cwd, ['branch', '--show-current']),
    status,
    diffStat: git(cwd, ['diff', '--stat']),
    changedFiles: parseGitStatus(status)
  };
}

function summarizeGitStatus(status) {
  if (!status) return 'unknown';
  if (status === 'clean' || status === 'not a git repo') return status;
  const lines = status.split(/\r?\n/).filter(Boolean);
  if (lines.length === 1) return lines[0];
  const staged = lines.filter(line => line[0] !== ' ' && line[0] !== '?').length;
  const unstaged = lines.filter(line => line[1] && line[1] !== ' ').length;
  const untracked = lines.filter(line => line.startsWith('??')).length;
  const parts = [`${lines.length} changed file(s)`];
  if (staged) parts.push(`${staged} staged`);
  if (unstaged) parts.push(`${unstaged} unstaged`);
  if (untracked) parts.push(`${untracked} untracked`);
  return parts.join(', ');
}

function summarizeDiffStat(diffStat) {
  const lines = diffStat.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  return lines.at(-1) || diffStat;
}

function summarizeChangedFiles(files, limit = 6) {
  const shown = files.slice(0, limit).map(file => `${file.path} (${file.status})`);
  if (files.length > limit) shown.push(`... ${files.length - limit} more`);
  return shown.join(', ');
}

function parseGitStatus(status) {
  if (!status || status === 'clean' || status === 'not a git repo') return [];
  return status.split(/\r?\n/)
    .filter(Boolean)
    .map(line => {
      const match = line.match(/^(.{1,2})\s+(.+)$/);
      const rawStatus = match ? match[1] : line.slice(0, 2);
      const pathText = (match ? match[2] : line.slice(2)).trim();
      const [from, to] = pathText.includes(' -> ') ? pathText.split(' -> ') : ['', pathText];
      const entry = { status: normalizeGitStatus(rawStatus), path: to || pathText };
      if (from) entry.previousPath = from;
      return entry;
    });
}

function normalizeGitStatus(rawStatus) {
  if (rawStatus === '??') return 'untracked';
  if (rawStatus === '!!') return 'ignored';
  const labels = {
    A: 'added',
    C: 'copied',
    D: 'deleted',
    M: 'modified',
    R: 'renamed',
    T: 'type-changed',
    U: 'unmerged'
  };
  const codes = [...new Set(rawStatus.trim().split('').filter(Boolean))];
  return codes.map(code => labels[code] || code).join('+') || rawStatus.trim();
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

function summarize(lines, exitCode, findings, options = {}) {
  const parts = [];
  if (options.timedOut) parts.push(`Command timed out after ${formatDuration(options.timeoutMs || 0)}.`);
  else parts.push(exitCode === 0 ? 'Command completed successfully.' : `Command failed with exit code ${exitCode}.`);
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

function normalizeTimeoutMs(value) {
  if (value === undefined || value === null || value === false) return 0;
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) throw new Error('timeoutMs must be a positive number');
  return Math.round(number);
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
