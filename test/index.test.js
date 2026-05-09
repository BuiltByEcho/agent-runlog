import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { analyzeOutput, formatHandoffMarkdown, redactSecrets, runLogged, writeHandoffFiles } from '../src/index.js';

test('analyzeOutput detects repeated lines and non-zero exits', () => {
  const text = ['looping forever', 'looping forever', 'looping forever', 'Error: nope'].join('\n');
  const analysis = analyzeOutput(text, 1, 100);
  assert.equal(analysis.status, 'failed');
  assert.ok(analysis.findings.some(f => f.type === 'repetition'));
  assert.ok(analysis.findings.some(f => f.type === 'exit'));
});

test('runLogged writes report files', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'agent-runlog-'));
  const { report, outDir } = await runLogged(process.execPath, ['-e', 'console.log("ok")'], { cwd: dir, quiet: true, outDir: 'runs/demo' });
  assert.equal(report.exitCode, 0);
  assert.equal(report.analysis.status, 'success');
  assert.ok(existsSync(join(outDir, 'report.md')));
  assert.ok(existsSync(join(outDir, 'run.json')));
  assert.ok(existsSync(join(outDir, 'handoff.md')));
  assert.match(readFileSync(join(outDir, 'stdout.log'), 'utf8'), /ok/);
});

test('secret-looking output is high severity', () => {
  const analysis = analyzeOutput('API_TOKEN="super-secret-token-value"', 0, 10);
  assert.ok(analysis.findings.some(f => f.severity === 'high' && f.type === 'secret'));
});


test('redactSecrets replaces sensitive-looking output and reports counts', () => {
  const raw = 'saw ghp_abcdefghijklmnopqrstuvwxyz123456 and API_TOKEN=\\"super-secret-token-value\\" and Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456';
  const { text, redactions } = redactSecrets(raw);
  assert.doesNotMatch(text, /ghp_abcdefghijklmnopqrstuvwxyz123456/);
  assert.doesNotMatch(text, /super-secret-token-value/);
  assert.doesNotMatch(text, /abcdefghijklmnopqrstuvwxyz123456/);
  assert.match(text, /\[REDACTED: GitHub token\]/);
  assert.ok(redactions.some(r => r.label === 'GitHub token' && r.count === 1));
  assert.ok(redactions.some(r => r.label === 'Bearer token' && r.count === 1));
});

test('runLogged redacts stored logs by default', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'agent-runlog-redact-'));
  const secret = 'API_TOKEN="super-secret-token-value"';
  const { report, outDir } = await runLogged(process.execPath, ['-e', `console.log(${JSON.stringify(secret)})`], { cwd: dir, quiet: true, outDir: 'runs/redact' });
  const stored = readFileSync(join(outDir, 'stdout.log'), 'utf8');
  assert.equal(report.output.storedRedacted, true);
  assert.doesNotMatch(stored, /super-secret-token-value/);
  assert.match(stored, /\[REDACTED: secret-looking assignment\]/);
  assert.ok(report.output.redactions.some(r => r.label === 'secret-looking assignment'));
});

test('runLogged can preserve raw logs when redaction is disabled', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'agent-runlog-raw-'));
  const secret = 'API_TOKEN="super-secret-token-value"';
  const { report, outDir } = await runLogged(process.execPath, ['-e', `console.log(${JSON.stringify(secret)})`], { cwd: dir, quiet: true, outDir: 'runs/raw', redact: false });
  const stored = readFileSync(join(outDir, 'stdout.log'), 'utf8');
  assert.equal(report.output.storedRedacted, false);
  assert.match(stored, /super-secret-token-value/);
});


test('analyzeOutput does not leak repeated secret values in findings', () => {
  const raw = Array(3).fill('API_TOKEN="super-secret-token-value"').join('\n');
  const analysis = analyzeOutput(raw, 0, 10);
  const serialized = JSON.stringify(analysis);
  assert.doesNotMatch(serialized, /super-secret-token-value/);
  assert.match(serialized, /REDACTED/);
});

test('runLogged redacts secret-looking command arguments in reports', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'agent-runlog-command-redact-'));
  const secretArg = 'API_TOKEN="super-secret-token-value"';
  const { report } = await runLogged(process.execPath, ['-e', 'console.log("ok")', secretArg], { cwd: dir, quiet: true, outDir: 'runs/cmd-redact' });
  assert.equal(report.output.storedRedacted, true);
  assert.doesNotMatch(JSON.stringify(report.command), /super-secret-token-value/);
  assert.match(JSON.stringify(report.command), /REDACTED/);
});

test('runLogged can stop hung commands with timeoutMs', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'agent-runlog-timeout-'));
  const { report, outDir } = await runLogged(process.execPath, ['-e', 'setTimeout(() => console.log("too late"), 1000)'], { cwd: dir, quiet: true, outDir: 'runs/timeout', timeoutMs: 50, timeoutKillAfterMs: 50 });
  assert.equal(report.timedOut, true);
  assert.equal(report.timeoutMs, 50);
  assert.equal(report.analysis.status, 'failed');
  assert.ok(report.analysis.findings.some(f => f.type === 'timeout'));
  assert.match(readFileSync(join(outDir, 'report.md'), 'utf8'), /Timeout: 50ms \(hit\)/);
});

test('formatHandoffMarkdown produces compact shareable run evidence', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'agent-runlog-handoff-'));
  const { report, outDir } = await runLogged(process.execPath, ['-e', 'console.log("handoff ok")'], { cwd: dir, quiet: true, outDir: 'runs/handoff' });
  const handoff = formatHandoffMarkdown(report, outDir);
  assert.match(handoff, /Agent Run Handoff: success/);
  assert.match(handoff, /Evidence:/);
  assert.match(handoff, /Treat this run as passing evidence/);
  assert.match(readFileSync(join(outDir, 'handoff.md'), 'utf8'), /handoff/);
});

test('formatHandoffMarkdown keeps dirty git state compact', () => {
  const report = {
    command: ['npm', 'test'],
    exitCode: 0,
    signal: null,
    durationMs: 1200,
    timedOut: false,
    cwd: '/tmp/example',
    analysis: { status: 'success', summary: 'Command completed successfully.', findings: [] },
    git: {
      before: { branch: 'main', status: ' M README.md\n M src/index.js', diffStat: '' },
      after: { branch: 'main', status: ' M README.md\n M src/index.js', diffStat: ' README.md | 2 +-\n src/index.js | 4 +++-\n 2 files changed, 4 insertions(+), 2 deletions(-)' }
    }
  };
  const handoff = formatHandoffMarkdown(report, '/tmp/example/.agent-runs/demo');
  assert.match(handoff, /2 changed file\(s\), 2 unstaged/);
  assert.match(handoff, /2 files changed, 4 insertions\(\+\), 2 deletions\(-\)/);
  assert.doesNotMatch(handoff, /\n M README\.md/);
});

test('writeHandoffFiles writes custom and GitHub summary files', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'agent-runlog-handoff-files-'));
  const { report, outDir } = await runLogged(process.execPath, ['-e', 'console.log("summary ok")'], { cwd: dir, quiet: true, outDir: 'runs/handoff-files' });
  writeHandoffFiles(report, outDir, { handoffFile: 'custom-handoff.md', githubSummaryFile: 'github-summary.md' });
  assert.match(readFileSync(join(dir, 'custom-handoff.md'), 'utf8'), /Agent Run Handoff: success/);
  assert.match(readFileSync(join(dir, 'github-summary.md'), 'utf8'), /Agent Run Handoff: success/);
});
