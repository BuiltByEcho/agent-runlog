import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { analyzeOutput, runLogged } from '../src/index.js';

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
  assert.match(readFileSync(join(outDir, 'stdout.log'), 'utf8'), /ok/);
});

test('secret-looking output is high severity', () => {
  const analysis = analyzeOutput('API_TOKEN="super-secret-token-value"', 0, 10);
  assert.ok(analysis.findings.some(f => f.severity === 'high' && f.type === 'secret'));
});
