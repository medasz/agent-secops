import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SKILL_DIR = path.join(__dirname, '..', '..', 'skills', 'secops-alert-analysis');

const SCRIPT = path.join(SKILL_DIR, 'scripts', 'threat-intel', 'external.js');
const SCRIPT_CWD = path.join(SKILL_DIR, 'scripts');
const TEST_CACHE = path.join(os.tmpdir(), `test-external-cache-${Date.now()}-${process.pid}.sqlite`);

afterEach(() => {
  if (fs.existsSync(TEST_CACHE)) fs.unlinkSync(TEST_CACHE);
});

function runCli(args, { expectNonZero = false, env = {} } = {}) {
  try {
    const stdout = execFileSync('node', [SCRIPT, ...args], {
      encoding: 'utf8',
      timeout: 10000,
      cwd: SCRIPT_CWD,
      env: { ...process.env, ...env },
    });
    return { stdout, stderr: '', exitCode: 0 };
  } catch (err) {
    if (expectNonZero) {
      return { stdout: err.stdout || '', stderr: err.stderr || '', exitCode: err.status };
    }
    throw err;
  }
}

describe('external.js', () => {
  describe('功能开关', () => {
    it('ENABLE_THREATBOOK=false → exit(1) + stderr "功能未启用"', () => {
      const result = runCli(['--ip', '8.8.8.8'], {
        expectNonZero: true,
        env: { ENABLE_THREATBOOK: 'false', THREATBOOK_CACHE_PATH: TEST_CACHE },
      });
      assert.equal(result.exitCode, 1);
      assert.ok(result.stderr.includes('功能未启用') || result.stderr.includes('ENABLE_THREATBOOK'));
    });
  });

  describe('--help', () => {
    it('显示帮助信息', () => {
      const result = runCli(['--help']);
      assert.ok(result.stdout.includes('--ip') || result.stdout.includes('用法') || result.stdout.includes('help'));
    });
  });

  describe('--reset-cache', () => {
    it('清空 SQLite 缓存文件', () => {
      const result = runCli(['--reset-cache'], {
        env: { ENABLE_THREATBOOK: 'false', THREATBOOK_CACHE_PATH: TEST_CACHE },
      });
      assert.equal(result.exitCode, 0);
      assert.ok(result.stdout.includes('缓存已清空'));
    });
  });
});
