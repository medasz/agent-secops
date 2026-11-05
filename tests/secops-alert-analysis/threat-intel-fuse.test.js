/**
 * threat-intel-fuse.test.js - Step 3d 情报融合测试
 *
 * 验证 fuse.js 读取 ban-ip-table md + threatbook-enrich JSON → 生成独立 threat-intel-table md。
 * 通过 CLI 子进程端到端验证。
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SCRIPT = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis', 'scripts', 'threat-intel', 'fuse.js');
const LABEL_MAP = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis', 'references', 'threatbook-label-map.json');

function runCli(args, env = {}) {
  const result = spawnSync('node', [SCRIPT, ...args], {
    encoding: 'utf-8',
    timeout: 30000,
    env: { ...process.env, ENABLE_THREATBOOK: 'true', ...env },
  });
  return {
    stdout: (result.stdout || '').trim(),
    stderr: (result.stderr || '').trim(),
    status: result.status,
  };
}

function makeTmpDir() {
  return fs.mkdtempSync(join(os.tmpdir(), 'fuse-test-'));
}

function writeBanTableMd(dir, ips) {
  const header = '| 告警日期时间戳 | 风险IP | 风险描述 | 风险IP的地理位置 |\n| --- | --- | --- | --- |\n';
  const rows = ips.map(r => `| ${r.ts} | ${r.ip} | ${r.desc} | ${r.geo} |`).join('\n');
  const content = header + rows + '\n';
  const path = join(dir, 'ban-ip-table-20260624.md');
  fs.writeFileSync(path, content, 'utf-8');
  return path;
}

function writeEnrichJson(dir, results, extra = {}) {
  const content = {
    source: 'threatbook',
    queried_at: '2026-06-24 12:00:00',
    mode: 'script',
    results,
    cache_stats: { hits: 0, misses: results.length },
    quota_stats: { daily_quota: 150, api_calls_made: 1, api_calls_remaining: 149, truncated: false, truncation_reason: null },
    errors: { terminated_early: false, termination_reason: null, failed_count: 0, failed_ips: [] },
    ...extra,
  };
  const path = join(dir, 'threatbook-enrich-20260624.json');
  fs.writeFileSync(path, JSON.stringify(content, null, 2), 'utf-8');
  return path;
}

function runFuseAndReadOutput(banTablePath, enrichPath, env = {}) {
  const tmpDir = makeTmpDir();
  const outputPath = join(tmpDir, 'threat-intel-table-20260624.md');
  const { status, stderr } = runCli(['--ban-ip-table', banTablePath, '--enrich', enrichPath, '--output', outputPath, '--label-map', LABEL_MAP], env);
  const output = fs.existsSync(outputPath) ? fs.readFileSync(outputPath, 'utf-8') : '';
  fs.rmSync(tmpDir, { recursive: true });
  return { status, stderr, output };
}

function parseTableRow(line) {
  return line.split('|').map(c => c.trim()).filter((_, i, arr) => i > 0 && i < arr.length - 1);
}

describe('fuse.js - Step 3d 情报融合（独立文件输出）', () => {

  it('可用 — 生成 5 列表格，包含所有列名', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: true, is_malicious: true, confidence: 'high', severity: 'high', threat_type: 'Zombie', tags: ['Mirai'], permalink: '' },
    ]);

    const { status, output } = runFuseAndReadOutput(banTablePath, enrichPath);
    assert.equal(status, 0);
    assert.ok(output.includes('风险IP'), '应包含"风险IP"列');
    assert.ok(output.includes('是否恶意'), '应包含"是否恶意"列');
    assert.ok(output.includes('可信度'), '应包含"可信度"列');
    assert.ok(output.includes('威胁类型'), '应包含"威胁类型"列');
    assert.ok(output.includes('情报标签'), '应包含"情报标签"列');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('可用 — 表头恰好 5 列', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: true, is_malicious: true, confidence: 'high', severity: 'high', threat_type: 'Zombie', tags: [], permalink: '' },
    ]);

    const { output } = runFuseAndReadOutput(banTablePath, enrichPath);
    const headerLine = output.split('\n')[0];
    const headers = parseTableRow(headerLine);
    assert.equal(headers.length, 5, `表头应为 5 列，实际 ${headers.length}: ${JSON.stringify(headers)}`);
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('is_malicious=true → "是"', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: true, is_malicious: true, confidence: 'high', severity: 'high', threat_type: 'Zombie', tags: ['Mirai'], permalink: '' },
    ]);

    const { output } = runFuseAndReadOutput(banTablePath, enrichPath);
    const dataRow = output.split('\n').find(l => l.includes('5.61.209.92'));
    assert.ok(dataRow, '应有数据行');
    const cells = parseTableRow(dataRow);
    assert.equal(cells[1], '是', 'is_malicious=true → "是"');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('is_malicious=false → "否"', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: false, is_malicious: false, confidence: 'low', severity: 'info', threat_type: '', tags: [], permalink: '' },
    ]);

    const { output } = runFuseAndReadOutput(banTablePath, enrichPath);
    const dataRow = output.split('\n').find(l => l.includes('5.61.209.92'));
    assert.ok(dataRow);
    const cells = parseTableRow(dataRow);
    assert.equal(cells[1], '否', 'is_malicious=false → "否"');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('confidence=high → "高"（经 label-map）', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: true, is_malicious: true, confidence: 'high', severity: 'high', threat_type: 'Zombie', tags: [], permalink: '' },
    ]);

    const { output } = runFuseAndReadOutput(banTablePath, enrichPath);
    const dataRow = output.split('\n').find(l => l.includes('5.61.209.92'));
    assert.ok(dataRow);
    const cells = parseTableRow(dataRow);
    assert.equal(cells[2], '高', 'confidence=high → "高"');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('映射缺失回退英文原值', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: true, is_malicious: true, confidence: 'unknown_level', severity: 'high', threat_type: 'Zombie', tags: [], permalink: '' },
    ]);
    const tmpMap = join(tmpDir, 'empty-map.json');
    fs.writeFileSync(tmpMap, JSON.stringify({ severity: {}, confidence: {} }), 'utf-8');

    const outTmpDir = makeTmpDir();
    const outputPath = join(outTmpDir, 'out.md');
    runCli(['--ban-ip-table', banTablePath, '--enrich', enrichPath, '--output', outputPath, '--label-map', tmpMap]);
    const output = fs.readFileSync(outputPath, 'utf-8');
    const dataRow = output.split('\n').find(l => l.includes('5.61.209.92'));
    assert.ok(dataRow);
    const cells = parseTableRow(dataRow);
    assert.equal(cells[2], 'unknown_level', '映射缺失应回退英文原值');
    fs.rmSync(tmpDir, { recursive: true });
    fs.rmSync(outTmpDir, { recursive: true });
  });

  it('tags 非空 → 逗号拼接', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: true, is_malicious: true, confidence: 'high', severity: 'high', threat_type: 'Zombie', tags: ['Mirai', 'Botnet'], permalink: '' },
    ]);

    const { output } = runFuseAndReadOutput(banTablePath, enrichPath);
    const dataRow = output.split('\n').find(l => l.includes('5.61.209.92'));
    assert.ok(dataRow);
    const cells = parseTableRow(dataRow);
    assert.equal(cells[4], 'Mirai,Botnet', 'tags 应逗号拼接');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('tags 为空 → "—"', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: true, is_malicious: true, confidence: 'high', severity: 'high', threat_type: 'Zombie', tags: [], permalink: '' },
    ]);

    const { output } = runFuseAndReadOutput(banTablePath, enrichPath);
    const dataRow = output.split('\n').find(l => l.includes('5.61.209.92'));
    assert.ok(dataRow);
    const cells = parseTableRow(dataRow);
    assert.equal(cells[4], '—', 'tags 为空 → "—"');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('无情报数据的 IP → 全 "—"', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
      { ts: '2026/6/24 10:20:54', ip: '192.34.108.210', desc: '30次暴力猜解攻击', geo: '美国' },
    ]);
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: true, is_malicious: true, confidence: 'high', severity: 'high', threat_type: 'Zombie', tags: ['Mirai'], permalink: '' },
    ]);

    const { output } = runFuseAndReadOutput(banTablePath, enrichPath);
    const dataRow = output.split('\n').find(l => l.includes('192.34.108.210'));
    assert.ok(dataRow, '应有 192.34.108.210 行');
    const cells = parseTableRow(dataRow);
    assert.equal(cells[1], '—', '是否恶意 → "—"');
    assert.equal(cells[2], '—', '可信度 → "—"');
    assert.equal(cells[3], '—', '威胁类型 → "—"');
    assert.equal(cells[4], '—', '情报标签 → "—"');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('ENABLE_THREATBOOK=false → 输出"威胁情报查询结果不可用"', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: true, is_malicious: true, confidence: 'high', severity: 'high', threat_type: 'Zombie', tags: ['Mirai'], permalink: '' },
    ]);

    const { status, output } = runFuseAndReadOutput(banTablePath, enrichPath, { ENABLE_THREATBOOK: 'false' });
    assert.equal(status, 0);
    assert.equal(output.trim(), '威胁情报查询结果不可用');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('enrich JSON 不存在 → 输出"威胁情报查询结果不可用"', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const nonexistentEnrich = join(tmpDir, 'nonexistent.json');

    const { status, output } = runFuseAndReadOutput(banTablePath, nonexistentEnrich);
    assert.equal(status, 0);
    assert.equal(output.trim(), '威胁情报查询结果不可用');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('enrich JSON terminated_early=true → 输出"威胁情报查询结果不可用"', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const enrichPath = writeEnrichJson(tmpDir, [], {
      errors: { terminated_early: true, termination_reason: 'QUOTA_EXHAUSTED', failed_count: 1, failed_ips: ['5.61.209.92'] },
    });

    const { status, output } = runFuseAndReadOutput(banTablePath, enrichPath);
    assert.equal(status, 0);
    assert.equal(output.trim(), '威胁情报查询结果不可用');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('ban-ip-table md 不存在 → 输出"威胁情报查询结果不可用"', () => {
    const tmpDir = makeTmpDir();
    const nonexistentBan = join(tmpDir, 'nonexistent-ban.md');
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: true, is_malicious: true, confidence: 'high', severity: 'high', threat_type: 'Zombie', tags: ['Mirai'], permalink: '' },
    ]);

    const { status, output } = runFuseAndReadOutput(nonexistentBan, enrichPath);
    assert.equal(status, 0);
    assert.equal(output.trim(), '威胁情报查询结果不可用');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('ban-ip-table md 未被修改', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const original = fs.readFileSync(banTablePath, 'utf-8');
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: true, is_malicious: true, confidence: 'high', severity: 'high', threat_type: 'Zombie', tags: ['Mirai'], permalink: '' },
    ]);

    runFuseAndReadOutput(banTablePath, enrichPath);
    const after = fs.readFileSync(banTablePath, 'utf-8');
    assert.equal(after, original, 'ban-ip-table md 应字节级不变');
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('--output 参数 → 写入指定路径', () => {
    const tmpDir = makeTmpDir();
    const banTablePath = writeBanTableMd(tmpDir, [
      { ts: '2026/6/24 3:25:26', ip: '5.61.209.92', desc: '220次代码执行攻击', geo: '西班牙' },
    ]);
    const enrichPath = writeEnrichJson(tmpDir, [
      { ip: '5.61.209.92', found: true, is_malicious: true, confidence: 'high', severity: 'high', threat_type: 'Zombie', tags: ['Mirai'], permalink: '' },
    ]);
    const outputPath = join(tmpDir, 'threat-intel-table-20260624.md');

    const { status } = runCli(['--ban-ip-table', banTablePath, '--enrich', enrichPath, '--output', outputPath, '--label-map', LABEL_MAP]);
    assert.equal(status, 0);
    assert.ok(fs.existsSync(outputPath), '输出文件应存在');
    const content = fs.readFileSync(outputPath, 'utf-8');
    assert.ok(content.includes('风险IP'), '输出应包含表格');
    fs.rmSync(tmpDir, { recursive: true });
  });
});
