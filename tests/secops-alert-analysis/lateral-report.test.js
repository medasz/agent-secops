/**
 * lateral-report.test.js - 横向攻击分析内嵌模板三文件跑通
 *
 * 验证设计文档 §12「横向分析内嵌模板」重构保留且跑通：
 *   - 构造 mock parsed-internal-{date}.json（含 lateral 字段）
 *   - 驱动 gen-md-report.js（--date + --stats 外部 + --internal-stats 内部），
 *     验证模板第 6 章（6.1~6.5）由 lateral 字段正确渲染、
 *     占位符（{{int_attack_type}}/{{lat_src_seq}}/{{lat_tgt_seq}}/{{lat_hour}} 等）被替换、无残留 {{...}}
 *   - 单独跑通 lateral-analysis.js，确认仍可独立产出 MD 片段
 *
 * 运行：node --test tests/secops-alert-analysis/lateral-report.test.js
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import { nodeBin, SKILL_ROOT } from './_mock_es.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const NODE = nodeBin();
const GEN_REPORT = join(SKILL_ROOT, 'scripts', 'reporting/gen-md-report.js');
const LATERAL = join(SKILL_ROOT, 'scripts', 'reporting/lateral-analysis.js');

const INTERNAL = {
  stats: {
    total_alerts: 500,
    lateral_alerts: 40,
    unique_internal_sources: 2,
    unique_internal_targets: 1,
    attack_types: [
      { type: '横向移动', count: 30 },
      { type: '内网扫描', count: 10 },
    ],
  },
  lateral: {
    sources: [
      { ip: '10.10.1.5', count: 20, attack_types: [{ type: '横向移动', count: 20 }], max_timestamp: '2026-07-15T03:00:00+08:00' },
      { ip: '10.10.1.9', count: 10, attack_types: [{ type: '内网扫描', count: 10 }], max_timestamp: '2026-07-15T04:00:00+08:00' },
    ],
    targets: [
      { ip: '10.10.2.10', count: 15, attack_types: [{ type: '横向移动', count: 15 }], max_timestamp: '2026-07-15T03:30:00+08:00' },
    ],
    pairs: [
      { source_ip: '10.10.1.5', target_ip: '10.10.2.10', count: 20, maxTimestamp: '2026-07-15T03:00:00+08:00' },
      { source_ip: '10.10.1.9', target_ip: '10.10.2.10', count: 10, maxTimestamp: '2026-07-15T04:00:00+08:00' },
    ],
    hourly_distribution: [
      { hour: 3, count: 25 },
      { hour: 4, count: 15 },
    ],
  },
};

const EXTERNAL = {
  stats: { total_alerts: 0, attack_types: [] },
  ips: [],
  domains: [],
  compromised_hosts: [],
};

let internalPath;
let externalPath;
let reportPath;

function runCli(script, args) {
  const result = spawnSync(NODE, [script, ...args], {
    encoding: 'utf-8',
    env: { ...process.env, LOG_LEVEL: 'ERROR' },
    timeout: 30000,
  });
  return { stdout: result.stdout || '', stderr: result.stderr || '', status: result.status };
}

describe('横向分析内嵌模板 - gen-md-report.js 由 lateral 字段渲染第 6 章', () => {
  before(() => {
    internalPath = join(os.tmpdir(), `parsed-internal-${Date.now()}.json`);
    externalPath = join(os.tmpdir(), `parsed-external-${Date.now()}.json`);
    reportPath = join(os.tmpdir(), `alert-report-${Date.now()}.md`);
    fs.writeFileSync(internalPath, JSON.stringify(INTERNAL), 'utf-8');
    fs.writeFileSync(externalPath, JSON.stringify(EXTERNAL), 'utf-8');
  });
  after(() => {
    for (const p of [internalPath, externalPath, reportPath]) {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  });

  it('报告由 lateral 字段生成，退出码 0', () => {
    const { status, stderr } = runCli(GEN_REPORT, [
      '--date', '20260715',
      '--stats', externalPath,
      '--internal-stats', internalPath,
      '--output', reportPath,
    ]);
    assert.equal(status, 0, `应退出码0，stderr=${stderr}`);
    assert.ok(fs.existsSync(reportPath), '应写出报告文件');
  });

  it('6.1 内部统计由 internalStats 渲染（internal_alerts/lateral_alerts/源/目标数）', () => {
    const md = fs.readFileSync(reportPath, 'utf-8').replace(/\s+/g, ' ');
    assert.ok(md.includes('| 500 |'), '应含内部攻击告警总数 500');
    assert.ok(md.includes('| 40 |'), '应含横向移动告警数 40');
    assert.ok(md.includes('| 2 |'), '应含横向移动源IP数 2');
    assert.ok(md.includes('| 1 |'), '应含横向移动目标IP数 1');
  });

  it('6.2 内部攻击类型分布由 lateral.stats.attack_types 渲染', () => {
    const md = fs.readFileSync(reportPath, 'utf-8');
    assert.ok(md.includes('横向移动'), '应含攻击类型 横向移动');
    assert.ok(md.includes('内网扫描'), '应含攻击类型 内网扫描');
  });

  it('6.3/6.4 横向移动源/目标 Top10 由 lateral.sources/targets 渲染', () => {
    const md = fs.readFileSync(reportPath, 'utf-8');
    assert.ok(md.includes('10.10.1.5'), '6.3 应含源IP 10.10.1.5');
    assert.ok(md.includes('横向移动(20)'), '6.3 应含源攻击类型聚合 横向移动(20)');
    assert.ok(md.includes('10.10.2.10'), '6.4 应含目标IP 10.10.2.10');
  });

  it('6.5 横向移动小时分布由 lateral.hourly_distribution 渲染', () => {
    const md = fs.readFileSync(reportPath, 'utf-8');
    assert.ok(md.includes('| 3 | 25 |'), '6.5 应含小时 3 / 25');
    assert.ok(md.includes('| 4 | 15 |'), '6.5 应含小时 4 / 15');
  });

  it('占位符全部被替换：无残留 {{...}}', () => {
    const md = fs.readFileSync(reportPath, 'utf-8');
    const leftover = md.match(/\{\{[^}]+\}\}/g);
    assert.equal(leftover, null, `报告不应残留占位符，实际: ${JSON.stringify(leftover)}`);
    for (const ph of ['int_attack_type', 'lat_src_seq', 'lat_src_ip', 'lat_tgt_seq', 'lat_tgt_ip', 'lat_hour', 'lat_hour_count']) {
      assert.ok(!md.includes(`{{${ph}}}`), `占位符 {{${ph}}} 未被替换`);
    }
  });
});

describe('横向分析内嵌模板 - lateral-analysis.js 独立产出 MD', () => {
  before(() => {
    // 自带 fixture，避免被上一个 describe 的 after 删除（原测试依赖共享变量导致 Input file not found）
    internalPath = join(os.tmpdir(), `parsed-internal-${Date.now()}.json`);
    fs.writeFileSync(internalPath, JSON.stringify(INTERNAL), 'utf-8');
  });
  after(() => {
    if (fs.existsSync(internalPath)) fs.unlinkSync(internalPath);
  });
  it('单独运行产出含 6.1~6.5 的 MD 片段，退出码 0', () => {
    const out = join(os.tmpdir(), `lateral-analysis-${Date.now()}.md`);
    const { status, stderr } = runCli(LATERAL, ['--input', internalPath, '--output', out]);
    assert.equal(status, 0, `应退出码0，stderr=${stderr}`);
    const md = fs.readFileSync(out, 'utf-8');
    assert.ok(md.includes('### 6.1 内部攻击统计'), '应含 6.1');
    assert.ok(md.includes('### 6.2 内部攻击-按类型分布'), '应含 6.2');
    assert.ok(md.includes('### 6.3 横向移动源IP Top10'), '应含 6.3');
    assert.ok(md.includes('### 6.4 横向移动目标IP Top10'), '应含 6.4');
    assert.ok(md.includes('### 6.5 横向移动趋势-按时间分布'), '应含 6.5');
    assert.ok(md.includes('10.10.1.5'), '应含源IP');
    assert.ok(md.includes('10.10.2.10'), '应含目标IP');
    fs.unlinkSync(out);
  });
});
