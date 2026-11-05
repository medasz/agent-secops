/**
 * dns-agg.test.js - 独立 DNS 全局聚合脚本（路径A 纯脚本，零 MCP）基础单测
 *
 * 覆盖：
 *  (a) 输入校验：缺 --date → 退出码 1；--help → 退出码 0
 *  (b) ES 不可达 → 退出码 2
 *  (c) 聚合计数 + TopN 截断 + 空结果（退出码仍 0，dns_domains/dns_alerts 为空数组）
 *  (d) 解析错误（合法 JSON 但缺 aggregations）→ 退出码 3
 *
 * 真实 ES（logfmt_746_{date}）不可用，全部用本地 mock ES 服务驱动，无外部依赖。
 *
 * 运行：node --test tests/secops-alert-analysis/dns-agg.test.js
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import { startMockEs, buildDnsAggResponse, nodeBin, SKILL_ROOT } from './_mock_es.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const NODE = nodeBin();
const SCRIPT = join(SKILL_ROOT, 'scripts', 'es-tool/dns-agg.js');

// 全量 DNS 域名（按 count 降序），用于验证聚合计数与 TopN 截断
const ALL_DOMAINS = [
  { key: 'b.example.com', doc_count: 500 },
  { key: 'a.example.com', doc_count: 300 },
  { key: 'c.example.com', doc_count: 100 },
  { key: 'd.example.com', doc_count: 50 },
  { key: 'e.example.com', doc_count: 20 },
  { key: 'f.example.com', doc_count: 10 },
  { key: 'g.example.com', doc_count: 5 },
];

const ALERTS = [
  {
    key: 'x.malicious.com',
    doc_count: 200,
    attack_types: [
      { type: '远控木马', count: 150 },
      { type: '代理工具', count: 50 },
    ],
    max_value: 1752081450000, // 2026-07-09T15:57:30Z
  },
  {
    key: 'y.malicious.com',
    doc_count: 80,
    attack_types: [{ type: '感染型病毒', count: 80 }],
    max_value: 1752081000000,
  },
];

function runCli(args, mockPort) {
  const env = {
    ...process.env,
    ES_HOST: '127.0.0.1',
    ES_PORT: String(mockPort ?? 1), // 默认指向无监听端口 → ES 不可达
    ES_INDEX_PREFIX: 'logfmt_746_',
    LOG_LEVEL: 'ERROR',
  };
  // 注意：必须用异步 spawn 而非 spawnSync——本进程的 mock ES 服务依赖事件循环，
  // 而 spawnSync 会阻塞事件循环，导致 mock 永远无法响应（脚本 hang → 超时）。
  return new Promise((resolve, reject) => {
    const child = spawn(NODE, [SCRIPT, ...args], { env, timeout: 30000 });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf-8');
    child.stderr.setEncoding('utf-8');
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', (e) => reject(e));
    child.on('close', (code, signal) => resolve({ stdout, stderr, status: code, signal }));
  });
}

let mock;

describe('dns-agg.js - (a) 输入校验', () => {
  it('缺 --date → 退出码 1', async () => {
    const { status, stderr } = await runCli(['--format', 'json']);
    assert.equal(status, 1, `缺 --date 应退出码1，实际 ${status}；stderr=${stderr}`);
    assert.ok(stderr.includes('--date'), `应提示 --date 必填，stderr=${stderr}`);
  });

  it('--date 格式非法（非 YYYYMMDD）→ 退出码 1', async () => {
    const { status, stderr } = await runCli(['--date', '2026-7-15']);
    assert.equal(status, 1, `非法 --date 应退出码1，实际 ${status}；stderr=${stderr}`);
  });

  it('--help → 退出码 0', async () => {
    const { status, stdout } = await runCli(['--help']);
    assert.equal(status, 0, `--help 应退出码0，实际 ${status}`);
    assert.ok(stdout.includes('Usage:'), `help 应输出用法说明，stdout=${stdout}`);
  });

  it('--format 非 json → 退出码 1', async () => {
    const { status, stderr } = await runCli(['--date', '20260715', '--format', 'csv']);
    assert.equal(status, 1, `非法 --format 应退出码1，实际 ${status}；stderr=${stderr}`);
  });
});

describe('dns-agg.js - (b) ES 不可达 → 退出码 2', () => {
  it('指向无监听端口 → 退出码 2', async () => {
    // ES_PORT=1 在 127.0.0.1 无服务监听 → ECONNREFUSED → 重试耗尽 → 退出码 2
    const { status, stderr } = await runCli(['--date', '20260715']);
    assert.equal(status, 2, `ES 不可达应退出码2，实际 ${status}；stderr=${stderr}`);
    assert.ok(stderr.includes('ES'), `应提示 ES 连接失败，stderr=${stderr}`);
  });
});

describe('dns-agg.js - (c) 聚合计数 / TopN 截断 / 空结果', () => {
  before(async () => {
    mock = await startMockEs((body) => {
      // 尊重 dns_domains 子聚合的 terms.size 做 TopN 截断
      const topN = body?.aggs?.dns_domains?.aggs?.dns_traffic?.aggs?.by_ioc?.terms?.size ?? 50;
      const domains = [...ALL_DOMAINS].sort((a, b) => b.doc_count - a.doc_count).slice(0, topN);
      return buildDnsAggResponse({ alerts: ALERTS, domains });
    });
  });

  after(async () => {
    if (mock) await mock.close();
  });

  it('stats.dns_domains 聚合计数正确（全量降序）', async () => {
    const outFile = join(os.tmpdir(), `dns-agg-t1-${Date.now()}.json`);
    const { status, stderr } = await runCli(['--date', '20260715', '--output', outFile], mock.port);
    assert.equal(status, 0, `成功应退出码0，stderr=${stderr}`);
    const data = JSON.parse(fs.readFileSync(outFile, 'utf-8'));
    fs.unlinkSync(outFile);

    const domains = data.stats.dns_domains;
    assert.equal(domains.length, ALL_DOMAINS.length, `域名数应=${ALL_DOMAINS.length}，实际 ${domains.length}`);
    for (let i = 1; i < domains.length; i++) {
      assert.ok(domains[i - 1].count >= domains[i].count, `应降序：${domains[i - 1].count} >= ${domains[i].count}`);
    }
    assert.equal(domains[0].domain, 'b.example.com');
    assert.equal(domains[0].count, 500);
    assert.deepEqual(Object.keys(domains[0]).sort(), ['count', 'domain']);
  });

  it('dns_alerts 列表 shape 正确（ioc/total_alerts/attack_types/max_timestamp）', async () => {
    const outFile = join(os.tmpdir(), `dns-agg-t2-${Date.now()}.json`);
    const { status } = await runCli(['--date', '20260715', '--output', outFile], mock.port);
    assert.equal(status, 0);
    const data = JSON.parse(fs.readFileSync(outFile, 'utf-8'));
    fs.unlinkSync(outFile);

    const alerts = data.dns_alerts;
    assert.equal(alerts.length, 2);
    const byIoc = Object.fromEntries(alerts.map((a) => [a.ioc, a]));
    assert.equal(byIoc['x.malicious.com'].total_alerts, 200);
    assert.deepEqual(byIoc['x.malicious.com'].attack_types, [
      { type: '远控木马', count: 150 },
      { type: '代理工具', count: 50 },
    ]);
    assert.equal(byIoc['x.malicious.com'].max_timestamp, new Date(1752081450000).toISOString());
  });

  it('--top N 截断 dns_domains 数量上限', async () => {
    const outFile = join(os.tmpdir(), `dns-agg-t3-${Date.now()}.json`);
    const { status } = await runCli(['--date', '20260715', '--top', '3', '--output', outFile], mock.port);
    assert.equal(status, 0);
    const data = JSON.parse(fs.readFileSync(outFile, 'utf-8'));
    fs.unlinkSync(outFile);

    const domains = data.stats.dns_domains;
    assert.equal(domains.length, 3, `Top3 应截断为 3 条，实际 ${domains.length}`);
    assert.equal(domains[0].domain, 'b.example.com');
    assert.equal(domains[2].domain, 'c.example.com');
  });

  it('空结果：dns_domains=[] 且 dns_alerts=[]，退出码仍 0', async () => {
    const emptyMock = await startMockEs(() => buildDnsAggResponse({ alerts: [], domains: [] }));
    const outFile = join(os.tmpdir(), `dns-agg-t4-${Date.now()}.json`);
    const { status } = await runCli(['--date', '20260715', '--output', outFile], emptyMock.port);
    assert.equal(status, 0, '空结果应退出码0');
    const data = JSON.parse(fs.readFileSync(outFile, 'utf-8'));
    fs.unlinkSync(outFile);
    assert.deepEqual(data.stats.dns_domains, [], '空结果 dns_domains 应为 []');
    assert.deepEqual(data.dns_alerts, [], '空结果 dns_alerts 应为 []');
    assert.equal(data.summary.total_dns_domains, 0);
    assert.equal(data.summary.total_dns_alerts, 0);
    await emptyMock.close();
  });

  it('输出含 date / query_range 元信息', async () => {
    const outFile = join(os.tmpdir(), `dns-agg-t5-${Date.now()}.json`);
    const { status } = await runCli(['--date', '20260715', '--output', outFile], mock.port);
    assert.equal(status, 0);
    const data = JSON.parse(fs.readFileSync(outFile, 'utf-8'));
    fs.unlinkSync(outFile);
    assert.equal(data.date, '20260715');
    assert.ok(data.query_range && data.query_range.index === 'logfmt_746_20260715', `index 应为 logfmt_746_20260715，实际 ${data.query_range?.index}`);
    assert.equal(data.query_range.start, '2026-07-15T00:00:00+08:00');
    assert.equal(data.query_range.end, '2026-07-15T23:59:59+08:00');
  });
});

describe('dns-agg.js - (d) 解析错误 → 退出码 3', () => {
  it('合法 JSON 但缺 aggregations → 退出码 3', async () => {
    const parseMock = await startMockEs(() => ({})); // 无 aggregations
    const outFile = join(os.tmpdir(), `dns-agg-t6-${Date.now()}.json`);
    const { status, stderr } = await runCli(['--date', '20260715', '--output', outFile], parseMock.port);
    assert.equal(status, 3, `缺 aggregations 应退出码3，实际 ${status}；stderr=${stderr}`);
    assert.ok(stderr.includes('aggregations') || stderr.includes('解析'), `应提示解析失败，stderr=${stderr}`);
    await parseMock.close();
    assert.ok(!fs.existsSync(outFile), '解析失败时不应写出输出文件');
  });
});
