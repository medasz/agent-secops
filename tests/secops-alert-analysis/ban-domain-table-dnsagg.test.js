/**
 * ban-domain-table-dnsagg.test.js - ban-domain-table.js 回归
 *
 * 验证工程师交付的两处改动：
 *  1) 输入源改为 dns-agg.js 输出（dns-domains-{date}.json 的 dns_alerts 数组）
 *     —— 构造含规则描述型 IOC 的 mock dns_alerts 喂 --input，验证四列封禁表渲染、
 *        规则描述型 IOC 被过滤、exit 0。
 *  2) @timestamp → timestamp 字段映射修复
 *     —— 用 smart mock ES 驱动 --date 直连模式，验证"时间字段不再恒空"。
 *        mock 读取 DSL 中 max_timestamp 实际请求的字段：请求 timestamp 则返回真实时间，
 *        请求 @timestamp（残留 bug）则返回空 → 触发 alert_timestamp='未知'。
 *
 * 运行：node --test tests/secops-alert-analysis/ban-domain-table-dnsagg.test.js
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import { startMockEs, nodeBin, SKILL_ROOT } from './_mock_es.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const NODE = nodeBin();
const SCRIPT = join(SKILL_ROOT, 'scripts', 'reporting/ban-domain-table.js');

const EXPECTED_HEADERS = ['最近告警时间', '风险域名', '风险描述', '告警次数'];

function runCli(args, mockPort) {
  const env = {
    ...process.env,
    ES_HOST: '127.0.0.1',
    ES_PORT: String(mockPort ?? 1),
    ES_INDEX_PREFIX: 'logfmt_746_',
    LOG_LEVEL: 'ERROR',
  };
  // 必须用异步 spawn：本进程的 mock ES 依赖事件循环，spawnSync 会阻塞事件循环导致 mock 无法响应。
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

// ---- 1) dns_alerts 输入源回归 ----
describe('ban-domain-table.js - dns_alerts 输入源（来自 dns-agg.js 输出）', () => {
  const fixturePath = join(os.tmpdir(), `dns-domains-${Date.now()}.json`);
  const fixture = {
    date: '20260715',
    stats: { dns_domains: [{ domain: 'b.example.com', count: 500 }] },
    dns_alerts: [
      // 规则描述型（数字+横线开头）→ 应被过滤
      { ioc: '24813-发现内网穿透工具Tailscale通信流量', total_alerts: 269, attack_types: [{ type: '代理工具', count: 269 }], max_timestamp: '2026-07-09T15:31:28.561Z' },
      // 通配符域名 → 应规整为去掉前导 *
      { ioc: '*mlcrosoft.vip', total_alerts: 216, attack_types: [{ type: '远控木马', count: 216 }], max_timestamp: '2026-07-09T15:13:47.434Z' },
      // 正常域名
      { ioc: '19.mlcro.net', total_alerts: 137, attack_types: [{ type: '远控木马', count: 137 }], max_timestamp: '2026-07-09T15:57:30.757Z' },
    ],
  };

  before(() => {
    fs.writeFileSync(fixturePath, JSON.stringify(fixture), 'utf-8');
  });
  after(() => {
    if (fs.existsSync(fixturePath)) fs.unlinkSync(fixturePath);
  });

  it('四列表头正确渲染（列名/列序/列数=4）', async () => {
    const { stdout, status } = await runCli(['--input', fixturePath, '--format', 'markdown']);
    assert.equal(status, 0, `应退出码0，stdout=${stdout}`);
    const lines = stdout.split('\n');
    const cells = lines[0].split('|').map((c) => c.trim()).filter(Boolean);
    assert.deepEqual(cells, EXPECTED_HEADERS);
  });

  it('正常域名入选、通配符被规整、规则描述型 IOC 被过滤', async () => {
    const { stdout } = await runCli(['--input', fixturePath, '--format', 'json']);
    const data = JSON.parse(stdout);
    const domains = data.rows.map((r) => r.risk_domain);
    assert.ok(domains.includes('mlcrosoft.vip'), '应含规整后的 mlcrosoft.vip');
    assert.ok(!domains.includes('*mlcrosoft.vip'), '不应含原始通配符 *mlcrosoft.vip');
    assert.ok(domains.includes('19.mlcro.net'), '正常域名应入选');
    assert.ok(!domains.some((d) => /^\d+-/.test(d)), '数字+横线规则描述型 IOC 应被过滤');
    assert.ok(!domains.some((d) => d.includes('发现')), '含中文规则描述型 IOC 应被过滤');
    assert.ok(data.rule_desc_filtered_count >= 1, `应过滤≥1条规则描述型IOC，实际 ${data.rule_desc_filtered_count}`);
  });

  it('max_timestamp 由 dns_alerts 正确转 Asia/Shanghai', async () => {
    const { stdout } = await runCli(['--input', fixturePath, '--format', 'json']);
    const data = JSON.parse(stdout);
    const byDomain = Object.fromEntries(data.rows.map((r) => [r.risk_domain, r.alert_timestamp]));
    // 19.mlcro.net max_timestamp=2026-07-09T15:57:30.757Z → +08:00 = 2026/7/9 23:57:30
    assert.equal(byDomain['19.mlcro.net'], '2026/7/9 23:57:30', `时间映射错误: ${byDomain['19.mlcro.net']}`);
  });
});

// ---- 2) @timestamp → timestamp 字段映射修复（--date 直连模式） ----
describe('ban-domain-table.js - @timestamp→timestamp 修复（--date 直连模式时间字段不再恒空）', () => {
  let mock;

  before(async () => {
    // 聪明 mock：读取 DSL 中 max_timestamp 实际请求的字段名
    mock = await startMockEs((body) => {
      const maxField = body?.aggs?.by_ioc?.aggs?.max_timestamp?.max?.field;
      // 正确字段 = timestamp → 返回真实时间；残留 bug 字段 = @timestamp → 返回空（模拟字段不存在）
      const maxTs =
        maxField === 'timestamp'
          ? { value_as_string: '2026-07-09T15:57:30.757Z' }
          : { value: null };
      return {
        aggregations: {
          by_ioc: {
            buckets: [
              {
                key: '19.mlcro.net',
                doc_count: 137,
                by_attack_type: { buckets: [{ key: '远控木马', doc_count: 137 }] },
                max_timestamp: maxTs,
              },
            ],
          },
        },
      };
    });
  });

  after(async () => {
    if (mock) await mock.close();
  });

  it('--date 直连模式：时间字段不再恒空（应映射 timestamp 而非 @timestamp）', async () => {
    const { stdout, status, stderr } = await runCli(['--date', '20260715', '--format', 'json'], mock.port);
    assert.equal(status, 0, `应退出码0，stderr=${stderr}`);
    const data = JSON.parse(stdout);
    const byDomain = Object.fromEntries(data.rows.map((r) => [r.risk_domain, r.alert_timestamp]));
    // 若工程师已把 line 192 的 @timestamp 改为 timestamp，mock 返回真实时间 → 非 '未知'
    assert.notEqual(byDomain['19.mlcro.net'], '未知',
      'BUG: --date 模式 alert_timestamp 仍为"未知"，说明 max_timestamp 子聚合仍引用 @timestamp（字段不存在）');
    assert.equal(byDomain['19.mlcro.net'], '2026/7/9 23:57:30',
      `时间映射应为 2026/7/9 23:57:30，实际 ${byDomain['19.mlcro.net']}`);
  });
});
