/**
 * ban-domain-table.test.js - Domain封禁建议表格生成器测试
 *
 * 覆盖 US1（格式）/ US2（准确性·规则描述过滤/域名规整/映射/时间戳）/ US3（可复现性）。
 * 通过 CLI 子进程端到端验证 reporting/ban-domain-table.js，使用 fixtures 模拟预聚合输出。
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
const SCRIPT = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis', 'scripts', 'reporting/ban-domain-table.js');
const FIXTURE = join(__dirname, 'fixtures', 'ban-domain-enrich-20260709.json');

const EXPECTED_HEADERS = ['最近告警时间', '风险域名', '风险描述', '告警次数'];

function runCli(args, stdin = null) {
  const result = spawnSync('node', [SCRIPT, ...args], {
    encoding: 'utf-8',
    input: stdin || undefined,
    timeout: 30000,
  });
  return {
    stdout: stripWarnings(result.stdout || ''),
    stderr: stripWarnings(result.stderr || ''),
    status: result.status,
  };
}

function stripWarnings(s) {
  if (!s) return s;
  return s
    .split('\n')
    .filter((l) => !l.includes('MODULE_TYPELESS_PACKAGE_JSON') && !l.includes('Reparsing as ES module') && !l.includes('To eliminate this warning') && !l.includes('trace-warnings'))
    .join('\n')
    .trim();
}

// ============================================================
// US1：Domain封禁表格格式
// ============================================================
describe('US1 - Domain封禁表格格式', () => {
  it('表头四列（列名、列序、列数=4）', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'markdown']);
    const lines = stdout.split('\n');
    const cells = lines[0].split('|').map((c) => c.trim()).filter(Boolean);
    assert.deepEqual(cells, EXPECTED_HEADERS);
  });

  it('分隔行存在且列数=4', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'markdown']);
    const lines = stdout.split('\n');
    const sepCount = (lines[1].match(/\|/g) || []).length;
    assert.equal(sepCount, 5, '分隔行应有4列（5个|）');
  });

  it('每行四列均有值，不存在整列空白或错位', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'markdown']);
    const lines = stdout.split('\n').slice(2);
    assert.ok(lines.length > 0, '应有数据行');
    for (const line of lines) {
      const cells = line.split('|').map((c) => c.trim()).filter(Boolean);
      assert.equal(cells.length, 4, `每行应4列，实际: ${cells.length} 行: ${line}`);
      for (const cell of cells) {
        assert.ok(cell.length > 0, `单元格不应空白: ${line}`);
      }
    }
  });

  it('空数据输出仅表头+分隔行，不报错', () => {
    const emptyFixture = join(__dirname, 'fixtures', 'ban-domain-empty.json');
    const { stdout } = runCli(['--input', emptyFixture, '--format', 'markdown']);
    const lines = stdout.split('\n');
    assert.equal(lines.length, 2, '空数据应仅表头+分隔行2行');
    const cells = lines[0].split('|').map((c) => c.trim()).filter(Boolean);
    assert.deepEqual(cells, EXPECTED_HEADERS);
  });
});

// ============================================================
// US2：数据准确性与规则描述过滤
// ============================================================
describe('US2 - 数据准确性与规则描述过滤', () => {
  it('规则描述型IOC被过滤（数字+横线开头 / 含中文）', () => {
    const { stdout, stderr } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    assert.ok(data.rule_desc_filtered_count >= 3, `应过滤≥3条规则描述型IOC，实际: ${data.rule_desc_filtered_count}`);
    const domains = data.rows.map((r) => r.risk_domain);
    assert.ok(!domains.some((d) => d.includes('发现')), '规则描述型IOC（含"发现"）不应出现');
    assert.ok(!domains.some((d) => /^\d+-/.test(d)), '数字+横线开头IOC不应出现');
    assert.ok(stderr.includes('规则描述型IOC过滤'), '应记录过滤日志');
  });

  it('通配符域名规整：去除前导 * 号', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const domains = data.rows.map((r) => r.risk_domain);
    assert.ok(domains.includes('mlcrosoft.vip'), '应含规整后的 mlcrosoft.vip（原始 *mlcrosoft.vip）');
    assert.ok(!domains.includes('*mlcrosoft.vip'), '不应含原始通配符形式 *mlcrosoft.vip');
  });

  it('max_timestamp 转 Asia/Shanghai 秒级 yyyy/M/d H:mm:ss（无前导零）', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const byDomain = Object.fromEntries(data.rows.map((r) => [r.risk_domain, r.alert_timestamp]));
    // 19.mlcro.net max_timestamp=2026-07-09T15:57:30.757Z → +08:00 = 2026/7/9 23:57:30
    assert.equal(byDomain['19.mlcro.net'], '2026/7/9 23:57:30');
    // xred.mooo.com max_timestamp=2026-07-09T12:27:41.093Z → +08:00 = 2026/7/9 20:27:41
    assert.equal(byDomain['xred.mooo.com'], '2026/7/9 20:27:41');
  });

  it('攻击类型名称映射生效', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const byDomain = Object.fromEntries(data.rows.map((r) => [r.risk_domain, r.risk_description]));
    // 远控木马 → 远控木马行为
    assert.equal(byDomain['19.mlcro.net'], '远控木马行为(137)');
    // 感染型病毒 → 感染型病毒行为
    assert.equal(byDomain['xred.mooo.com'], '感染型病毒行为(70)');
    // 僵尸网络 → 僵尸网络行为
    assert.equal(byDomain['msg.whxic.cn'], '僵尸网络行为(2)');
  });

  it('攻击类型映射缺失回退 ES 原始名 + INFO 日志', () => {
    const customMap = join(os.tmpdir(), `test-ban-domain-mapping-${Date.now()}.json`);
    fs.writeFileSync(customMap, JSON.stringify({ 远控木马: '远控木马行为' }));
    const { stdout, stderr } = runCli(['--input', FIXTURE, '--format', 'json', '--attack-type-mapping', customMap]);
    const data = JSON.parse(stdout);
    const byDomain = Object.fromEntries(data.rows.map((r) => [r.risk_domain, r.risk_description]));
    // 感染型病毒 不在 minimal 映射中 → 回退原始名
    assert.ok(byDomain['xred.mooo.com'].includes('感染型病毒'), `映射缺失应回退原始名: ${byDomain['xred.mooo.com']}`);
    assert.ok(stderr.includes('攻击类型映射缺失'), `应记 INFO 回退日志: ${stderr}`);
    fs.unlinkSync(customMap);
  });

  it('阈值筛选：告警次数 < min-attacks 不入选', () => {
    // fixture 含 msg.whxic.cn (total_alerts=2)，默认 min-attacks=1 应入选
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const domains = data.rows.map((r) => r.risk_domain);
    assert.ok(domains.includes('msg.whxic.cn'), '2 >= 1 应入选');
    // 提高 min-attacks=10 后 msg.whxic.cn(2) 被排除
    const { stdout: stdout2 } = runCli(['--input', FIXTURE, '--format', 'json', '--min-attacks', '10']);
    const data2 = JSON.parse(stdout2);
    const domains2 = data2.rows.map((r) => r.risk_domain);
    assert.ok(!domains2.includes('msg.whxic.cn'), '2 < 10 应排除');
    assert.ok(domains2.includes('19.mlcro.net'), '137 >= 10 应入选');
  });

  it('告警次数列正确反映 by_ioc 桶 doc_count', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const byDomain = Object.fromEntries(data.rows.map((r) => [r.risk_domain, r.alert_count]));
    assert.equal(byDomain['mlcrosoft.vip'], 216);
    assert.equal(byDomain['19.mlcro.net'], 137);
    assert.equal(byDomain['johnhop77.ddns.net'], 48);
  });
});

// ============================================================
// US3：可复现性
// ============================================================
describe('US3 - 可复现性', () => {
  it('同输入两次运行输出逐行一致', () => {
    const { stdout: out1 } = runCli(['--input', FIXTURE, '--format', 'markdown']);
    const { stdout: out2 } = runCli(['--input', FIXTURE, '--format', 'markdown']);
    assert.equal(out1, out2, '同输入两次 markdown 输出应逐行一致');
  });

  it('JSON 输出（除 generated_at 外）逐行一致', () => {
    const { stdout: j1 } = runCli(['--input', FIXTURE, '--format', 'json']);
    const { stdout: j2 } = runCli(['--input', FIXTURE, '--format', 'json']);
    const d1 = JSON.parse(j1);
    const d2 = JSON.parse(j2);
    delete d1.generated_at;
    delete d2.generated_at;
    assert.deepEqual(d1, d2, 'JSON 输出（除 generated_at）应一致');
  });

  it('HTML 与 markdown 同数据源同行数据', () => {
    const { stdout: md } = runCli(['--input', FIXTURE, '--format', 'markdown']);
    const { stdout: html } = runCli(['--input', FIXTURE, '--format', 'html']);
    const mdLines = md.split('\n').slice(2);
    const htmlRows = html.match(/<tr><td>(.*?)<\/td><td>(.*?)<\/td><td>(.*?)<\/td><td>(.*?)<\/td><\/tr>/g) || [];
    assert.equal(mdLines.length, htmlRows.length, `行数应一致: md=${mdLines.length} html=${htmlRows.length}`);
    for (let i = 0; i < mdLines.length; i++) {
      const mdCells = mdLines[i].split('|').map((c) => c.trim()).filter(Boolean);
      const htmlCells = htmlRows[i].match(/<td>(.*?)<\/td>/g).map((c) => c.replace(/<\/?td>/g, ''));
      assert.deepEqual(mdCells, htmlCells, `行 ${i} MD/HTML 数据应一致`);
    }
  });

  it('风险域名顺序确定性：按告警次数降序，次数相同按域名字典序', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const domains = data.rows.map((r) => r.risk_domain);
    // 216 > 137 > 70 > 67 > 66 > 48 > 2
    assert.deepEqual(domains, ['mlcrosoft.vip', '19.mlcro.net', 'xred.mooo.com', '3qq.qcommerceshop.com', 'enyepeieo.cn', 'johnhop77.ddns.net', 'msg.whxic.cn']);
  });
});

// ============================================================
// US4：--candidates-output 输出 ban-domain-candidates JSON
// ============================================================
describe('US4 - candidates-output', () => {
  it('输出 ban-domain-candidates JSON 文件，candidates 数组与 rows 中 risk_domain 一致', () => {
    const tmpFile = join(os.tmpdir(), `test-domain-candidates-${Date.now()}.json`);
    const { stderr } = runCli(['--input', FIXTURE, '--format', 'json', '--candidates-output', tmpFile]);
    assert.ok(stderr.includes('Domain candidates written'), `应输出 candidates 写入日志: ${stderr}`);
    const cand = JSON.parse(fs.readFileSync(tmpFile, 'utf-8'));
    assert.ok(Array.isArray(cand.candidates), 'candidates 应为数组');
    assert.ok(cand.candidates.length > 0, 'candidates 不为空');
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const riskDomains = data.rows.map((r) => r.risk_domain);
    assert.deepEqual(cand.candidates, riskDomains, 'candidates 应与 rows 中 risk_domain 列表一致');
    fs.unlinkSync(tmpFile);
  });

  it('candidates JSON 包含 total 和 generated_at 字段', () => {
    const tmpFile = join(os.tmpdir(), `test-domain-candidates-${Date.now()}.json`);
    runCli(['--input', FIXTURE, '--format', 'json', '--candidates-output', tmpFile]);
    const cand = JSON.parse(fs.readFileSync(tmpFile, 'utf-8'));
    assert.equal(cand.total, cand.candidates.length, 'total 应等于 candidates 数量');
    assert.ok(cand.generated_at, '应有 generated_at 时间戳');
    fs.unlinkSync(tmpFile);
  });

  it('未指定 --candidates-output 时不生成文件', () => {
    const { stderr } = runCli(['--input', FIXTURE, '--format', 'json']);
    assert.ok(!stderr.includes('Domain candidates written'), '不应输出 candidates 日志');
  });
});
