/**
 * ban-ip-table.test.js - 封禁IP表格生成器测试
 *
 * 覆盖 US1（格式）/ US2（准确性·白名单/规整/映射/时间戳）/ US3（可复现性）。
 * 通过 CLI 子进程端到端验证 reporting/ban-ip-table.js，使用 fixtures 模拟 analyzer/enrich.js 输出，
 * 与 quickstart.md 验证路径一致（非模块内部函数测试，避免改脚本导出接口）。
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
const SCRIPT = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis', 'scripts', 'reporting/ban-ip-table.js');
const FIXTURE = join(__dirname, 'fixtures', 'ban-ip-enrich-20260624.json');

// 与样例 docs/dev/风险IP处置入库数据样例.md 表头逐字一致（FR-001/002，SC-001）
const EXPECTED_HEADERS = ['告警日期时间戳', '风险IP', '风险描述', '风险IP的地理位置'];

/**
 * 运行 reporting/ban-ip-table.js CLI，返回 stdout + stderr（剥离 node module 警告）
 */
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
// US1：封禁IP以目标格式化表格输出（格式）
// ============================================================
describe('US1 - 封禁IP表格格式', () => {
  it('表头四列与样例逐字一致（列名、列序、列数=4）', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'markdown']);
    const lines = stdout.split('\n');
    const headerLine = lines[0];
    const cells = headerLine.split('|').map((c) => c.trim()).filter(Boolean);
    assert.deepEqual(cells, EXPECTED_HEADERS, '表头四列应与样例逐字一致');
  });

  it('分隔行存在且列数=4', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'markdown']);
    const lines = stdout.split('\n');
    const sepLine = lines[1];
    const sepCount = (sepLine.match(/\|/g) || []).length;
    assert.equal(sepCount, 5, '分隔行应有4列（5个|）');
  });

  it('每行四列均有值，不存在整列空白或错位', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'markdown']);
    const lines = stdout.split('\n').slice(2); // 跳过表头与分隔行
    assert.ok(lines.length > 0, '应有数据行');
    for (const line of lines) {
      const cells = line.split('|').map((c) => c.trim()).filter(Boolean);
      assert.equal(cells.length, 4, `每行应4列，实际: ${cells.length} 行: ${line}`);
      for (const cell of cells) {
        assert.ok(cell.length > 0, `单元格不应空白: ${line}`);
      }
    }
  });

  it('空数据输出仅表头+分隔行，不报错（FR 边界）', () => {
    const emptyFixture = join(__dirname, 'fixtures', 'ban-ip-empty.json');
    const { stdout } = runCli(['--input', emptyFixture, '--format', 'markdown']);
    const lines = stdout.split('\n');
    assert.equal(lines.length, 2, '空数据应仅表头+分隔行2行');
    const cells = lines[0].split('|').map((c) => c.trim()).filter(Boolean);
    assert.deepEqual(cells, EXPECTED_HEADERS);
  });
});

// ============================================================
// US2：封禁IP信息与IDS告警数据比对验证准确无误
// ============================================================
describe('US2 - 数据准确性与二次白名单过滤', () => {
  it('二次白名单过滤排除白名单IP（FR-013，SC-004）', () => {
    // fixture 含 198.51.100.1（在白名单 198.51.100.0/24 内）与 172.21.67.102（在 172.16.0.0/12 内）
    const { stdout, stderr } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    assert.ok(data.whitelist_secondary_filtered_count >= 2, `应过滤≥2个白名单IP，实际: ${data.whitelist_secondary_filtered_count}`);
    const riskIps = data.rows.map((r) => r.risk_ip);
    assert.ok(!riskIps.includes('198.51.100.1'), '198.51.100.1 属白名单范围，不应出现在封禁表格');
    assert.ok(!riskIps.includes('172.21.67.102'), '172.21.67.102 属 172.16/12，不应出现');
    assert.ok(stderr.includes('二次白名单过滤'), '应记录二次过滤日志');
  });

  it('风险IP全部通过白名单过滤（白名单混入率=0，SC-004）', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    // 逐一验证 rows 中的 risk_ip 不在白名单（用 isExternal 复核）
    for (const row of data.rows) {
      // 简单校验：非私有段、非白名单已知IP。完整校验由 whitelist.test.js 覆盖 isExternal。
      assert.ok(row.risk_ip && !row.risk_ip.startsWith('10.'), `不应含 10.x 私网IP: ${row.risk_ip}`);
    }
  });

  it('sip_addr 多形态规整（FR-014）：国家--城市 / 仅国家 / 未知', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const byIp = Object.fromEntries(data.rows.map((r) => [r.risk_ip, r.risk_geo_location]));
    // 5.61.209.92 → 西班牙--瓦伦西亚自治区--阿利坎特（去经纬度括号，country-city 保留全段）
    assert.equal(byIp['5.61.209.92'], '西班牙--瓦伦西亚自治区--阿利坎特');
    // 192.34.108.210 → 美国--华盛顿州--西雅图
    assert.equal(byIp['192.34.108.210'], '美国--华盛顿州--西雅图');
    // 172.110.223.197 → 未知（sip_addr=未知(...)）
    assert.equal(byIp['172.110.223.197'], '未知');
  });

  it('country 截取粒度仅输出国家（FR-014 可配置）', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json', '--geo-truncation', 'country']);
    const data = JSON.parse(stdout);
    const byIp = Object.fromEntries(data.rows.map((r) => [r.risk_ip, r.risk_geo_location]));
    assert.equal(byIp['5.61.209.92'], '西班牙');
    assert.equal(byIp['192.34.108.210'], '美国');
    assert.equal(byIp['1.14.142.185'], '中国');
  });

  it('max_timestamp 转 Asia/Shanghai 秒级 yyyy/M/d H:mm:ss（FR-010，无前导零）', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const byIp = Object.fromEntries(data.rows.map((r) => [r.risk_ip, r.alert_timestamp]));
    // 5.61.209.92 max_timestamp=2026-06-23T19:25:26.952Z → +08:00 = 2026/6/24 3:25:26
    assert.equal(byIp['5.61.209.92'], '2026/6/24 3:25:26');
    // 192.34.108.210 max_timestamp=2026-06-24T02:20:54.295Z → +08:00 = 2026/6/24 10:20:54
    assert.equal(byIp['192.34.108.210'], '2026/6/24 10:20:54');
  });

  it('风险描述格式：单类型 "{type}({n})"，多类型逗号分隔（FR-004/FR-011，经映射可读名）', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const byIp = Object.fromEntries(data.rows.map((r) => [r.risk_ip, r.risk_description]));
    // 5.61.209.92: 代码执行攻击(220)
    assert.equal(byIp['5.61.209.92'], '代码执行攻击(220)');
    // 192.34.108.210: 暴力猜解攻击(30)
    assert.equal(byIp['192.34.108.210'], '暴力猜解攻击(30)');
    // 5.187.35.142: 目录遍历探测(14)
    assert.equal(byIp['5.187.35.142'], '目录遍历探测(14)');
  });

  it('多攻击类型按 "{type}({n}), {type}({n})" 模式聚合（FR-004，经映射可读名）', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const byIp = Object.fromEntries(data.rows.map((r) => [r.risk_ip, r.risk_description]));
    // 1.14.142.185: 信息泄露行为(8), 黑市工具行为(4)
    assert.equal(byIp['1.14.142.185'], '信息泄露行为(8), 黑市工具行为(4)');
  });

  it('阈值筛选：攻击次数 ≤ min-attacks 不入选', () => {
    // fixture 含 9.9.9.9 (total_alerts=5)，默认 min-attacks=10 应排除
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const riskIps = data.rows.map((r) => r.risk_ip);
    assert.ok(!riskIps.includes('9.9.9.9'), '9.9.9.9 攻击次数=5 ≤ 10，不应入选');
    // 提高 min-attacks 后 192.34.108.210(30) 仍入选，但 5.187.35.142(14) 被排除
    const { stdout: stdout2 } = runCli(['--input', FIXTURE, '--format', 'json', '--min-attacks', '20']);
    const data2 = JSON.parse(stdout2);
    const riskIps2 = data2.rows.map((r) => r.risk_ip);
    assert.ok(riskIps2.includes('192.34.108.210'), '30 > 20 应入选');
    assert.ok(!riskIps2.includes('5.187.35.142'), '14 ≤ 20 应排除');
  });
});

// ============================================================
// US3：风险描述与地理位置由脚本可复现生成
// ============================================================
describe('US3 - 可复现性', () => {
  it('同输入两次运行输出逐行一致（FR-007，SC-005）', () => {
    const { stdout: out1 } = runCli(['--input', FIXTURE, '--format', 'markdown']);
    const { stdout: out2 } = runCli(['--input', FIXTURE, '--format', 'markdown']);
    assert.equal(out1, out2, '同输入两次 markdown 输出应逐行一致');
  });

  it('JSON 输出（除 generated_at 外）逐行一致', () => {
    const { stdout: j1 } = runCli(['--input', FIXTURE, '--format', 'json']);
    const { stdout: j2 } = runCli(['--input', FIXTURE, '--format', 'json']);
    const d1 = JSON.parse(j1);
    const d2 = JSON.parse(j2);
    // 排除 generated_at（时间敏感），其余字段应一致
    delete d1.generated_at;
    delete d2.generated_at;
    assert.deepEqual(d1, d2, 'JSON 输出（除 generated_at）应一致');
  });

  it('HTML 与 markdown 同数据源同行数据（FR-009）', () => {
    const { stdout: md } = runCli(['--input', FIXTURE, '--format', 'markdown']);
    const { stdout: html } = runCli(['--input', FIXTURE, '--format', 'html']);
    const mdLines = md.split('\n').slice(2); // 跳表头分隔
    // HTML 中每个 <tr> 的 <td> 应与 markdown 行单元格一致
    const htmlRows = html.match(/<tr><td>(.*?)<\/td><td>(.*?)<\/td><td>(.*?)<\/td><td>(.*?)<\/td><\/tr>/g) || [];
    assert.equal(mdLines.length, htmlRows.length, `行数应一致: md=${mdLines.length} html=${htmlRows.length}`);
    for (let i = 0; i < mdLines.length; i++) {
      const mdCells = mdLines[i].split('|').map((c) => c.trim()).filter(Boolean);
      const htmlCells = htmlRows[i].match(/<td>(.*?)<\/td>/g).map((c) => c.replace(/<\/?td>/g, ''));
      assert.deepEqual(mdCells, htmlCells, `行 ${i} MD/HTML 数据应一致`);
    }
  });

  it('风险IP顺序确定性：按攻击次数降序，次数相同按IP字典序（FR-007 无随机性）', () => {
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const ips = data.rows.map((r) => r.risk_ip);
    // 220 > 30 > 14 > 14 > 12；两个14的IP按字典序：172.110.223.197 < 5.187.35.142
    assert.deepEqual(ips, ['5.61.209.92', '192.34.108.210', '172.110.223.197', '5.187.35.142', '1.14.142.185']);
  });
});

// ============================================================
// US4：--candidates-output 输出 ban-ip-candidates JSON
// ============================================================
describe('US4 - candidates-output', () => {
  it('输出 ban-ip-candidates JSON 文件，candidates 数组与 rows 中 risk_ip 一致', () => {
    const tmpFile = join(os.tmpdir(), `test-candidates-${Date.now()}.json`);
    const { stderr } = runCli(['--input', FIXTURE, '--format', 'json', '--candidates-output', tmpFile]);
    assert.ok(stderr.includes('Candidates written'), `应输出 candidates 写入日志: ${stderr}`);
    const cand = JSON.parse(fs.readFileSync(tmpFile, 'utf-8'));
    assert.ok(Array.isArray(cand.candidates), 'candidates 应为数组');
    assert.ok(cand.candidates.length > 0, 'candidates 不为空');
    // 与正常 JSON 输出的 rows 比对
    const { stdout } = runCli(['--input', FIXTURE, '--format', 'json']);
    const data = JSON.parse(stdout);
    const riskIps = data.rows.map((r) => r.risk_ip);
    assert.deepEqual(cand.candidates, riskIps, 'candidates 应与 rows 中 risk_ip 列表一致');
    fs.unlinkSync(tmpFile);
  });

  it('candidates JSON 包含 total 和 date 字段', () => {
    const tmpFile = join(os.tmpdir(), `test-candidates-${Date.now()}.json`);
    runCli(['--input', FIXTURE, '--format', 'json', '--candidates-output', tmpFile]);
    const cand = JSON.parse(fs.readFileSync(tmpFile, 'utf-8'));
    assert.equal(cand.total, cand.candidates.length, 'total 应等于 candidates 数量');
    assert.ok(cand.generated_at, '应有 generated_at 时间戳');
    fs.unlinkSync(tmpFile);
  });

  it('未指定 --candidates-output 时不生成文件', () => {
    const { stderr } = runCli(['--input', FIXTURE, '--format', 'json']);
    assert.ok(!stderr.includes('Candidates written'), '不应输出 candidates 日志');
  });
});
