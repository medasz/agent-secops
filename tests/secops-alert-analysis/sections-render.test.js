import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { renderExternalTypeSection, renderExternalTimeSection } from '../../skills/secops-alert-analysis/scripts/reporting/sections/render-external-section.js';
import { renderInternalSection } from '../../skills/secops-alert-analysis/scripts/reporting/sections/render-internal-section.js';
import { renderCompromisedSection } from '../../skills/secops-alert-analysis/scripts/reporting/sections/render-compromised-section.js';
import { renderSpecialSection } from '../../skills/secops-alert-analysis/scripts/reporting/sections/render-special-section.js';
import { deriveThreatTopics } from '../../skills/secops-alert-analysis/scripts/shared/threat-categories.js';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

describe('renderExternalTypeSection / renderExternalTimeSection (模板驱动，渲染器不带标题)', () => {
  const analysis = {
    stats: { total_alerts: 100, external_alerts: 90, unique_external_ips: 12, compromised_alerts: 3 },
    attackTypes: [
      { type: '弱口令', count: 50, percentage: '50.0%', ipCount: 8 },
      { type: '远控木马', count: 30, percentage: '30.0%', ipCount: 4 },
    ],
    hourly: {
      rows: [{ hour: '08:00', count: 10 }, { hour: '09:00', count: 80 }],
      total: 90,
      peakHour: '09:00',
      peakCount: 80,
      highRiskHours: '09:00（80次）',
    },
  };

  it('renderExternalTypeSection: 类型表 + 全局统计，且自带 §2.4 标题（标题由模板提供）', () => {
    const md = renderExternalTypeSection(analysis);
    assert.match(md, /弱口令 \| 50 \| 50\.0% \| 8/);
    assert.match(md, /外部攻击告警 90 次/);
    assert.ok(!md.includes('### 2.4'), '类型节不应自带 §2.4 标题，避免与模板重复');
  });

  it('renderExternalTimeSection: 小时表 + 峰值/高危时段，且不自带 §2.5 标题', () => {
    const md = renderExternalTimeSection(analysis);
    assert.match(md, /高危时段/);
    assert.match(md, /最活跃时段/);
    assert.ok(!md.includes('### 2.5'), '时间节不应自带 §2.5 标题，避免与模板重复');
  });

  it('空输入不抛错（优雅占位）', () => {
    assert.doesNotThrow(() => renderExternalTypeSection());
    assert.doesNotThrow(() => renderExternalTimeSection());
  });
});

describe('renderInternalSection (模板驱动，渲染器不带标题)', () => {
  const analysis = {
    stats: {
      total_alerts: 40,
      internal_alerts: 40,
      lateral_alerts: 10,
      unique_internal_sources: 5,
      unique_internal_targets: 7,
      attack_types: [{ type: '非授权访问/权限绕过', count: 20 }],
    },
    lateral: {
      sources: [{ ip: '10.1.1.5', count: 6, attack_types: [{ type: '探测', count: 6 }], max_timestamp: '09:00' }],
      targets: [{ ip: '10.1.1.9', count: 4, attack_types: [{ type: '探测', count: 4 }], max_timestamp: '09:05' }],
      pairs: [{ source: '10.1.1.5', target: '10.1.1.9', count: 4, max_timestamp: '09:05' }],
      hourly_distribution: [{ hour: '09:00', count: 4 }],
      host_states: [],
    },
  };

  it('返回各子节内容体对象，且不含任何 ### 标题（标题由模板提供）', () => {
    const sec = renderInternalSection(analysis);
    for (const n of ['4.1', '4.2', '4.3', '4.4', '4.5']) {
      assert.ok(sec[n] !== undefined, `子节 ${n} 应存在`);
      assert.ok(!sec[n].includes('###'), `子节 ${n} 不应自带 ### 标题，避免与模板重复`);
    }
  });

  it('各子节内容体正确（统计表 / 攻击类型表 / 横向移动表）', () => {
    const sec = renderInternalSection(analysis);
    assert.match(sec['4.1'], /内部攻击告警总数/);
    assert.match(sec['4.2'], /非授权访问\/权限绕过/);
    assert.match(sec['4.3'], /10\.1\.1\.5/); // 横向源
    assert.match(sec['4.4'], /10\.1\.1\.9/); // 横向目标
    assert.match(sec['4.5'], /09:00/);       // 小时分布
  });

  it('handles null lateral gracefully（无横向移动时占位提示）', () => {
    const sec = renderInternalSection({ stats: analysis.stats, lateral: null });
    assert.match(sec['4.3'], /无横向移动源/);
    assert.ok(!sec['4.3'].includes('###'), '子节 4.3 不应自带 ### 标题');
  });
});

describe('renderCompromisedSection', () => {
  const hosts = [
    { ip: '10.1.1.1', count: 5, states: ['攻击成功'], risk_desc: '弱口令(5)', opinion: '建议处置|复查', attack_source: '外部', first_seen: '08:00' },
    { ip: '10.1.1.2', count: 3, states: ['失陷'], risk_desc: 'x', opinion: 'o2', attack_source: '内网', first_seen: '09:00' },
    { ip: '10.1.1.3', count: 2, states: ['失陷'], risk_desc: 'y', opinion: 'o3', attack_source: '未知', first_seen: '10:00' },
  ];

  it('7-column header includes 受害IP and 攻击类型 (renamed from 主机IP/风险描述)', () => {
    const md = renderCompromisedSection(hosts);
    assert.match(md, /\| 最近告警时间 \| 受害IP \| 攻击次数 \| 攻击结果 \| 攻击类型 \| 攻击来源 \| 研判意见 \|/);
    // 旧表头不应再出现
    assert.ok(!md.includes('| 主机IP |'), '旧表头 主机IP 应已移除');
    assert.ok(!md.includes('| 风险描述 |'), '旧表头 风险描述 应已移除');
  });

  it('renders attack_source values and escapes pipes in opinion (content still from risk_desc)', () => {
    const md = renderCompromisedSection(hosts);
    assert.match(md, /\| 10\.1\.1\.1 \| 5 \| 攻击成功 \| 弱口令\(5\) \| 外部 \| 建议处置\/复查 \|/);
    assert.match(md, /\| 内网 \|/);
    assert.match(md, /\| 未知 \|/);
  });

  it('renders a placeholder row for empty hosts', () => {
    const md = renderCompromisedSection([]);
    assert.match(md, /无失陷主机/);
  });
});

// ---------------------------------------------------------------------------
// §5 专项研判：受害 IP 表格（需求A）+ 缺陷修复校验
// ---------------------------------------------------------------------------
describe('renderSpecialSection (模板驱动，渲染器不带标题 + 缺陷修复)', () => {
  // 失陷/攻击成功主机：覆盖各专项类别；10.1.1.5 为「代理工具」应被排除在 C2 之外
  const compromised = [
    { ip: '10.1.1.1', count: 50, attack_types: [{ type: '弱口令', count: 50 }], last_seen: '2026-07-18 23:00:00', first_seen: '2026-07-18 00:00:00' },
    { ip: '10.1.1.2', count: 30, attack_types: [{ type: '非授权访问/权限绕过', count: 30 }], last_seen: '2026-07-18 22:00:00' },
    { ip: '10.1.1.3', count: 20, attack_types: [{ type: '远控木马', count: 20 }], last_seen: '2026-07-18 21:00:00' },
    { ip: '10.1.1.4', count: 10, attack_types: [{ type: '挖矿', count: 10 }], last_seen: '2026-07-18 20:00:00' },
    { ip: '10.1.1.5', count: 5, attack_types: [{ type: '代理工具', count: 5 }], last_seen: '2026-07-18 19:00:00' },
  ];
  const domains = [
    { ioc: '268569560-发现后门程序 Mozi', attack_types: [{ type: '后门程序', count: 3 }] },
    { ioc: '12345-弱口令爆破行为', attack_types: [{ type: '弱口令', count: 1 }] },
  ];
  const attackTypes = [
    { type: '弱口令', count: 50 },
    { type: '暴力猜解', count: 60 },
    { type: '非授权访问/权限绕过', count: 30 },
    { type: '远控木马', count: 20 },
    { type: '后门程序', count: 3 },
    { type: '挖矿', count: 10 },
    { type: '代理工具', count: 5 },
  ];
  const topics = deriveThreatTopics({ attackTypes, ips: [], domains, compromised });

  it('deriveThreatTopics 为各专项派生 details 且代理工具不进 C2', () => {
    assert.ok(Array.isArray(topics.weak_password.details) && topics.weak_password.details.length === 2);
    assert.ok(Array.isArray(topics.c2_rat.details) && topics.c2_rat.details.length === 1);
    assert.ok(Array.isArray(topics.mining_ransom.details) && topics.mining_ransom.details.length === 1);
    // 10.1.1.5 为代理工具，不应出现在 c2_rat 受害主机中
    assert.ok(topics.c2_rat.details.every((d) => d.victimIp !== '10.1.1.5'));
    assert.equal(topics.c2_rat.details[0].victimIp, '10.1.1.3');
    // 弱口令按攻击次数降序：10.1.1.1(50) 在前
    assert.equal(topics.weak_password.details[0].victimIp, '10.1.1.1');
    assert.match(topics.weak_password.details[0].action, /弱口令整改/);
  });

  it('返回 §5.1–§5.4 各子节内容体，且不含 ### 标题（标题由模板提供）', () => {
    const xff = {
      meta: {},
      total_xff_alerts: 120,
      external_unique_clients: 15,
      external_clients: [{ real_client_ip: '1.2.3.4', alerts: 40, via_cdn: true, cdn_hops: 2, chains: [] }],
      spoofed_or_internal_xff: { total: 3 },
    };
    const sec = renderSpecialSection({ topics, xff });
    for (const n of ['5.1', '5.2', '5.3', '5.4']) {
      assert.ok(sec[n] !== undefined, `子节 ${n} 应存在`);
      assert.ok(!/^### 5\.\d/m.test(sec[n]), `子节 ${n} 不应自带 ### 节标题（#### 子子标题属内容体，允许），避免与模板重复`);
    }
    // 内容正确性抽查
    assert.match(sec['5.1'], /XFF 相关告警总数/);
    assert.match(sec['5.2'], /10\.1\.1\.1/); // 弱口令受害主机
    assert.match(sec['5.3'], /10\.1\.1\.3/); // C2 受害主机
    assert.match(sec['5.4'], /10\.1\.1\.4/); // 挖矿受害主机
  });

  it('degrades gracefully when xff is null (no crash, prompt only)', () => {
    const sec = renderSpecialSection({ topics, xff: null });
    assert.match(sec['5.1'], /未提供 XFF 代理攻击预跑产物/);
    assert.ok(!sec['5.1'].includes('### 5.1'), '§5.1 不应自带 ### 标题');
    assert.match(sec['5.2'], /相关攻击类型/); // 弱口令内容体概览
    assert.match(sec['5.4'], /10\.1\.1\.4/);  // 挖矿受害主机
  });

  it('§5.2/5.3/5.4 渲染受害IP表格列头', () => {
    const sec = renderSpecialSection({ topics, xff: null });
    // 专项受害 IP 表（弱口令/远控/挖矿共用同一列头），出现在 §5.2 内容体
    assert.match(sec['5.2'], /\| 最近告警时间 \| 受害IP \| 攻击类型 \|/);
  });

  it('§5.1 仅输出三项指标（表格由模板 {{xff_*}} 占位符注入，渲染器不硬编码标题/表格）', () => {
    const xff = {
      meta: {},
      total_xff_alerts: 117,
      external_unique_clients: 8,
      external_clients: [{ real_client_ip: '1.2.3.4', alerts: 40, via_cdn: true, cdn_hops: 2, chains: [] }],
      spoofed_or_internal_xff: { total: 0 },
    };
    const xffJudgment = {
      total_xff_alerts: 117,
      external_unique_clients: 8,
      spoofed_or_internal_xff: 0,
      report_tables: {
        ip_ban_table_md: '| 外部真实客户端IP | 受害IP | 告警数 | 攻击类型 |\n| --- | --- | --- | --- |\n| `1.2.3.4` | 9.9.9.9 | 40 | 扫描 |',
        victim_investigate_table_md: '| 受害IP | 外部真实客户端IP | 告警数 | 攻击类型 |\n| --- | --- | --- | --- |\n| `9.9.9.9` | 1.2.3.4 | 40 | 扫描 |',
        threat_intel_table_md: '| 风险IP | 是否恶意 | 可信度 | 威胁类型 | 情报标签 |\n| --- | --- | --- | --- |\n| `1.2.3.4` | 是 | 高 | 傀儡机 | api目录扫描 |',
      },
    };
    const sec = renderSpecialSection({ topics, xff, xffJudgment });
    // 三项指标应存在
    assert.match(sec['5.1'], /XFF 相关告警总数：117/);
    assert.match(sec['5.1'], /外部真实客户端 IP 数：8/);
    assert.match(sec['5.1'], /伪造\/内网 XFF 告警数：0/);
    // 渲染器不再输出表格与标题（改由模板占位符注入，禁止重算/硬编码）
    assert.ok(!sec['5.1'].includes('### XFF-IP封禁建议表'), '§5.1 不应硬编码 XFF 表标题，标题由模板拥有');
    assert.ok(!sec['5.1'].includes('| 风险IP |'), '§5.1 不应内嵌表格，表格由模板 {{xff_*}} 注入');
  });

  it('§5.1 表格标题与 {{xff_*}} 占位符由模板拥有（单源，渲染器不硬编码）', () => {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const template = readFileSync(resolve(__dirname, '../../skills/secops-alert-analysis/templates/alert-report-template.md'), 'utf8');
    // 模板 §5.1 应含三个 XFF 表子标题（#### 级别）与对应占位符（xff_ 前缀，隔离 §2.3 撞名）
    for (const t of ['XFF-IP封禁建议表', 'XFF-受害IP', 'XFF-IP威胁情报']) {
      assert.ok(template.includes(`#### ${t}`), `模板 §5.1 应含子标题：#### ${t}`);
    }
    assert.ok(template.includes('{{xff_real_client_investigate_table}}'), '模板 §5.1 应含 {{xff_real_client_investigate_table}}');
    assert.ok(template.includes('{{xff_victim_investigate_table}}'), '模板 §5.1 应含 {{xff_victim_investigate_table}}');
    assert.ok(template.includes('{{xff_threat_intel_table}}'), '模板 §5.1 应含 {{xff_threat_intel_table}}');
    assert.ok(template.includes('{{xff_ban_ip_table}}'), '模板 §5.1 应含 {{xff_ban_ip_table}}（XFF 4列封禁表）');
    // 渲染器仍只输出指标，不硬编码标题/表格
    const xff = {
      meta: {}, total_xff_alerts: 117, external_unique_clients: 8,
      external_clients: [{ real_client_ip: '1.2.3.4', alerts: 40, via_cdn: true, cdn_hops: 2, chains: [] }],
      spoofed_or_internal_xff: { total: 0 },
    };
    const sec = renderSpecialSection({ topics, xff });
    assert.ok(!sec['5.1'].includes('XFF-IP封禁建议表'), '§5.1 渲染体不应硬编码 XFF 表标题');
  });

  it('清洗后的 ioc 无前导数字编号', () => {
    const sec = renderSpecialSection({ topics, xff: null });
    assert.ok(sec['5.3'].includes('发现后门程序 Mozi'), 'ioc 应已清洗前导编号');
    assert.ok(!sec['5.3'].includes('268569560-'), '原始带编号 ioc 不应出现');
  });

  it('代理工具主机不出现在 C2 节（应有 受害IP 表且不含 10.1.1.5）', () => {
    const sec = renderSpecialSection({ topics, xff: null });
    assert.ok(!sec['5.3'].includes('10.1.1.5'), '代理工具主机不应进入 C2 受害主机表');
  });

});

// ---------------------------------------------------------------------------
// §5.1.4 XFF-IP 封禁建议表：与 §2.1 对齐（白名单过滤 + 阈值 alerts>10 + top-3 风险描述）
// 以下 2 行内容为离线重生成的权威值（judgment-xff/gen-md-report-xff.js buildReportTables）。
// ---------------------------------------------------------------------------
describe('XFF-IP 封禁建议表（§5.1.4）与 §2.1 对齐：仅 external 且 alerts>10 的 top-3', () => {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const recPath = resolve(__dirname, '../../output/judgment-xff-ban-recommendation-20260723.json');
  let rec = null;
  try {
    rec = JSON.parse(readFileSync(recPath, 'utf-8'));
  } catch (e) {
    // 未找到重生成产物时跳过，避免无数据环境误报（不掩盖真实回归）
  }

  // 取自首轮离线重生成的实际值（alerts>10 仅 185.177.72.38=275、52.139.36.144=12 通过）
  const EXPECTED_XFF_BAN_TABLE_MD = [
    '| 告警日期时间戳 | 风险IP | 风险描述 | 风险IP的地理位置 |',
    '| --- | --- | --- | --- |',
    '| 2026/7/23 19:50:44 | 185.177.72.38 | 目录遍历探测(120), 非授权访问/权限绕过行为(77), 信息泄露行为(37) | 未知 |',
    '| 2026/7/23 2:34:27 | 52.139.36.144 | webshell利用(12) | 未知 |',
  ].join('\n');

  it('report_tables.xff_ban_ip_table_md 仅 2 行（external 且 alerts>10），风险描述为 top-3', (t) => {
    if (!rec) { t.skip('未找到重生成产物: ' + recPath); return; }
    const md = rec.report_tables.xff_ban_ip_table_md;
    assert.equal(md, EXPECTED_XFF_BAN_TABLE_MD, '§5.1.4 XFF 封禁表应与离线重生成值逐字一致');
    const dataRows = md.split('\n').filter((l) => /^\| 20/.test(l));
    assert.equal(dataRows.length, 2, '应仅收录 2 个客户端（185.177.72.38 / 52.139.36.144）');
  });

  it('§5.1.4 表头与 §2.1 HEADERS 逐字一致（4 列封禁表）', () => {
    if (!rec) return;
    const md = rec.report_tables.xff_ban_ip_table_md;
    assert.ok(md.startsWith('| 告警日期时间戳 | 风险IP | 风险描述 | 风险IP的地理位置 |'));
  });
});

// ---------------------------------------------------------------------------
// §5.1.1 XFF-IP封禁建议表 / §5.1.2 XFF-受害IP排查表：攻击类型列必须带次数 (count)
// 锁定回归：防止被改回纯类型名（目录遍历、信息泄露…）。实际值在离线重生成的
// judgment-xff-ban-recommendation-20260723.json 的 report_tables 中。
// 这两个 md 经主报告模板注入 {{xff_real_client_investigate_table}} / {{xff_victim_investigate_table}}。
// ---------------------------------------------------------------------------
describe('§5.1.1/§5.1.2 攻击类型列必须带 (count) 格式（锁定回归，防改回纯类型名）', () => {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const recPath = resolve(__dirname, '../../output/judgment-xff-ban-recommendation-20260723.json');
  let rec = null;
  try {
    rec = JSON.parse(readFileSync(recPath, 'utf-8'));
  } catch (e) {
    // 未找到重生成产物时跳过，避免无数据环境误报（不掩盖真实回归）
  }

  /**
   * 取 markdown 表第 4 列（攻击类型）单元格，断言至少一个含 (count) 格式。
   */
  function assertAttackTypeHasCount(md, label) {
    const lines = md.split('\n').filter((l) => l.trim().startsWith('|'));
    const dataRows = lines.slice(2); // 跳过表头与分隔行
    assert.ok(dataRows.length > 0, `${label} 应至少含 1 行数据`);
    const found = dataRows.some((row) => {
      const cells = row.replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
      const attackCell = cells[3]; // 攻击类型 列（第 4 列）
      return attackCell && /\(\d+\)/.test(attackCell);
    });
    assert.ok(found, `${label} 的「攻击类型」单元格应包含 (count) 格式（如 目录遍历探测(120)），防止被改回纯类型名`);
  }

  it('report_tables.ip_ban_table_md（§5.1.1 即 {{xff_real_client_investigate_table}}）攻击类型列含 (count)', () => {
    if (!rec) return; // 无产物环境跳过，不掩盖真实回归
    assertAttackTypeHasCount(rec.report_tables.ip_ban_table_md, '§5.1.1 XFF-IP封禁建议表');
  });

  it('report_tables.victim_investigate_table_md（§5.1.2 即 {{xff_victim_investigate_table}}）攻击类型列含 (count)', () => {
    if (!rec) return;
    assertAttackTypeHasCount(rec.report_tables.victim_investigate_table_md, '§5.1.2 XFF-受害IP排查表');
  });
});
