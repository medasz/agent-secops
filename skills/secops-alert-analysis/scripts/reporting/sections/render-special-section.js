/**
 * render-special-section.js - 渲染层：专项研判章节（§5.1–§5.4）
 *
 * 纯渲染函数：输入 { topics: deriveThreatTopics 输出, xff: query-xff JSON|null,
 * xffJudgment?: gen-md-report-xff 权威口径 JSON|null }，返回各子节内容体对象
 * { '5.1': Markdown, '5.2': Markdown, ... }（仅表格/列表/子子标题，不含 ### 标题）。
 * 不调用 ES、不拼装业务分支（数据已在分析层派生完毕）。
 *
 * 各节：
 *   5.1 XFF 代理攻击 —— 消费 query-xff.js 预跑 JSON；未预跑时**优雅降级**为提示，不阻断报告
 *   5.2 弱口令攻击   —— 由 topics.weak_password 驱动
 *   5.3 远控木马/C2攻击  —— 由 topics.c2_rat 驱动（叠加关联攻击特征标签）
 *   5.4 挖矿/勒索攻击    —— 由 topics.mining_ransom 驱动（叠加关联矿池/勒索行为标签）
 *
 * 注意：本函数只输出 §5.1–§5.4 内容体；「## 5. 专项研判」整章标题与
 * 「### 5.1–§5.4」子标题均由模板 alert-report-template.md 提供，避免与模板重复
 * （与 §2.4/§2.5、§4.1–§4.5 既定模式一致：模板拥有标题、渲染器只渲染内容体）。
 * 其中 §5.1 的四张 XFF 表（#### XFF-外部真实客户端IP / #### XFF-受害IP / #### XFF-IP封禁建议表 / #### XFF-IP威胁情报）
 * 的标题、引言与占位符（{{xff_real_client_investigate_table}} 等）已全部收归模板 alert-report-template.md §5.1 正文，
 * 数据来自 gen-md-report-xff.js 产出的 report_tables（单源），与 XFF 子技能报告同源、零重算。
 */

import { cleanIoc } from '../../shared/threat-categories.js';

/**
 * 渲染单个专项类别块（弱口令 / 远控C2 / 挖矿勒索）为可交处置人员的受害 IP 表格。
 *
 * 列：| 最近告警时间 | 受害IP | 攻击类型 |（已取消「处置建议」列）。
 * 处置建议提升为「标题下方第一个条目」（小节级），取受害明细中的处置口径聚合而成
 * （同类受害 IP 的处置口径通常统一，故聚合后作为整节首条建议，无信息损耗）。
 * 数据来自 topic.details（attackTypes 格式化为 `类型(次数), ...`）。
 * 若无 details（空数组）则输出占位提示，表示本期未发现该特征的受害主机（此时无具体处置对象，不渲染处置建议条目）。
 * 同时保留一行清洗后的 ioc/行为特征补充（若 topic.domains 且非空）。
 *
 * @param {string} label 小节标题文本（不含编号，如「弱口令攻击」；### 标题由模板提供）
 * @param {object} topic { attackTypes:[{type,count}], ipCount, domains:string[], hostCount, details:[{victimIp,lastTime,attackTypes,action}] }
 * @param {object} [opts] { domainsLabel?:string }
 * @returns {string}
 */
function renderTopicBlock(label, topic = {}, opts = {}) {
  const t = topic || {};
  const attackTypes = t.attackTypes || [];
  const ipCount = t.ipCount ?? 0;
  const hostCount = t.hostCount ?? 0;
  const domains = t.domains || [];
  const details = t.details || [];
  // 受害主机数标签：默认「命中受害主机数」；真实失陷类（如 §5.3 C2）可经 opts.hostCountLabel 改回「命中失陷主机数」
  // （Fix B / Bug-03：避免把内网受害主机（攻击成功）误统称为「失陷」，误导应急）。
  const hostCountLabel = opts.hostCountLabel || '命中受害主机数';
  // 防御性再清洗：domain 来自分析层已清洗，此处兜底剥离可能残留的前导编号（如 `268569560-` / `1. `）。
  const cleanDomains = domains.map((d) => cleanIoc(d));

  // 内容体不以空行开头：标题后的空行由模板占位符提供，避免双空行。
  const lines = [];

  // 小节级处置建议：聚合受害明细中的处置口径，作为标题下第一个条目。
  // 仅在有受害 IP 明细时呈现（无明细则无具体处置对象）。
  let sectionAction = '';
  if (details.length > 0) {
    const actions = [...new Set(details.map((d) => (d.action || '').trim()).filter(Boolean))];
    sectionAction = actions.join('；');
  }

  // 处置建议（小节级首条）——无明细时不渲染
  if (sectionAction) {
    lines.push(`- 处置建议：${sectionAction}`);
  }
  // 攻击类型概览（始终展示，便于快速了解分布）
  lines.push(`- 相关攻击类型（${attackTypes.length} 类）：${attackTypes.map((a) => `${a.type}(${a.count}次)`).join('、') || '无'}`);
  lines.push(`- 涉及外部源IP数：${ipCount}`);
  lines.push(`- ${hostCountLabel}：${hostCount}`);
  if (cleanDomains.length > 0) {
    lines.push(`- ${opts.domainsLabel || '关联攻击特征标签'}（${cleanDomains.length} 个）：${cleanDomains.join('、')}`);
  }
  lines.push('');

  // 受害 IP 处置表（已取消「处置建议」列；处置口径已提升为小节级首条建议）
  if (details.length === 0) {
    lines.push(`> 本期未发现明显${label}特征的受害主机。`);
    lines.push('');
    return lines.join('\n');
  }

  const header = '| 最近告警时间 | 受害IP | 攻击类型 |';
  const separator = '| --- | --- | --- |';
  const rows = details.map((d) => {
    const ats = (d.attackTypes || []).map((a) => `${a.type}(${a.count})`).join(', ') || 'N/A';
    return `| ${d.lastTime || 'N/A'} | ${d.victimIp} | ${ats} |`;
  });
  lines.push(header);
  lines.push(separator);
  lines.push(rows.join('\n'));
  lines.push('');
  return lines.join('\n');
}

/**
 * 渲染 §5.1 XFF 代理攻击（平铺、全量、精准；含未预跑优雅降级）。
 *
 * 设计约束（来自研判需求）：
 *   - 取消下级章节（不再有 5.1.1 / 5.1.2），所有内容平铺在 ### 5.1 标题下。
 *   - 三项核心指标（告警总数 / 外部真实客户端 IP 数 / 伪造内网 XFF 数）由本函数输出为内容体。
 *   - 四张表（XFF-IP封禁建议表 / XFF-受害IP排查表 / XFF-外部真实客户端IP / XFF-IP威胁情报）的标题、引言与占位符
 *     已全部收归模板 alert-report-template.md §5.1 正文（占位符统一 xff_ 前缀），
 *     数据来自 gen-md-report-xff.js 产出的 report_tables（单源，禁止主报告重算聚合）；
 *     本函数不再输出表格、也不再硬编码任何 ### / #### 标题。
 *
 * @param {object|null} xff query-xff.js 产物
 * @param {object|null} xffJudgment gen-md-report-xff.js 产物（权威封禁口径，含 report_tables 两张表）
 * @returns {string}
 */
function renderXff(xff, xffJudgment) {
  if (!xff) {
    return [
      '> ⚠️ 未提供 XFF 代理攻击预跑产物（query-xff JSON）。本节跳过 XFF 专项研判，不阻断报告生成。',
      '> 如需 XFF 代理攻击研判，请以 `node` 预跑 `query-xff.js` 产出 JSON，并以 `--xff` 传入；权威封禁口径可由 `gen-md-report-xff.js` 经 `--xff-judgment` 注入。',
      '',
    ].join('\n');
  }

  // 三个核心指标：优先取权威封禁口径 xffJudgment（子技能最终产出），回退 query-xff。
  const authoritative = xffJudgment && typeof xffJudgment === 'object' ? xffJudgment : null;
  const total = (authoritative && authoritative.total_xff_alerts) ?? xff.total_xff_alerts ?? 0;
  const uniqueClients = (authoritative && authoritative.external_unique_clients) ?? xff.external_unique_clients ?? 0;
  const spoofedRaw = (authoritative && authoritative.spoofed_or_internal_xff) ?? xff.spoofed_or_internal_xff ?? 0;
  // 兼容 number 与 { total } 两种形态。
  const spoofed = (typeof spoofedRaw === 'object' && spoofedRaw !== null)
    ? (spoofedRaw.total ?? 0)
    : (spoofedRaw || 0);

  // §5.1 仅输出三项指标（内容体）；四张表由模板占位符 {{xff_real_client_investigate_table}} / {{xff_ban_ip_table}} 等直接注入，
  // 数据统一来自子技能 report_tables（单源），与 XFF 子技能报告同源。
  const lines = [
    `- XFF 相关告警总数：${total}`,
    `- 外部真实客户端 IP 数：${uniqueClients}`,
    `- 伪造/内网 XFF 告警数：${spoofed}`,
    '',
  ];
  return lines.join('\n');
}

/**
 * 渲染专项研判章节（§5.1–§5.4）。
 * @param {object} input
 * @param {object} [input.topics] - deriveThreatTopics 输出 { weak_password, c2_rat, mining_ransom }
 * @param {object|null} [input.xff] - query-xff.js 预跑 JSON（null = 未预跑，优雅降级）
 * @param {object|null} [input.xffJudgment] - gen-md-report-xff.js 权威口径 JSON（可选）
 * @returns {Object<string,string>} 各子节内容体，键为 '5.1'–'5.4'，值为 Markdown（仅内容体）
 */
export function renderSpecialSection({ topics = {}, xff = null, xffJudgment = null } = {}) {
  const t = topics || {};
  // 各子节仅渲染内容体（表格/列表/子子标题），不带 ### 标题；
  // §5.1–§5.4 子标题由模板 alert-report-template.md 提供，避免重复。
  return {
    '5.1': renderXff(xff, xffJudgment),
    '5.2': renderTopicBlock('弱口令攻击', t.weak_password || {}),
    '5.3': renderTopicBlock('远控木马/C2 外联攻击', t.c2_rat || {}, { domainsLabel: '关联 C2/恶意行为标签', hostCountLabel: '命中失陷主机数' }),
    '5.4': renderTopicBlock('挖矿/勒索攻击', t.mining_ransom || {}, { domainsLabel: '关联矿池/勒索行为标签' }),
  };
}

export { renderXff, renderSpecialSection as default };
