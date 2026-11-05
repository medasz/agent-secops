/**
 * render-external-section.js - 渲染层：外部攻击研判章节（§2.4 / §2.5）
 *
 * 纯渲染函数：输入 analyzeExternal(parsed) 的输出，返回 Markdown 章节串。
 * 不调用 ES、不拼装业务分支（数据已在分析层计算完毕）。
 *
 * 设计原则（对齐模板 alert-report-template.md）：
 *   - 模板拥有所有章节标题（## 2 / ### 2.4 / ### 2.5 …），渲染器 **不自带** 任何 `### N` 标题，
 *     避免与模板标题重复。每个占位符只渲染自身的「内容体」，实现「每一节单独渲染」。
 *   - 拆为两个独立函数，分别注入模板的 {{external_section}}（§2.4 按类型）与
 *     {{external_time_section}}（§2.5 按时间）。
 *
 * 旧版 renderExternalSection（自带 ### 2.4 / ### 2.5 标题的合并函数）已移除，
 * 由下面两个函数取代；测试 sections-render.test.js 同步改为断言两函数。
 */

/**
 * 渲染 §2.4 外部攻击-按类型分布 内容体（不含章节标题）。
 * @param {object} analysis - analyzeExternal 输出：
 *   { stats:{total_alerts,external_alerts,unique_external_ips,compromised_alerts},
 *     attackTypes:[{type,count,percentage,ipCount}] }
 * @returns {string} Markdown 内容体
 */
export function renderExternalTypeSection(analysis = {}) {
  const stats = analysis.stats || {};
  const attackTypes = analysis.attackTypes || [];

  const attackTypeRows = attackTypes.map(
    (a) => `| ${a.type} | ${a.count} | ${a.percentage} | ${a.ipCount} |`
  );
  const attackTypeTable = attackTypeRows.length
    ? `| 攻击类型 | 攻击次数 | 占比 | 相关IP数 |\n| --- | --- | --- | --- |\n${attackTypeRows.join('\n')}`
    : '| 攻击类型 | 攻击次数 | 占比 | 相关IP数 |\n| --- | --- | --- | --- |\n| - | 无外部攻击类型数据 | - | - |';

  return [
    `> 全局统计：外部攻击告警 ${stats.external_alerts ?? stats.total_alerts ?? 0} 次，涉及外部IP ${stats.unique_external_ips ?? 0} 个，其中命中失陷 ${stats.compromised_alerts ?? 0} 个。`,
    ``,
    attackTypeTable,
  ].join('\n');
}

/**
 * 渲染 §6.2 外部攻击IP完整列表（附录·含表头）。
 * @param {Array} ips - parsedExternal.ips，shape [{ip,total_alerts,attack_types,max_timestamp,sip_addr}]
 * @returns {string} 完整 Markdown 表格（含表头+分隔行+数据行）
 */
export function renderFullIpSection(ips = []) {
  const header = '| 最近告警时间     | 攻击IP | 攻击次数 | 归属地 | 攻击类型(次数) |';
  const separator = '| ---------------- | ------ | -------- | ------ | -------------- |';
  const rows = ips.map(ip => {
    const types = (ip.attack_types || []).map(t => `${t.type}(${t.count})`).join(', ') || '';
    return `| ${ip.max_timestamp || 'N/A'} | ${ip.ip} | ${ip.total_alerts} | ${ip.sip_addr || 'N/A'} | ${types} |`;
  });
  return [header, separator, ...rows].join('\n');
}

/**
 * 渲染 §2.5 外部攻击-按时间分布 内容体（不含章节标题）。
 * @param {object} analysis - analyzeExternal 输出：
 *   { hourly:{rows:[{hour,count}],total,peakHour,peakCount,highRiskHours} }
 * @returns {string} Markdown 内容体
 */
export function renderExternalTimeSection(analysis = {}) {
  const hourly = analysis.hourly || {};

  const hourlyRows = (hourly.rows || []).map((h) => `| ${h.hour} | ${h.count} |`);
  const hourlyTable = hourlyRows.length
    ? `| 时段 | 告警次数 |\n| --- | --- |\n${hourlyRows.join('\n')}`
    : '| 时段 | 告警次数 |\n| --- | --- |\n| - | 0 |';

  const peakHour = hourly.peakHour || 'N/A';
  const peakCount = hourly.peakCount ?? 0;
  const highRiskHours = hourly.highRiskHours || '无';
  const total = hourly.total ?? 0;

  return [
    `> 以下数据仅统计外部攻击IP的告警，已排除白名单IP。`,
    ``,
    hourlyTable,
    ``,
    `**总计**：${total} 次外部攻击告警`,
    ``,
    `- **最活跃时段**：\`${peakHour}\` 时（${peakCount} 次攻击）`,
    `- **高危时段**（次数 > 均值×1.5）：${highRiskHours}`,
  ].join('\n');
}

export { renderExternalTypeSection as default };
