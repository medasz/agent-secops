/**
 * render-internal-section.js - 渲染层：内部攻击研判章节（§4.1–§4.5）
 *
 * 纯渲染函数：输入 analyzeInternal(parsed) 的输出，返回各子节内容体对象
 * { '4.1': Markdown, '4.2': Markdown, ... }（仅表格/列表，不含 ### 标题）。
 * 不调用 ES、不拼装业务分支（数据已在分析层计算完毕）。
 *
 * §4.1–§4.5 子标题由模板 alert-report-template.md 提供，本渲染器只输出内容体，
 * 避免与模板重复（与 §2.4/§2.5 既定模式一致：模板拥有标题、渲染器只渲染内容体）。
 *
 * 输出覆盖旧模板的：
 *   - §6.1 内部攻击统计 / §6.2 内部攻击类型分布 / §6.3–§6.5 横向移动
 */

/**
 * 攻击类型数组 → "类型(次数), 类型(次数)" 紧凑串。
 * @param {Array<{type:string,count:number}>} types
 * @returns {string}
 */
function formatAttackTypes(types) {
  if (!types || types.length === 0) return 'N/A';
  return types.map((t) => `${t.type}(${t.count})`).join(', ');
}

/**
 * 渲染内部攻击研判章节（内容体，不含 ### 标题）。
 * @param {object} analysis - analyzeInternal 输出：
 *   { stats:{total_alerts,internal_alerts,lateral_alerts,unique_internal_sources,unique_internal_targets,attack_types,host_states},
 *     lateral:{sources[],targets[],pairs[],hourly_distribution[],host_states[]}|null }
 * @returns {Object<string,string>} 各子节内容体，键为 '4.1'–'4.5'，值为 Markdown（仅表格/列表）
 */
export function renderInternalSection(analysis = {}) {
  const stats = analysis.stats || {};
  const lateral = analysis.lateral || null;

  const internalAlerts = stats.internal_alerts ?? 'N/A';
  const lateralAlerts = stats.lateral_alerts ?? 0;
  const srcCount = stats.unique_internal_sources ?? 0;
  const tgtCount = stats.unique_internal_targets ?? 0;

  const statsTable = [
    '| 指标 | 数值 |',
    '| --- | --- |',
    `| 内部攻击告警总数 | ${internalAlerts} |`,
    `| 横向移动告警数 | ${lateralAlerts} |`,
    `| 横向移动源IP数 | ${srcCount} |`,
    `| 横向移动目标IP数 | ${tgtCount} |`,
  ].join('\n');

  const total = stats.total_alerts || 0;
  const attackTypes = stats.attack_types || [];
  const atRows = attackTypes
    .map((item) => {
      const pct = total > 0 ? ((item.count / total) * 100).toFixed(1) + '%' : '0%';
      return `| ${item.type} | ${item.count} | ${pct} |`;
    })
    .join('\n');
  const atTable = atRows
    ? `| 攻击类型 | 攻击次数 | 占比 |\n| --- | --- | --- |\n${atRows}`
    : `| 攻击类型 | 攻击次数 | 占比 |\n| --- | --- | --- |\n| - | 无数据 | - |`;

  const srcRows = lateral
    ? lateral.sources.slice(0, 10).map((s) => `| ${s.max_timestamp || 'N/A'} | ${s.ip} | ${s.count} | ${formatAttackTypes(s.attack_types)} |`).join('\n')
    : '';
  const srcTable = srcRows
    ? `| 最近告警时间 | 源IP | 告警次数 | 攻击类型 |\n| --- | --- | --- | --- |\n${srcRows}`
    : `| 最近告警时间 | 源IP | 告警次数 | 攻击类型 |\n| --- | --- | --- | --- |\n| - | 无横向移动源 | - | - |`;

  const tgtRows = lateral
    ? lateral.targets.slice(0, 10).map((t) => `| ${t.max_timestamp || 'N/A'} | ${t.ip} | ${t.count} | ${formatAttackTypes(t.attack_types)} |`).join('\n')
    : '';
  const tgtTable = tgtRows
    ? `| 最近告警时间 | 目标IP | 告警次数 | 攻击类型 |\n| --- | --- | --- | --- |\n${tgtRows}`
    : `| 最近告警时间 | 目标IP | 告警次数 | 攻击类型 |\n| --- | --- | --- | --- |\n| - | 无横向移动目标 | - | - |`;

  const hourlyRows = lateral
    ? (lateral.hourly_distribution || []).map((h) => `| ${h.hour} | ${h.count} |`).join('\n')
    : '';
  const hourlyTable = hourlyRows
    ? `| 时段 | 告警次数 |\n| --- | --- |\n${hourlyRows}`
    : `| 时段 | 告警次数 |\n| --- | --- |\n| - | 0 |`;

  // 各子节仅渲染内容体（表格/列表），不带 ### 标题；
  // §4.1–§4.5 子标题由模板 alert-report-template.md 提供，避免重复。
  return {
    '4.1': statsTable,
    '4.2': atTable,
    '4.3': srcTable,
    '4.4': tgtTable,
    '4.5': hourlyTable,
  };
}

export { renderInternalSection as default };
