/**
 * render-compromised-section.js - 渲染层：攻击成功/失陷主机研判章节（§3）
 *
 * 纯渲染函数：输入 analyzeCompromised(hosts) 的输出（每项含 attack_source），
 * 返回 Markdown 章节串。不调用 ES、不拼装业务分支。
 *
 * 输出覆盖旧模板的 §5 失陷主机清单，并按设计新增「攻击来源」列（位于「攻击类型」与
 * 「研判意见」之间），表头 7 列：
 *   | 最近告警时间 | 受害IP | 攻击次数 | 攻击结果 | 攻击类型 | 攻击来源 | 研判意见 |
 * 注：「攻击类型」列内容仍取原 risk_desc 字段（真实数据中该字段即攻击类型明细，如
 * 「非授权访问/权限绕过行为(2298)」），仅改表头命名使语义自洽。
 */

/**
 * 转义表格单元格内容：将 `|` 替换为 `/`（避免破坏 markdown 表格），折叠换行。
 * @param {*} value
 * @returns {string}
 */
function escCell(value) {
  return String(value == null ? '' : value).replace(/\|/g, '/').replace(/\r?\n+/g, ' ').trim();
}

/**
 * 渲染失陷主机研判章节。
 * @param {Array<{ip,count,attack_types,states,first_seen,last_seen,risk_desc,opinion,reason,sip_addrs,attack_source}>} hosts
 * @returns {string} Markdown 章节串（含 7 列表头）
 */
export function renderCompromisedSection(hosts = []) {
  const list = Array.isArray(hosts) ? hosts : [];
  const header = '| 最近告警时间 | 受害IP | 攻击次数 | 攻击结果 | 攻击类型 | 攻击来源 | 研判意见 |';
  const separator = '| --- | --- | --- | --- | --- | --- | --- |';

  if (list.length === 0) {
    return [header, separator, '| - | 无失陷主机 | - | - | - | - | - |'].join('\n');
  }

  const sorted = [...list].sort((a, b) => (b.count || 0) - (a.count || 0));
  const rows = sorted.map((h) => {
    const states = (h.states || []).join('、') || '';
    const riskDesc = escCell(h.risk_desc || 'N/A');
    const opinion = escCell(h.opinion || '');
    const attackSource = escCell(h.attack_source || '未知');
    return `| ${h.first_seen || 'N/A'} | ${h.ip} | ${h.count} | ${states} | ${riskDesc} | ${attackSource} | ${opinion} |`;
  });

  return [header, separator, ...rows].join('\n');
}

export { renderCompromisedSection as default };
