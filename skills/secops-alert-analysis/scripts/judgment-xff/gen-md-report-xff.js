#!/usr/bin/env node

/**

 * gen-md-report-xff.js — 合并 XFF 客户端 + 受害主机 + 微步情报 → 封禁建议报告

 *

 * 路径 A（纯脚本、零 MCP）。消费三步产物，生成：

 *   - Markdown 封禁建议报告（按 templates/judgment-xff-ban-template.md 填占位符）

 *   - 机读 JSON（含 judgment 权威口径块，供防火墙/WAF 批量下发）

 *

 * 用法：

 *   node scripts/judgment-xff/gen-md-report-xff.js \

 *       --xff output/judgment-xff-{start}-{end}.json \

 *       --victims output/judgment-xff-victimhosts-{start}-{end}.json \

 *       --threatbook output/threatbook-enrich-{date}.json \

 *       --end-date {end} [--report-time "YYYY-MM-DD HH:MM"]

 *

 * 退出码：0=成功 1=参数/输入错误

 */

import fs from 'fs';

import { resolve, dirname } from 'path';

import { fileURLToPath } from 'url';

import { parseArgs, showHelp } from '../shared/cli-args.js';

import { renderXff } from '../reporting/sections/render-special-section.js';
import { toShanghaiTime } from '../shared/time-utils.js';
import { renderMarkdownTable } from '../shared/report-renderer.js';
import { loadWhitelist, isExternal } from '../shared/whitelist.js';



const __dirname = dirname(fileURLToPath(import.meta.url));

const TEMPLATE = resolve(__dirname, '../../templates/judgment-xff-ban-template.md');



const SCHEMA = {

  xff: { type: 'string', required: true, description: 'query-xff.js 输出 JSON' },

  victims: { type: 'string', description: 'victim-hosts.js 输出 JSON（可选，缺省则受害主机为空）' },

  threatbook: { type: 'string', description: 'threat-intel/external.js --batch 输出 JSON（可选）' },

  'end-date': { type: 'string', required: true, description: '结束日 YYYYMMDD（用于命名与区间）' },

  'start-date': { type: 'string', description: '起始日 YYYYMMDD（用于区间显示）' },

  'report-time': { type: 'string', description: '报告时间（默认当前 ISO）' },

  'output-md': { type: 'string', description: 'MD 输出路径（默认 output/judgment-xff-ban-recommendation-{end}.md）' },

  'output-json': { type: 'string', description: 'JSON 输出路径（默认 output/judgment-xff-ban-recommendation-{end}.json）' },

  'ban-ip-append': { type: 'string', description: '将 XFF 4列封禁表并入指定 ban-ip-table-<date>.md 同一张 4 列表（§2.1 行在前，XFF 行在后；不存在则新建；幂等去除旧独立小节）' },
  help: { type: 'boolean', description: '显示帮助' },

};



function loadThreatbook(path) {

  const map = new Map();

  if (!path) return map;

  const data = JSON.parse(fs.readFileSync(path, 'utf8'));

  const results = data.results || [];

  const arr = Array.isArray(results) ? results : Object.values(results);

  for (const r of arr) {

    if (r && r.ip) map.set(r.ip, r);

  }

  return map;

}



function mdCell(v) {

  return String(v == null ? '—' : v).replace(/\|/g, '/').replace(/\n/g, ' ');

}



function loadAttackTypeMapping(path) {
  try {
    return JSON.parse(fs.readFileSync(path, 'utf-8'));
  } catch (e) {
    console.warn(`[WARN] 攻击类型映射加载失败 (${path}): ${e.message}`);
    return {};
  }
}

const ATTACK_TYPE_MAP = loadAttackTypeMapping(resolve(__dirname, '../../references/attack-type-mapping.json'));

// XFF 4 列封禁表头（与 §2.1 ban_ip_table 完全一致，供 fuse.js 下游按同布局抽取）
const XFF_BAN_HEADERS = ['告警日期时间戳', '风险IP', '风险描述', '风险IP的地理位置'];

// XFF 封禁表阈值：与 §2.1 ban-ip-table.js 默认 min-attacks=10 对齐（严格大于）
const XFF_MIN_ATTACKS = 10;

/**
 * max_timestamp（ISO UTC 或 epoch ms）→ Asia/Shanghai 秒级 yyyy/M/d H:mm:ss
 * （年/月/日/时无前导零，分/秒有前导零，例 2026/7/23 7:03:11），与 ban-ip-table.js 规则一致。
 */
function formatAlertTimestamp(isoOrMs) {
  if (!isoOrMs) return '未知';
  const d = toShanghaiTime(isoOrMs);
  if (isNaN(d.getTime())) return '未知';
  const year = d.getUTCFullYear();
  const month = d.getUTCMonth() + 1;
  const day = d.getUTCDate();
  const hour = d.getUTCHours();
  const minute = String(d.getUTCMinutes()).padStart(2, '0');
  const second = String(d.getUTCSeconds()).padStart(2, '0');
  return `${year}/${month}/${day} ${hour}:${minute}:${second}`;
}

/**
 * 风险描述聚合：格式 "{name}({n})"，name 经 attack-type-mapping.json 映射（缺失回退原始名），
 * 与 ban-ip-table.js buildRiskDescription 一致。
 */
function buildXffRiskDescription(attackTypes, attackTypeMap) {
  if (!attackTypes || attackTypes.length === 0) return '未知攻击';
  const parts = attackTypes.map((at) => {
    const name = attackTypeMap[at.type] || at.type;
    return `${name}(${at.count})`;
  });
  return parts.join(', ');
}

/**
 * 把一个 markdown 表解析为 { header:[...], rows:[[...],...] }，跳过表头(第1行)与分隔(第2行)。
 * 仅接受以 | 开头的行，单元格按 | 切分并去首尾空白。
 * @param {string} md markdown 文本
 * @returns {{ header:string[], rows:string[][] }}
 */
function parseMarkdownTable(md) {
  const lines = md.split('\n').filter((l) => l.trim().startsWith('|'));
  if (lines.length < 2) return { header: [], rows: [] };
  const splitRow = (l) => l.replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
  return { header: splitRow(lines[0]), rows: lines.slice(2).map(splitRow) };
}

/**
 * 将 XFF 4 列封禁表并入 ban-ip-table-<date>.md 的同一张 4 列表（fuse.js 下游按同布局抽取）。
 * - 目标不存在：直接写出 XFF 表（含表头）。
 * - 目标存在：幂等去除上一轮可能残留的独立「## XFF-IP 封禁建议表（追加）」小节（兼容旧格式），
 *   解析 §2.1 主表，将 XFF 行拼接到主表行之后，用 renderMarkdownTable 重渲染（列宽对齐与 §2.1 一致）。
 * 最终文件始终为「一张」以 §2.1 表头对齐的 4 列表，不再带独立小节/第二份表头。
 * @param {string} targetPath 目标 ban-ip-table-<date>.md 路径
 * @param {string} tableMd XFF 4 列封禁表 markdown（由 buildReportTables 生成）
 */
function appendXffBanTable(targetPath, tableMd) {
  const dir = dirname(targetPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const xff = parseMarkdownTable(tableMd);
  if (xff.rows.length === 0) {
    console.error('[INFO] XFF 封禁表无数据行，跳过合并。');
    return;
  }
  if (!fs.existsSync(targetPath)) {
    // 目标不存在：直接写出 XFF 表（含表头）
    fs.writeFileSync(targetPath, renderMarkdownTable(xff.header, xff.rows) + '\n', 'utf-8');
    console.error(`[OK] 已写出 XFF 封禁表到: ${targetPath}`);
    return;
  }
  let existing = fs.readFileSync(targetPath, 'utf-8');
  // 幂等：去掉上一轮可能残留的独立 XFF 小节（兼容旧格式）
  const markerIdx = existing.indexOf('## XFF-IP 封禁建议表（追加）');
  if (markerIdx > -1) existing = existing.slice(0, markerIdx);
  const base = parseMarkdownTable(existing);
  const header = base.header.length ? base.header : xff.header;
  const mergedRows = base.rows.concat(xff.rows); // §2.1 行在前，XFF 行附加在后
  const merged = renderMarkdownTable(header, mergedRows);
  fs.writeFileSync(targetPath, merged + '\n', 'utf-8');
  console.error(`[OK] 已合并 XFF 封禁表（${xff.rows.length} 行）到主表: ${targetPath}`);
}

function buildBanRows(xff, tbMap) {

  const rows = [];

  for (const c of xff.external_clients || []) {

    const tb = tbMap.get(c.real_client_ip) || null;

    const isMal = tb ? tb.is_malicious === true : null; // null=未查/未知

    const priority = isMal ? 'P0' : c.alerts >= 20 ? 'P1' : 'P2';

    rows.push({

      rank: rows.length + 1,

      client_ip: c.real_client_ip,

      alerts: c.alerts,

      is_malicious: isMal,

      severity: tb?.severity || '—',

      confidence: tb?.confidence || '—',

      threat_type: tb?.threat_type || '—',

      tags: Array.isArray(tb?.tags) ? tb.tags.join(',') : (tb?.tags || '—'),

      via_cdn: c.via_cdn,

      cdn_hops: c.cdn_hops || [],

      permalink: tb?.permalink || '',

      priority,

      victims: c.victims || [],

    });

  }

  return rows;

}



/**

 * 从 victim-hosts 产物派生「两张权威表」，供子技能 MD 与主报告 §5.1 直接复用（禁止主报告重算）。

 *

 *  - XFF-IP封禁建议表：按攻击 IP 分组（处置人员封禁攻击源用），受害 IP 以逗号分隔

 *  - XFF-受害IP排查表：按受害 IP 分组（资产责任人排查主机用），攻击 IP 以逗号分隔

 *

 * 数据源：victimData.clients[].{ client_ip, alerts, victims:[{ dip, count, attack_types:[{type,count}] }] }

 *
xff_real_client_investigate_table
 * @param {object} victimData victim-hosts.js 产物

 * @returns {{ ipBanRows:Array, victimRows:Array }}

 */

function buildReportTables(victimData, whitelistEntries) {

  const clients = victimData?.clients || [];



  // IP 封禁建议表：按攻击 IP 聚合

  const ipBanRows = [];

  for (const client of clients) {

    const victimIps = (client.victims || []).map((v) => v.dip);

    const typeCount = new Map();

    for (const v of client.victims || []) {

      for (const a of v.attack_types || []) {

        typeCount.set(a.type, (typeCount.get(a.type) || 0) + (a.count || 0));

      }

    }

    const attackTypes = [...typeCount.entries()].sort((a, b) => b[1] - a[1]).map(([type, count]) => ({ type, count }));

    ipBanRows.push({

      attacker_ip: client.client_ip,

      victim_ips: victimIps,

      alerts: client.alerts,

      attack_types: attackTypes,

    });

  }

  ipBanRows.sort((a, b) => b.alerts - a.alerts);



  // 受害 IP 排查表：按受害 IP 聚合

  const victimMap = new Map();

  for (const client of clients) {

    for (const v of client.victims || []) {

      if (!victimMap.has(v.dip)) {

        victimMap.set(v.dip, { host: v.dip, attackers: new Set(), typeCount: new Map(), alertCount: 0 });

      }

      const h = victimMap.get(v.dip);

      h.attackers.add(client.client_ip);

      h.alertCount += v.count || 0;

      for (const a of v.attack_types || []) {

        h.typeCount.set(a.type, (h.typeCount.get(a.type) || 0) + (a.count || 0));

      }

    }

  }

  const victimRows = [...victimMap.values()].map((h) => ({

    host: h.host,

    attacker_ips: [...h.attackers],

    alerts: h.alertCount,

    attack_types: [...h.typeCount.entries()].sort((a, b) => b[1] - a[1]).map(([type, count]) => ({ type, count })),

  }));

  victimRows.sort((a, b) => b.alerts - a.alerts);



  // XFF 4 列封禁表（告警日期时间戳 | 风险IP | 风险描述 | 风险IP的地理位置）：
  // 风险IP=真实客户端IP；时间戳=该 client 的 max_timestamp（上海）；风险描述=攻击类型汇总；地理位置=未知（XFF 真实客户端无地理位置字段）。
  const xffBanRows = [];
  for (const client of clients) {
    // 白名单过滤（与 §2.1 一致，非 external 则剔除）
    const { external } = isExternal(client.client_ip, whitelistEntries);
    if (!external) continue;
    // 阈值筛选（与 §2.1 默认 min-attacks=10 对齐，严格大于）
    if (!(client.alerts > XFF_MIN_ATTACKS)) continue;
    const typeCount = new Map();
    for (const v of client.victims || []) {
      for (const a of v.attack_types || []) {
        typeCount.set(a.type, (typeCount.get(a.type) || 0) + (a.count || 0));
      }
    }
    const attackTypes = [...typeCount.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([type, count]) => ({ type, count }));
    xffBanRows.push({
      alerts: client.alerts || 0,
      row: [
        formatAlertTimestamp(client.max_timestamp),
        client.client_ip,
        buildXffRiskDescription(attackTypes, ATTACK_TYPE_MAP),
        '未知',
      ],
    });
  }
  xffBanRows.sort((a, b) => b.alerts - a.alerts);
  const xffBanIpTableMd = tableToMd(XFF_BAN_HEADERS, xffBanRows.map((r) => r.row));

  return { ipBanRows, victimRows, xffBanIpTableMd };

}



/**

 * 从威胁情报富化的攻击 IP 列表（banRows）派生「IP威胁情报表」，供子技能 MD 与主报告 §5.1 直接复用。

 * 列：风险IP | 是否恶意 | 可信度 | 威胁类型 | 情报标签

 * 数据源：buildBanRows 输出（已合并 --threatbook 情报；未查为 null → 渲染为「未查」/「—」）

 * @param {Array} banRows buildBanRows 输出

 * @returns {Array<{risk_ip,is_malicious,confidence,threat_type,tags}>}

 */

function buildThreatIntelRows(banRows) {

  return (banRows || []).map((r) => ({

    risk_ip: r.client_ip,

    is_malicious: r.is_malicious === null ? '未查' : (r.is_malicious === true ? '是' : '否'),

    confidence: r.confidence || '—',

    threat_type: r.threat_type || '—',

    tags: r.tags || '—',

  }));

}



/** 通用管道表渲染（表头/分隔/行）。单元格经 mdCell 转义。 */

function tableToMd(headers, rows) {

  const head = `| ${headers.join(' | ')} |`;

  const sep = `| ${headers.map(() => '---').join(' | ')} |`;

  const body = rows.map((r) => `| ${r.map((c) => mdCell(c)).join(' | ')} |`).join('\n');

  return `${head}\n${sep}\n${body}`;

}



function renderMd(template, ctx) {

  if (!fs.existsSync(template)) {

    return `# XFF 代理攻击封禁建议\n\n(模板缺失，使用内联渲染)\n\n报告时间: ${ctx.report_time}\n区间: ${ctx.date_range}\n`;

  }

  let s = fs.readFileSync(template, 'utf8');

  const repl = {

    '{{report_time}}': ctx.report_time,

    '{{date_range}}': ctx.date_range,

    '{{xff_metrics}}': ctx.xff_metrics,

    '{{xff_ban_ip_table}}': ctx.xff_ban_ip_table_md,

    '{{xff_victim_investigate_table}}': ctx.victim_investigate_table_md,

    '{{xff_threat_intel_table}}': ctx.threat_intel_table_md,

    '{{enforcement_note}}': ctx.enforcement_note,

  };

  for (const [k, v] of Object.entries(repl)) {

    s = s.split(k).join(v);

  }

  return s;

}



function main() {

  const { flags } = parseArgs(process.argv, SCHEMA);

  if (flags.help) {

    showHelp('scripts/judgment-xff/gen-md-report-xff.js', '--xff <f> --end-date YYYYMMDD', SCHEMA);

    return;

  }

  if (!flags.xff || !flags['end-date']) {

    console.error('[ERROR] 必须提供 --xff 与 --end-date');

    process.exit(1);

  }



  const xff = JSON.parse(fs.readFileSync(flags.xff, 'utf8'));

  const victims = flags.victims ? JSON.parse(fs.readFileSync(flags.victims, 'utf8')) : { clients: [] };

  const tbMap = loadThreatbook(flags.threatbook);

  // 加载白名单，供 §5.1.4 XFF 封禁表二次过滤（与 §2.1 一致，FR-013）
  const whitelistEntries = loadWhitelist(resolve(__dirname, '../../references/ipWhite.md'));



  const banRows = buildBanRows({ external_clients: xff.external_clients }, tbMap);



  // === 主报告 §5.1 直接复用的两张表（取自子技能输出，禁止主报告重算） ===

  const { ipBanRows, victimRows, xffBanIpTableMd } = buildReportTables(victims, whitelistEntries);

  const ipBanMd = tableToMd(

    ['外部真实客户端IP', '受害IP', '告警数', '攻击类型'],

    ipBanRows.map((r) => [`\`${r.attacker_ip}\``, r.victim_ips.join(', '), r.alerts, buildXffRiskDescription(r.attack_types, ATTACK_TYPE_MAP)]),

  );

  const victimMd = tableToMd(

    ['受害IP', '外部真实客户端IP', '告警数', '攻击类型'],

    victimRows.map((r) => [`\`${r.host}\``, r.attacker_ips.join(', '), r.alerts, buildXffRiskDescription(r.attack_types, ATTACK_TYPE_MAP)]),

  );



  // === 第三张表：IP威胁情报（同样取自子技能、禁止主报告重算） ===

  const threatIntelRows = buildThreatIntelRows(banRows);

  const threatIntelMd = tableToMd(

    ['风险IP', '是否恶意', '可信度', '威胁类型', '情报标签'],

    threatIntelRows.map((r) => [`\`${r.risk_ip}\``, r.is_malicious, r.confidence, r.threat_type, r.tags]),

  );



  const dateRange = `${flags['start-date'] || flags['end-date']} ~ ${flags['end-date']}`;

  const reportTime = flags['report-time'] || new Date().toISOString();

  const enforcementNote = '经 CDN 进来的真实源，边界防火墙（L3/4）看到的是 CDN 边缘 IP，只能在 WAF（L7，能读 XFF）上按「XFF 最左端公网 IP」规则拦截；直连真实源不受此限。';



  // §概览指标：复用 renderXff（与主报告 §5.1 的 xff_metrics 同函数同源，杜绝两套 bullet 代码）

  const xffMetrics = renderXff(xff, null);



  const banIps = banRows.map((r) => ({ ip: r.client_ip, priority: r.priority, alerts: r.alerts, is_malicious: r.is_malicious }));



  const md = renderMd(TEMPLATE, {

    report_time: reportTime,

    date_range: dateRange,

    xff_metrics: xffMetrics,

    ip_ban_table_md: ipBanMd,
    xff_ban_ip_table_md: xffBanIpTableMd,

    victim_investigate_table_md: victimMd,

    threat_intel_table_md: threatIntelMd,

    enforcement_note: enforcementNote,

  });



  const outMd = flags['output-md'] || `output/judgment-xff-ban-recommendation-${flags['end-date']}.md`;

  const outJson = flags['output-json'] || `output/judgment-xff-ban-recommendation-${flags['end-date']}.json`;

  fs.mkdirSync('output', { recursive: true });

  fs.writeFileSync(outMd, md, 'utf-8');



  const json = {

    meta: { generated_at: reportTime, date_range: { start: flags['start-date'] || flags['end-date'], end: flags['end-date'] }, source: 'judgment-xff skill' },

    total_xff_alerts: xff.total_xff_alerts,

    external_unique_clients: xff.external_unique_clients,

    spoofed_or_internal_xff: xff.spoofed_or_internal_xff?.total ?? 0,

    ban_table: banRows,

    report_tables: {

      ip_ban_table_md: ipBanMd,
      xff_ban_ip_table_md: xffBanIpTableMd,

      victim_investigate_table_md: victimMd,

      threat_intel_table_md: threatIntelMd,

      ip_ban_rows: ipBanRows,

      victim_rows: victimRows,

      threat_intel_rows: threatIntelRows,

    },

    judgment: {

      ban_ips: banIps,

      enforcement_note: enforcementNote,

    },

  };

  fs.writeFileSync(outJson, JSON.stringify(json, null, 2), 'utf-8');

  if (flags['ban-ip-append']) {
    appendXffBanTable(flags['ban-ip-append'], xffBanIpTableMd);
  }



  console.log(`[OK] 封禁建议 MD: ${outMd}`);

  console.log(`[OK] 封禁建议 JSON: ${outJson}`);

  console.log(JSON.stringify({ ban_ips: banIps.length, malicious: [...tbMap.values()].filter((t) => t.is_malicious === true).length }));

}



main();

