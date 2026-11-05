#!/usr/bin/env node
/**
 * gen-md-report.js - 编排器：读 parsed → 调 analyze* → 派生专项 → 调 render* → 注入模板
 *
 * 三层拆分后的薄编排层（详见 docs/superpowers/plans/2026-07-21-secops-report-refactor-design.md）：
 *   查询层 scripts/shared/es-query.js
 *   分析层 scripts/analysis/{analyze-external,analyze-internal,analyze-compromised}.js + shared/threat-categories.js
 *   渲染层 scripts/reporting/sections/{render-external,render-internal,render-compromised,render-special}-section.js
 *
 * 本文件不再内联任何表行生成逻辑（旧 L165–225），也不再做逐行正则 replace（旧 L305–344）；
 * 改为调用四个 renderXxxSection，并将结果作为块占位符注入模板的 vars。
 *
 * Usage:
 *   --date <YYYYMMDD>                         报告日期（必填）
 *   --stats <parsed.json>                     外部 parsed JSON（extract.js --parsed-output / parse-mcp.js 产物，必填）
 *   --internal-stats <parsed.json>            内部 parsed JSON（含 lateral）
 *   --compromised <parsed.json>               失陷主机 JSON（最高优先级覆盖）
 *   --ban-ip / --ban-domain / --threat-intel  封禁/情报表格文件（文件注入，保留）
 *   --template <t.md> / --output <report.md>  模板/输出（保留）
 *   --xff <query-xff.json>                    XFF 预跑产物（§5.1 专项，缺失则优雅降级）
 *   --xff-judgment <gen-md-report-xff.json>      XFF 权威封禁口径（§5.1.2，可选）
 *   --whitelist / --min-attacks               白名单/阈值（附录 IP 过滤，保留）
 */
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { parseArgs, showHelp } from '../shared/cli-args.js';
import { renderTemplate } from '../shared/report-renderer.js';
import { loadWhitelist, isExternal } from '../shared/whitelist.js';
import { analyzeExternal } from '../analysis/analyze-external.js';
import { analyzeInternal } from '../analysis/analyze-internal.js';
import { analyzeCompromised } from '../analysis/analyze-compromised.js';
import { deriveThreatTopics } from '../shared/threat-categories.js';
import { renderExternalTypeSection, renderExternalTimeSection, renderFullIpSection } from './sections/render-external-section.js';
import { renderInternalSection } from './sections/render-internal-section.js';
import { renderCompromisedSection } from './sections/render-compromised-section.js';
import { renderSpecialSection } from './sections/render-special-section.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SCHEMA = {
  date: { type: 'string', required: true, description: 'Report date (YYYYMMDD)' },
  template: { alias: 't', type: 'string', default: join(__dirname, '..', '..', 'templates', 'alert-report-template.md'), description: 'MD template file' },
  'ban-ip': { type: 'string', description: 'Ban IP table file' },
  'ban-domain': { type: 'string', description: 'Ban domain table file' },
  'threat-intel': { type: 'string', description: 'Threat intel table file' },
  stats: { alias: 's', type: 'string', required: true, description: 'Parsed external stats JSON file (parsed-external-{date}.json)' },
  'report-time': { type: 'string', description: 'Report generation time' },
  output: { alias: 'o', type: 'string', description: 'Output MD file (default: stdout)' },
  'internal-stats': { type: 'string', description: 'Internal parsed stats JSON file (parsed-internal-{date}.json)' },
  'compromised': { type: 'string', description: 'Compromised hosts JSON file (parsed-compromised-{date}.json)' },
  lateral: { type: 'string', description: 'Legacy lateral analysis MD file (lateral-analysis-{date}.md)' },
  whitelist: { alias: 'w', type: 'string', default: join(__dirname, '..', '..', 'references', 'ipWhite.md'), description: 'Whitelist file' },
  'min-attacks': { type: 'number', default: 10, description: '风险IP入选阈值（与 ban-ip-table.js --min-attacks 保持一致）' },
  xff: { type: 'string', description: 'XFF 预跑产物 JSON (judgment-xff/query-xff.js 产出)，供 §5.1 专项研判' },
  'xff-judgment': { type: 'string', description: 'XFF 权威封禁口径 JSON (gen-md-report-xff.js 产出)，可选注入 §5.1.2' },
};

const { flags } = parseArgs(process.argv, SCHEMA);

if (flags.help) {
  showHelp('scripts/reporting/gen-md-report.js', '--date <YYYYMMDD> --stats <parsed.json> [--template <t>] [--output <md>] [--xff <xff.json>]', SCHEMA);
}

const missing = [];
if (!flags.date) missing.push('--date');
if (!flags.stats) missing.push('--stats');
if (missing.length > 0) {
  console.error(`[ERROR] Missing required options: ${missing.join(', ')}`);
  process.exit(1);
}

if (!fs.existsSync(flags.template)) {
  console.error(`[ERROR] Template file not found: ${flags.template}`);
  process.exit(1);
}

if (!fs.existsSync(flags.stats)) {
  console.error(`[ERROR] Stats file not found: ${flags.stats}`);
  console.error('[INFO] Run Step 1 first (extract.js --parsed-output or parse-mcp.js)');
  process.exit(1);
}

/** 安全读取 JSON 文件；不存在返回 null。 */
function readJsonOrNull(path) {
  if (!path || !fs.existsSync(path)) return null;
  try {
    return JSON.parse(fs.readFileSync(path, 'utf-8'));
  } catch (e) {
    console.error(`[WARN] Failed to parse JSON ${path}: ${e.message}`);
    return null;
  }
}

const templateStr = fs.readFileSync(flags.template, 'utf-8');
const parsedExternal = JSON.parse(fs.readFileSync(flags.stats, 'utf-8'));

// --- 防呆：同期内部/失陷数据已落盘却漏传参数时，静默降级会渲染成空章节；先告警止损 ---
// 推导规则：以 --stats 的目录为基准，按命名约定探测 parsed-internal-{date}.json /
// parsed-compromised-{date}.json。文件存在但未传对应参数 → stderr 警告（不阻断，保持优雅降级）。
if (flags.date) {
  const dataDir = flags.stats ? dirname(flags.stats) : '.';
  const expectedInternal = join(dataDir, `parsed-internal-${flags.date}.json`);
  const expectedCompromised = join(dataDir, `parsed-compromised-${flags.date}.json`);
  if (fs.existsSync(expectedInternal) && !flags['internal-stats']) {
    process.stderr.write(
      `[WARN-DEGRADE] 检测到 ${expectedInternal} 存在，但未传入 --internal-stats；` +
      `§4 内部攻击章节将渲染为"未执行/空"。请补 --internal-stats ${expectedInternal}\n`
    );
  }
  if (fs.existsSync(expectedCompromised) && !flags['compromised']) {
    process.stderr.write(
      `[WARN-DEGRADE] 检测到 ${expectedCompromised} 存在，但未传入 --compromised；` +
      `§3 失陷/攻击成功主机章节将渲染为"无失陷主机"。请补 --compromised ${expectedCompromised}\n`
    );
  }
}

const parsedInternal = readJsonOrNull(flags['internal-stats']);
const parsedCompromised = readJsonOrNull(flags['compromised']);

// --- Fix E（Bug-05）：按报告真实查询窗口裁剪小时分布轴，剔除窗口外（多为全零）时段 ---
// 单日模式：query_start/query_end 即为本自然日全量，裁剪等价于原行为（零回归）；
// 跨天模式：仅保留落在 [query_start, query_end] 内的小时桶，使 §2.5/§4.5 不再列出窗口外时段。
// 注意：hour 字段为 "YYYY-MM-DD HH:mm:ss"（Asia/Shanghai），与窗口字符串同格式，可直接比较。
function cropHourlyToWindow(rows, start, end) {
  if (!Array.isArray(rows) || !start || !end) return rows;
  return rows.filter((r) => r && r.hour >= start && r.hour <= end);
}
const reportWindow = {
  start: parsedExternal.stats?.query_start,
  end: parsedExternal.stats?.query_end,
};

// --- 分析层：外部 / 内部 / 失陷 ---
if (reportWindow.start && reportWindow.end) {
  parsedExternal.stats.hourly_distribution = cropHourlyToWindow(
    parsedExternal.stats.hourly_distribution, reportWindow.start, reportWindow.end);
}
const externalAnalysis = analyzeExternal(parsedExternal);

let internalAnalysis = { stats: {}, lateral: null };
if (parsedInternal) {
  // Fix E：同步按真实查询窗口裁剪 §4.5 横向移动小时分布轴
  if (reportWindow.start && reportWindow.end && parsedInternal.lateral?.hourly_distribution) {
    parsedInternal.lateral.hourly_distribution = cropHourlyToWindow(
      parsedInternal.lateral.hourly_distribution, reportWindow.start, reportWindow.end);
  }
  internalAnalysis = analyzeInternal(parsedInternal);
}

// 失陷主机优先级：--compromised > --internal-stats > 外部 parsed
let compromisedHosts = [];
if (parsedCompromised?.compromised_hosts?.length) {
  compromisedHosts = parsedCompromised.compromised_hosts;
} else if (parsedInternal?.compromised_hosts?.length) {
  compromisedHosts = parsedInternal.compromised_hosts;
}
const compromisedAnalysis = analyzeCompromised(compromisedHosts);

// --- 专项研判派生（纯函数）---
const topics = deriveThreatTopics({
  attackTypes: parsedExternal.stats?.attack_types || [],
  ips: parsedExternal.ips || [],
  domains: parsedExternal.domains || [],
  compromised: compromisedHosts,
});

// --- XFF 预跑产物（§5.1，缺失则渲染层优雅降级）---
const xff = readJsonOrNull(flags.xff);
const xffJudgment = readJsonOrNull(flags['xff-judgment']);

// --- 渲染层：四 section 章节串 ---
const externalSection = renderExternalTypeSection(externalAnalysis);
const externalTimeSection = renderExternalTimeSection(externalAnalysis);
const internalSections = renderInternalSection(internalAnalysis);
const compromisedSection = renderCompromisedSection(compromisedAnalysis);
const specialSections = renderSpecialSection({
  topics,
  xff,
  xffJudgment,
});

// --- 格式化日期：20260715 -> 2026-07-15 ---
function formatDateStr(dateStr) {
  if (!dateStr || dateStr.length !== 8) return dateStr || '';
  return `${dateStr.slice(0, 4)}-${dateStr.slice(4, 6)}-${dateStr.slice(6, 8)}`;
}
const dateFormatted = formatDateStr(flags.date);

// --- 表格文件注入（优雅降级）---
function readFileOrWarn(path, label) {
  if (!path) return '[表格未生成]';
  if (!fs.existsSync(path)) {
    process.stderr.write(`[WARN] ${label} file not found: ${path}\n`);
    return '[表格生成失败]';
  }
  return fs.readFileSync(path, 'utf-8').trim();
}

// --- 附录：IP 白名单 + 阈值过滤对比 ---
const ips = parsedExternal.ips || [];
const minAttacks = flags['min-attacks'];
let whitelistCount = 0;
let detectedExternalIps = ips.length;
let validExternalIps = 0;
let whitelistedExcluded = 0;
let thresholdExcluded = 0;

const whitelistPath = flags.whitelist;
if (fs.existsSync(whitelistPath)) {
  const entries = loadWhitelist(whitelistPath);
  whitelistCount = entries.length;
  for (const ipData of ips) {
    const result = isExternal(ipData.ip, entries);
    if (!result.external) {
      whitelistedExcluded++;
      continue;
    }
    if (!(ipData.total_alerts > minAttacks)) {
      thresholdExcluded++;
      continue;
    }
    validExternalIps++;
  }
} else {
  for (const ipData of ips) {
    if (!(ipData.total_alerts > minAttacks)) {
      thresholdExcluded++;
      continue;
    }
    validExternalIps++;
  }
}

const filterParts = [];
if (whitelistedExcluded > 0) filterParts.push(`白名单过滤${whitelistedExcluded}个IP`);
if (thresholdExcluded > 0) filterParts.push(`阈值过滤${thresholdExcluded}个IP（攻击次数≤${minAttacks}）`);
const filterSummary = filterParts.length === 0
  ? `无IP被过滤，有效外部攻击IP：${validExternalIps}个`
  : `经${filterParts.join('，')}，有效外部攻击IP：${validExternalIps}个`;

// --- 附录：完整外部攻击 IP 列表（渲染层构造，含表头）---
const fullIpList = renderFullIpSection(ips);

// --- 变量字典：注入模板（含四个块占位符）---
const stats = parsedExternal.stats || {};

// 真实告警总数 = 外部 + 内部（缺陷3：原实现只取外部 parsed 的 stats.exact_total /
// count_query_total，导致 §1 精确总数与 ES 计数查询总数误填为 4343）。
// 三项（total_alerts / exact_total / count_query_total）统一取该合并值。
const realTotal = (stats.total_alerts ?? 0) + (internalAnalysis.stats.total_alerts ?? 0);

// 标题后缀：起止时间窗 YYYY-MM-DD-HH:mm:ss ~ YYYY-MM-DD-HH:mm:ss
function formatTitleWindow(start, end) {
  if (!start || !end) return '';
  const fmt = (s) => s.replace(' ', '-'); // 2026-07-22 21:00:00 -> 2026-07-22-21:00:00
  return ` ${fmt(start)} ~ ${fmt(end)}`;
}
const titleWindow = formatTitleWindow(
  stats.query_start || `${dateFormatted} 00:00:00`,
  stats.query_end || stats.last_timestamp || `${dateFormatted} 23:59:59`
);

const vars = {
  // 文件注入（保留）
  ban_ip_table: readFileOrWarn(flags['ban-ip'], 'Ban IP table'),
  ban_domain_table: readFileOrWarn(flags['ban-domain'], 'Ban domain table'),
  threat_intel_table: readFileOrWarn(flags['threat-intel'], 'Threat intel table'),

  // §1 概述统计
  total_alerts: realTotal,
  external_alerts: stats.external_alerts ?? stats.total_alerts ?? 0,
  internal_alerts: internalAnalysis.stats.internal_alerts ?? 'N/A（内部查询未执行）',
  lateral_alerts: internalAnalysis.stats.lateral_alerts ?? 0,
  compromised_alerts: compromisedAnalysis.length,
  unique_external_ips: stats.unique_external_ips ?? 0,
  unique_internal_hosts: internalAnalysis.stats.unique_internal_hosts ?? 0,
  exact_total: realTotal,
  count_query_total: realTotal,

  // 时间
  report_time: flags['report-time'] || '',
  start_time: stats.query_start || `${dateFormatted} 00:00:00`,
  end_time: stats.query_end || stats.last_timestamp || `${dateFormatted} 23:59:59`,
  title_window: titleWindow,
  analyst: 'SecOps Agent',

  // 四 section 块占位符（核心重构点）；external 按模板拆分为 §2.4 + §2.5 两节单独渲染
  external_section: externalSection,
  external_time_section: externalTimeSection,
  compromised_section: compromisedSection,
  // §4 各子节单独渲染（标题在模板，渲染器只输出内容体，与 §2.4/§2.5 模式一致）
  internal_4_1: internalSections['4.1'],
  internal_4_2: internalSections['4.2'],
  internal_4_3: internalSections['4.3'],
  internal_4_4: internalSections['4.4'],
  internal_4_5: internalSections['4.5'],
  // §5 各子节单独渲染（标题在模板，渲染器只输出内容体）
  // §5.1：指标由渲染器输出为内容体（xff_metrics），四张表占位符统一 xff_ 前缀，
  //        数据来自子技能 report_tables（单源，禁止主报告重算，且与 §2.3 threat_intel_table 撞名隔离）。
  xff_metrics: specialSections['5.1'],
  xff_real_client_investigate_table: xffJudgment?.report_tables?.ip_ban_table_md || '[XFF 封禁建议表缺失：未传入 --xff-judgment]',
  xff_victim_investigate_table: xffJudgment?.report_tables?.victim_investigate_table_md || '[XFF 受害IP排查表缺失：未传入 --xff-judgment]',
  xff_threat_intel_table: xffJudgment?.report_tables?.threat_intel_table_md || '[XFF IP威胁情报表缺失：未传入 --xff-judgment]',
  xff_ban_ip_table: xffJudgment?.report_tables?.xff_ban_ip_table_md || '[XFF 封禁表缺失：未传入 --xff-judgment]',
  special_5_2: specialSections['5.2'],
  special_5_3: specialSections['5.3'],
  special_5_4: specialSections['5.4'],

  // 附录
  external_full_ip_section: fullIpList,
  detected_external_ips: detectedExternalIps,
  valid_external_ips: validExternalIps,
  whitelisted_excluded: whitelistedExcluded,
  threshold_excluded: thresholdExcluded,
  filter_summary: filterSummary,
  lateral_analysis: readFileOrWarn(flags.lateral, 'Lateral analysis'),
};

// --- 渲染：仅需简单变量替换（块占位符已预渲染为整段 MD）---
const result = renderTemplate(templateStr, vars);

// --- 输出 ---
if (flags.output) {
  const outputDir = dirname(flags.output);
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(flags.output, result, 'utf-8');
  console.error(`[INFO] MD report written to ${flags.output}`);
} else {
  console.log(result);
}
