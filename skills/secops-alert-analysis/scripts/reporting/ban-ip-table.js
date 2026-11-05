#!/usr/bin/env node
/**
 * ban-ip-table.js - 封禁IP表格生成器
 *
 * 消费 analyzer/enrich.js 输出（--input/stdin）或直连 ES（--date），生成符合
 * docs/dev/风险IP处置入库数据样例.md 样例的四列封禁表格：
 *   告警日期时间戳 | 风险IP | 风险描述 | 风险IP的地理位置
 *
 * 三列数据值全部取自 ES 数据源该IP查询时段真实告警记录（FR-015）：
 *   - alert_timestamp  ← max(@timestamp) 子聚合（经 shared/time-utils.js 转 Asia/Shanghai）
 *   - risk_geo_location ← field_values.sip_addr terms 子聚合（经格式规整，FR-014）
 *   - risk_description  ← field_values.attack_type terms 子聚合（经 attack-type-mapping.json 映射，FR-011）
 *
 * 可复现（FR-007）：无随机性、无 LLM 介入、无时间敏感逻辑（generated_at 除外）。
 * 二次白名单过滤兜底（FR-013）：复用 shared/whitelist.js isExternal()。
 *
 * 退出码：0=成功 1=输入错误 2=ES连接错误 3=解析错误
 */
import { fileURLToPath } from 'url';
import { dirname, join, resolve, isAbsolute } from 'path';
import fs from 'fs';
import { loadWhitelist, isExternal } from '../shared/whitelist.js';
import { esQuery, getEsConfig } from '../shared/es-query.js';
import { parseArgs, showHelp } from '../shared/cli-args.js';
import { toShanghaiTime, formatDate, buildDateRangeFilter } from '../shared/time-utils.js';
import { renderMarkdownTable } from '../shared/report-renderer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SCHEMA = {
  date: { alias: 'd', type: 'string', description: '分析日期 YYYYMMDD（查询时段为该自然日 Asia/Shanghai）；与 --input 二选一' },
  input: { alias: 'i', type: 'string', description: '消费 analyzer/enrich.js 输出 JSON（已有 max_timestamp/sip_addr）；与 --date 二选一' },
  format: { alias: 'f', type: 'string', default: 'markdown', description: '输出格式: json | markdown | html' },
  output: { alias: 'o', type: 'string', description: '输出文件路径（默认: stdout）' },
  whitelist: { alias: 'w', type: 'string', default: join(__dirname, '..', '..', 'references', 'ipWhite.md'), description: '白名单文件（二次过滤 FR-013）' },
  'geo-truncation': { type: 'string', default: 'country-city', description: 'sip_addr 规整截取粒度: country | country-city（FR-014）' },
  'min-attacks': { type: 'number', default: 10, description: '风险IP入选阈值（攻击次数 > N，沿用既有高危口径）' },
  'top-attack-types': { type: 'number', default: 3, description: 'risk_description 聚合的攻击类型数量上限' },
  'attack-type-mapping': { type: 'string', default: join(__dirname, '..', '..', 'references', 'attack-type-mapping.json'), description: '攻击类型名称映射配置（FR-011）' },
  'candidates-output': { type: 'string', description: '输出 ban-ip-candidates JSON 路径（供 threat-intel/external.js --batch 消费）' },
  help: { alias: 'h', type: 'boolean', description: '显示帮助' },
};

const { flags } = parseArgs(process.argv, SCHEMA);

if (flags.help) {
  showHelp('scripts/reporting/ban-ip-table.js', '[--date YYYYMMDD | --input <file>] [--format json|markdown|html] [--output <path>]', SCHEMA);
}

// 表头四列与样例 docs/dev/风险IP处置入库数据样例.md 逐字一致（FR-001/002，SC-001）
const HEADERS = ['告警日期时间戳', '风险IP', '风险描述', '风险IP的地理位置'];

main().catch((e) => {
  console.error(`[ERROR] ${e.message}`);
  process.exit(3);
});

async function main() {
  // 参数互斥校验（契约：--date 与 --input 二选一，两者皆无则走 stdin 管道）
  if (flags.date && flags.input) {
    console.error('[ERROR] --date 与 --input 互斥，请二选一。');
    process.exit(1);
  }
  if (!['json', 'markdown', 'html'].includes(flags.format)) {
    console.error(`[ERROR] --format 仅支持 json|markdown|html，收到: ${flags.format}`);
    process.exit(1);
  }
  if (!['country', 'country-city'].includes(flags['geo-truncation'])) {
    console.error(`[ERROR] --geo-truncation 仅支持 country|country-city，收到: ${flags['geo-truncation']}`);
    process.exit(1);
  }

  let dateForWindow = flags.date || null;
  let enrichmentIps = null;

  // 路径 A：消费 analyzer/enrich.js 输出（--input 文件 或 stdin 管道）
  if (flags.input) {
    enrichmentIps = await readEnrichmentFromFile(flags.input);
  } else if (flags.date) {
    // 路径 B：直连 ES（--date），复用 es-query.js，发 by_sip 聚合含 max_timestamp + by_sip_addr 子聚合
    enrichmentIps = await fetchEnrichmentFromEs(flags.date);
  } else {
    // 路径 C：stdin 管道模式（无 --date 且无 --input）
    enrichmentIps = await readEnrichmentFromStdin();
  }

  if (!Array.isArray(enrichmentIps) || enrichmentIps.length === 0) {
    // 空数据：输出仅表头不报错（FR 边界）
    console.error('[INFO] 查询时段无告警数据，输出空表。');
    emitEmpty();
    process.exit(0);
  }

  // 二次白名单过滤（FR-013）：复用 shared/whitelist.js
  const whitelistEntries = loadWhitelist(flags.whitelist);

  // 攻击类型名称映射（FR-011）：缺失时回退 ES 原始名
  const attackTypeMap = loadAttackTypeMapping(flags['attack-type-mapping']);

  // 选风险IP + 构造 BanIpRow
  const { rows, filteredCount, thresholdFilteredCount, withUnknownGeo, withUnknownTimestamp } = buildBanRows(
    enrichmentIps,
    whitelistEntries,
    flags['min-attacks'],
    flags['top-attack-types'],
    flags['geo-truncation'],
    attackTypeMap,
  );

  if (filteredCount > 0) {
    console.error(`[INFO] 二次白名单过滤排除 ${filteredCount} 个IP（FR-013）。`);
  }
  if (thresholdFilteredCount > 0) {
    console.error(`[INFO] 阈值筛选排除 ${thresholdFilteredCount} 个IP（攻击次数 ≤ ${flags['min-attacks']}）。`);
  }

  // 查询时段（QueryWindow）
  const queryWindow = buildQueryWindow(dateForWindow, enrichmentIps);

  // 生成输出
  const generatedAt = nowShanghaiIso();
  const payload = {
    query_window: queryWindow,
    generated_at: generatedAt,
    whitelist_secondary_filtered_count: filteredCount,
    threshold_filtered_count: thresholdFilteredCount,
    min_attacks: flags['min-attacks'],
    rows,
    summary: {
      total_risk_ips: rows.length,
      with_unknown_geo: withUnknownGeo,
      with_unknown_timestamp: withUnknownTimestamp,
    },
  };

  const output = renderOutput(payload, flags.format);
  writeOutput(output, flags.output);

  if (flags['candidates-output']) {
    writeCandidates(flags['candidates-output'], rows, queryWindow, generatedAt, filteredCount, thresholdFilteredCount, flags['min-attacks']);
  }

  process.exit(0);
}

/**
 * 从文件读取 analyzer/enrich.js 输出 JSON
 */
async function readEnrichmentFromFile(path) {
  let content;
  try {
    content = fs.readFileSync(path, 'utf-8');
  } catch (e) {
    console.error(`[ERROR] 无法读取 --input 文件: ${path} (${e.message})`);
    process.exit(1);
  }
  return parseEnrichmentJson(content);
}

/**
 * 从 stdin 读取 analyzer/enrich.js 输出 JSON（管道模式）
 */
function readEnrichmentFromStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(parseEnrichmentJson(data)));
    process.stdin.on('error', reject);
  });
}

/**
 * 解析 analyzer/enrich.js 输出 JSON，返回 ips 数组
 */
function parseEnrichmentJson(content) {
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch (e) {
    console.error(`[ERROR] enrich.js 输出 JSON 解析失败: ${e.message}`);
    process.exit(3);
  }
  const ips = parsed?.ips;
  if (!Array.isArray(ips)) {
    console.error('[ERROR] enrich.js 输出缺少 ips 数组。');
    process.exit(3);
  }
  return ips;
}

/**
 * 直连 ES 取 per-IP 聚合（含 max_timestamp + by_sip_addr 子聚合），结构对齐 analyzer/enrich.js 输出
 */
async function fetchEnrichmentFromEs(dateYYYYMMDD) {
  const esConfig = getEsConfig();
  const dateRange = buildDateRangeFilter(dateYYYYMMDD);
  const indexName = `${esConfig.indexPrefix}${dateYYYYMMDD}`;

  // 白名单 single IP 做 ES 端 must_not 过滤（与 analyzer/enrich.js 一致）
  const entries = loadWhitelist(flags.whitelist);
  const whitelistIps = entries.filter((e) => e.format === 'single').map((e) => e.baseIp);

  const query = {
    size: 0,
    query: {
      bool: {
        must: [{ range: { '@timestamp': dateRange } }],
      },
    },
    aggs: {
      by_sip: {
        terms: { field: 'field_values.sip', size: 10000 },
        aggs: {
          by_attack_type: { terms: { field: 'field_values.attack_type', size: 100 } },
          by_hazard_rating: { terms: { field: 'field_values.hazard_rating', size: 10 } },
          max_timestamp: { max: { field: '@timestamp' } },
          by_sip_addr: { terms: { field: 'field_values.sip_addr', size: 1 } },
        },
      },
    },
  };
  if (whitelistIps.length > 0) {
    query.query.bool.must_not = [{ terms: { 'field_values.sip': whitelistIps } }];
  }

  let response;
  try {
    response = await esQuery(indexName, query);
  } catch (e) {
    console.error(`[ERROR] ES 连接失败: ${e.message}`);
    console.error('[INFO] 提示: 可改用 --input 消费 analyzer/enrich.js 输出，或经 MCP 提取后管道传入。');
    process.exit(2);
  }

  const buckets = response.aggregations?.by_sip?.buckets || [];
  const ips = buckets.map((bucket) => {
    const attackTypes = (bucket.by_attack_type?.buckets || [])
      .map((b) => ({ type: b.key, count: b.doc_count }))
      .sort((a, b) => b.count - a.count);
    const hazardBuckets = bucket.by_hazard_rating?.buckets || [];
    const maxTsAgg = bucket.max_timestamp;
    let maxTimestamp = null;
    if (maxTsAgg && maxTsAgg.value_as_string) maxTimestamp = maxTsAgg.value_as_string;
    else if (maxTsAgg && typeof maxTsAgg.value === 'number') maxTimestamp = new Date(maxTsAgg.value).toISOString();
    const sipAddrBuckets = bucket.by_sip_addr?.buckets || [];
    return {
      ip: bucket.key,
      total_alerts: bucket.doc_count,
      attack_types: attackTypes,
      hazard_rating: hazardBuckets.length > 0 ? hazardBuckets[0].key : '',
      max_timestamp: maxTimestamp,
      sip_addr: sipAddrBuckets.length > 0 ? sipAddrBuckets[0].key : '',
    };
  });
  return ips;
}

/**
 * 加载攻击类型名称映射（FR-011）
 */
/**
 * 构造封禁表格行：二次白名单过滤 + 阈值筛选 + 列规整
 */
function buildBanRows(ips, whitelistEntries, minAttacks, topN, geoTruncation, attackTypeMap) {
  const rows = [];
  let filteredCount = 0;
  let thresholdFilteredCount = 0;
  let withUnknownGeo = 0;
  let withUnknownTimestamp = 0;

  for (const ipData of ips) {
    // 二次白名单过滤兜底（FR-013）
    const { external } = isExternal(ipData.ip, whitelistEntries);
    if (!external) {
      filteredCount++;
      continue;
    }
    // 阈值筛选（攻击次数 > N，沿用既有高危口径）
    if (!(ipData.total_alerts > minAttacks)) {
      thresholdFilteredCount++;
      continue;
    }

    const alertTimestamp = formatAlertTimestamp(ipData.max_timestamp);
    if (alertTimestamp === '未知') withUnknownTimestamp++;

    const riskDescription = buildRiskDescription(ipData.attack_types, attackTypeMap, topN);
    const { geo, unknown } = normalizeGeo(ipData.sip_addr, geoTruncation);
    if (unknown) withUnknownGeo++;

    rows.push({
      alert_timestamp: alertTimestamp,
      risk_ip: ipData.ip,
      risk_description: riskDescription,
      risk_geo_location: geo,
    });
  }

  // 可复现排序（FR-007）：按攻击次数降序，次数相同按 IP 字典序（确定性）
  rows.sort((a, b) => {
    const aCount = findCount(ips, a.risk_ip);
    const bCount = findCount(ips, b.risk_ip);
    if (bCount !== aCount) return bCount - aCount;
    return a.risk_ip.localeCompare(b.risk_ip);
  });

  return { rows, filteredCount, thresholdFilteredCount, withUnknownGeo, withUnknownTimestamp };
}

function findCount(ips, riskIp) {
  const found = ips.find((x) => x.ip === riskIp);
  return found ? found.total_alerts : 0;
}

/**
 * max_timestamp（ISO UTC）→ Asia/Shanghai 秒级 yyyy/M/d H:mm:ss（无前导零，FR-010）
 */
function formatAlertTimestamp(isoOrMs) {
  if (!isoOrMs) {
    console.warn('[WARN] 某IP max_timestamp 缺失，输出"未知"。');
    return '未知';
  }
  const d = toShanghaiTime(isoOrMs);
  if (isNaN(d.getTime())) {
    console.warn(`[WARN] max_timestamp 无法解析: ${isoOrMs}，输出"未知"。`);
    return '未知';
  }
  const year = d.getUTCFullYear();
  const month = d.getUTCMonth() + 1;
  const day = d.getUTCDate();
  const hour = d.getUTCHours();
  const minute = String(d.getUTCMinutes()).padStart(2, '0');
  const second = String(d.getUTCSeconds()).padStart(2, '0');
  return `${year}/${month}/${day} ${hour}:${minute}:${second}`;
}

/**
 * 风险描述聚合（FR-004/FR-011）：
 *   格式与7.1节攻击类型(次数)一致："{type}({n}), {type}({n})"
 *   type 经 attack-type-mapping.json 映射为人类可读名（缺失回退原始名）
 */
function buildRiskDescription(attackTypes, attackTypeMap, topN) {
  if (!attackTypes || attackTypes.length === 0) return '未知攻击';
  const top = attackTypes.slice(0, topN);
  const parts = top.map((at) => {
    const name = attackTypeMap[at.type] || at.type;
    if (!attackTypeMap[at.type]) {
      console.error(`[INFO] 攻击类型映射缺失，回退原始名: ${at.type}（FR-011）`);
    }
    return `${name}(${at.count})`;
  });
  return parts.join(', ');
}

/**
 * 加载攻击类型名称映射（FR-011）
 */
function loadAttackTypeMapping(path) {
  try {
    const content = fs.readFileSync(path, 'utf-8');
    return JSON.parse(content);
  } catch (e) {
    console.warn(`[WARN] 攻击类型映射加载失败 (${path}): ${e.message}。将回退 ES 原始名。`);
    return {};
  }
}

/**
 * sip_addr 格式规整（FR-014/FR-012）：
 *   1. 去尾部经纬度括号 (...)
 *   2. 按 geoTruncation 截取：country=第一段，country-city=保留全段
 *   3. 未知/缺失 → "未知"
 */
function normalizeGeo(sipAddr, geoTruncation) {
  if (!sipAddr || !sipAddr.trim()) {
    console.warn('[WARN] 某 risk IP 的 sip_addr 为空，地理输出"未知"（FR-012）。');
    return { geo: '未知', unknown: true };
  }
  let s = sipAddr.trim();
  // 未知(...) 形态
  if (s.startsWith('未知')) {
    return { geo: '未知', unknown: true };
  }
  // 去尾部经纬度括号
  const parenIdx = s.indexOf('(');
  if (parenIdx > -1) {
    s = s.slice(0, parenIdx).trim();
  }
  if (!s) {
    return { geo: '未知', unknown: true };
  }
  // 截取粒度
  if (geoTruncation === 'country') {
    const segs = s.split('--');
    return { geo: segs[0] || '未知', unknown: false };
  }
  // country-city：保留全段（国家--行政区--城市 或 国家）
  return { geo: s, unknown: false };
}

/**
 * 构造查询时段 QueryWindow
 */
function buildQueryWindow(dateForWindow, ips) {
  if (dateForWindow) {
    const year = dateForWindow.slice(0, 4);
    const month = dateForWindow.slice(4, 6);
    const day = dateForWindow.slice(6, 8);
    return {
      start: `${year}-${month}-${day}T00:00:00+08:00`,
      end: `${year}-${month}-${day}T23:59:59+08:00`,
    };
  }
  // --input 模式：从 enrichment 数据的 min/max timestamp 推断（尽力而为）
  const tsList = ips.map((x) => x.max_timestamp).filter(Boolean).sort();
  if (tsList.length === 0) return { start: '未知', end: '未知' };
  return { start: tsList[0], end: tsList[tsList.length - 1] };
}

/**
 * 当前时刻 ISO（Asia/Shanghai），仅用于 generated_at（不影响可复现性）
 */
function nowShanghaiIso() {
  const d = toShanghaiTime(Date.now());
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}+08:00`;
}

/**
 * 渲染输出
 */
function renderOutput(payload, format) {
  if (format === 'json') {
    return JSON.stringify(payload, null, 2);
  }
  if (format === 'html') {
    return renderHtml(payload);
  }
  return renderMarkdown(payload);
}

function renderMarkdown(payload) {
  const rows = payload.rows.map((r) => [
    r.alert_timestamp,
    r.risk_ip,
    r.risk_description,
    r.risk_geo_location,
  ]);
  // 空数据仅表头+分隔行（FR 边界）
  if (rows.length === 0) {
    return renderMarkdownTable(HEADERS, []);
  }
  return renderMarkdownTable(HEADERS, rows);
}

function renderHtml(payload) {
  const ths = HEADERS.map((h) => `<th>${h}</th>`).join('');
  const trs = payload.rows
    .map((r) => `    <tr><td>${escapeHtml(r.alert_timestamp)}</td><td>${escapeHtml(r.risk_ip)}</td><td>${escapeHtml(r.risk_description)}</td><td>${escapeHtml(r.risk_geo_location)}</td></tr>`)
    .join('\n');
  return `<table>
  <thead><tr>${ths}</tr></thead>
  <tbody>
${trs}
  </tbody>
</table>`;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function emitEmpty() {
  const output = renderOutput(
    {
      query_window: flags.date ? buildQueryWindow(flags.date, []) : { start: '未知', end: '未知' },
      generated_at: nowShanghaiIso(),
      whitelist_secondary_filtered_count: 0,
      rows: [],
      summary: { total_risk_ips: 0, with_unknown_geo: 0, with_unknown_timestamp: 0 },
    },
    flags.format,
  );
  writeOutput(output, flags.output);
}

function writeOutput(output, outputPath) {
  if (outputPath) {
    fs.writeFileSync(outputPath, output, 'utf-8');
    console.error(`[INFO] Output written to ${outputPath}`);
  } else {
    console.log(output);
  }
}

function writeCandidates(outputPath, rows, queryWindow, generatedAt, whitelistFilteredCount, thresholdFilteredCount, minAttacks) {
  const candidates = rows.map(r => r.risk_ip);
  const payload = {
    date: queryWindow.start || '',
    generated_at: generatedAt,
    candidates,
    total: candidates.length,
    whitelist_secondary_filtered_count: whitelistFilteredCount || 0,
    threshold_filtered_count: thresholdFilteredCount || 0,
    min_attacks: minAttacks || 10,
    summary: {
      total_risk_ips: rows.length,
      query_window: queryWindow,
    },
  };
  const resolved = isAbsolute(outputPath) ? outputPath : resolve(process.cwd(), outputPath);
  const dir = dirname(resolved);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(resolved, JSON.stringify(payload, null, 2), 'utf-8');
  console.error(`[INFO] Candidates written to ${resolved} (${candidates.length} IPs)`);
}
