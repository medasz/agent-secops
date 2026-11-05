#!/usr/bin/env node
/**
 * ban-domain-table.js - Domain封禁建议表格生成器（内部DNS相关域名）
 *
 * 消费预聚合 JSON（--input/stdin）或直连 ES（--date），生成四列Domain封禁表格：
 *   最近告警时间 | 风险域名 | 风险描述 | 告警次数
 *
 * 数据取自内部DNS服务（192.0.2.10/11/12）查询时段真实告警记录：
 *   - alert_timestamp  ← max(timestamp) 子聚合（经 shared/time-utils.js 转 Asia/Shanghai）
 *   - risk_domain      ← field_values.ioc（经格式规整，排除规则描述型条目）
 *   - risk_description ← field_values.attack_type terms 子聚合 + attack-type-mapping.json 映射
 *   - alert_count      ← by_ioc 桶 doc_count
 *
 * 可复现（FR-007）：无随机性、无 LLM 介入、无时间敏感逻辑（generated_at 除外）。
 *
 * 退出码：0=成功 1=输入错误 2=ES连接错误 3=解析错误
 */
import { fileURLToPath } from 'url';
import { dirname, join, resolve, isAbsolute } from 'path';
import fs from 'fs';
import { esQuery, getEsConfig } from '../shared/es-query.js';
import { parseArgs, showHelp } from '../shared/cli-args.js';
import { toShanghaiTime, formatDate, buildDateRangeFilter } from '../shared/time-utils.js';
import { renderMarkdownTable } from '../shared/report-renderer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DNS_SERVER_IPS = ['192.0.2.10', '192.0.2.11', '192.0.2.12'];

const SCHEMA = {
  date: { alias: 'd', type: 'string', description: '分析日期 YYYYMMDD（查询时段为该自然日 Asia/Shanghai）；与 --input 二选一' },
  input: { alias: 'i', type: 'string', description: '消费预聚合 JSON（含 domains 数组，每项有 ioc/total_alerts/attack_types/max_timestamp）；与 --date 二选一' },
  start: { type: 'string', description: '跨天查询窗口起点 (Asia/Shanghai, YYYY-MM-DD HH:mm:ss)；与 --end 配套，覆盖 --date 单日范围，用于 ES 查询 range 与行级窗口过滤' },
  end: { type: 'string', description: '跨天查询窗口终点 (Asia/Shanghai, YYYY-MM-DD HH:mm:ss)；与 --start 配套' },
  format: { alias: 'f', type: 'string', default: 'markdown', description: '输出格式: json | markdown | html' },
  output: { alias: 'o', type: 'string', description: '输出文件路径（默认: stdout）' },
  'attack-type-mapping': { type: 'string', default: join(__dirname, '..', '..', 'references', 'attack-type-mapping.json'), description: '攻击类型名称映射配置（FR-011）' },
  'min-attacks': { type: 'number', default: 1, description: '风险域名入选阈值（告警次数 >= N）' },
  'top-attack-types': { type: 'number', default: 3, description: 'risk_description 聚合的攻击类型数量上限' },
  'candidates-output': { type: 'string', description: '输出 ban-domain-candidates JSON 路径' },
  help: { alias: 'h', type: 'boolean', description: '显示帮助' },
};

const { flags } = parseArgs(process.argv, SCHEMA);

if (flags.help) {
  showHelp('scripts/reporting/ban-domain-table.js', '[--date YYYYMMDD | --input <file>] [--format json|markdown|html] [--output <path>]', SCHEMA);
}

const HEADERS = ['最近告警时间', '风险域名', '风险描述', '告警次数'];

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main().catch((e) => {
    console.error(`[ERROR] ${e.message}`);
    process.exit(3);
  });
}

async function main() {
  if (flags.date && flags.input) {
    console.error('[ERROR] --date 与 --input 互斥，请二选一。');
    process.exit(1);
  }
  if (!['json', 'markdown', 'html'].includes(flags.format)) {
    console.error(`[ERROR] --format 仅支持 json|markdown|html，收到: ${flags.format}`);
    process.exit(1);
  }

  let dateForWindow = flags.date || null;
  // Fix F（Bug-06）：跨天自定义窗口。--start/--end 配套给出真实查询窗口；
  // 缺省时回退为 null（沿用 --date 单日模式，行为不变，解释为何"今日"跑无问题）。
  const windowRange = (flags.start && flags.end) ? { start: flags.start, end: flags.end } : null;
  let domainsData = null;

  if (flags.input) {
    domainsData = await readDomainsFromFile(flags.input);
  } else if (flags.date) {
    domainsData = await fetchDomainsFromEs(flags.date, windowRange);
  } else {
    domainsData = await readDomainsFromStdin();
  }

  if (!Array.isArray(domainsData) || domainsData.length === 0) {
    console.error('[INFO] 查询时段无内部DNS相关域名告警数据，输出空表。');
    emitEmpty();
    process.exit(0);
  }

  const attackTypeMap = loadAttackTypeMapping(flags['attack-type-mapping']);

  const { rows, filteredCount, withUnknownTimestamp } = buildDomainRows(
    domainsData,
    attackTypeMap,
    flags['min-attacks'],
    flags['top-attack-types'],
    windowRange,
  );

  if (filteredCount > 0) {
    console.error(`[INFO] 规则描述型IOC过滤排除 ${filteredCount} 条（非域名型ioc）。`);
  }

  const queryWindow = buildQueryWindow(dateForWindow, domainsData, windowRange);
  const generatedAt = nowShanghaiIso();
  const payload = {
    query_window: queryWindow,
    generated_at: generatedAt,
    dns_servers: DNS_SERVER_IPS,
    rule_desc_filtered_count: filteredCount,
    rows,
    summary: {
      total_risk_domains: rows.length,
      with_unknown_timestamp: withUnknownTimestamp,
    },
  };

  const output = renderOutput(payload, flags.format);
  writeOutput(output, flags.output);

  if (flags['candidates-output']) {
    writeCandidates(flags['candidates-output'], rows, queryWindow, generatedAt);
  }

  process.exit(0);
}

/**
 * 从文件读取预聚合 JSON
 */
async function readDomainsFromFile(path) {
  let content;
  try {
    content = fs.readFileSync(path, 'utf-8');
  } catch (e) {
    console.error(`[ERROR] 无法读取 --input 文件: ${path} (${e.message})`);
    process.exit(1);
  }
  return parseDomainsJson(content);
}

/**
 * 从 stdin 读取预聚合 JSON（管道模式）
 */
function readDomainsFromStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(parseDomainsJson(data)));
    process.stdin.on('error', reject);
  });
}

/**
 * 解析预聚合 JSON，返回 domains 数组
 */
function parseDomainsJson(content) {
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch (e) {
    console.error(`[ERROR] 输入 JSON 解析失败: ${e.message}`);
    process.exit(3);
  }
  const domains = parsed?.dns_alerts || parsed?.domains || parsed?.iocs;
  if (!Array.isArray(domains)) {
    console.error('[ERROR] 输入缺少 domains/iocs 数组。');
    process.exit(3);
  }
  return domains;
}

/**
 * 直连 ES 取 per-ioc 聚合（含 max_timestamp + by_attack_type 子聚合），
 * 过滤条件: dip ∈ DNS服务器IP + proto=dns + dport=53
 */
async function fetchDomainsFromEs(dateYYYYMMDD, rangeOverride) {
  const esConfig = getEsConfig();
  const dateRange = rangeOverride || buildDateRangeFilter(dateYYYYMMDD);

  // Fix F（Bug-06）：跨天窗口可能跨越多个 ES 日索引。依据窗口起点/终点推导需查询的日索引集合，
  // 逐索引查询后在内存中按 ioc 合并（doc_count 累加、attack_type 合并、max_timestamp 取最大）。
  const indices = rangeOverride
    ? dayIndicesInRange(rangeOverride.start, rangeOverride.end, esConfig.indexPrefix)
    : [`${esConfig.indexPrefix}${dateYYYYMMDD}`];

  const query = {
    size: 0,
    query: {
      bool: {
        must: [
          { range: { timestamp: dateRange } },
          { terms: { 'field_values.dip': DNS_SERVER_IPS } },
          { term: { 'field_values.proto': 'dns' } },
          { term: { 'field_values.dport': '53' } },
        ],
      },
    },
    aggs: {
      by_ioc: {
        terms: { field: 'field_values.ioc', size: 10000 },
        aggs: {
          by_attack_type: { terms: { field: 'field_values.attack_type', size: 100 } },
          max_timestamp: { max: { field: 'timestamp' } },
        },
      },
    },
  };

  let allBuckets = [];
  for (const indexName of indices) {
    let response;
    try {
      response = await esQuery(indexName, query);
    } catch (e) {
      // 窗口边界日索引可能不存在（无数据），跳过而非中断
      if (e && /index_not_found|no such index|404/i.test(e.message || '')) continue;
      console.error(`[ERROR] ES 连接失败: ${e.message}`);
      console.error('[INFO] 提示: 可改用 --input 消费 dns-agg.js 预聚合 JSON（output/dns-domains-{date}.json）。');
      process.exit(2);
    }
    allBuckets = allBuckets.concat(response.aggregations?.by_ioc?.buckets || []);
  }

  const buckets = mergeIocBuckets(allBuckets);
  const domains = buckets.map((bucket) => {
    const attackTypes = (bucket.by_attack_type?.buckets || [])
      .map((b) => ({ type: b.key, count: b.doc_count }))
      .sort((a, b) => b.count - a.count);
    const maxTsAgg = bucket.max_timestamp;
    let maxTimestamp = null;
    if (maxTsAgg && maxTsAgg.value_as_string) maxTimestamp = maxTsAgg.value_as_string;
    else if (maxTsAgg && typeof maxTsAgg.value === 'number') maxTimestamp = new Date(maxTsAgg.value).toISOString();
    return {
      ioc: bucket.key,
      total_alerts: bucket.doc_count,
      attack_types: attackTypes,
      max_timestamp: maxTimestamp,
    };
  });
  return domains;
}

/**
 * 依据窗口起点/终点（Asia/Shanghai "YYYY-MM-DD HH:mm:ss"）推导需查询的 ES 日索引集合。
 * @param {string} startStr
 * @param {string} endStr
 * @param {string} prefix ES 索引前缀
 * @returns {string[]}
 */
function dayIndicesInRange(startStr, endStr, prefix) {
  const startDay = (startStr || '').slice(0, 10).replace(/-/g, '');
  const endDay = (endStr || '').slice(0, 10).replace(/-/g, '');
  if (!/^\d{8}$/.test(startDay) || !/^\d{8}$/.test(endDay)) return [];
  const indices = [];
  let cur = new Date(`${startDay.slice(0, 4)}-${startDay.slice(4, 6)}-${startDay.slice(6, 8)}T00:00:00Z`);
  const end = new Date(`${endDay.slice(0, 4)}-${endDay.slice(4, 6)}-${endDay.slice(6, 8)}T00:00:00Z`);
  let guard = 0;
  while (cur <= end && guard < 400) {
    const y = cur.getUTCFullYear();
    const m = String(cur.getUTCMonth() + 1).padStart(2, '0');
    const d = String(cur.getUTCDate()).padStart(2, '0');
    indices.push(`${prefix}${y}${m}${d}`);
    cur = new Date(cur.getTime() + 24 * 3600 * 1000);
    guard++;
  }
  return indices;
}

/**
 * 合并跨多个 ES 日索引查得的同 ioc 桶：doc_count 累加、attack_type 合并、max_timestamp 取最大。
 * @param {Array} buckets
 * @returns {Array}
 */
function mergeIocBuckets(buckets) {
  const map = new Map();
  for (const b of buckets) {
    if (!b || b.key == null) continue;
    if (!map.has(b.key)) {
      map.set(b.key, { key: b.key, doc_count: 0, by_attack_type: { buckets: [] }, max_timestamp: { value_as_string: null, value: null } });
    }
    const entry = map.get(b.key);
    entry.doc_count += b.doc_count || 0;
    for (const at of b.by_attack_type?.buckets || []) {
      const existing = entry.by_attack_type.buckets.find((x) => x.key === at.key);
      if (existing) existing.doc_count += at.doc_count;
      else entry.by_attack_type.buckets.push({ key: at.key, doc_count: at.doc_count });
    }
    const mt = b.max_timestamp;
    if (mt) {
      const curMs = entry.max_timestamp.value_as_string
        ? Date.parse(entry.max_timestamp.value_as_string)
        : (typeof entry.max_timestamp.value === 'number' ? entry.max_timestamp.value : -Infinity);
      const newMs = mt.value_as_string
        ? Date.parse(mt.value_as_string)
        : (typeof mt.value === 'number' ? mt.value : -Infinity);
      if (newMs > curMs) {
        entry.max_timestamp = { value_as_string: mt.value_as_string || null, value: mt.value ?? null };
      }
    }
  }
  for (const entry of map.values()) {
    entry.by_attack_type.buckets.sort((a, b) => b.doc_count - a.doc_count);
  }
  return [...map.values()];
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
 * 判断 ioc 是否为规则描述型（非域名）
 * 规则描述型特征：以数字+横线开头（如 "24813-发现..."），或含中文字符
 */
function isRuleDescription(ioc) {
  if (!ioc || typeof ioc !== 'string') return true;
  if (/^\d+-/.test(ioc)) return true;
  if (/[\u4e00-\u9fff]/.test(ioc)) return true;
  return false;
}

/**
 * 规整风险域名：去除前导通配符 *
 */
function normalizeDomain(ioc) {
  let d = ioc.trim();
  if (d.startsWith('*')) d = d.slice(1);
  return d;
}

/**
 * 将 Asia/Shanghai "YYYY-MM-DD HH:mm:ss" 字符串解析为 UTC 毫秒（用于与 ISO UTC 的 max_timestamp 比较）。
 * 入参缺省或非法时返回 NaN。
 * @param {string} str
 * @returns {number}
 */
function parseShanghaiMs(str) {
  if (!str || typeof str !== 'string') return NaN;
  const iso = str.includes('T') ? str : `${str.replace(' ', 'T')}+08:00`;
  const ms = Date.parse(iso);
  return ms;
}

/**
 * 构造Domain封禁表格行：规则描述过滤 + 阈值筛选 + 列规整
 */
export function buildDomainRows(domains, attackTypeMap, minAttacks, topN, window) {
  const rows = [];
  let filteredCount = 0;
  let withUnknownTimestamp = 0;

  // Fix F（Bug-06）：仅保留 max_timestamp 落在报告真实查询窗口 [start,end] 内的域名，
  // 剔除被单日查询/预聚合捎带进来的窗口外域名（如窗口起点前的告警 slok9.xyz 19:13）。
  // 双保险：即便 ES 查询 range 未精确覆盖窗口，行级过滤也能保证 §2.2 不含窗口外域名。
  let windowStartMs = null;
  let windowEndMs = null;
  if (window && window.start && window.end) {
    windowStartMs = parseShanghaiMs(window.start);
    windowEndMs = parseShanghaiMs(window.end);
  }

  for (const domData of domains) {
    if (isRuleDescription(domData.ioc)) {
      filteredCount++;
      continue;
    }
    if (!(domData.total_alerts >= minAttacks)) {
      continue;
    }
    if (windowStartMs !== null && windowEndMs !== null) {
      const tsMs = domData.max_timestamp ? Date.parse(domData.max_timestamp) : NaN;
      if (!isNaN(tsMs) && (tsMs < windowStartMs || tsMs > windowEndMs)) {
        continue;
      }
    }

    const alertTimestamp = formatAlertTimestamp(domData.max_timestamp);
    if (alertTimestamp === '未知') withUnknownTimestamp++;

    const riskDomain = normalizeDomain(domData.ioc);
    const riskDescription = buildRiskDescription(domData.attack_types, attackTypeMap, topN);

    rows.push({
      alert_timestamp: alertTimestamp,
      risk_domain: riskDomain,
      risk_description: riskDescription,
      alert_count: domData.total_alerts,
    });
  }

  rows.sort((a, b) => {
    if (b.alert_count !== a.alert_count) return b.alert_count - a.alert_count;
    return a.risk_domain.localeCompare(b.risk_domain);
  });

  return { rows, filteredCount, withUnknownTimestamp };
}

/**
 * max_timestamp（ISO UTC）→ Asia/Shanghai 秒级 yyyy/M/d H:mm:ss（无前导零，FR-010）
 */
function formatAlertTimestamp(isoOrMs) {
  if (!isoOrMs) {
    console.warn('[WARN] 某域名 max_timestamp 缺失，输出"未知"。');
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
 *   单类型 → "{n}次{name}"
 *   多类型 → "{n1}次{name1}，发现{n2}次{name2}，发现{n3}次{name3}"
 * 映射缺失回退 ES 原始名 + INFO 日志
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
 * 构造查询时段 QueryWindow
 */
function buildQueryWindow(dateForWindow, domains, window) {
  if (window && window.start && window.end) {
    return { start: window.start, end: window.end };
  }
  if (dateForWindow) {
    const year = dateForWindow.slice(0, 4);
    const month = dateForWindow.slice(4, 6);
    const day = dateForWindow.slice(6, 8);
    return {
      start: `${year}-${month}-${day}T00:00:00+08:00`,
      end: `${year}-${month}-${day}T23:59:59+08:00`,
    };
  }
  const tsList = domains.map((x) => x.max_timestamp).filter(Boolean).sort();
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
    r.risk_domain,
    r.risk_description,
    String(r.alert_count),
  ]);
  if (rows.length === 0) {
    return renderMarkdownTable(HEADERS, []);
  }
  return renderMarkdownTable(HEADERS, rows);
}

function renderHtml(payload) {
  const ths = HEADERS.map((h) => `<th>${h}</th>`).join('');
  const trs = payload.rows
    .map((r) => `    <tr><td>${escapeHtml(r.alert_timestamp)}</td><td>${escapeHtml(r.risk_domain)}</td><td>${escapeHtml(r.risk_description)}</td><td>${escapeHtml(String(r.alert_count))}</td></tr>`)
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
      dns_servers: DNS_SERVER_IPS,
      rule_desc_filtered_count: 0,
      rows: [],
      summary: { total_risk_domains: 0, with_unknown_timestamp: 0 },
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

function writeCandidates(outputPath, rows, queryWindow, generatedAt) {
  const candidates = rows.map(r => r.risk_domain);
  const payload = {
    date: queryWindow.start || '',
    generated_at: generatedAt,
    candidates,
    total: candidates.length,
    summary: {
      total_risk_domains: rows.length,
      query_window: queryWindow,
    },
  };
  const resolved = isAbsolute(outputPath) ? outputPath : resolve(process.cwd(), outputPath);
  const dir = dirname(resolved);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(resolved, JSON.stringify(payload, null, 2), 'utf-8');
  console.error(`[INFO] Domain candidates written to ${resolved} (${candidates.length} domains)`);
}
