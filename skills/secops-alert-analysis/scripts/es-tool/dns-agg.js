#!/usr/bin/env node
/**
 * dns-agg.js - 独立 DNS 全局聚合脚本（路径A 纯脚本，零 MCP）
 *
 * 职责：替代原 MCP `dns_domains` global agg，覆盖**全量 DNS 流量**
 * （proto=dns + dport=53），并产出内部 DNS 服务相关的风险域名列表，
 * 供 Domain 封禁表（ban-domain-table.js --input）与 DNS 维度研判消费。
 *
 * 数据来源：Elasticsearch IDS 日志（logfmt_746_{date}），经 es-query.js 直连，
 * 不调用任何 MCP 工具（宪法 VI：路径A 纯脚本）。
 *
 * 跨天窗口（Fix G / Bug 跨天）：
 *   - 默认 `--date YYYYMMDD` 单日模式（索引 logfmt_746_{date}，时间范围当天 00:00:00~23:59:59）。
 *   - 传 `--start/--end`（YYYYMMDD 或 YYYYMMDDHHmmss）进入跨天模式：按窗口起点/终点推导
 *     多个 ES 日索引，逐索引查询后在内存按 ioc 合并（doc_count 累加、attack_type 合并、
 *     max_timestamp 取最大），边界日索引缺失（404）自动跳过，保证 §2.2 数据完整且不含窗口外域名。
 *
 * 退出码：0=成功 1=输入错误 2=ES连接错误 3=解析错误
 */
import { fileURLToPath } from 'url';
import { dirname, join, isAbsolute, resolve } from 'path';
import fs from 'fs';
import { esQuery, getEsConfig } from '../shared/es-query.js';
import { parseArgs, showHelp } from '../shared/cli-args.js';
import { buildDateRangeFilter } from '../shared/time-utils.js';
import { createLogger } from '../shared/logger.js';
import { retry } from '../shared/retry.js';
import { getLogConfig } from '../shared/env.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// 内部 DNS 服务 IP（与 ban-domain-table.js 语义一致；风险域名取自其查询时段真实告警）
const DNS_SERVER_IPS = ['192.0.2.10', '192.0.2.11', '192.0.2.12'];

const SCHEMA = {
  date: { alias: 'd', type: 'string', required: true, description: '分析日期 YYYYMMDD（如 20260715）；必填，用于输出文件名与单日缺省 fallback' },
  start: { type: 'string', description: '跨天查询窗口起点 YYYYMMDD 或 YYYYMMDDHHmmss；与 --end 配套，覆盖 --date 单日范围' },
  end: { type: 'string', description: '跨天查询窗口终点 YYYYMMDD 或 YYYYMMDDHHmmss；与 --start 配套' },
  output: { alias: 'o', type: 'string', description: '输出文件路径（默认: output/dns-domains-{date}.json）' },
  format: { alias: 'f', type: 'string', default: 'json', description: '输出格式: json（默认，仅 json 受支持）' },
  whitelist: { alias: 'w', type: 'string', default: join(__dirname, '..', '..', 'references', 'ipWhite.md'), description: '白名单文件（保留参数，本脚本仅聚合统计不执行封禁）' },
  top: { type: 'number', default: 50, description: 'stats.dns_domains Top N 域名数量上限' },
  help: { alias: 'h', type: 'boolean', description: '显示帮助' },
};

const { flags } = parseArgs(process.argv, SCHEMA);

if (flags.help) {
  showHelp('scripts/es-tool/dns-agg.js', '--date YYYYMMDD [--start YYYYMMDD|YYYYMMDDHHmmss --end YYYYMMDD|YYYYMMDDHHmmss] [--output <path>] [--format json] [--top 50]', SCHEMA);
}

const logger = createLogger({ level: getLogConfig().level });

/**
 * 依据跨天窗口起点/终点（YYYYMMDD 或 YYYYMMDDHHmmss）构造 ES range 与原始字符串。
 * 8 位 → 起点补 00:00:00、终点补 23:59:59；14 位 → 原样保留时分秒。
 * 返回的 range.gte/lt 均为 Asia/Shanghai(+08:00) 格式。
 * 若 start/end 任一缺失则返回 null（单日模式，调用方回退 buildDateRangeFilter）。
 * @param {string} startStr
 * @param {string} endStr
 * @returns {{start:string,end:string,range:{gte:string,lt:string}}|null}
 */
export function buildWindowRange(startStr, endStr) {
  if (!startStr || !endStr) return null;
  const pad2 = (n) => String(n).padStart(2, '0');
  const fmt = (s, isStart) => {
    if (/^\d{8}$/.test(s)) {
      return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${isStart ? '00:00:00' : '23:59:59'}+08:00`;
    }
    if (/^\d{14}$/.test(s)) {
      return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}+08:00`;
    }
    // 已是 YYYY-MM-DD HH:mm:ss / ISO，统一补 +08:00
    const fixed = s.includes('T') ? s : s.replace(' ', 'T');
    return fixed.includes('+') ? fixed : `${fixed}+08:00`;
  };
  return {
    start: startStr,
    end: endStr,
    range: { gte: fmt(startStr, true), lt: fmt(endStr, false) },
  };
}

/**
 * 依据跨天窗口起点/终点推导需查询的 ES 日索引集合（支持 YYYYMMDD / YYYYMMDDHHmmss /
 * YYYY-MM-DD HH:mm:ss 多种格式）。逐日推入，guard 防死循环。
 * @param {string} startStr
 * @param {string} endStr
 * @param {string} prefix ES 索引前缀
 * @returns {string[]}
 */
export function dayIndicesInRange(startStr, endStr, prefix) {
  const pad2 = (n) => String(n).padStart(2, '0');
  const normDay = (s) => (s || '').replace(/[-:T]/g, '').slice(0, 8);
  const startDay = normDay(startStr);
  const endDay = normDay(endStr);
  if (!/^\d{8}$/.test(startDay) || !/^\d{8}$/.test(endDay)) return [];
  const indices = [];
  let cur = new Date(`${startDay.slice(0, 4)}-${startDay.slice(4, 6)}-${startDay.slice(6, 8)}T00:00:00Z`);
  const end = new Date(`${endDay.slice(0, 4)}-${endDay.slice(4, 6)}-${endDay.slice(6, 8)}T00:00:00Z`);
  let guard = 0;
  while (cur <= end && guard < 400) {
    const y = cur.getUTCFullYear();
    const m = pad2(cur.getUTCMonth() + 1);
    const d = pad2(cur.getUTCDate());
    indices.push(`${prefix}${y}${m}${d}`);
    cur = new Date(cur.getTime() + 24 * 3600 * 1000);
    guard++;
  }
  return indices;
}

/**
 * 合并跨多个 ES 日索引查得的同 ioc 桶：
 *   - doc_count 累加
 *   - 同 key 的 by_attack_type 子桶 doc_count 累加
 *   - max_timestamp（兼容 max_timestamp / domain_max_timestamp）取最大
 * 输出 shape 与原单索引响应一致（供 dns_alerts / dns_domains 解析复用）。
 * @param {Array} buckets
 * @returns {Array}
 */
export function mergeDnsBuckets(buckets) {
  const map = new Map();
  for (const b of buckets) {
    if (!b || b.key == null) continue;
    if (!map.has(b.key)) {
      map.set(b.key, {
        key: b.key,
        doc_count: 0,
        by_attack_type: { buckets: [] },
        max_timestamp: { value: null },
      });
    }
    const entry = map.get(b.key);
    entry.doc_count += b.doc_count || 0;

    if (b.by_attack_type && Array.isArray(b.by_attack_type.buckets)) {
      for (const at of b.by_attack_type.buckets) {
        const existing = entry.by_attack_type.buckets.find((x) => x.key === at.key);
        if (existing) existing.doc_count += at.doc_count;
        else entry.by_attack_type.buckets.push({ key: at.key, doc_count: at.doc_count });
      }
    }

    const mt = b.max_timestamp || b.domain_max_timestamp;
    if (mt && typeof mt.value === 'number') {
      const cur = entry.max_timestamp.value;
      if (cur === null || mt.value > cur) {
        entry.max_timestamp = { value: mt.value };
      }
    }
  }
  for (const entry of map.values()) {
    if (entry.by_attack_type.buckets.length) {
      entry.by_attack_type.buckets.sort((a, b) => b.doc_count - a.doc_count);
    }
  }
  return [...map.values()];
}

async function main() {
  // --- 输入校验（退出码 1）---
  if (!/^\d{8}$/.test(flags.date || '')) {
    console.error('[ERROR] --date 必填且必须为 YYYYMMDD（如 20260715）。');
    process.exit(1);
  }
  if (flags.format !== 'json') {
    console.error(`[ERROR] --format 仅支持 json，收到: ${flags.format}`);
    process.exit(1);
  }

  const date = flags.date;
  const esConfig = getEsConfig();

  // Fix G（跨天 Bug）：--start/--end 配套给出真实查询窗口；缺省回退 --date 单日。
  const windowRange = (flags.start && flags.end)
    ? buildWindowRange(flags.start, flags.end)
    : null;

  // 时间过滤：窗口模式用 windowRange.range，否则单日 buildDateRangeFilter(date)
  const dateRange = windowRange ? windowRange.range : buildDateRangeFilter(date);
  // 索引列表：窗口模式推导多日索引，否则单日索引
  const indexNames = windowRange
    ? dayIndicesInRange(flags.start, flags.end, esConfig.indexPrefix)
    : [`${esConfig.indexPrefix}${date}`];
  const topN = flags.top > 0 ? flags.top : 50;

  // 单次查询模板（对每个索引执行同一 query）：
  //  - query 上下文 = 内部 DNS 服务相关 DNS 告警
  //      (dip ∈ DNS_SERVER_IPS + proto=dns + dport=53 + timestamp 窗口 range)
  //      → 供 dns_alerts（风险域名列表，与 ban-domain-table.js --date 语义一致）
  //  - aggs.dns_domains（global）→ filter（proto=dns + dport=53，全量 DNS 流量）→ terms(ioc)
  //      → 供 stats.dns_domains（Top 域名，覆盖全量 DNS 流量，不限于 DNS 服务 IP）
  const query = {
    size: 0,
    track_total_hits: true,
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
      dns_alerts_by_ioc: {
        terms: { field: 'field_values.ioc', size: 10000 },
        aggs: {
          by_attack_type: { terms: { field: 'field_values.attack_type', size: 100 } },
          max_timestamp: { max: { field: 'timestamp' } },
        },
      },
      dns_domains: {
        global: {},
        aggs: {
          dns_traffic: {
            filter: {
              bool: {
                must: [
                  { term: { 'field_values.proto': 'dns' } },
                  { term: { 'field_values.dport': '53' } },
                ],
              },
            },
            aggs: {
              by_ioc: {
                terms: { field: 'field_values.ioc', size: topN },
                aggs: {
                  domain_max_timestamp: { max: { field: 'timestamp' } },
                },
              },
            },
          },
        },
      },
    },
  };

  // --- ES 查询（退出码 2/3：连接/查询失败 / 结构异常）---
  // 遍历 indexNames：每个索引跑同一 query，跨索引 buckets 各自 concat；
  // 边界日索引缺失（index_not_found/404）跳过不中断（照搬 ban-domain-table.js）。
  let allAlertBuckets = [];
  let allDomainBuckets = [];
  let successCount = 0;
  for (const indexName of indexNames) {
    let response;
    try {
      response = await retry(() => esQuery(indexName, query), {
        maxAttempts: 3,
        delayMs: 1000,
        onRetry: (attempt, error) => logger.warn('DNS 聚合查询失败，重试', { attempt, index: indexName, error: error.message }),
      });
    } catch (e) {
      // 窗口边界日索引可能不存在（无数据），跳过而非中断
      if (e && /index_not_found|no such index|404/i.test(e.message || '')) {
        logger.warn('索引不存在，跳过', { index: indexName, error: e.message });
        continue;
      }
      console.error(`[ERROR] ES 连接/查询失败: ${e.message}`);
      process.exit(2);
    }
    if (!response.aggregations) {
      if (!windowRange) {
        console.error('[ERROR] ES 响应缺少 aggregations 字段，解析失败。');
        process.exit(3);
      }
      logger.warn('响应缺少 aggregations，跳过', { index: indexName });
      continue;
    }
    successCount++;
    allAlertBuckets = allAlertBuckets.concat(response.aggregations?.dns_alerts_by_ioc?.buckets || []);
    allDomainBuckets = allDomainBuckets.concat(response.aggregations?.dns_domains?.dns_traffic?.by_ioc?.buckets || []);
  }

  // 全部目标索引查询失败：单日模式视为连接失败（exit 2）；窗口模式视为无数据（exit 3）
  if (successCount === 0) {
    if (!windowRange) {
      console.error('[ERROR] ES 连接/查询失败: 目标索引不存在或连接异常。');
      process.exit(2);
    }
    console.error('[ERROR] 窗口内索引均不存在或无聚合数据，解析失败。');
    process.exit(3);
  }

  // 合并跨索引 buckets（输出 shape 与原单索引响应一致）
  const alertBuckets = mergeDnsBuckets(allAlertBuckets);
  const domainBuckets = mergeDnsBuckets(allDomainBuckets);

  // dns_alerts：风险域名列表（shape 兼容 ban-domain-table.js --input：ioc/total_alerts/attack_types/max_timestamp）
  const dnsAlerts = alertBuckets
    .map((bucket) => {
      const attackTypes = (bucket.by_attack_type?.buckets || [])
        .map((b) => ({ type: b.key, count: b.doc_count }))
        .sort((a, b) => b.count - a.count);
      let maxTimestamp = null;
      if (bucket.max_timestamp && typeof bucket.max_timestamp.value === 'number') {
        maxTimestamp = new Date(bucket.max_timestamp.value).toISOString();
      }
      return {
        ioc: bucket.key,
        total_alerts: bucket.doc_count,
        attack_types: attackTypes,
        max_timestamp: maxTimestamp,
      };
    })
    .sort((a, b) => b.total_alerts - a.total_alerts);

  // stats.dns_domains：Top 域名（覆盖全量 DNS 流量）
  const dnsDomains = domainBuckets
    .map((bucket) => ({ domain: bucket.key, count: bucket.doc_count }))
    .sort((a, b) => b.count - a.count);

  const result = {
    date,
    query_range: windowRange
      ? {
          index: indexNames.join(','),
          start: windowRange.start,
          end: windowRange.end,
          gte: windowRange.range.gte,
          lt: windowRange.range.lt,
        }
      : {
          index: indexNames[0],
          start: dateRange.gte,
          end: dateRange.lt,
        },
    stats: {
      dns_domains: dnsDomains,
    },
    dns_alerts: dnsAlerts,
    summary: {
      total_dns_domains: dnsDomains.length,
      total_dns_alerts: dnsAlerts.length,
    },
  };

  const outputPath = flags.output || join('output', `dns-domains-${date}.json`);
  const resolved = isAbsolute(outputPath) ? outputPath : resolve(process.cwd(), outputPath);
  const outDir = dirname(resolved);
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(resolved, JSON.stringify(result, null, 2), 'utf-8');

  console.error(`[INFO] DNS 聚合完成: ${resolved}`);
  console.error(`[INFO] 全量DNS域名 Top ${dnsDomains.length}（${topN} 上限），风险域名（DNS服务）${dnsAlerts.length} 条`);
  process.exit(0);
}

// Run if executed directly (guard so importing this module does not trigger a query)
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main().catch((e) => {
    console.error(`[ERROR] ${e.message}`);
    process.exit(3);
  });
}
