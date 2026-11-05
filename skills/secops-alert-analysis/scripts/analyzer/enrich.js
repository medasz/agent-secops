#!/usr/bin/env node
/**
 * enrich.js - Batch ES aggregation for per-IP attack type enrichment
 *
 * Single ES query: terms(field_values.sip) with sub-aggs on attack_type and hazard_rating.
 * Replaces per-IP approximation with actual per-IP data.
 */
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { loadWhitelist, isExternal } from '../shared/whitelist.js';
import { esQuery, getEsConfig } from '../shared/es-query.js';
import { buildDateRangeFilter } from '../shared/time-utils.js';
import { parseArgs, showHelp, validateRequired } from '../shared/cli-args.js';
import { renderMarkdownTable } from '../shared/report-renderer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SCHEMA = {
  date: { alias: 'd', type: 'string', required: true, description: 'Analysis date YYYYMMDD' },
  whitelist: { alias: 'w', type: 'string', default: join(__dirname, '..', '..', 'references', 'ipWhite.md'), description: 'Path to whitelist file' },
  format: { alias: 'f', type: 'string', default: 'json', description: 'Output format: json or markdown' },
  output: { alias: 'o', type: 'string', description: 'Output file path (default: stdout)' },
};

const { positional, flags } = parseArgs(process.argv, SCHEMA);

if (flags.help) {
  showHelp('scripts/analyzer/enrich.js', '--date YYYYMMDD [--whitelist <path>] [--format json|markdown] [--output <path>]', SCHEMA);
}

const missing = validateRequired(flags, SCHEMA);
if (missing.length > 0) {
  console.error(`[ERROR] Missing required options: ${missing.join(', ')}`);
  process.exit(1);
}

const esConfig = getEsConfig();
const dateRange = buildDateRangeFilter(flags.date);
const indexName = `${esConfig.indexPrefix}${flags.date}`;

// Load whitelist and build must_not filter for whitelisted IPs
const entries = loadWhitelist(flags.whitelist);
const whitelistIps = entries
  .filter(e => e.format === 'single')
  .map(e => e.baseIp);

// Build ES aggregation query
const query = {
  size: 0,
  query: {
    bool: {
      must: [
        { range: { '@timestamp': dateRange } },
      ],
    },
  },
  aggs: {
    by_sip: {
      terms: {
        field: 'field_values.sip',
        size: 10000,
      },
      aggs: {
        by_attack_type: {
          terms: {
            field: 'field_values.attack_type',
            size: 100,
          },
        },
        by_hazard_rating: {
          terms: {
            field: 'field_values.hazard_rating',
            size: 10,
          },
        },
        // 新增（FR-005）：该IP查询时段最近告警时刻，max 聚合返回 {value, value_as_string}
        max_timestamp: {
          max: {
            field: '@timestamp',
          },
        },
        // 新增（FR-006）：该IP最高频地理地址，取 buckets[0].key（原始字符串，含经纬度括号）
        by_sip_addr: {
          terms: {
            field: 'field_values.sip_addr',
            size: 1,
          },
        },
      },
    },
  },
};

// Add must_not filter if we have single IPs to exclude
if (whitelistIps.length > 0) {
  query.query.bool.must_not = [
    { terms: { 'field_values.sip': whitelistIps } },
  ];
}

const startTime = Date.now();

try {
  const response = await esQuery(indexName, query);
  const elapsed = Date.now() - startTime;

  const buckets = response.aggregations?.by_sip?.buckets || [];
  const sumOtherDocCount = response.aggregations?.by_sip?.sum_other_doc_count || 0;

  const ips = [];
  let totalAlerts = 0;

  for (const bucket of buckets) {
    const ip = bucket.key;
    const count = bucket.doc_count;
    totalAlerts += count;

    // Get attack types
    const attackTypes = (bucket.by_attack_type?.buckets || []).map(b => ({
      type: b.key,
      count: b.doc_count,
    })).sort((a, b) => b.count - a.count);

    // Get hazard rating (most frequent)
    const hazardBuckets = bucket.by_hazard_rating?.buckets || [];
    const hazardRating = hazardBuckets.length > 0 ? hazardBuckets[0].key : '';

    // 新增（FR-005）：该IP最近告警时刻，取 max 聚合 value_as_string（UTC ISO）；缺失为 null
    const maxTsAgg = bucket.max_timestamp;
    let maxTimestamp = null;
    if (maxTsAgg && maxTsAgg.value_as_string) {
      maxTimestamp = maxTsAgg.value_as_string;
    } else if (maxTsAgg && typeof maxTsAgg.value === 'number') {
      maxTimestamp = new Date(maxTsAgg.value).toISOString();
    }

    // 新增（FR-006）：该IP最高频地理地址原始值，取 buckets[0].key；缺失为空串
    const sipAddrBuckets = bucket.by_sip_addr?.buckets || [];
    const sipAddr = sipAddrBuckets.length > 0 ? sipAddrBuckets[0].key : '';

    ips.push({
      ip,
      total_alerts: count,
      attack_types: attackTypes,
      hazard_rating: hazardRating,
      max_timestamp: maxTimestamp,
      sip_addr: sipAddr,
    });
  }

  // Sort by total_alerts descending
  ips.sort((a, b) => b.total_alerts - a.total_alerts);

  // 降级可观测性（constitution IV）：统计 max_timestamp / sip_addr 缺失的 IP 数
  const missingTs = ips.filter(ip => !ip.max_timestamp).length;
  const missingAddr = ips.filter(ip => !ip.sip_addr).length;
  if (missingTs > 0) {
    console.warn(`[WARN] ${missingTs}/${ips.length} IPs missing max_timestamp (sub-agg degraded, mapping drift?). Timestamp will be "未知" downstream.`);
  }
  if (missingAddr > 0) {
    console.warn(`[WARN] ${missingAddr}/${ips.length} IPs missing sip_addr (sub-agg degraded, mapping drift?). Geo will be "未知" downstream.`);
  }

  const result = {
    query_info: {
      index: indexName,
      total_external_ips: ips.length,
      total_alerts: totalAlerts,
      sum_other_doc_count: sumOtherDocCount,
      query_time_ms: elapsed,
    },
    ips,
  };

  let output;
  if (flags.format === 'markdown') {
    output = formatMarkdown(result);
  } else {
    output = JSON.stringify(result, null, 2);
  }

  if (flags.output) {
    const fs = await import('fs');
    fs.writeFileSync(flags.output, output, 'utf-8');
    console.error(`[INFO] Output written to ${flags.output}`);
  } else {
    console.log(output);
  }

  process.exit(0);
} catch (e) {
  console.error(`[ERROR] ES query failed: ${e.message}`);
  console.error('[INFO] Tip: Use reporting/parse-mcp.js as fallback when ES is unavailable.');
  process.exit(2);
}

function formatMarkdown(data) {
  const lines = [];
  lines.push('# IP Attack Type Enrichment Results\n');
  lines.push(`**Index**: ${data.query_info.index}`);
  lines.push(`**External IPs**: ${data.query_info.total_external_ips}`);
  lines.push(`**Total Alerts**: ${data.query_info.total_alerts}`);
  lines.push(`**Query Time**: ${data.query_info.query_time_ms}ms\n`);

  const headers = ['IP', 'Total Alerts', 'Top Attack Types', 'Hazard Rating', 'Max Timestamp', 'Sip Addr'];
  const rows = data.ips.map(ip => [
    ip.ip,
    String(ip.total_alerts),
    ip.attack_types.slice(0, 3).map(t => `${t.type}(${t.count})`).join(', '),
    ip.hazard_rating,
    ip.max_timestamp || '未知',
    ip.sip_addr || '未知',
  ]);

  lines.push(renderMarkdownTable(headers, rows));
  return lines.join('\n');
}
