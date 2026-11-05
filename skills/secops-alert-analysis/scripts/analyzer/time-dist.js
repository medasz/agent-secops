#!/usr/bin/env node
/**
 * time-dist.js - Hourly attack distribution analysis
 *
 * ES date_histogram aggregation filtered to external IPs only.
 * Outputs 24 hourly buckets with peak hour identification.
 */
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { loadWhitelist } from '../shared/whitelist.js';
import { esQuery, getEsConfig } from '../shared/es-query.js';
import { buildDateRangeFilter } from '../shared/time-utils.js';
import { parseArgs, showHelp, validateRequired } from '../shared/cli-args.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SCHEMA = {
  date: { alias: 'd', type: 'string', required: true, description: 'Analysis date YYYYMMDD' },
  whitelist: { alias: 'w', type: 'string', default: join(__dirname, '..', '..', 'references', 'ipWhite.md'), description: 'Path to whitelist file' },
  external: { alias: 'x', type: 'boolean', description: 'Only external attacks (exclude LAN)' },
  format: { alias: 'f', type: 'string', default: 'json', description: 'Output format: json or markdown' },
  output: { alias: 'o', type: 'string', description: 'Output file path (default: stdout)' },
};

const { positional, flags } = parseArgs(process.argv, SCHEMA);

if (flags.help) {
  showHelp('scripts/analyzer/time-dist.js', '--date YYYYMMDD [--external-only] [--whitelist <path>] [--format json|markdown] [--output <path>]', SCHEMA);
}

const missing = validateRequired(flags, SCHEMA);
if (missing.length > 0) {
  console.error(`[ERROR] Missing required options: ${missing.join(', ')}`);
  process.exit(1);
}

const esConfig = getEsConfig();
const dateRange = buildDateRangeFilter(flags.date);
const indexName = `${esConfig.indexPrefix}${flags.date}`;

// Load whitelist for must_not filter
const entries = loadWhitelist(flags.whitelist);
const whitelistIps = entries
  .filter(e => e.format === 'single')
  .map(e => e.baseIp);

// 构建日期范围过滤器：使用 timestamp 字段（非 @timestamp）
const dateFilter = { range: { timestamp: { gte: dateRange.gte, lt: dateRange.lt } } };

const query = {
  size: 0,
  query: {
    bool: {
      must: [dateFilter],
    },
  },
  aggs: {
    hourly: {
      date_histogram: {
        field: 'timestamp',
        calendar_interval: 'hour',
        min_doc_count: 0,
        time_zone: 'Asia/Shanghai',
      },
    },
  },
};

// 排除白名单 IP
if (whitelistIps.length > 0) {
  query.query.bool.must_not = [
    { terms: { 'field_values.sip': whitelistIps } },
  ];
}

// 排除局域网（仅统计外部攻击）
if (flags.external) {
  query.query.bool.must_not.push({
    term: { 'field_values.sip_addr': '局域网' },
  });
}

try {
  const response = await esQuery(indexName, query);
  const buckets = response.aggregations?.hourly?.buckets || [];

  // Parse date for display
  const year = flags.date.slice(0, 4);
  const month = flags.date.slice(4, 6);
  const day = flags.date.slice(6, 8);
  const dateDisplay = `${year}-${month}-${day}`;

  // Build 24 hourly buckets (fill missing with 0)
  const hourlyMap = new Map();
  for (const bucket of buckets) {
    const ts = new Date(bucket.key_as_string || bucket.key);
    // Convert to Shanghai hour
    const shanghaiTs = new Date(ts.getTime() + 8 * 3600 * 1000);
    const hour = shanghaiTs.getUTCHours();
    hourlyMap.set(hour, bucket.doc_count);
  }

  const hourly = [];
  let total = 0;
  for (let h = 0; h < 24; h++) {
    const count = hourlyMap.get(h) || 0;
    hourly.push({ hour: h, count });
    total += count;
  }

  // Find peak hours (top 3)
  const sorted = [...hourly].sort((a, b) => b.count - a.count);
  const peakHours = sorted.slice(0, 3).filter(h => h.count > 0);

  const result = {
    date: dateDisplay,
    timezone: 'Asia/Shanghai',
    hourly,
    peak_hours: peakHours,
    total,
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
  process.exit(2);
}

function formatMarkdown(data) {
  const lines = [];
  lines.push(`# Time Distribution Analysis - ${data.date}\n`);
  lines.push(`**Timezone**: ${data.timezone}`);
  lines.push(`**Total Alerts**: ${data.total}\n`);

  // Text-based bar chart
  const maxCount = Math.max(...data.hourly.map(h => h.count), 1);
  const barWidth = 40;

  lines.push('## Hourly Distribution\n');
  lines.push('```');
  for (const h of data.hourly) {
    const hourStr = String(h.hour).padStart(2, '0');
    const barLen = Math.round((h.count / maxCount) * barWidth);
    const bar = '█'.repeat(barLen) + '░'.repeat(barWidth - barLen);
    lines.push(`${hourStr}: ${bar} ${h.count}`);
  }
  lines.push('```\n');

  // Peak hours
  if (data.peak_hours.length > 0) {
    lines.push('## Peak Hours\n');
    for (const p of data.peak_hours) {
      lines.push(`- **${String(p.hour).padStart(2, '0')}:00** — ${p.count} alerts`);
    }
  }

  return lines.join('\n');
}
