#!/usr/bin/env node
/**
 * calculate.js - Exact total calculator
 *
 * Runs two ES queries: size:0 count query + terms aggregation.
 * Verifies both totals match, uses hits.total.value as authoritative.
 */
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { esQuery, getEsConfig } from '../shared/es-query.js';
import { buildDateRangeFilter } from '../shared/time-utils.js';
import { parseArgs, showHelp, validateRequired } from '../shared/cli-args.js';
import { calculateExactTotal } from '../shared/report-renderer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SCHEMA = {
  date: { alias: 'd', type: 'string', required: true, description: 'Analysis date YYYYMMDD' },
  format: { alias: 'f', type: 'string', default: 'json', description: 'Output format: json or markdown' },
  output: { alias: 'o', type: 'string', description: 'Output file path (default: stdout)' },
};

const { positional, flags } = parseArgs(process.argv, SCHEMA);

if (flags.help) {
  showHelp('scripts/analyzer/calculate.js', '--date YYYYMMDD [--format json|markdown] [--output <path>]', SCHEMA);
}

const missing = validateRequired(flags, SCHEMA);
if (missing.length > 0) {
  console.error(`[ERROR] Missing required options: ${missing.join(', ')}`);
  process.exit(1);
}

const esConfig = getEsConfig();
const dateRange = buildDateRangeFilter(flags.date);
const indexName = `${esConfig.indexPrefix}${flags.date}`;

// Query 1: size:0 count query
const countQuery = {
  size: 0,
  query: {
    bool: {
      must: [
        { range: { '@timestamp': dateRange } },
      ],
    },
  },
};

// Query 2: terms aggregation
const aggQuery = {
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
    },
  },
};

try {
  const [countResponse, aggResponse] = await Promise.all([
    esQuery(indexName, countQuery),
    esQuery(indexName, aggQuery),
  ]);

  const totalFromCount = countResponse.hits?.total?.value ?? 0;

  const buckets = aggResponse.aggregations?.by_sip?.buckets || [];
  const bucketSum = buckets.reduce((sum, b) => sum + b.doc_count, 0);
  const sumOtherDocCount = aggResponse.aggregations?.by_sip?.sum_other_doc_count || 0;
  const totalFromAgg = calculateExactTotal(bucketSum, sumOtherDocCount);

  const verified = totalFromCount === totalFromAgg;

  if (!verified) {
    console.warn(`[WARN] Total mismatch: count query=${totalFromCount}, aggregation=${totalFromAgg}`);
    console.warn('[WARN] Using hits.total.value as authoritative.');
  }

  const result = {
    index: indexName,
    total_from_count_query: totalFromCount,
    total_from_aggregation: totalFromAgg,
    bucket_sum: bucketSum,
    sum_other_doc_count: sumOtherDocCount,
    verified,
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
  lines.push('# Exact Total Calculation Results\n');
  lines.push(`**Index**: ${data.index}\n`);
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Total (count query) | ${data.total_from_count_query} |`);
  lines.push(`| Total (aggregation) | ${data.total_from_aggregation} |`);
  lines.push(`| Bucket sum | ${data.bucket_sum} |`);
  lines.push(`| Sum other doc count | ${data.sum_other_doc_count} |`);
  lines.push(`| Verified | ${data.verified ? 'YES' : 'NO'} |`);

  if (!data.verified) {
    lines.push('\n**WARNING**: Totals do not match. Using count query total as authoritative.');
  }

  return lines.join('\n');
}
