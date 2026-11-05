#!/usr/bin/env node
/**
 * parse-mcp.js - Parse MCP aggregation response into structured data
 *
 * Input formats (auto-detected):
 *   1. MCP protocol:  {content: [{type:"text", text:"<ES JSON>"}]}
 *   2. MCP array:     [{type:"text", text:"<ES JSON>"}]
 *   3. MCP single:    {type:"text", text:"<ES JSON>"}
 *   4. Flat ES:       {took:..., hits:{...}, aggregations:{...}}
 *
 * Output: { stats, ips, domains, compromised_hosts[, lateral] }
 *
 * consumers:
 *   - ban-ip-table.js --input     reads .ips[]
 *   - ban-domain-table.js --input  reads .domains[]
 *   - Agent (Step 2)               reads .stats + .compromised_hosts[]
 *   - lateral-analysis.js          reads .lateral (internal query only)
 */
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { parseArgs, showHelp } from '../shared/cli-args.js';
import { judgeVictim, riskDescription } from '../shared/infra-exclude.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SCHEMA = {
  format: { alias: 'f', type: 'string', default: 'json', description: 'Output format: json or markdown' },
  output: { alias: 'o', type: 'string', description: 'Output file path (default: stdout)' },
  internal: { type: 'boolean', default: false, description: 'Parse internal alert query (lateral movement)' },
};

function main() {
const { positional, flags } = parseArgs(process.argv, SCHEMA);

if (flags.help) {
  showHelp('scripts/reporting/parse-mcp.js', '<input-file> [--format json|markdown] [--output <path>]', SCHEMA);
}

if (positional.length === 0) {
  console.error('[ERROR] No input file provided.');
  console.error('Usage: node scripts/reporting/parse-mcp.js <input-file> [--format json|markdown] [--output <path>]');
  process.exit(1);
}

const inputFile = positional[0];

if (!fs.existsSync(inputFile)) {
  console.error(`[ERROR] Input file not found: ${inputFile}`);
  process.exit(1);
}

// Phase 1: Read and parse outer JSON
  let rawContent;
  try {
    rawContent = fs.readFileSync(inputFile, 'utf-8');
  } catch (e) {
    console.error(`[ERROR] Cannot read file: ${inputFile} — ${e.message}`);
    process.exit(1);
  }

  let esResponse;
  try {
    esResponse = normalizeInput(rawContent, inputFile);
  } catch (e) {
    if (e.code === 'PARSE_ERROR') {
      process.exit(3);
    }
    throw e;
  }

// Phase 3: Extract structured data from aggregation response
const aggs = esResponse.aggregations;
const totalAlerts = esResponse.hits?.total?.value ?? 0;

  // --- stats ---
  const stats = {
    total_alerts: totalAlerts,
    unique_external_ips: aggs.unique_external_ips?.value ?? 0,
    attack_types: extractTerms(aggs.attack_types),
    hazard_ratings: extractTerms(aggs.hazard_ratings),
    top_targets: extractTerms(aggs.top_targets),
    hourly_distribution: (aggs.hourly_distribution?.buckets || []).map(b => ({
      hour: b.key_as_string || '',
      count: b.doc_count,
    })),
    external_alerts: totalAlerts,
    unique_internal_hosts: (aggs.top_targets?.buckets || []).length,
    compromised_alerts: 0, // 在 compromisedHosts 计算后回填（= 经特征研判后的真实受害主机数，非原始分桶数）
    internal_alerts: flags.internal ? totalAlerts : null,
    last_timestamp: (() => {
      const buckets = aggs.hourly_distribution?.buckets || [];
      for (let i = buckets.length - 1; i >= 0; i--) {
        if (buckets[i].doc_count > 0) return buckets[i].key_as_string || null;
      }
      return null;
    })(),
    exact_total: (aggs.attack_ips?.sum_other_doc_count || 0) +
      (aggs.attack_ips?.buckets || []).reduce((sum, b) => sum + b.doc_count, 0),
    count_query_total: totalAlerts,
  };

  if (flags.internal) {
    stats.lateral_alerts = aggs.lateral_movement?.doc_count ?? 0;
    stats.unique_internal_sources = (aggs.attack_ips?.buckets || []).length;
    stats.unique_internal_targets = (aggs.top_targets?.buckets || []).length;
    stats.host_states = extractTerms(aggs.host_states);
  }

  // --- ips (for ban-ip-table.js --input) ---
  const ips = (aggs.attack_ips?.buckets || []).map(bucket => ({
    ip: bucket.key,
    total_alerts: bucket.doc_count,
    attack_types: extractTerms(bucket.ip_attack_types),
    hazard_rating: '',
    max_timestamp: bucket.max_timestamp?.value_as_string || null,
    sip_addr: bucket.geo_locations?.buckets?.[0]?.key || '',
  }));

  // --- domains (for ban-domain-table.js --input) ---
  const dnsTraffic = aggs.dns_domains?.dns_traffic;
  const domains = (dnsTraffic?.by_ioc?.buckets || []).map(bucket => ({
    ioc: bucket.key,
    total_alerts: bucket.doc_count,
    attack_types: extractTerms(bucket.domain_attack_types),
    max_timestamp: bucket.domain_max_timestamp?.value_as_string || null,
  }));

  // --- compromised_hosts ---
  // 基于「攻击成功/失陷」告警特征研判真实受害方（judgeVictim）：
  //   - 主导协议=DNS 且 alarm_sip 命中基础设施清单 → 判为转发设备误标，从清单剔除（底层告警保留）
  //   - 其余 → 保留为真实受害主机，附 风险描述（复用 attack-type-mapping）+ 研判意见
  const compromisedHosts = (aggs.compromised_hosts?.by_victim?.buckets || [])
    .map(bucket => {
      const protoBuckets = bucket.victim_proto?.buckets || [];
      const dominantProto = [...protoBuckets].sort((a, b) => b.doc_count - a.doc_count)[0]?.key || '';
      const attackTypes = extractTerms(bucket.victim_attack_types);
      const j = judgeVictim({
        alarm_sip: bucket.key,
        proto: dominantProto,
        host_state: bucket.victim_states?.buckets?.[0]?.key || '失陷',
        attack_type: attackTypes[0]?.type || '',
        attack_types: attackTypes,
        ioc: bucket.victim_ioc?.buckets?.[0]?.key || '',
      });
      if (!j.isVictim) return null; // DNS 转发设备误标：剔除该设备
      return {
        ip: bucket.key,
        count: bucket.doc_count,
        attack_types: attackTypes,
        states: (bucket.victim_states?.buckets || []).map(b => b.key),
        sip_addrs: (bucket.victim_sip_addrs?.buckets || []).map(b => b.key),
        first_seen: bucket.first_seen?.value_as_string || null,
        last_seen: bucket.last_seen?.value_as_string || null,
        risk_desc: riskDescription(attackTypes),
        opinion: j.opinion,
        reason: j.reason,
      };
    })
    .filter(Boolean);

  stats.compromised_alerts = compromisedHosts.length; // 经特征研判后的真实受害主机数（非原始分桶数）
  const result = { stats, ips, domains, compromised_hosts: compromisedHosts };

  if (flags.internal) {
    result.lateral = extractLateral(aggs);
  }

// Phase 4: Output
let output;
if (flags.format === 'markdown') {
  output = formatMarkdown(result);
} else {
  output = JSON.stringify(result, null, 2);
}

  if (flags.output) {
    const lateralInfo = result.lateral ? `, ${result.lateral.sources.length} lateral sources, ${result.lateral.targets.length} lateral targets` : '';
    fs.writeFileSync(flags.output, output, 'utf-8');
    console.error(`[INFO] Output written to ${flags.output} (${ips.length} IPs, ${domains.length} domains, ${compromisedHosts.length} compromised hosts${lateralInfo})`);
  } else {
  console.log(output);
}

process.exit(0);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) main();

// --- helpers ---

/**
 * Normalize MCP/ES input into a single ES response object.
 *
 * Supported formats (auto-detected):
 *   1. MCP protocol:  {content: [{type:"text", text:"<ES JSON>"}]}
 *   2. MCP array:     [{type:"text", text:"<ES JSON>"}]
 *   3. MCP single:    {type:"text", text:"<ES JSON>"}
 *   4. Flat ES:       {took:..., hits:{...}, aggregations:{...}}
 *
 * @param {string} rawContent - Raw file content
 * @param {string} inputFile - File path (for error messages)
 * @returns {object} ES response with .aggregations
 * @throws {{code:'PARSE_ERROR'}} on malformed JSON or no ES response found
 */
function normalizeInput(rawContent, inputFile) {
  let parsed;
  try {
    parsed = JSON.parse(rawContent);
  } catch (e) {
    const offset = e.message.match(/position (\d+)/)?.[1];
    console.error(`[ERROR] Malformed JSON in ${inputFile}${offset ? ` at byte ${offset}` : ''}: ${e.message}`);
    const err = new Error('Malformed JSON');
    err.code = 'PARSE_ERROR';
    throw err;
  }

  const items = collectContentItems(parsed);
  let esResponse = findEsResponse(items);

  if (!esResponse) {
    console.error('[ERROR] Input file does not contain an ES aggregation response.');
    console.error('[ERROR] No "aggregations" key found in any MCP envelope item.');
    console.error('[INFO] Document-level hits format is no longer supported.');
    console.error('[INFO] Use the extended aggregation DSL from Appendix A, or use extract.js for direct ES access.');
    const err = new Error('No ES response found');
    err.code = 'PARSE_ERROR';
    throw err;
  }

  if (!esResponse.aggregations) {
    console.error('[ERROR] ES response found but contains no "aggregations" key.');
    console.error('[INFO] Ensure the MCP search uses the extended aggregation DSL from Appendix A.');
    const err = new Error('No aggregations key');
    err.code = 'PARSE_ERROR';
    throw err;
  }

  return esResponse;
}

/**
 * Collect all content items from various MCP wrapper formats.
 * Returns an array of objects that might contain ES data.
 */
function collectContentItems(parsed) {
  if (Array.isArray(parsed)) {
    return parsed;
  }

  if (parsed && typeof parsed === 'object') {
    if (parsed.content && Array.isArray(parsed.content)) {
      return parsed.content;
    }
    if (parsed.type === 'text' && parsed.text) {
      return [parsed];
    }
    if (parsed.aggregations || parsed.hits) {
      return [parsed];
    }
  }

  return [parsed];
}

/**
 * Search through content items for an ES response.
 * Handles text-wrapped JSON and flat ES objects.
 */
function findEsResponse(items) {
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (!item) continue;

    if (item.type === 'text' && item.text) {
      try {
        const inner = JSON.parse(item.text);
        if (inner.aggregations || inner.hits) {
          return inner;
        }
      } catch (e) {
        console.error(`[WARN] Skipping item ${i}: inner JSON parse error: ${e.message}`);
        continue;
      }
    }

    if (item.aggregations || item.hits) {
      return item;
    }
  }

  return null;
}

export function normalizeAttackType(value) {
  if (!value || typeof value !== 'string') return value;

  const variants = [
    { pattern: '暴力\ufffd解', correct: '暴力猜解' },
    { pattern: '\ufffd码执行', correct: '代码执行' },
  ];

  for (const v of variants) {
    if (value === v.pattern) return v.correct;
    if (value.includes('\ufffd') && value.replace('\ufffd', '') === v.correct.replace(v.pattern.replace('\ufffd', ''), '')) {
      return v.correct;
    }
  }

  if (value.includes('\ufffd')) {
    console.error(`[WARN] Unknown attack_type variant: ${value}`);
  }

  return value;
}

function extractTerms(agg) {
  if (!agg?.buckets) return [];
  const normalized = agg.buckets.map(b => ({
    type: normalizeAttackType(b.key),
    count: b.doc_count,
  }));
  const merged = {};
  for (const item of normalized) {
    if (merged[item.type]) {
      merged[item.type].count += item.count;
    } else {
      merged[item.type] = { ...item };
    }
  }
  return Object.values(merged);
}

/**
 * Extract lateral movement data from internal query aggregations.
 *
 * @param {object} aggs - The aggregations from internal query
 * @returns {{sources, targets, pairs, hourly_distribution, host_states}}
 */
function extractLateral(aggs) {
  const lm = aggs.lateral_movement;

  const sources = (lm?.lateral_sources?.buckets || []).map(bucket => ({
    ip: bucket.key,
    count: bucket.doc_count,
    attack_types: extractTerms(bucket.source_attack_types),
    max_timestamp: bucket.max_timestamp?.value_as_string || null,
  }));

  const targets = (lm?.lateral_targets?.buckets || []).map(bucket => ({
    ip: bucket.key,
    count: bucket.doc_count,
    attack_types: extractTerms(bucket.target_attack_types),
    max_timestamp: bucket.max_timestamp?.value_as_string || null,
  }));

  const pairs = [];
  for (const srcBucket of (lm?.lateral_pairs?.buckets || [])) {
    for (const tgtBucket of (srcBucket.target_ips?.buckets || [])) {
      pairs.push({
        source: srcBucket.key,
        target: tgtBucket.key,
        count: tgtBucket.doc_count,
        attack_types: extractTerms(tgtBucket.pair_attack_types),
        max_timestamp: tgtBucket.pair_max_timestamp?.value_as_string || null,
      });
    }
  }

  const hourlyDistribution = (lm?.lateral_hourly?.buckets || []).map(b => ({
    hour: b.key_as_string || '',
    count: b.doc_count,
  }));

  const hostStates = extractTerms(lm?.lateral_host_states);

  return { sources, targets, pairs, hourly_distribution: hourlyDistribution, host_states: hostStates };
}

function formatMarkdown(data) {
  const lines = [];
  const isInternal = !!data.lateral;
  const title = isInternal ? 'MCP Internal Alert Parse Results' : 'MCP Aggregation Parse Results';
  lines.push(`# ${title}\n`);
  lines.push(`**Total Alerts**: ${data.stats.total_alerts}`);
  if (isInternal) {
    lines.push(`**Internal Alerts**: ${data.stats.internal_alerts}`);
    lines.push(`**Lateral Alerts**: ${data.stats.lateral_alerts}`);
    lines.push(`**Unique Internal Sources**: ${data.stats.unique_internal_sources}`);
    lines.push(`**Unique Internal Targets**: ${data.stats.unique_internal_targets}`);
  } else {
    lines.push(`**Unique External IPs**: ${data.stats.unique_external_ips}`);
  }
  lines.push(`**Attack IPs**: ${data.ips.length}`);
  lines.push(`**DNS Domains**: ${data.domains.length}`);
  lines.push(`**Compromised Hosts**: ${data.compromised_hosts.length}\n`);

  if (isInternal && data.stats.host_states && data.stats.host_states.length > 0) {
    lines.push('## Host States\n');
    lines.push('| State | Count |');
    lines.push('|-------|-------|');
    for (const hs of data.stats.host_states) {
      lines.push(`| ${hs.type} | ${hs.count} |`);
    }
    lines.push('');
  }

  lines.push('## Attack IPs\n');
  lines.push('| IP | Alerts | Max Timestamp | Geo | Attack Types |');
  lines.push('|----|--------|---------------|-----|--------------|');
  for (const ip of data.ips) {
    const types = ip.attack_types.map(a => `${a.type}(${a.count})`).join(', ');
    lines.push(`| ${ip.ip} | ${ip.total_alerts} | ${ip.max_timestamp || 'N/A'} | ${ip.sip_addr || 'N/A'} | ${types} |`);
  }

  if (data.domains.length > 0) {
    lines.push('\n## DNS Domains\n');
    lines.push('| Domain | Alerts | Max Timestamp | Attack Types |');
    lines.push('|--------|--------|---------------|--------------|');
    for (const d of data.domains) {
      const types = d.attack_types.map(a => `${a.type}(${a.count})`).join(', ');
      lines.push(`| ${d.ioc} | ${d.total_alerts} | ${d.max_timestamp || 'N/A'} | ${types} |`);
    }
  }

  if (data.compromised_hosts.length > 0) {
    lines.push('\n## Compromised Hosts\n');
    lines.push('| IP | Count | States | Attack Types | First Seen | Last Seen |');
    lines.push('|----|-------|--------|--------------|------------|-----------|');
    for (const h of data.compromised_hosts) {
      const types = h.attack_types.map(a => `${a.type}(${a.count})`).join(', ');
      lines.push(`| ${h.ip} | ${h.count} | ${h.states.join(', ')} | ${types} | ${h.first_seen || 'N/A'} | ${h.last_seen || 'N/A'} |`);
    }
  }

  if (data.lateral) {
    if (data.lateral.sources.length > 0) {
      lines.push('\n## Lateral Sources\n');
      lines.push('| IP | Count | Max Timestamp | Attack Types |');
      lines.push('|----|-------|---------------|--------------|');
      for (const s of data.lateral.sources) {
        const types = s.attack_types.map(a => `${a.type}(${a.count})`).join(', ');
        lines.push(`| ${s.ip} | ${s.count} | ${s.max_timestamp || 'N/A'} | ${types} |`);
      }
    }

    if (data.lateral.targets.length > 0) {
      lines.push('\n## Lateral Targets\n');
      lines.push('| IP | Count | Max Timestamp | Attack Types |');
      lines.push('|----|-------|---------------|--------------|');
      for (const t of data.lateral.targets) {
        const types = t.attack_types.map(a => `${a.type}(${a.count})`).join(', ');
        lines.push(`| ${t.ip} | ${t.count} | ${t.max_timestamp || 'N/A'} | ${types} |`);
      }
    }

    if (data.lateral.pairs.length > 0) {
      lines.push('\n## Lateral Pairs\n');
      lines.push('| Source | Target | Count | Max Timestamp | Attack Types |');
      lines.push('|--------|--------|-------|---------------|--------------|');
      for (const p of data.lateral.pairs) {
        const types = p.attack_types.map(a => `${a.type}(${a.count})`).join(', ');
        lines.push(`| ${p.source} | ${p.target} | ${p.count} | ${p.max_timestamp || 'N/A'} | ${types} |`);
      }
    }
  }

  return lines.join('\n');
}
