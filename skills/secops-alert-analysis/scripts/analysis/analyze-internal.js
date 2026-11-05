#!/usr/bin/env node
/**
 * analyze-internal.js - 分析层：内部攻击研判
 *
 * 纯函数 analyzeInternal(parsed) 输入内部 parsed JSON（含可选 lateral），
 * 输出结构化分析数据（内部攻击统计 + 横向移动）。不调用 ES、不拼 Markdown。
 *
 * CLI：
 *   --input <file>   读取 parsed JSON 文件（extract.js --parsed-output --internal / parse-mcp.js --internal）
 *   --self-run --date 直接经 ES 查询（需能连通 ES_HOST，默认 203.0.113.10:9200，ctx=internal）
 *   无参数则从 stdin 读取 parsed JSON
 */
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { parseArgs, showHelp } from '../shared/cli-args.js';

const SCHEMA = {
  input: { alias: 'i', type: 'string', description: 'Parsed internal JSON file' },
  selfRun: { type: 'boolean', default: false, description: 'Query ES directly (WSL+VPN) instead of reading --input' },
  date: { type: 'string', description: 'Date (YYYYMMDD) for --self-run' },
};

/**
 * 分析内部攻击 parsed JSON。
 * @param {object} parsed - { stats, lateral }
 * @returns {{ stats: object, lateral: object|null }}
 */
export function analyzeInternal(parsed = {}) {
  const stats = parsed.stats || {};
  const lateral = parsed.lateral || null;

  // 涉及内部主机数 = 横向移动源 ∪ 目标的 IP 去重并集（无 lateral 时为 0）。
  // 反映本期真正牵扯到的内网主机规模，供 §1「涉及内部主机数」展示。
  let uniqueInternalHosts = 0;
  if (lateral) {
    const hostIps = new Set();
    for (const s of lateral.sources || []) if (s.ip) hostIps.add(s.ip);
    for (const t of lateral.targets || []) if (t.ip) hostIps.add(t.ip);
    uniqueInternalHosts = hostIps.size;
  }

  return {
    stats: {
      total_alerts: stats.total_alerts || 0,
      internal_alerts: stats.internal_alerts ?? null,
      lateral_alerts: stats.lateral_alerts ?? 0,
      unique_internal_sources: stats.unique_internal_sources ?? 0,
      unique_internal_targets: stats.unique_internal_targets ?? 0,
      unique_internal_hosts: uniqueInternalHosts,
      attack_types: stats.attack_types || [],
      host_states: stats.host_states || [],
    },
    lateral: lateral
      ? {
          sources: lateral.sources || [],
          targets: lateral.targets || [],
          pairs: lateral.pairs || [],
          hourly_distribution: lateral.hourly_distribution || [],
          host_states: lateral.host_states || [],
        }
      : null,
  };
}

/**
 * Read all of stdin as a UTF-8 string.
 * @returns {Promise<string>}
 */
async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf-8');
}

/**
 * Self-run: query ES directly (WSL+VPN only) and aggregate with internal context.
 * @param {object} flags - CLI flags
 * @returns {Promise<object>}
 */
async function runSelf(flags) {
  const { queryAlerts, computeAggregations, getIndexName, getDayRange } = await import('../es-tool/extract.js');
  const date = flags.date || 'today';
  const indexName = getIndexName(date);
  const { startMs, endMs } = getDayRange(date);
  const { alerts } = await queryAlerts({ startMs, endMs }, indexName, 'internal');
  return computeAggregations(alerts, { date, internal: true });
}

async function main() {
  const { flags } = parseArgs(process.argv, SCHEMA);
  if (flags.help) {
    showHelp('scripts/analysis/analyze-internal.js',
      '[--input <file>] [--self-run --date <YYYYMMDD>]', SCHEMA);
  }
  let parsed;
  if (flags.selfRun) {
    parsed = await runSelf(flags);
  } else if (flags.input) {
    parsed = JSON.parse(readFileSync(flags.input, 'utf-8'));
  } else {
    parsed = JSON.parse(await readStdin());
  }
  process.stdout.write(JSON.stringify(analyzeInternal(parsed), null, 2) + '\n');
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main().catch((err) => {
    console.error('Error:', err.message);
    process.exit(1);
  });
}

export { analyzeInternal as default };
