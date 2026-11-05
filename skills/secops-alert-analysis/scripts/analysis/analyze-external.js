#!/usr/bin/env node
/**
 * analyze-external.js - 分析层：外部攻击研判
 *
 * 纯函数 analyzeExternal(parsed) 输入 parse-mcp / extract 产出的 parsed JSON，
 * 输出结构化分析数据（攻击类型分布 + 按小时分布 + 高峰时段）。
 * 不调用 ES、不拼 Markdown（渲染交由 render-external-section.js）。
 *
 * CLI：
 *   --input <file>   读取 parsed JSON 文件（extract.js --parsed-output / parse-mcp.js 产物）
 *   --self-run --date 直接经 ES 查询（需能连通 ES_HOST，默认 203.0.113.10:9200）
 *   无参数则从 stdin 读取 parsed JSON
 */
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { parseArgs, showHelp } from '../shared/cli-args.js';

const SCHEMA = {
  input: { alias: 'i', type: 'string', description: 'Parsed JSON file (extract.js --parsed-output / parse-mcp.js output)' },
  selfRun: { type: 'boolean', default: false, description: 'Query ES directly (WSL+VPN) instead of reading --input' },
  date: { type: 'string', description: 'Date (YYYYMMDD) for --self-run' },
  ctx: { type: 'string', default: 'external', description: 'Query context for --self-run: external|internal|compromised|all' },
};

/**
 * 分析外部攻击 parsed JSON。
 * @param {object} parsed - { stats, ips[], domains[], compromised_hosts[] }
 * @returns {{ stats: object, attackTypes: Array<{type,count,percentage,ipCount}>, hourly: object }}
 */
export function analyzeExternal(parsed = {}) {
  const stats = parsed.stats || {};
  const ips = parsed.ips || [];
  const compromised = parsed.compromised_hosts || [];
  const totalAlerts = stats.total_alerts || 0;

  const attackTypes = (stats.attack_types || []).map((item) => {
    const count = item.count || 0;
    const percentage = totalAlerts > 0 ? ((count / totalAlerts) * 100).toFixed(1) + '%' : '0%';
    const ipCount = ips.filter((ip) => (ip.attack_types || []).some((t) => t.type === item.type)).length;
    return { type: item.type, count, percentage, ipCount };
  });

  const hourlyDist = stats.hourly_distribution || [];
  const rows = hourlyDist.map((h) => ({ hour: h.hour, count: h.count || 0 }));
  const total = rows.reduce((sum, h) => sum + h.count, 0);
  let peakHour = '';
  let peakCount = 0;
  for (const h of rows) {
    if (h.count > peakCount) {
      peakCount = h.count;
      peakHour = h.hour;
    }
  }
  const avg = rows.length > 0 ? total / rows.length : 0;
  const highRiskHours = rows
    .filter((h) => h.count > avg * 1.5 && h.count > 0)
    .map((h) => `${h.hour}（${h.count}次）`)
    .join('、') || '无';

  return {
    stats: {
      total_alerts: totalAlerts,
      external_alerts: stats.external_alerts ?? totalAlerts,
      unique_external_ips: stats.unique_external_ips ?? 0,
      compromised_alerts: compromised.length,
    },
    attackTypes,
    hourly: { rows, total, peakHour, peakCount, highRiskHours },
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
 * Self-run: query ES directly (WSL+VPN only) and aggregate.
 * @param {object} flags - CLI flags
 * @returns {Promise<object>} parsed-shaped aggregation
 */
async function runSelf(flags) {
  const { queryAlerts, computeAggregations, getIndexName, getDayRange } = await import('../es-tool/extract.js');
  const date = flags.date || 'today';
  const indexName = getIndexName(date);
  const { startMs, endMs } = getDayRange(date);
  const ctx = flags.ctx || 'external';
  const { alerts } = await queryAlerts({ startMs, endMs }, indexName, ctx);
  return computeAggregations(alerts, { date, external: ctx === 'external', internal: ctx === 'internal' });
}

async function main() {
  const { flags } = parseArgs(process.argv, SCHEMA);
  if (flags.help) {
    showHelp('scripts/analysis/analyze-external.js',
      '[--input <file>] [--self-run --date <YYYYMMDD> [--ctx external|internal|compromised|all]]', SCHEMA);
  }
  let parsed;
  if (flags.selfRun) {
    parsed = await runSelf(flags);
  } else if (flags.input) {
    parsed = JSON.parse(readFileSync(flags.input, 'utf-8'));
  } else {
    parsed = JSON.parse(await readStdin());
  }
  process.stdout.write(JSON.stringify(analyzeExternal(parsed), null, 2) + '\n');
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main().catch((err) => {
    console.error('Error:', err.message);
    process.exit(1);
  });
}

export { analyzeExternal as default };
