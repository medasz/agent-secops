#!/usr/bin/env node
/**
 * analyze-compromised.js - 分析层：攻击成功/失陷主机研判
 *
 * 纯函数 analyzeCompromised(hosts) 对每个受害主机基于 sip_addrs 计算 attack_source，
 * 并原样保留 parse-mcp / extract 产出的 risk_desc / opinion / reason（沿用 judgeVictim），
 * 不重写研判逻辑。
 *
 * CLI：
 *   --input <file>   读取含 compromised_hosts 的 parsed JSON 文件
 *   --self-run --date 直接经 ES 查询（仅 WSL+VPN，ctx=compromised）
 *   无参数则从 stdin 读取 parsed JSON（识别 .compromised_hosts 数组）
 */
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { parseArgs, showHelp } from '../shared/cli-args.js';

const SCHEMA = {
  input: { alias: 'i', type: 'string', description: 'Parsed JSON file containing compromised_hosts[]' },
  selfRun: { type: 'boolean', default: false, description: 'Query ES directly (WSL+VPN) instead of reading --input' },
  date: { type: 'string', description: 'Date (YYYYMMDD) for --self-run' },
};

/**
 * 判定受害主机的攻击来源（基于 sip_addrs）。
 *
 * 定案口径（主理人 2026-07-21）：
 *   - 缺失 / 非数组 / 全空（仅含空串或缺失）→ '未知'（避免把未知误标为确证内网）
 *   - 全部为 '局域网' → '内网'
 *   - 存在任一「非 '局域网' 且非空」的值 → '外部'
 *
 * @param {Array<string>|*} sipAddrs
 * @returns {'外部'|'内网'|'未知'}
 */
export function classifyAttackSource(sipAddrs) {
  const addrs = Array.isArray(sipAddrs) ? sipAddrs : [];
  const real = addrs.filter((a) => a != null && String(a).trim() !== '');
  if (real.length === 0) return '未知';
  const hasExternal = real.some((a) => a !== '局域网');
  return hasExternal ? '外部' : '内网';
}

/**
 * 对失陷主机列表补全 attack_source 字段。
 * @param {Array<{ip,count,attack_types,states,first_seen,last_seen,risk_desc,opinion,reason,sip_addrs?}>} hosts
 * @returns {Array} 原 host 追加 attack_source
 */
export function analyzeCompromised(hosts = []) {
  return (hosts || []).map((h) => ({
    ...h,
    attack_source: classifyAttackSource(h && h.sip_addrs),
  }));
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
 * Self-run: query ES directly (WSL+VPN only) and aggregate with compromised context.
 * @param {object} flags - CLI flags
 * @returns {Promise<object>}
 */
async function runSelf(flags) {
  const { queryAlerts, computeAggregations, getIndexName, getDayRange } = await import('../es-tool/extract.js');
  const date = flags.date || 'today';
  const indexName = getIndexName(date);
  const { startMs, endMs } = getDayRange(date);
  const { alerts } = await queryAlerts({ startMs, endMs }, indexName, 'compromised');
  return computeAggregations(alerts, { date });
}

async function main() {
  const { flags } = parseArgs(process.argv, SCHEMA);
  if (flags.help) {
    showHelp('scripts/analysis/analyze-compromised.js',
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
  const hosts = parsed.compromised_hosts || [];
  process.stdout.write(JSON.stringify(analyzeCompromised(hosts), null, 2) + '\n');
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main().catch((err) => {
    console.error('Error:', err.message);
    process.exit(1);
  });
}

export { analyzeCompromised as default };
