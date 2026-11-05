#!/usr/bin/env node
/**
 * check-host-state.js — 核验单/多主机是否「攻击成功/失陷」
 *
 * 路径 A（纯脚本、零 MCP）。针对给定内网主机，查询其经 XFF 进来的外部攻击
 * 中 host_state 分布，并统计全局（任意来源）「攻击成功/失陷」计数，
 * 直接回答「该主机是否已失陷」。
 *
 * 用法（脚本以 `node` 直接运行）：
 *   node <skill>/scripts/judgment-xff/check-host-state.js --host 192.0.2.31 --start-date 20260712 --end-date 20260718
 *   node <skill>/scripts/judgment-xff/check-host-state.js --hosts 192.0.2.31,192.0.2.32 --start-date 20260712 --end-date 20260718
 */
import fs from 'fs';
import { esQuery, getEsConfig } from '../shared/es-query.js';
import { parseArgs, showHelp } from '../shared/cli-args.js';

const SCHEMA = {
  host: { type: 'string', description: '单个主机 IP' },
  hosts: { type: 'string', description: '逗号分隔多主机 IP（与 --host 二选一）' },
  'start-date': { type: 'string', required: true, description: '起始日 YYYYMMDD（含）' },
  'end-date': { type: 'string', required: true, description: '结束日 YYYYMMDD（含）' },
  output: { type: 'string', description: '输出目录（默认 output/，文件名 xff-host-state-{host}.json）' },
  help: { type: 'boolean', description: '显示帮助' },
};

function buildIndexList(startDate, endDate) {
  const dates = [];
  const s = new Date(`${startDate.slice(0, 4)}-${startDate.slice(4, 6)}-${startDate.slice(6, 8)}T00:00:00+08:00`);
  const e = new Date(`${endDate.slice(0, 4)}-${endDate.slice(4, 6)}-${endDate.slice(6, 8)}T00:00:00+08:00`);
  let cur = new Date(s);
  while (cur <= e) {
    const y = cur.getFullYear();
    const m = String(cur.getMonth() + 1).padStart(2, '0');
    const d = String(cur.getDate()).padStart(2, '0');
    dates.push(`${y}${m}${d}`);
    cur.setDate(cur.getDate() + 1);
  }
  const prefix = getEsConfig().indexPrefix;
  return dates.map((d) => `${prefix}${d}`).join(',');
}

// 查询某主机：XFF 外部命中 + 全局攻击成功/失陷
async function checkHost(indexList, host) {
  // 1) XFF 外部命中该主机的 host_state 分布 + 直连源
  const bodyXff = {
    size: 0,
    track_total_hits: true,
    query: {
      bool: {
        must: [
          { term: { 'field_values.dip': host } },
          { exists: { field: 'field_values.x_forwarded_for' } },
        ],
        must_not: [{ term: { 'field_values.sip_addr': '局域网' } }],
      },
    },
    aggs: {
      host_states: { terms: { field: 'field_values.host_state', size: 10 } },
      by_client: { terms: { field: 'field_values.sip', size: 50 } },
    },
  };
  // 2) 全局（任意来源）攻击成功/失陷计数
  const bodyComp = {
    size: 0,
    track_total_hits: true,
    query: {
      bool: {
        must: [
          { term: { 'field_values.dip': host } },
          { terms: { 'field_values.host_state': ['攻击成功', '失陷'] } },
        ],
      },
    },
  };

  const [rXff, rComp] = await Promise.all([esQuery(indexList, bodyXff), esQuery(indexList, bodyComp)]);
  const xffTotal = rXff.hits?.total?.value ?? 0;
  const compTotal = rComp.hits?.total?.value ?? 0;
  const hostStates = (rXff.aggregations?.host_states?.buckets || []).map((b) => ({ state: b.key, count: b.doc_count }));
  const clients = (rXff.aggregations?.by_client?.buckets || []).map((b) => ({ sip: b.key, count: b.doc_count }));

  const states = Object.fromEntries(hostStates.map((x) => [x.state, x.count]));
  const compromisedViaXff = (states['攻击成功'] || 0) + (states['失陷'] || 0);
  const verdict = compTotal > 0 || compromisedViaXff > 0 ? '疑似失陷/已攻击成功' : '已核实未失陷';

  return {
    host,
    total_xff_alerts: xffTotal,
    host_state_breakdown: states,
    compromised_via_xff: compromisedViaXff,
    compromised_global: compTotal,
    attacking_clients: clients,
    verdict,
  };
}

async function main() {
  const { flags } = parseArgs(process.argv, SCHEMA);
  if (flags.help) {
    showHelp('scripts/judgment-xff/check-host-state.js', '--host <ip> | --hosts a,b,c', SCHEMA);
    return;
  }
  if (!flags['start-date'] || !flags['end-date']) {
    console.error('[ERROR] 必须提供 --start-date 与 --end-date');
    process.exit(1);
  }
  const targets = flags.hosts ? flags.hosts.split(',').map((s) => s.trim()).filter(Boolean) : flags.host ? [flags.host] : [];
  if (targets.length === 0) {
    console.error('[ERROR] 必须提供 --host 或 --hosts');
    process.exit(1);
  }

  const indexList = buildIndexList(flags['start-date'], flags['end-date']);
  const outDir = flags.output || 'output';
  fs.mkdirSync(outDir, { recursive: true });
  const results = [];
  for (const host of targets) {
    const r = await checkHost(indexList, host);
    results.push(r);
    const p = `${outDir}/xff-host-state-${host}.json`;
    fs.writeFileSync(p, JSON.stringify(r, null, 2), 'utf-8');
    console.log(`[OK] ${host}: ${r.verdict}（XFF命中 ${r.total_xff_alerts}，全局失陷 ${r.compromised_global}）→ ${p}`);
  }
  // 汇总到 stdout
  console.log(JSON.stringify(results.map((r) => ({ host: r.host, verdict: r.verdict, compromised_global: r.compromised_global }))));
}

main().catch((e) => {
  console.error(`[ERROR] ${e.message}`);
  process.exit(2);
});
