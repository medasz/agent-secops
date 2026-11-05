#!/usr/bin/env node

/**

 * victim-hosts.js — 各 XFF 外部客户端的受害主机归因

 *

 * 路径 A（纯脚本、零 MCP）。读取 query-xff.js 的聚合 JSON，对其中每个

 * 外部客户端，用其全部 XFF 链做 terms 过滤（ES 无「最左端公网 IP」存储字段，

 * 必须按链过滤再聚合 dip），得到受害主机 + 攻击类型 + 攻击结果分布。

 *

 * 用法（脚本以 `node` 直接运行）：

 *   node <skill>/scripts/judgment-xff/victim-hosts.js \

 *       --input output/judgment-xff-{start}-{end}.json \

 *       [--start-date S --end-date E] \

 *       [--output output/judgment-xff-victimhosts-{start}-{end}.json]

 *

 * 也可用 --ips 1.2.3.4,5.6.7.8 直接指定客户端（此时仍需 --start-date/--end-date 拼索引）。

 */

import fs from 'fs';

import { esQuery, getEsConfig } from '../shared/es-query.js';

import { parseArgs, showHelp } from '../shared/cli-args.js';



const SCHEMA = {

  input: { type: 'string', description: 'query-xff.js 输出 JSON（含 external_clients[].chains）' },

  ips: { type: 'string', description: '逗号分隔客户端 IP 列表（与 --input 二选一）' },

  'start-date': { type: 'string', description: '起始日 YYYYMMDD（含），用于拼索引' },

  'end-date': { type: 'string', description: '结束日 YYYYMMDD（含）' },

  output: { type: 'string', description: '输出路径（默认 output/judgment-xff-victimhosts-{start}-{end}.json）' },

  'min-alerts': { type: 'number', default: 1, description: '客户端告警数下限（过滤噪声）' },

  help: { type: 'boolean', description: '显示帮助' },

};



async function queryVictimsForClient(indexList, chains) {

  const body = {

    size: 0,

    track_total_hits: true,

    query: {

      bool: {

        must: [

          { terms: { 'field_values.x_forwarded_for': chains } },

          { exists: { field: 'field_values.x_forwarded_for' } },

        ],

        must_not: [{ term: { 'field_values.sip_addr': '局域网' } }],

      },

    },

    aggs: {

      max_timestamp: { max: { field: '@timestamp' } },

      by_victim: {

        terms: { field: 'field_values.dip', size: 50 },

        aggs: {

          attack_types: { terms: { field: 'field_values.attack_type', size: 10 } },

          host_states: { terms: { field: 'field_values.host_state', size: 5 } },

        },

      },

    },

  };

  const resp = await esQuery(indexList, body);

  const total = resp.hits?.total?.value ?? 0;

  const victims = (resp.aggregations?.by_victim?.buckets || []).map((b) => ({

    dip: b.key,

    count: b.doc_count,

    attack_types: (b.attack_types?.buckets || []).map((x) => ({ type: x.key, count: x.doc_count })),

    host_states: (b.host_states?.buckets || []).map((x) => ({ state: x.key, count: x.doc_count })),

  }));

  const maxTimestamp = resp.aggregations?.max_timestamp?.value ?? null;

  return { total, victims, max_timestamp: maxTimestamp };

}



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



async function main() {

  const { flags } = parseArgs(process.argv, SCHEMA);

  if (flags.help) {

    showHelp('scripts/judgment-xff/victim-hosts.js', '--input <xff.json> | --ips a,b,c', SCHEMA);

    return;

  }

  if (!flags['start-date'] || !flags['end-date']) {

    console.error('[ERROR] 必须提供 --start-date 与 --end-date 以拼索引');

    process.exit(1);

  }

  const indexList = buildIndexList(flags['start-date'], flags['end-date']);

  const outPath = flags.output || `output/judgment-xff-victimhosts-${flags['start-date']}-${flags['end-date']}.json`;



  // 收集客户端（ip -> chains）

  const clientMap = new Map();

  if (flags.input) {

    const data = JSON.parse(fs.readFileSync(flags.input, 'utf8'));

    for (const c of data.external_clients || []) {

      if ((c.alerts || 0) < (flags['min-alerts'] || 1)) continue;

      clientMap.set(c.real_client_ip, c.chains.map((x) => x.chain));

    }

  } else if (flags.ips) {

    for (const ip of flags.ips.split(',').map((s) => s.trim())) {

      if (ip) clientMap.set(ip, [ip]); // 无链信息时退化：直接用 IP 作 term（命中 sip 或 XFF 任一位置）

    }

  } else {

    console.error('[ERROR] 必须提供 --input 或 --ips');

    process.exit(1);

  }



  const clients = [];

  for (const [ip, chains] of clientMap.entries()) {

    const { total, victims, max_timestamp } = await queryVictimsForClient(indexList, chains);

    clients.push({ client_ip: ip, alerts: total, victims, max_timestamp });

    console.error(`[victim] ${ip}: ${total} 条, ${victims.length} 受害主机`);

  }



  fs.mkdirSync('output', { recursive: true });

  fs.writeFileSync(outPath, JSON.stringify({ meta: { index_list: indexList }, clients }, null, 2), 'utf-8');

  console.log(`[OK] 受害主机归因: ${outPath}（${clients.length} 个客户端）`);

}



main().catch((e) => {

  console.error(`[ERROR] ${e.message}`);

  process.exit(2);

});

