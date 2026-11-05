#!/usr/bin/env node

/**

 * query-xff.js — XFF 代理攻击外部源查询与真实客户端解析

 *

 * 路径 A（纯脚本、零 MCP）：经 shared/es-query.js 直连 ES。

 * 查询「有 XFF 且非空且源非局域网」的告警，按 XFF 链聚合，

 * 取每条链【最左端公网 IP】作为真实外部客户端，去重排名，

 * 标注 CDN 中转跳，输出聚合 JSON + 微步候选文件。

 *

 * 用法（脚本以 `node` 直接运行）：

 *   node <skill>/scripts/judgment-xff/query-xff.js --start-date 20260712 --end-date 20260718

 *   node <skill>/scripts/judgment-xff/query-xff.js --date 20260718

 *

 * 退出码：0=成功 1=参数错误 2=ES 连接错误

 */

import fs from 'fs';

import { esQuery, getEsConfig } from '../shared/es-query.js';

import { parseArgs, showHelp, validateRequired } from '../shared/cli-args.js';



const SCHEMA = {

  date: { type: 'string', description: '单日 YYYYMMDD（与 --start-date/--end-date 二选一）' },

  'start-date': { type: 'string', description: '起始日 YYYYMMDD（含）' },

  'end-date': { type: 'string', description: '结束日 YYYYMMDD（含）' },

  output: { type: 'string', description: '聚合 JSON 输出路径（默认 output/judgment-xff-{start}-{end}.json）' },

  'candidates-output': { type: 'string', description: '微步候选 JSON 输出路径（默认 output/judgment-xff-candidates-{start}-{end}.json）' },

  'top-n': { type: 'number', default: 200, description: '外部客户端排名展示上限' },

  help: { type: 'boolean', description: '显示帮助' },

};



// ---- IP 工具 ----

function isPublic(ip) {

  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;

  const o = ip.split('.').map(Number);

  if (o.some((n) => n > 255)) return false;

  const [a, b] = o;

  if (a === 127) return false;                                  // loopback

  if (a === 10) return false;                                   // private 10/8

  if (a === 172 && b >= 16 && b <= 31) return false;            // private 172.16/12

  if (a === 192 && b === 168) return false;                     // private 192.168/16

  if (a === 169 && b === 254) return false;                     // link-local

  if (a === 100 && b >= 64 && b <= 127) return false;           // CGNAT 100.64/10

  if (a >= 224 && a <= 239) return false;                       // multicast

  if (a >= 240) return false;                                   // reserved

  if (a === 0) return false;                                    // 0.0.0.0/8

  return true;

}



function cdnTag(ip) {

  if (ip.startsWith('175.12.90.') || ip.startsWith('183.60.227.') || ip.startsWith('47.105.')) return 'TencentCDN';

  if (ip.startsWith('172.64.') || ip.startsWith('172.69.') || ip.startsWith('162.158.')) return 'Cloudflare';

  return null;

}



// 取链最左端公网 IP（跳过 127/私网/空）

function leftmostPublic(chain) {

  const tokens = chain.split(',').map((t) => t.trim()).filter(Boolean);

  for (const t of tokens) {

    if (isPublic(t)) return t;

  }

  return null;

}



// ---- 日期范围 → 索引名（逗号拼接）----

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



function buildQueryBody() {

  return {

    size: 0,

    track_total_hits: true,

    query: {

      bool: {

        must: [{ exists: { field: 'field_values.x_forwarded_for' } }],

        must_not: [

          { term: { 'field_values.x_forwarded_for': '' } },

          { term: { 'field_values.sip_addr': '局域网' } },

        ],

      },

    },

    aggs: {

      daily_trend: { date_histogram: { field: 'timestamp', calendar_interval: 'day', time_zone: 'Asia/Shanghai' } },

      by_xff: { terms: { field: 'field_values.x_forwarded_for', size: 1000 } },

      by_attack_type: { terms: { field: 'field_values.attack_type', size: 30 } },

      by_host_state: { terms: { field: 'field_values.host_state', size: 10 } },

      by_target: { terms: { field: 'field_values.dip', size: 20 } },

      by_sip: { terms: { field: 'field_values.sip', size: 50 } },

    },

  };

}



function termsToArr(bucket) {

  if (!bucket || !bucket.buckets) return [];

  return bucket.buckets.map((b) => ({ key: b.key, count: b.doc_count }));

}



function parseXffBuckets(buckets) {

  const clients = new Map(); // clientIp -> { alerts, chains:[{chain,count}], via_cdn, cdn_hops:Set }

  let spoofedTotal = 0;

  const spoofedSamples = [];

  for (const b of buckets) {

    const chain = b.key;

    const count = b.count;

    const client = leftmostPublic(chain);

    if (!client) {

      spoofedTotal += count;

      if (spoofedSamples.length < 20) spoofedSamples.push({ chain, count });

      continue;

    }

    if (!clients.has(client)) {

      clients.set(client, { alerts: 0, chains: [], via_cdn: false, cdn_hops: new Set() });

    }

    const entry = clients.get(client);

    entry.alerts += count;

    entry.chains.push({ chain, count });

    for (const tok of chain.split(',').map((t) => t.trim())) {

      const tag = cdnTag(tok);

      if (tag && !isPublic(tok)) {

        entry.via_cdn = true;

        entry.cdn_hops.add(tok);

      }

    }

  }

  const ranking = [...clients.entries()]

    .map(([ip, v]) => ({

      real_client_ip: ip,

      alerts: v.alerts,

      via_cdn: v.via_cdn,

      cdn_hops: [...v.cdn_hops],

      chains: v.chains.sort((a, b) => b.count - a.count),

    }))

    .sort((a, b) => b.alerts - a.alerts);

  return { ranking, spoofedTotal, spoofedSamples };

}



async function main() {

  const { flags } = parseArgs(process.argv, SCHEMA);

  if (flags.help) {

    showHelp('scripts/judgment-xff/query-xff.js', '[--date YYYYMMDD | --start-date S --end-date E] [--output PATH]', SCHEMA);

    return;

  }

  const missing = validateRequired(flags, {});

  // 自定义互斥校验

  const hasRange = flags['start-date'] && flags['end-date'];

  const hasSingle = !!flags.date;

  if (!hasRange && !hasSingle) {

    console.error('[ERROR] 必须提供 --date 或 --start-date + --end-date');

    process.exit(1);

  }

  if (hasRange && hasSingle) {

    console.error('[ERROR] --date 与 --start-date/--end-date 互斥');

    process.exit(1);

  }



  let startDate, endDate;

  if (hasSingle) {

    startDate = endDate = flags.date;

  } else {

    startDate = flags['start-date'];

    endDate = flags['end-date'];

  }

  if (!/^\d{8}$/.test(startDate) || !/^\d{8}$/.test(endDate)) {

    console.error('[ERROR] 日期须为 YYYYMMDD');

    process.exit(1);

  }



  const indexList = buildIndexList(startDate, endDate);

  const outPath = flags.output || `output/judgment-xff-${startDate}-${endDate}.json`;

  const candPath = flags['candidates-output'] || `output/judgment-xff-candidates-${startDate}-${endDate}.json`;



  console.error(`[query-xff] 索引: ${indexList}`);

  let resp;

  try {

    resp = await esQuery(indexList, buildQueryBody());

  } catch (e) {

    console.error(`[ERROR] ES 查询失败: ${e.message}`);

    process.exit(2);

  }



  const total = resp.hits?.total?.value ?? 0;

  const aggs = resp.aggregations || {};

  const { ranking, spoofedTotal, spoofedSamples } = parseXffBuckets(termsToArr(aggs.by_xff));



  const result = {

    meta: {

      generated_at: new Date().toISOString(),

      index_list: indexList,

      date_range: { start: startDate, end: endDate },

      note: '真实客户端 = XFF 链最左端公网 IP；CDN 中转跳不计入真实源',

    },

    total_xff_alerts: total,

    daily_trend: (aggs.daily_trend?.buckets || []).map((b) => ({ date: (b.key_as_string || '').slice(0, 10), count: b.doc_count })),

    by_attack_type: termsToArr(aggs.by_attack_type),

    by_host_state: termsToArr(aggs.by_host_state),

    by_target: termsToArr(aggs.by_target).map((x) => ({ ip: x.key, count: x.count })),

    by_sip_top: termsToArr(aggs.by_sip).map((x) => ({ ip: x.key, count: x.count })),

    external_clients: ranking.slice(0, flags['top-n']),

    external_unique_clients: ranking.length,

    spoofed_or_internal_xff: { total: spoofedTotal, sample_chains: spoofedSamples },

  };



  fs.mkdirSync('output', { recursive: true });

  fs.writeFileSync(outPath, JSON.stringify(result, null, 2), 'utf-8');



  // 微步候选（兼容 external.js --batch：{ips:[...], candidates:[{ip,alerts}]}）

  const candidates = ranking.map((c) => ({ ip: c.real_client_ip, alerts: c.alerts, via_cdn: c.via_cdn }));

  fs.writeFileSync(candPath, JSON.stringify({ ips: candidates.map((c) => c.ip), candidates }, null, 2), 'utf-8');



  console.log(`[OK] 外部 XFF 告警 ${total} 条，真实客户端 ${ranking.length} 个，伪造/内网链 ${spoofedTotal} 条`);

  console.log(`[OK] 聚合: ${outPath}`);

  console.log(`[OK] 候选: ${candPath}`);

  // 仅向 stdout 输出精简摘要，便于下游消费

  console.log(JSON.stringify({ total_xff_alerts: total, external_unique_clients: ranking.length, top5: ranking.slice(0, 5).map((c) => ({ ip: c.real_client_ip, alerts: c.alerts })) }));

}



main().catch((e) => {

  console.error(`[ERROR] ${e.message}`);

  process.exit(1);

});



export { isPublic, cdnTag, leftmostPublic };

