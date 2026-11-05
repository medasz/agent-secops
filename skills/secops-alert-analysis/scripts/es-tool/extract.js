#!/usr/bin/env node
/**
 * extract.js - 直接 ES 查询脚本
 *
 * 职责：通过 ES HTTP API 查询告警，使用 PIT 分页确保完整提取
 */
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { createLogger } from '../shared/logger.js';
import { retry } from '../shared/retry.js';
import { getLogConfig } from '../shared/env.js';
import { getEsConfig, createEsRequest, buildQuery } from '../shared/es-query.js';
import { judgeVictim, riskDescription } from '../shared/infra-exclude.js';
import { queryAllWithPIT, toShanghaiTimeString } from './paginate.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ES config from env.js
const esConfig = getEsConfig();
let ES_HOST = esConfig.host;
let ES_PORT = esConfig.port;
let ES_USER = esConfig.username;
let ES_PASSWORD = esConfig.password;
let INDEX_PREFIX = esConfig.indexPrefix;

// Initialize logger
let logger = createLogger({ level: getLogConfig().level });

export function getIndexName(dateStr = null) {
  if (!dateStr || dateStr.toLowerCase() === 'today') {
    const pad = n => String(n).padStart(2, '0');
    const now = new Date();
    dateStr = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`;
  }
  return `${INDEX_PREFIX}${dateStr}`;
}

function pad(n) {
  return String(n).padStart(2, '0');
}

function formatTimestamp(ms) {
  const d = new Date(ms);
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

function formatDate(ms) {
  const d = new Date(ms);
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}`;
}

function formatDateTime(ms) {
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function generateOutputFilename(opts, timeRange) {
  const ext = opts.format === 'json' ? 'json' : 'md';

  if (opts.hours !== null) {
    return `output/alerts-${formatTimestamp(timeRange.startMs)}-${formatTimestamp(timeRange.endMs)}.${ext}`;
  }

  if (opts.start && opts.end) {
    const startStr = opts.start;
    const endStr = opts.end;

    const startHasTime = startStr.length === 14;
    const endHasTime = endStr.length === 14;

    if (startHasTime && endHasTime) {
      return `output/alerts-${startStr}-${endStr}.${ext}`;
    }

    if (!startHasTime && !endHasTime) {
      return `output/alerts-${startStr}-${endStr}.${ext}`;
    }

    if (opts.date) {
      const datePart = opts.date.length === 8 ? opts.date : formatDate(timeRange.startMs);
      if (!startHasTime) {
        return `output/alerts-${datePart}${startStr}-${datePart}${endStr}.${ext}`;
      }
      return `output/alerts-${startStr}-${endStr}.${ext}`;
    }

    return `output/alerts-${formatTimestamp(timeRange.startMs)}-${formatTimestamp(timeRange.endMs)}.${ext}`;
  }

  if (opts.date) {
    const dateStr = opts.date.toLowerCase() === 'today'
      ? formatDate(Date.now())
      : opts.date;
    return `output/alerts-${dateStr}.${ext}`;
  }

  return `output/alerts-${formatTimestamp(Date.now())}.${ext}`;
}

function parseTimeStr(timeStr, asEndOfDay = false, dateStr = null) {
  const s = timeStr.trim();
  let year, month, day, hour = 0, min = 0, sec = 0;

  if (s.length === 6 && /^\d{6}$/.test(s)) {
    const h = parseInt(s.slice(0, 2), 10);
    const m = parseInt(s.slice(2, 4), 10);
    const secVal = parseInt(s.slice(4, 6), 10);
    if (h > 23 || m > 59 || secVal > 59) {
      throw new Error(`Invalid time values: ${timeStr}`);
    }
    hour = h; min = m; sec = secVal;

    if (dateStr) {
      const d = parseDateStr(dateStr);
      year = d.year; month = d.month; day = d.day;
    } else {
      const now = new Date();
      year = now.getFullYear();
      month = now.getMonth();
      day = now.getDate();
    }
  } else if (s.length === 8 && /^\d{8}$/.test(s)) {
    year = parseInt(s.slice(0, 4), 10);
    month = parseInt(s.slice(4, 6), 10) - 1;
    day = parseInt(s.slice(6, 8), 10);
    if (asEndOfDay) {
      hour = 23; min = 59; sec = 59;
    }
  } else if (s.length === 14 && /^\d{14}$/.test(s)) {
    year = parseInt(s.slice(0, 4), 10);
    month = parseInt(s.slice(4, 6), 10) - 1;
    day = parseInt(s.slice(6, 8), 10);
    hour = parseInt(s.slice(8, 10), 10);
    min = parseInt(s.slice(10, 12), 10);
    sec = parseInt(s.slice(12, 14), 10);
    if (month < 0 || month > 11 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 59) {
      throw new Error(`Invalid datetime values: ${timeStr}`);
    }
  } else {
    throw new Error(`Invalid time format: ${timeStr}`);
  }

  return new Date(year, month, day, hour, min, sec).getTime();
}

export function getDayRange(dateStr) {
  const d = parseDateStr(dateStr);
  const startOfDay = new Date(d.year, d.month, d.day, 0, 0, 0);
  const endOfDay = new Date(d.year, d.month, d.day, 23, 59, 59, 999);

  return {
    startMs: startOfDay.getTime(),
    endMs: endOfDay.getTime()
  };
}

function parseDateStr(dateStr) {
  const s = dateStr.trim();
  let year, month, day;

  if (s.toLowerCase() === 'today') {
    const now = new Date();
    year = now.getFullYear();
    month = now.getMonth();
    day = now.getDate();
  } else if (s.length === 8 && /^\d{8}$/.test(s)) {
    year = parseInt(s.slice(0, 4), 10);
    month = parseInt(s.slice(4, 6), 10) - 1;
    day = parseInt(s.slice(6, 8), 10);
    if (month < 0 || month > 11 || day < 1 || day > 31) {
      throw new Error(`Invalid date values: ${dateStr}`);
    }
  } else {
    throw new Error(`Invalid date format: ${dateStr}`);
  }

  return { year, month, day };
}

function getCurrentHourRange(hours) {
  const now = new Date();
  const endMs = now.getTime();
  const startMs = now.getTime() - (hours * 3600 * 1000);

  return { startMs, endMs };
}

function transformAlert(hit) {
  const src = hit._source || {};
  const fv = src.field_values || {};
  const tsMs = src.timestamp || 0;

  return {
    timestamp: toShanghaiTimeString(tsMs),
    sip: fv.sip || '',
    dip: fv.dip || '',
    alarm_sip: fv.alarm_sip || '',
    sip_addr: fv.sip_addr || '',
    dip_addr: fv.dip_addr || '',
    host_state: fv.host_state || '',
    rule_key: fv.rule_key || '',
    attack_type: fv.attack_type || '',
    hazard_level: fv.hazard_rating || '',
    ioc: fv.ioc || '',
    vuln_name: fv.vuln_name || '',
    dport: fv.dport || '',
    sport: fv.sport || '',
    uri: fv.uri || '',
    payload: fv.payload || ''
  };
}

/**
 * Convert a Map<type, count> to sorted array of {type, count}
 * Matches parse-mcp.js extractTerms() output shape
 */
function toTermsArray(map) {
  return [...map.entries()]
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);
}

/**
 * Compute aggregations from flat hits (parse-mcp.js compatible output)
 * @param {Array} alerts - transformAlert() output array
 * @param {Object} opts - { external: bool, date: string }
 * @returns {Object} { stats, ips, domains, compromised_hosts }
 */
export function computeAggregations(alerts, opts, timeRange = null) {
  const totalAlerts = alerts.length;

  // --- IP aggregation (matches parse-mcp.js ips[] shape) ---
  const ipMap = new Map();
  for (const a of alerts) {
    if (!ipMap.has(a.sip)) {
      ipMap.set(a.sip, { total_alerts: 0, attackTypeMap: new Map(), maxTimestamp: a.timestamp, sip_addr: a.sip_addr });
    }
    const entry = ipMap.get(a.sip);
    entry.total_alerts++;
    if (a.attack_type) {
      entry.attackTypeMap.set(a.attack_type, (entry.attackTypeMap.get(a.attack_type) || 0) + 1);
    }
    if (a.timestamp > entry.maxTimestamp) entry.maxTimestamp = a.timestamp;
    if (!entry.sip_addr && a.sip_addr) entry.sip_addr = a.sip_addr;
  }

  // --- Domain aggregation (matches parse-mcp.js domains[] shape) ---
  const domainMap = new Map();
  for (const a of alerts) {
    if (!a.ioc) continue;
    if (!domainMap.has(a.ioc)) {
      domainMap.set(a.ioc, { total_alerts: 0, attackTypeMap: new Map(), maxTimestamp: a.timestamp });
    }
    const entry = domainMap.get(a.ioc);
    entry.total_alerts++;
    if (a.attack_type) {
      entry.attackTypeMap.set(a.attack_type, (entry.attackTypeMap.get(a.attack_type) || 0) + 1);
    }
    if (a.timestamp > entry.maxTimestamp) entry.maxTimestamp = a.timestamp;
  }

  // --- Compromised hosts aggregation (matches parse-mcp.js compromised_hosts[] shape) ---
  // 按 alarm_sip（受害 IP / 被攻击方）聚合，而非 dip。
  // 研判：基于「攻击成功/失陷」告警特征（judgeVictim）做「按协议特征研判」——
  //   - DNS 协议 + 命中 ipInfra → 判为转发设备误标，从清单剔除该设备（底层告警保留，不忽视）
  //   - 非 DNS + 命中 ipInfra / 其余 → 保留为真实受害主机，附 风险描述 + 研判意见
  // 每条受害主机输出含 risk_desc（复用 ban-ip-table 的 attack-type-mapping）、opinion（研判意见）。
  const compromisedMap = new Map();
  for (const a of alerts) {
    if (!a.host_state || !/攻击成功|失陷/.test(a.host_state)) continue;
    const j = judgeVictim(a); // 基于攻击成功/失陷主机特征研判真实受害方（按协议特征）
    if (!j.isVictim) continue; // DNS 转发设备误标：剔除该设备，不计入受害 IP（底层告警保留）
    const victimKey = j.victimIp;
    if (!compromisedMap.has(victimKey)) {
      compromisedMap.set(victimKey, { count: 0, attackTypeMap: new Map(), states: new Set(), sipAddrs: new Set(), dipAddr: a.dip_addr || '', firstSeen: a.timestamp, lastSeen: a.timestamp, reason: '', opinion: '' });
    }
    const entry = compromisedMap.get(victimKey);
    entry.count++;
    if (a.attack_type) {
      entry.attackTypeMap.set(a.attack_type, (entry.attackTypeMap.get(a.attack_type) || 0) + 1);
    }
    entry.states.add(a.host_state);
    if (a.sip_addr) entry.sipAddrs.add(a.sip_addr);
    if (!entry.dipAddr && a.dip_addr) entry.dipAddr = a.dip_addr;
    if (a.timestamp < entry.firstSeen) entry.firstSeen = a.timestamp;
    if (a.timestamp > entry.lastSeen) entry.lastSeen = a.timestamp;
    if (!entry.opinion) { entry.opinion = j.opinion; entry.reason = j.reason; }
  }

  // --- host_state 统计（内部攻击需要攻击结果分布）---
  const hostStateMap = new Map();
  for (const a of alerts) {
    if (a.host_state) hostStateMap.set(a.host_state, (hostStateMap.get(a.host_state) || 0) + 1);
  }

  // 当 opts.internal 为 true 时，额外计算横向移动聚合
  let lateral = null;
  let lateralAlertsCount = 0;
  if (opts.internal) {
    lateral = computeLateralAggregations(alerts, opts);
    lateralAlertsCount = alerts.filter(a => a.dip_addr === '局域网').length;
  }

  // --- Stats aggregation ---
  const attackTypeMap = new Map();
  const hazardRatingMap = new Map();
  const topTargetMap = new Map();
  const hourlyMap = new Map();
  let lastTimestamp = alerts.length > 0 ? alerts[0].timestamp : null;

  for (const a of alerts) {
    if (a.attack_type) attackTypeMap.set(a.attack_type, (attackTypeMap.get(a.attack_type) || 0) + 1);
    if (a.hazard_level) hazardRatingMap.set(a.hazard_level, (hazardRatingMap.get(a.hazard_level) || 0) + 1);
    if (a.dip) topTargetMap.set(a.dip, (topTargetMap.get(a.dip) || 0) + 1);
    const hour = a.timestamp ? a.timestamp.substring(0, 13) + ':00:00' : null;
    if (hour) hourlyMap.set(hour, (hourlyMap.get(hour) || 0) + 1);
    if (a.timestamp && a.timestamp > lastTimestamp) lastTimestamp = a.timestamp;
  }

  // Fill empty hourly buckets (matches date_histogram agg behavior)
  const rawDate = opts.date || (alerts.length > 0 ? alerts[0].timestamp?.substring(0, 10) : '');
  const datePrefix = rawDate && rawDate.length === 8
    ? `${rawDate.slice(0, 4)}-${rawDate.slice(4, 6)}-${rawDate.slice(6, 8)}`
    : rawDate;
  if (datePrefix) {
    for (let h = 0; h < 24; h++) {
      const hourStr = `${datePrefix} ${String(h).padStart(2, '0')}:00:00`;
      if (!hourlyMap.has(hourStr)) hourlyMap.set(hourStr, 0);
    }
  }

  return {
    stats: {
      total_alerts: totalAlerts,
      unique_external_ips: opts.internal ? 0 : new Set(alerts.map(a => a.sip)).size,
      attack_types: toTermsArray(attackTypeMap),
      hazard_ratings: toTermsArray(hazardRatingMap),
      top_targets: toTermsArray(topTargetMap),
      hourly_distribution: [...hourlyMap.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([hour, count]) => ({ hour, count })),
      external_alerts: opts.external ? totalAlerts : null,
      unique_internal_hosts: new Set(alerts.map(a => a.dip)).size,
      compromised_alerts: compromisedMap.size,
      internal_alerts: opts.internal ? totalAlerts : null,
      lateral_alerts: opts.internal ? lateralAlertsCount : 0,
      unique_internal_sources: opts.internal ? new Set(alerts.map(a => a.sip)).size : 0,
      unique_internal_targets: opts.internal ? new Set(alerts.map(a => a.dip)).size : 0,
      host_states: opts.internal ? toTermsArray(hostStateMap) : undefined,
      last_timestamp: lastTimestamp,
      query_start: (timeRange && timeRange.startMs != null) ? formatDateTime(timeRange.startMs) : undefined,
      query_end: (timeRange && timeRange.endMs != null) ? formatDateTime(timeRange.endMs) : undefined,
      exact_total: totalAlerts,
      count_query_total: totalAlerts,
    },
    ips: [...ipMap.entries()].map(([ip, data]) => ({
      ip,
      total_alerts: data.total_alerts,
      attack_types: toTermsArray(data.attackTypeMap),
      hazard_rating: '',
      max_timestamp: data.maxTimestamp,
      sip_addr: data.sip_addr,
    })),
    domains: [...domainMap.entries()].map(([ioc, data]) => ({
      ioc,
      total_alerts: data.total_alerts,
      attack_types: toTermsArray(data.attackTypeMap),
      max_timestamp: data.maxTimestamp,
    })),
    compromised_hosts: [...compromisedMap.entries()].map(([ip, data]) => ({
      ip,
      count: data.count,
      attack_types: toTermsArray(data.attackTypeMap),
      states: [...data.states],
      sip_addrs: [...data.sipAddrs],
      dip_addr: data.dipAddr,
      first_seen: data.firstSeen,
      last_seen: data.lastSeen,
      risk_desc: riskDescription(toTermsArray(data.attackTypeMap)),
      opinion: data.opinion || '',
      reason: data.reason || '',
    })),
    lateral,
  };
}

/**
 * 计算横向移动聚合（内部攻击中 dip_addr = "局域网" 的子集）
 * @param {Array} alerts - 全部内部攻击（transformAlert 输出）
 * @param {Object} opts - { date: string }
 * @returns {Object} { sources[], targets[], pairs[], hourly_distribution[], host_states[] }
 */
function computeLateralAggregations(alerts, opts) {
  const lateralAlerts = alerts.filter(a => a.dip_addr === '局域网');

  // --- 横向源IP Top N ---
  const sourceMap = new Map();
  for (const a of lateralAlerts) {
    if (!sourceMap.has(a.sip)) {
      sourceMap.set(a.sip, { total_alerts: 0, attackTypeMap: new Map(), maxTimestamp: a.timestamp });
    }
    const entry = sourceMap.get(a.sip);
    entry.total_alerts++;
    if (a.attack_type) entry.attackTypeMap.set(a.attack_type, (entry.attackTypeMap.get(a.attack_type) || 0) + 1);
    if (a.timestamp > entry.maxTimestamp) entry.maxTimestamp = a.timestamp;
  }

  // --- 横向目标IP Top N ---
  const targetMap = new Map();
  for (const a of lateralAlerts) {
    if (!targetMap.has(a.dip)) {
      targetMap.set(a.dip, { total_alerts: 0, attackTypeMap: new Map(), maxTimestamp: a.timestamp });
    }
    const entry = targetMap.get(a.dip);
    entry.total_alerts++;
    if (a.attack_type) entry.attackTypeMap.set(a.attack_type, (entry.attackTypeMap.get(a.attack_type) || 0) + 1);
    if (a.timestamp > entry.maxTimestamp) entry.maxTimestamp = a.timestamp;
  }

  // --- 横向 IP 对（源→目的）---
  const pairMap = new Map();
  for (const a of lateralAlerts) {
    const key = `${a.sip}→${a.dip}`;
    if (!pairMap.has(key)) {
      pairMap.set(key, { source_ip: a.sip, target_ip: a.dip, count: 0, attackTypeMap: new Map(), maxTimestamp: a.timestamp });
    }
    const entry = pairMap.get(key);
    entry.count++;
    if (a.attack_type) entry.attackTypeMap.set(a.attack_type, (entry.attackTypeMap.get(a.attack_type) || 0) + 1);
    if (a.timestamp > entry.maxTimestamp) entry.maxTimestamp = a.timestamp;
  }

  // --- 横向小时分布 ---
  const lateralHourlyMap = new Map();
  for (const a of lateralAlerts) {
    const hour = a.timestamp ? a.timestamp.substring(0, 13) + ':00:00' : null;
    if (hour) lateralHourlyMap.set(hour, (lateralHourlyMap.get(hour) || 0) + 1);
  }
  // 填充空桶
  const rawLatDate = opts.date || (lateralAlerts.length > 0 ? lateralAlerts[0].timestamp?.substring(0, 10) : '');
  const latDatePrefix = rawLatDate && rawLatDate.length === 8
    ? `${rawLatDate.slice(0, 4)}-${rawLatDate.slice(4, 6)}-${rawLatDate.slice(6, 8)}`
    : rawLatDate;
  if (latDatePrefix) {
    for (let h = 0; h < 24; h++) {
      const hourStr = `${latDatePrefix} ${String(h).padStart(2, '0')}:00:00`;
      if (!lateralHourlyMap.has(hourStr)) lateralHourlyMap.set(hourStr, 0);
    }
  }

  // --- 横向攻击结果统计 ---
  const lateralHostStateMap = new Map();
  for (const a of lateralAlerts) {
    if (a.host_state) lateralHostStateMap.set(a.host_state, (lateralHostStateMap.get(a.host_state) || 0) + 1);
  }

  return {
    sources: [...sourceMap.entries()].map(([ip, data]) => ({
      ip, count: data.total_alerts,
      attack_types: toTermsArray(data.attackTypeMap),
      max_timestamp: data.maxTimestamp,
    })).sort((a, b) => b.count - a.count),
    targets: [...targetMap.entries()].map(([ip, data]) => ({
      ip, count: data.total_alerts,
      attack_types: toTermsArray(data.attackTypeMap),
      max_timestamp: data.maxTimestamp,
    })).sort((a, b) => b.count - a.count),
    pairs: [...pairMap.values()].sort((a, b) => b.count - a.count),
    hourly_distribution: [...lateralHourlyMap.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([hour, count]) => ({ hour, count })),
    host_states: toTermsArray(lateralHostStateMap),
  };
}

/**
 * Query alerts from ES with PIT pagination
 * @param {Object} timeRange - {startMs, endMs} or {hours} for backwards compat
 * @param {string|null} indexName - ES index name
 * @param {number} size - Max records to return (unused, kept for API compat)
 * @param {boolean} externalOnly - Only external attacks (exclude LAN)
 * @returns {Promise<Object>} ExtractionResult
 */
export async function queryAlerts(timeRange, indexName = null, ctx = 'all') {
  if (!indexName) indexName = getIndexName();

  const esRequest = createEsRequest();
  const query = buildQuery(ctx, timeRange);

  const alerts = await queryAllWithPIT(esRequest, {
    index: indexName,
    query,
    batchSize: 5000
  });

  const rangeDesc = timeRange.startMs !== undefined
    ? `${toShanghaiTimeString(timeRange.startMs)} ~ ${toShanghaiTimeString(timeRange.endMs)}`
    : `${timeRange.hours} hours`;

  return {
    total: alerts.length,
    query_range: rangeDesc,
    index: indexName,
    query_time: toShanghaiTimeString(Date.now()),
    alerts
  };
}

/**
 * QueryAll - new API using shared pagination module
 * @param {Object} timeRange - {startMs, endMs} or {hours}
 * @param {string|null} indexName - ES index name
 * @param {boolean} externalOnly - Only external attacks (exclude LAN)
 * @returns {Promise<Object>} ExtractionResult
 */
export async function queryAll(timeRange, indexName = null, ctx = 'all') {
  return queryAlerts(timeRange, indexName, ctx);
}

function formatMarkdown(alerts, isExternal = false) {
  const title = isExternal ? '外部攻击' : '告警';
  if (!alerts.length) return `# 今日${title}\n\n暂无数据\n`;

  const lines = [`# 今日${title}\n`];
  const now = new Date();
  lines.push(`**查询时间**: ${now.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}\n`);
  lines.push(`**总计**: ${alerts.length} 条告警\n`);
  lines.push('\n## 告警详情\n\n');
  lines.push('| 时间 | 源IP | 源地理位置 | 目标IP | 目标地理位置 | 攻击类型 | 攻击结果 | 危害等级 |\n');
  lines.push('|------|------|------------|--------|--------------|----------|----------|----------|\n');

  for (const a of alerts) {
    const ts = (a.timestamp || '').slice(0, 19);
    lines.push(`| ${ts} | ${a.sip || ''} | ${a.sip_addr || ''} | ${a.dip || ''} | ${a.dip_addr || ''} | ${a.attack_type || ''} | ${a.host_state || ''} | ${a.hazard_level || ''} |\n`);
  }

  return lines.join('');
}

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    hours: null,
    date: null,
    start: null,
    end: null,
    external: false,
    internal: false,
    compromised: false,
    format: 'md',
    size: 50000,
    output: null,
    parsedOutput: null,
    source: 'production'
  };

  const validShort = { h: true, H: true, d: true, s: true, e: true, x: true, f: true, S: true, o: true, a: true };
  const validLong = {
    hours: true, date: true, start: true, end: true,
    external: true, internal: true, compromised: true, format: true, size: true, output: true,
    'parsed-output': true,
    source: true, help: true
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const long = arg.slice(2);
      if (!validLong[long]) { showHelp(); process.exit(1); }
    } else if (arg.startsWith('-')) {
      const short = arg.slice(1);
      if (!validShort[short]) { showHelp(); process.exit(1); }
    }

    switch (arg) {
      case '-h':
      case '--help':
        showHelp();
        process.exit(0);
        break;
      case '-H':
      case '--hours':
        const hoursVal = args[++i];
        if (!/^\d+$/.test(hoursVal) || parseInt(hoursVal, 10) <= 0) {
          console.error(`Invalid hours value: ${hoursVal} (must be positive integer)`);
          process.exit(1);
        }
        opts.hours = parseInt(hoursVal, 10);
        break;
      case '-d':
      case '--date':
        const dateVal = args[++i];
        if (!/^\d{8}$/.test(dateVal) && dateVal.toLowerCase() !== 'today') {
          console.error(`Invalid date: ${dateVal} (must be YYYYMMDD or 'today')`);
          process.exit(1);
        }
        opts.date = dateVal;
        break;
      case '-s':
      case '--start':
        const startVal = args[++i];
        if (!/^\d{8}$/.test(startVal) && !/^\d{14}$/.test(startVal)) {
          console.error(`Invalid start time: ${startVal} (must be YYYYMMDD or YYYYMMDDHHmmss)`);
          process.exit(1);
        }
        opts.start = startVal;
        break;
      case '-e':
      case '--end':
        const endVal = args[++i];
        if (!/^\d{8}$/.test(endVal) && !/^\d{14}$/.test(endVal)) {
          console.error(`Invalid end time: ${endVal} (must be YYYYMMDD or YYYYMMDDHHmmss)`);
          process.exit(1);
        }
        opts.end = endVal;
        break;
      case '-x':
      case '--external':
        opts.external = true;
        break;
      case '--internal':
        opts.internal = true;
        break;
      case '--compromised':
        opts.compromised = true;
        break;
      case '-f':
      case '--format':
        const fmt = args[++i];
        if (!/^(md|json)$/i.test(fmt)) {
          console.error(`Invalid format: ${fmt} (must be 'md' or 'json')`);
          process.exit(1);
        }
        opts.format = fmt.toLowerCase();
        break;
      case '-S':
      case '--size':
        const sizeVal = args[++i];
        if (!/^\d+$/.test(sizeVal) || parseInt(sizeVal, 10) <= 0) {
          console.error(`Invalid size value: ${sizeVal} (must be positive integer)`);
          process.exit(1);
        }
        opts.size = parseInt(sizeVal, 10);
        break;
      case '-o':
      case '--output':
        opts.output = args[++i];
        break;
      case '--parsed-output':
        opts.parsedOutput = args[++i];
        break;
      case '-a':
      case '--source':
        opts.source = args[++i];
        break;
    }
  }

  const hasHours = opts.hours !== null;
  const hasDate = opts.date !== null;
  const hasStart = opts.start !== null;
  const hasEnd = opts.end !== null;

  if (hasHours && (hasDate || hasStart || hasEnd)) {
    console.error('--hours cannot be combined with any other arguments!');
    showHelp();
    process.exit(1);
  }

  if (!hasHours && !hasDate && !hasStart && !hasEnd) {
    opts.date = 'today';
  }

  return opts;
}

function validateOpts(opts) {
  const hasHours = opts.hours !== null;
  const hasDate = opts.date !== null;
  const hasStart = opts.start !== null;
  const hasEnd = opts.end !== null;

  if (hasStart && hasEnd) {
    const startMs = parseTimeStr(opts.start, false, opts.date);
    const endMs = parseTimeStr(opts.end, true, opts.date);
    if (startMs >= endMs) {
      console.error(`Error: --start (${opts.start}) must be earlier than --end (${opts.end})`);
      process.exit(1);
    }
  }

  if (hasHours && (hasDate || hasStart || hasEnd)) {
    console.error(`Error: -H/--hours cannot be combined with -d/-s/-e`);
    process.exit(1);
  }

  if (hasStart && hasDate) {
    console.error(`Error: -s/--start and -d/--date cannot be used together (use YYYYMMDDHHmmss instead)`);
    process.exit(1);
  }

  if (hasEnd && hasDate) {
    console.error(`Error: -e/--end and -d/--date cannot be used together (use YYYYMMDDHHmmss instead)`);
    process.exit(1);
  }

  const now = Date.now();
  if (hasStart) {
    const startMs = parseTimeStr(opts.start, false, opts.date);
    if (startMs > now) {
      console.error(`Error: --start time (${opts.start}) cannot be in the future`);
      process.exit(1);
    }
  }
  if (hasEnd) {
    const endMs = parseTimeStr(opts.end, true, opts.date);
    if (endMs > now) {
      console.error(`Error: --end time (${opts.end}) cannot be in the future`);
      process.exit(1);
    }
  }

}

/**
 * Map CLI flags to a single query context enum (priority: compromised > internal > external > all).
 * @param {object} opts - Parsed CLI options
 * @returns {('external'|'internal'|'compromised'|'all')}
 */
function resolveCtx(opts) {
  if (opts.compromised) return 'compromised';
  if (opts.internal) return 'internal';
  if (opts.external) return 'external';
  return 'all';
}

function showHelp() {
  console.log(`
Usage: node es-tool/extract.js [options]

Options:
  -H, --hours N     Query last N hours (EXCLUSIVE, cannot combine with others)
  -d, --date DATE   Date (YYYYMMDD or 'today'). Queries full day 00:00-23:59
  -s, --start TIME  Start time (YYYYMMDD or YYYYMMDDHHmmss)
  -e, --end TIME    End time (YYYYMMDD or YYYYMMDDHHmmss)
  -x, --external    Query only external attacks (exclude LAN)
      --internal        Query only internal alerts (sip_addr = 局域网)
      --compromised     Query only compromised/attack-success alerts (host_state = 攻击成功|失陷)
  -f, --format FMT  Output format: md or json (default: md)
  -S, --size N      Max records to return (default: 50000)
  -o, --output FILE Output file path
       --parsed-output FILE  Parsed aggregation output (JSON, parse-mcp.js compatible shape)
  -a, --source NAME Data source name (default: production)
  -h, --help        Show this help message

Examples:
  es-tool/extract.js -d 20260415 -x              # Full day, external only
  es-tool/extract.js -H 1                        # Last 1 hour (EXCLUSIVE)
  es-tool/extract.js -d 20260415 -x --parsed-output output/parsed-20260415.json
  es-tool/extract.js -d 20260415 --internal --parsed-output output/parsed-internal-20260415.json
  es-tool/extract.js -d 20260415 --compromised --parsed-output output/parsed-compromised-20260415.json
  es-tool/extract.js -s 20260415000000 -e 20260415235959
`.trim());
}

function ensureOutputDir() {
  const dir = 'output';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function getDateRange(startStr, endStr) {
  const dates = [];
  const startDate = parseDateStr(startStr.slice(0, 8));
  const endDate = parseDateStr(endStr.slice(0, 8));

  const current = new Date(startDate.year, startDate.month, startDate.day);
  const end = new Date(endDate.year, endDate.month, endDate.day);

  while (current <= end) {
    const pad = n => String(n).padStart(2, '0');
    dates.push(`${current.getFullYear()}${pad(current.getMonth() + 1)}${pad(current.getDate())}`);
    current.setDate(current.getDate() + 1);
  }

  return dates;
}

async function main() {
  const opts = parseArgs();
  validateOpts(opts);

  if (!ES_USER || !ES_PASSWORD) {
    const missing = [];
    if (!ES_USER) missing.push('ES_USERNAME');
    if (!ES_PASSWORD) missing.push('ES_PASSWORD');
    console.error(`Error: Missing required credentials: ${missing.join(', ')}`);
    console.error('Please set these in .env file or as environment variables.');
    process.exit(1);
  }

  let timeRange;
  if (opts.hours !== null) {
    const { startMs, endMs } = getCurrentHourRange(opts.hours);
    timeRange = { startMs, endMs };
  } else if (opts.start && opts.end) {
    timeRange = {
      startMs: parseTimeStr(opts.start, false, opts.date),
      endMs: parseTimeStr(opts.end, true, opts.date)
    };
  } else if (opts.date) {
    const { startMs, endMs } = getDayRange(opts.date);
    timeRange = { startMs, endMs };
  } else {
    const { startMs, endMs } = getDayRange('today');
    timeRange = { startMs, endMs };
  }

  let indexDates;
  if (opts.hours !== null) {
    const pad = n => String(n).padStart(2, '0');
    const end = new Date();
    const start = new Date(end.getTime() - opts.hours * 3600 * 1000);
    indexDates = [];
    const current = new Date(start.getFullYear(), start.getMonth(), start.getDate());
    const endDay = new Date(end.getFullYear(), end.getMonth(), end.getDate());
    while (current <= endDay) {
      indexDates.push(`${current.getFullYear()}${pad(current.getMonth() + 1)}${pad(current.getDate())}`);
      current.setDate(current.getDate() + 1);
    }
  } else if (opts.start && opts.end) {
    indexDates = getDateRange(opts.start, opts.end);
  } else if (opts.date) {
    indexDates = [opts.date];
  } else {
    const pad = n => String(n).padStart(2, '0');
    const now = new Date();
    indexDates = [`${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`];
  }

  try {
    let allAlerts = [];
    const indexNames = indexDates.map(d => getIndexName(d));

    for (const indexName of indexNames) {
      const result = await retry(
        () => queryAlerts(timeRange, indexName, resolveCtx(opts)),
        {
          maxAttempts: 3,
          delayMs: 1000,
          onRetry: (attempt, error) => {
            logger.warn('ES query failed, retrying', { attempt, error: error.message });
          }
        }
      );

      allAlerts = allAlerts.concat(result.alerts || []);
      logger.info('Query completed for index', { total: result.alerts?.length || 0, index: indexName });
    }

    allAlerts.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));

    logger.info('Query completed', { total: allAlerts.length, indices: indexNames.join(', ') });

    // Parsed output: compute aggregations and write JSON sidecar
    if (opts.parsedOutput) {
      const aggregations = computeAggregations(allAlerts, opts, timeRange);
      ensureOutputDir();
      fs.writeFileSync(opts.parsedOutput, JSON.stringify(aggregations, null, 2), 'utf-8');
      console.log(`[parsed-output] 写入聚合数据: ${opts.parsedOutput} (${aggregations.ips.length} IPs, ${aggregations.stats.total_alerts} alerts)`);
    }

    if (opts.format === 'md') {
      let content = formatMarkdown(allAlerts, opts.external);
      let outputPath = opts.output;
      if (!outputPath) {
        outputPath = generateOutputFilename(opts, timeRange);
      }
      ensureOutputDir();
      fs.writeFileSync(outputPath, content, 'utf-8');
      console.log(`已保存到 ${outputPath}, 共 ${allAlerts.length} 条告警`);
    } else {
      let outputPath = opts.output;
      let output = JSON.stringify({ total: allAlerts.length, indices: indexNames, alerts: allAlerts }, null, 2);
      if (!outputPath) {
        outputPath = generateOutputFilename(opts, timeRange);
      }
      ensureOutputDir();
      fs.writeFileSync(outputPath, output, 'utf-8');
      console.log(`已保存到 ${outputPath}, 共 ${allAlerts.length} 条告警`);
    }
  } catch (e) {
    logger.errorWithStack('Failed to query ES after retries', e);
    process.exit(1);
  }
}

// Run if executed directly (guard so importing this module does not trigger a query)
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main().catch((err) => {
    console.error('Error:', err.message);
    process.exit(1);
  });
}

// Exports: computeAggregations (export function above) and getIndexName (export function above)
// are reused by the analysis layer self-run CLI.