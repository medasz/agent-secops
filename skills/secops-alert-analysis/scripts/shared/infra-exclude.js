/**
 * infra-exclude.js - 内部基础设施失陷研判模块（按特征研判，非白名单忽视）
 *
 * 与 whitelist.js（判定 sip 是否外部）独立。本模块用于「失陷主机清单」基于
 * 「攻击成功/失陷」告警特征研判真实受害方（alarm_sip），并输出：
 *   - 风险描述（复用 ban-ip-table 的 attack-type-mapping.json 映射，与封禁建议表口径一致）
 *   - 研判意见（opinion）
 *
 * 研判原则（依据 2026-07-18/21 真实 ES 数据定性）：
 *   1. 仅处理 host_state ∈ {攻击成功, 失陷} 的告警，受害方 = alarm_sip（缺失兜底 dip）。
 *   2. 【DNS 协议 + 命中基础设施清单(ipInfra.md)】→ 判定为「DNS 转发设备出向查询被 IDS 误标」，
 *      从失陷主机清单剔除该转发设备（底层告警/ban-domain 数据保留，不忽视）。
 *      说明：单条告警中 sip==alarm_sip==基础设施自身、dip 为正常 DNS，并无独立"真实发起查询主机 IP"，
 *            IDS 已把转发设备自身写成 alarm_sip，单条层面无法还原发起方，故仅剔除转发设备、不虚构受害 IP。
 *   3. 【非 DNS 协议 + 命中基础设施清单】→ 不能盲目剔除（可能是真实被打基础设施），
 *      保留为受害主机，附风险描述 + 研判意见，提示人工复核。
 *   4. 其余（alarm_sip 非基础设施，或 DNS 但非基础设施）→ 真实受害主机，附风险描述 + 研判意见。
 *
 * 注意：切勿复用 ipWhite.md（含整段私网）做此排除，否则误伤真实内网失陷主机。
 * 排除清单见 references/ipInfra.md（已由用户手动从 infra-exclude.md 更名）。
 */
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { loadWhitelist, ip2long, matchesEntry } from './whitelist.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const INFRA_FILE = path.resolve(__dirname, '..', '..', 'references', 'ipInfra.md');
const ATM_FILE = path.resolve(__dirname, '..', '..', 'references', 'attack-type-mapping.json');

let _entries = null;
function loadInfra() {
  if (_entries === null) {
    _entries = loadWhitelist(INFRA_FILE);
  }
  return _entries;
}

let _atm = null;
function loadAtm() {
  if (_atm === null) {
    try {
      _atm = JSON.parse(fs.readFileSync(ATM_FILE, 'utf-8'));
    } catch {
      _atm = {};
    }
  }
  return _atm;
}

/**
 * 判断某 IP 是否命中内部基础设施清单（ipInfra.md）
 * @param {string} ip
 * @returns {boolean}
 */
export function isInfrastructure(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const ipLong = ip2long(ip);
  if (ipLong === -1) return false;
  for (const entry of loadInfra()) {
    if (matchesEntry(ipLong, entry)) return true;
  }
  return false;
}

/**
 * 风险描述：攻击类型 → 人类可读名（复用 ban-ip-table 的 attack-type-mapping.json，与封禁建议表口径一致）
 * 形如 "{类型}({次数}), {类型}({次数})"
 * @param {Array<{type:string,count:number}>} attackTypes
 * @param {number} topN
 * @returns {string}
 */
export function riskDescription(attackTypes, topN = 3) {
  if (!attackTypes || attackTypes.length === 0) return '未知攻击';
  const atm = loadAtm();
  return attackTypes.slice(0, topN)
    .map(a => `${atm[a.type] || a.type}(${a.count})`)
    .join(', ');
}

/**
 * 基于「攻击成功/失陷」告警特征研判真实受害方（alarm_sip）。
 *
 * 与"按 ipInfra 一刀切当白名单忽视"不同：本函数只在「协议=DNS 且 alarm_sip 命中基础设施」时
 * 判定为转发设备误标（isVictim=false，从清单剔除该设备，但底层告警保留）；其余情况均保留，
 * 并由调用方附上风险描述与研判意见，绝不忽视告警信息。
 *
 * @param {object} alert - 需含 { alarm_sip?, dip?, proto?, host_state, attack_type?, ioc?, attack_types? }
 * @returns {{isVictim:boolean, victimIp:?string, reason:string, opinion:string, riskDesc:string}}
 */
export function judgeVictim(alert) {
  const hostState = (alert && alert.host_state) || '';
  const victimIp = (alert && (alert.alarm_sip || alert.dip)) || '';
  const proto = ((alert && alert.proto) || '').toLowerCase();

  if (!/攻击成功|失陷/.test(hostState) || !victimIp) {
    return { isVictim: false, victimIp: null, reason: '非「攻击成功/失陷」告警或缺少受害 IP', opinion: '', riskDesc: '' };
  }

  const infra = isInfrastructure(victimIp);
  const rd = riskDescription(alert.attack_types || (alert.attack_type ? [{ type: alert.attack_type, count: 1 }] : []));

  // ① DNS 协议：仅命中基础设施清单才判为转发设备误标（剔除转发设备，保留底层告警）
  if (proto === 'dns') {
    if (infra) {
      return {
        isVictim: false,
        victimIp: null,
        reason: 'DNS转发设备误标',
        riskDesc: rd,
        opinion: `协议=DNS 且 alarm_sip(${victimIp}) 命中基础设施清单：系 DNS 服务器/网关出向查询被 IDS 误标为"${hostState}"，非真实失陷主机，已从失陷主机清单剔除该转发设备；底层告警与封禁建议数据保留，建议推 IDS 同事修正探测配置。`,
      };
    }
    return {
      isVictim: true,
      victimIp,
      reason: 'DNS 真实失陷',
      riskDesc: rd,
      opinion: `协议=DNS，alarm_sip(${victimIp}) 非基础设施：内网主机经 DNS 外联恶意域名(${alert.ioc || 'N/A'})被标"${hostState}"，判定为真实失陷主机。`,
    };
  }

  // ② 非 DNS 协议
  if (infra) {
    // 存在基础设施自身被真实攻击的可能，不可盲目剔除 → 保留并附风险描述 + 研判意见，提示人工复核
    return {
      isVictim: true,
      victimIp,
      reason: '基础设施-非DNS攻击(需复核)',
      riskDesc: rd,
      opinion: `协议=${proto} 非 DNS，alarm_sip(${victimIp}) 命中基础设施清单：存在基础设施自身被真实攻击的可能，已从"DNS转发误标"剔除逻辑中排除，保留为受害主机并附风险描述，需人工复核是否真失陷。`,
    };
  }

  // ③ 普通内网主机真实失陷/攻击成功
  return {
    isVictim: true,
    victimIp,
    reason: '真实失陷/攻击成功主机',
    riskDesc: rd,
    opinion: `协议=${proto}，alarm_sip(${victimIp}) 非基础设施，攻击类型"${alert.attack_type || 'N/A'}"，判定为真实${hostState}主机。`,
  };
}
