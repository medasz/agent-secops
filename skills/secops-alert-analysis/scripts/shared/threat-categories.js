/**
 * threat-categories.js - 专项研判攻击类别映射 + 派生纯函数
 *
 * 攻击类型 → 专项类别配置见 threat-categories.json（唯一事实来源）。
 * deriveThreatTopics 为纯函数（无 ES 依赖），供 gen-md-report.js 在编排阶段
 * 聚合 §5 专项研判（弱口令 / 远控C2 / 挖矿勒索）相关数据。
 *
 * 本模块同时定义了：
 *   - CATEGORY_ACTION：每个专项类别对应的「处置建议」文案（供 §5 表格"处置建议"列使用）
 *   - cleanIoc：剥离 ioc 标签前导数字编号（如 `24669-发现sip协议爆破行为` → `发现sip协议爆破行为`）
 *   - deriveThreatTopics：在既有 {attackTypes,ipCount,hostCount,domains} 基础上，为每个专项类别
 *     额外派生 `details` 数组（受害主机/横向链路 + 处置建议），供渲染层直接落表。
 */
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const FALLBACK = {
  weak_password: ['弱口令', '暴力猜解', '暴力猜测', '非授权访问/权限绕过'],
  c2_rat: ['远控木马', '僵尸网络', '后门程序'],
  mining_ransom: ['挖矿', '挖矿病毒', '感染型病毒', '勒索'],
};

let _categories = null;

/**
 * 加载攻击类型 → 专项类别映射（优先读 threat-categories.json，失败回退内联）。
 * @returns {{weak_password:string[], c2_rat:string[], mining_ransom:string[]}}
 */
export function loadThreatCategories() {
  if (_categories === null) {
    try {
      _categories = JSON.parse(fs.readFileSync(join(__dirname, 'threat-categories.json'), 'utf-8'));
    } catch {
      _categories = FALLBACK;
    }
  }
  return _categories;
}

/** 攻击类型 → 专项类别映射（运行时导出） */
export const THREAT_CATEGORIES = loadThreatCategories();

/**
 * 各专项类别的处置建议文案，供渲染层「处置建议」列使用。
 * @type {{weak_password:string, c2_rat:string, mining_ransom:string}}
 */
export const CATEGORY_ACTION = {
  weak_password: '弱口令整改：修改相关账户口令、强制口令复杂度策略、排查弱口令暴露面与爆破来源',
  c2_rat: '病毒查杀+隔离：断网取证、查杀远控木马/后门、封堵 C2 外联域名',
  mining_ransom: '矿池阻断+查杀：阻断矿池/勒索域名、查杀挖矿/勒索进程、排查持久化',
};

/**
 * 剥离 ioc 标签前导数字编号。
 * 支持两种真实数据形态：
 *   - 情报库 ID 前缀：`268569560-发现后门程序 Mozi...` → `发现后门程序 Mozi...`
 *   - 序号前缀+空格：`1. evil-c2.example.com` → `evil-c2.example.com`
 * 真实数据域名/行为标签常带前导编号（情报库 ID / 序号），用于展示前需清洗。
 * @param {string|number} ioc
 * @returns {string}
 */
export function cleanIoc(ioc) {
  return String(ioc == null ? '' : ioc).replace(/^\d+[.\-]\s*/, '');
}

/**
 * 判断某攻击类型是否属于给定类别集合。
 * @param {string} type
 * @param {string[]} categoryTypes
 * @returns {boolean}
 */
function matchesCategory(type, categoryTypes) {
  if (!type) return false;
  return categoryTypes.includes(type);
}

/**
 * 从失陷/攻击成功主机中筛选命中某类别的主机，派生处置明细（按攻击次数降序）。
 * @param {string[]} categoryTypes
 * @param {string} action 处置建议文案（来自 CATEGORY_ACTION）
 * @param {Array<{ip:string,count?:number,attack_types?:Array<{type:string,count:number}>,last_seen?:string,first_seen?:string}>} compromised
 * @returns {Array<{victimIp:string,lastTime:string,attackTypes:Array<{type:string,count:number}>,action:string}>}
 */
function buildHostDetails(categoryTypes, action, compromised = []) {
  return (compromised || [])
    .filter((h) => (h.attack_types || []).some((t) => matchesCategory(t.type, categoryTypes)))
    .sort((a, b) => (b.count || 0) - (a.count || 0))
    .map((h) => ({
      victimIp: h.ip,
      lastTime: h.last_seen || h.first_seen || 'N/A',
      attackTypes: (h.attack_types || []).filter((t) => matchesCategory(t.type, categoryTypes)),
      action,
    }));
}

/**
 * 从攻击类型 / 域名 / 失陷主机 按类别聚合（纯函数，无 ES）。
 * @param {object} input
 * @param {Array<{type:string,count:number}>} [input.attackTypes] - 全局攻击类型分布
 * @param {Array<{ip:string, attack_types?:Array}>} [input.ips] - 外部攻击 IP 列表
 * @param {Array<{ioc:string, attack_types?:Array}>} [input.domains] - 攻击行为标签列表（ES 抽取层暂以 `domains` 命名字段，实为攻击特征标签，非域名）
 * @param {Array<{ip:string,count?:number,attack_types?:Array,last_seen?:string,first_seen?:string}>} [input.compromised] - 失陷主机列表
 * @returns {{
 *   weak_password:{attackTypes:Array,ipCount:number,domains:string[],hostCount:number,details:Array},
 *   c2_rat:{attackTypes:Array,ipCount:number,domains:string[],hostCount:number,details:Array},
 *   mining_ransom:{attackTypes:Array,ipCount:number,domains:string[],hostCount:number,details:Array}
 * }}
 */
export function deriveThreatTopics({
  attackTypes = [],
  ips = [],
  domains = [],
  compromised = [],
} = {}) {
  const deriveCategory = (categoryKey) => {
    const categoryTypes = THREAT_CATEGORIES[categoryKey] || [];
    const action = CATEGORY_ACTION[categoryKey];
    const catAttackTypes = (attackTypes || []).filter((a) => matchesCategory(a.type, categoryTypes));
    const ipCount = (ips || [])
      .filter((ip) => (ip.attack_types || []).some((t) => matchesCategory(t.type, categoryTypes))).length;
    const hostCount = (compromised || [])
      .filter((h) => (h.attack_types || []).some((t) => matchesCategory(t.type, categoryTypes))).length;
    const catDomains = (domains || [])
      .filter((d) => (d.attack_types || []).some((t) => matchesCategory(t.type, categoryTypes)))
      .map((d) => cleanIoc(d.ioc));
    const details = buildHostDetails(categoryTypes, action, compromised);

    // Fix A（Bug-02，跨天窗口场景）：让「相关攻击类型」计数与受害明细表、模板 §5.2 标题口径一致。
    // 某些类别（如 weak_password 的「非授权访问/权限绕过」）主要出现在受害主机 attack_types 中，
    // 却未纳入全局 attackTypes 分布，导致「相关攻击类型（N 类）」少于受害表与标题。
    // 此处把受害明细中命中本类、但未出现在全局 attackTypes 的类型（按受害主机计数累加）补入，
    // 不改变既有全局计数，仅补全缺失类别，消除计数矛盾。
    const atTypeSet = new Set(catAttackTypes.map((a) => a.type));
    const augCountByType = new Map();
    for (const d of details) {
      for (const at of d.attackTypes || []) {
        if (matchesCategory(at.type, categoryTypes) && !atTypeSet.has(at.type)) {
          augCountByType.set(at.type, (augCountByType.get(at.type) || 0) + (at.count || 0));
          atTypeSet.add(at.type);
        }
      }
    }
    for (const [type, count] of augCountByType) {
      catAttackTypes.push({ type, count });
    }

    return { attackTypes: catAttackTypes, ipCount, domains: catDomains, hostCount, details };
  };

  return {
    weak_password: deriveCategory('weak_password'),
    c2_rat: deriveCategory('c2_rat'),
    mining_ransom: deriveCategory('mining_ransom'),
  };
}
