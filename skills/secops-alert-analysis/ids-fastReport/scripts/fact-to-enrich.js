#!/usr/bin/env node
/**
 * fact-to-enrich.js - IDS快报：事实基座 → 复用父 skill 模块的适配器
 *
 * 本脚本只做「数据形状转换」，不做白名单剔除/情报查询（那些由父 skill 既有模块负责）：
 *
 *   1) 白名单剔除 + 封禁表 + 微步候选  →  复用 reporting/ban-ip-table.js
 *   2) 微步威胁情报查询              →  复用 threat-intel/external.js --batch
 *   3) 情报表融合                    →  复用 threat-intel/fuse.js
 *   4) 失陷主机基础设施角色修正       →  复用 shared/infra-exclude.js（isInfrastructure）
 *
 * 输出（供上述父 skill 模块消费）：
 *   enrich-ip-{date}.json        → {ips:[{ip,total_alerts,attack_types,hazard_rating,max_timestamp,sip_addr}]}
 *                                  （喂给 ban-ip-table.js --input）
 *   enrich-domain-{date}.json    → {domains:[{ioc,total_alerts,attack_types,max_timestamp}]}
 *                                  （喂给 ban-domain-table.js --input）
 *   ids-infra-report-{date}.md   → 命中 ipInfra.md 的失陷主机角色修正清单
 *   merged-mapping-{date}.json   → 父 attack-type-mapping.json 与 skill-local lv2 兜底映射的合并
 *                                  喂给 ban-ip-table.js / ban-domain-table.js 的 --attack-type-mapping，
 *                                  避免父表缺失的 LV2（配置不当/错误等）触发 FR-011 回退噪音
 *
 * 使用:
 *   node fact-to-enrich.js --fact output/ids-fact-{date}.json \
 *       --out-ip output/enrich-ip-{date}.json \
 *       --out-domain output/enrich-domain-{date}.json \
 *       --infra-report output/ids-infra-report-{date}.md \
 *       --out-mapping output/merged-mapping-{date}.json
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { isInfrastructure } from '../../scripts/shared/infra-exclude.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// skill-local LV2 兜底映射。父 `references/attack-type-mapping.json` 已覆盖绝大多数 LV2 短 token；
// 本表仅补齐父表缺失的少量 LV2（配置不当/错误、其他攻击利用、其他拒绝服务、webshell利用、文件写入、网络蠕虫）。
// 适配器不在此表做词形替换，而是将其与父表合并生成 merged-mapping（见 buildMergedMapping），
// 交给父 ban 脚本 --attack-type-mapping 统一映射——从源头消除 FR-011 回退噪音。父表保持只读。
function loadLv2Mapping() {
  const p = path.join(__dirname, 'lv2-attack-type-mapping.json');
  try {
    return JSON.parse(fs.readFileSync(p, 'utf-8'));
  } catch (e) {
    console.warn(`[WARN] LV2 映射加载失败 (${p}): ${e.message}，回退原始名。`);
    return {};
  }
}

// 合并父映射 + skill-local LV2 兜底映射（父表保持只读，合并结果供 ban 脚本消费）。
// 返回 merge 后的映射对象；父表缺失的 LV2 由 skill-local 补齐，父表已有的以父表为准。
function buildMergedMapping() {
  const parentPath = path.join(__dirname, '..', '..', 'references', 'attack-type-mapping.json');
  let parent = {};
  try {
    parent = JSON.parse(fs.readFileSync(parentPath, 'utf-8'));
  } catch (e) {
    console.warn(`[WARN] 父 attack-type-mapping 加载失败 (${parentPath}): ${e.message}，仅用 skill-local 映射。`);
  }
  return { ...parent, ...loadLv2Mapping() };
}

// LV2 短 token → 直接透传原始 token（喂父脚本，由父/合并映射统一映射为可读名）。
// 不再预替换：预替换会让父脚本在父表（key 为原始短 token）上二次查找已替换名而失配 → FR-011 回退噪音。
function toFeedType(type) {
  return type && String(type).trim() ? String(type).trim() : null;
}

function help() {
  console.log(`用法:
  node fact-to-enrich.js --fact <fact.json> [options]

选项:
  --fact <path>          事实基座（parse-ids-excel.py 产物，必填）
  --out-ip <path>        IP enrich JSON（喂 ban-ip-table.js --input）
  --out-domain <path>    域名 enrich JSON（喂 ban-domain-table.js --input）
  --infra-report <path>  基础设施/角色修正清单 markdown
  --out-mapping <path>   合并攻击类型映射 JSON（喂 ban 脚本 --attack-type-mapping）
  --help`);
}

function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--fact') a.fact = argv[++i];
    else if (argv[i] === '--out-ip') a.outIp = argv[++i];
    else if (argv[i] === '--out-domain') a.outDomain = argv[++i];
    else if (argv[i] === '--infra-report') a.infraReport = argv[++i];
    else if (argv[i] === '--out-mapping') a.outMapping = argv[++i];
    else if (argv[i] === '--help') a.help = true;
  }
  return a;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) return help();
  if (!args.fact) {
    console.error('[ERROR] 缺少 --fact');
    return (process.exitCode = 2);
  }
  const factPath = path.resolve(process.cwd(), args.fact);
  if (!fs.existsSync(factPath)) {
    console.error(`[ERROR] 事实基座不存在: ${factPath}`);
    return (process.exitCode = 2);
  }
  const fact = JSON.parse(fs.readFileSync(factPath, 'utf8'));

  // ---- 1) IP enrich 形状（喂 ban-ip-table.js --input）----
  const ext = (fact.classification && fact.classification.external) || [];
  const ips = ext.map((e) => {
    // e: {ip, geo, count, records, top_threat:[[threat,cnt]..], top_lv2:[[lv2,cnt]..], levels, victim_count, first, last}
    // 攻击类型改用「二级告警类型」(top_lv2) —— 干净短 token，透传原始短 token；
    // 映射统一交给 ban 脚本（--attack-type-mapping 传入合并映射），从源头消除 FR-011 回退噪音
    // （CVE 细节保留在报告/URI，不进 risk_description）。
    const lv2Types = (Array.isArray(e.top_lv2) ? e.top_lv2 : [])
      .map((t) => (Array.isArray(t) ? { type: toFeedType(t[0]), count: t[1] } : { type: toFeedType(String(t)), count: 1 }))
      .filter((t) => t && t.type);
    return {
      ip: e.ip,
      total_alerts: e.count || e.records || 0,
      attack_types: lv2Types,
      hazard_rating: null,
      max_timestamp: e.last || null,
      sip_addr: e.geo || '',
    };
  });
  if (args.outIp) {
    fs.writeFileSync(args.outIp, JSON.stringify({ ips }, null, 2), 'utf8');
    console.log(`[OK] IP enrich: ${args.outIp} (${ips.length})`);
  }

  // ---- 2) 域名 enrich 形状（喂 ban-domain-table.js --input）----
  // 事实基座 ioc.domains 现为 DNS-only(proto=dns) 域名，每项含 attack_types(LV2) + max_timestamp
  const doms = (fact.ioc && fact.ioc.domains) || [];
  const domains = doms
    .map((d) => {
      const name = typeof d === 'string' ? d : d && d.domain;
      const cnt = typeof d === 'string' ? 1 : (d && d.count) || 1;
      if (typeof name !== 'string' || !name.includes('.')) return null;
      const attackTypes = Array.isArray(d && d.attack_types)
        ? d.attack_types
            .map((t) => ({ type: toFeedType(t.type || t), count: t.count || 1 }))
            .filter((t) => t && t.type)
        : [];
      return { ioc: name, total_alerts: cnt, attack_types: attackTypes, max_timestamp: (d && d.max_timestamp) || null };
    })
    .filter(Boolean);
  if (args.outDomain) {
    fs.writeFileSync(args.outDomain, JSON.stringify({ domains }, null, 2), 'utf8');
    console.log(`[OK] Domain enrich: ${args.outDomain} (${domains.length})`);
  }

  // ---- 3) 基础设施/角色修正清单（复用 shared/infra-exclude.js）----
  if (args.infraReport) {
    const comp = fact.compromised || [];
    const lines = [];
    lines.push('## 基础设施/角色修正清单（ipInfra.md 命中）');
    lines.push('');
    lines.push('> 以下失陷/攻击成功主机命中 `references/ipInfra.md`（交换机/网关/DNS 设备）。');
    lines.push('> 命中仅代表其作为五元组源/目的出现，多为**流经转发的连接被 IDS 误标**，需结合告警协议与资产信息确认是否为失陷本体。');
    lines.push('');
    const infraHits = comp.filter((c) => isInfrastructure(c.ip));
    if (infraHits.length === 0) {
      lines.push('（无命中）');
    } else {
      lines.push('| 受害IP | 攻击结果 | 威胁级别 | 主要威胁 | 来源 | 研判意见 |');
      lines.push('| --- | --- | --- | --- | --- | --- |');
      for (const c of infraHits) {
        const result = typeof c.result === 'object' ? Object.entries(c.result).map(([k, v]) => `${k}${v}`).join(';') : c.result;
        const level = typeof c.level === 'object' ? Object.entries(c.level).map(([k, v]) => `${k}${v}`).join(';') : c.level;
        const counters = c.threat || c.top_threat || {};
        const threat = Array.isArray(counters)
          ? counters.map((t) => (Array.isArray(t) ? `${t[0]}×${t[1]}` : t)).join(';')
          : (typeof counters === 'object'
              ? Object.entries(counters).map(([k, v]) => `${k}×${v}`).slice(0, 4).join(';')
              : String(counters));
        const src = Array.isArray(c.sources) ? c.sources.slice(0, 8).join(',') : '—';
        lines.push(`| ${c.ip} | ${result} | ${level} | ${threat} | ${src} | 命中 ipInfra.md（交换机/网关/DNS 设备）：仅代表流经转发连接，需结合告警协议与资产信息确认是否为失陷本体，勿直接视为业务主机被控。 |`);
      }
    }
    fs.writeFileSync(args.infraReport, lines.join('\n') + '\n', 'utf8');
    console.log(`[OK] 基础设施清单: ${args.infraReport} (命中 ${infraHits.length})`);
  }

  // ---- 4) 合并攻击类型映射（喂 ban 脚本 --attack-type-mapping，消除 FR-011 回退）----
  if (args.outMapping) {
    const merged = buildMergedMapping();
    fs.writeFileSync(args.outMapping, JSON.stringify(merged, null, 2), 'utf8');
    console.log(`[OK] 合并映射: ${args.outMapping} (${Object.keys(merged).length} 项)`);
  }
}

main();
