#!/usr/bin/env node
/**
 * fuse.js - Step 3d 情报融合
 *
 * 读取 ban-ip-table-{date}.md（取 IP 列表）+ threatbook-enrich-{date}.json（取情报数据），
 * 生成独立的 threat-intel-table-{date}.md（5 列情报表格）。
 *
 * 输出表格列: 风险IP | 是否恶意 | 可信度 | 威胁类型 | 情报标签
 *
 * 可用性判定: ENABLE_THREATBOOK=false / 输入文件缺失 / 查询失败 → 输出"威胁情报查询结果不可用"
 *
 * CLI:
 *   node fuse.js --ban-ip-table <path> --enrich <path> --output <path> [--label-map <path>]
 */
import { fileURLToPath } from 'url';
import { dirname, join, resolve, isAbsolute } from 'path';
import fs from 'fs';
import { isFeatureEnabled } from '../shared/env.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const UNAVAILABLE_MSG = '威胁情报查询结果不可用';

function parseArgs(argv) {
  const args = { help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { args.help = true; continue; }
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const val = argv[i + 1];
      if (val && !val.startsWith('--')) { args[key] = val; i++; }
      else { args[key] = true; }
    }
  }
  return args;
}

function showHelp() {
  console.log(`情报融合 CLI - Step 3d

用法:
  node fuse.js --ban-ip-table <path> --enrich <path> --output <path> [options]

参数:
  --ban-ip-table <path>  ban-ip-table markdown 文件路径（读取 IP 列表，不修改）
  --enrich <path>        threatbook-enrich JSON 文件路径
  --output <path>        输出文件路径（未提供时输出到 stdout）
  --label-map <path>     severity/confidence 中文映射表路径（默认 references/threatbook-label-map.json）
  --help                 显示帮助
`);
}

function loadLabelMap(labelMapPath) {
  const resolved = labelMapPath
    ? (isAbsolute(labelMapPath) ? labelMapPath : resolve(process.cwd(), labelMapPath))
    : join(__dirname, '..', '..', 'references', 'threatbook-label-map.json');
  try {
    return JSON.parse(fs.readFileSync(resolved, 'utf-8'));
  } catch (e) {
    console.error(`[WARN] 映射表加载失败: ${e.message}，使用空映射（回退英文原值）`);
    return { severity: {}, confidence: {} };
  }
}

function mapLabel(value, mapping) {
  if (!value) return '—';
  return mapping[value] || value;
}

/**
 * 从 ban-ip-table md 中解析 IP 列表。
 * 按 markdown 表格结构定位"风险IP"列，不依赖其他列名。
 */
function extractIpsFromBanTable(content) {
  const lines = content.split('\n');
  let headerIdx = -1;
  let ipColIdx = -1;

  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('|') && lines[i].includes('风险IP')) {
      const headers = lines[i].split('|').map(h => h.trim());
      for (let j = 0; j < headers.length; j++) {
        if (headers[j] === '风险IP') { ipColIdx = j; headerIdx = i; break; }
      }
      if (ipColIdx !== -1) break;
    }
  }

  if (headerIdx === -1 || ipColIdx === -1) {
    return [];
  }

  const ips = [];
  for (let i = headerIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.startsWith('|') || line.includes('---')) continue;
    const cells = line.split('|');
    if (ipColIdx < cells.length) {
      const ip = cells[ipColIdx].trim();
      if (ip) ips.push(ip);
    }
  }
  return ips;
}

export function buildIntelCell(intel, labelMap) {
  if (!intel) {
    return { malicious: '—', confidence: '—', threatType: '—', tagsClasses: '—' };
  }
  // Fix C（Bug-04）：区分三种状态，避免把「未查询/查询失败/无情报」兜底伪装成「否（非恶意）」：
  //   (1) 明确查到恶意            → 是
  //   (2) 查到且判定非恶意（有可信度判定） → 否
  //   (3) 未查询 / 查询失败（含 error_code）/ 无情报（无 is_malicious 或空壳）→ 未知
  if (intel.is_malicious === true) {
    return {
      malicious: '是',
      confidence: mapLabel(intel.confidence, labelMap.confidence || {}),
      threatType: intel.threat_type || '—',
      tagsClasses: intel.tags?.length ? intel.tags.join(',') : '—',
    };
  }
  // 非恶意：进一步区分「查到清白（有判定）」与「未知 / 无情报失败」
  // 明确清白的对象带有 is_malicious:false 且有可信度/判定信息（如 confidence 非空）；
  // 失败/无情报对象常缺 is_malicious 字段或仅有 error_code、reasoning 为「无此 IP 数据」。
  const hasVerdict = intel.is_malicious === false
    && intel.confidence !== undefined && intel.confidence !== null && intel.confidence !== ''
    && !intel.error_code
    && intel.reasoning !== 'ThreatBook 无此 IP 数据';
  if (hasVerdict) {
    return {
      malicious: '否',
      confidence: mapLabel(intel.confidence, labelMap.confidence || {}),
      threatType: intel.threat_type || '—',
      tagsClasses: intel.tags?.length ? intel.tags.join(',') : '—',
    };
  }
  // 未查询 / 查询失败 / 无情报 → 未知（不伪装成「否」）
  return {
    malicious: '未知',
    confidence: '未知',
    threatType: '未知',
    tagsClasses: '未知',
  };
}

function buildIntelTable(ips, enrichData, labelMap) {
  const intelByIp = {};
  if (Array.isArray(enrichData.results)) {
    for (const r of enrichData.results) {
      if (r.ip) intelByIp[r.ip] = r;
    }
  }

  const header = '| 风险IP | 是否恶意 | 可信度 | 威胁类型 | 情报标签 |';
  const separator = '| --- | --- | --- | --- | --- |';
  const rows = ips.map(ip => {
    const intel = intelByIp[ip];
    const c = buildIntelCell(intel, labelMap);
    return `| ${ip} | ${c.malicious} | ${c.confidence} | ${c.threatType} | ${c.tagsClasses} |`;
  });

  return [header, separator, ...rows].join('\n') + '\n';
}

function isAvailable(banTableContent, enrichData) {
  if (!banTableContent) return false;
  if (!enrichData) return false;
  if (enrichData.errors?.terminated_early === true) return false;
  if (!Array.isArray(enrichData.results) || enrichData.results.length === 0) return false;
  const allFailed = enrichData.results.every(r => r.error_code);
  if (allFailed) return false;
  return true;
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    showHelp();
    process.exit(0);
  }

  if (!args['ban-ip-table'] || !args.enrich) {
    console.error('[ERROR] --ban-ip-table 和 --enrich 为必填参数');
    process.exit(1);
  }

  const banTablePath = isAbsolute(args['ban-ip-table']) ? args['ban-ip-table'] : resolve(process.cwd(), args['ban-ip-table']);
  const enrichPath = isAbsolute(args.enrich) ? args.enrich : resolve(process.cwd(), args.enrich);

  let banTableContent = null;
  try {
    banTableContent = fs.readFileSync(banTablePath, 'utf-8');
  } catch (e) {
    // ban-ip-table 不存在 → 不可用
  }

  let enrichData = null;
  try {
    enrichData = JSON.parse(fs.readFileSync(enrichPath, 'utf-8'));
  } catch (e) {
    // enrich JSON 不存在或解析失败 → 不可用
  }

  // 检查 ENABLE_THREATBOOK
  if (!isFeatureEnabled('THREATBOOK')) {
    const output = UNAVAILABLE_MSG;
    if (args.output) {
      const outPath = isAbsolute(args.output) ? args.output : resolve(process.cwd(), args.output);
      fs.writeFileSync(outPath, output, 'utf-8');
      console.error(`[INFO] 微步情报功能未启用，输出: ${outPath}`);
    } else {
      process.stdout.write(output);
    }
    process.exit(0);
  }

  // 可用性判定
  if (!isAvailable(banTableContent, enrichData)) {
    const output = UNAVAILABLE_MSG;
    if (args.output) {
      const outPath = isAbsolute(args.output) ? args.output : resolve(process.cwd(), args.output);
      fs.writeFileSync(outPath, output, 'utf-8');
      console.error(`[INFO] 威胁情报查询结果不可用，输出: ${outPath}`);
    } else {
      process.stdout.write(output);
    }
    process.exit(0);
  }

  // 提取 IP 列表
  const ips = extractIpsFromBanTable(banTableContent);
  if (ips.length === 0) {
    const output = UNAVAILABLE_MSG;
    if (args.output) {
      const outPath = isAbsolute(args.output) ? args.output : resolve(process.cwd(), args.output);
      fs.writeFileSync(outPath, output, 'utf-8');
      console.error(`[INFO] 未从 ban-ip-table 提取到 IP，输出: ${outPath}`);
    } else {
      process.stdout.write(output);
    }
    process.exit(0);
  }

  const labelMap = loadLabelMap(args['label-map']);
  const tableContent = buildIntelTable(ips, enrichData, labelMap);

  if (args.output) {
    const outPath = isAbsolute(args.output) ? args.output : resolve(process.cwd(), args.output);
    fs.writeFileSync(outPath, tableContent, 'utf-8');
    console.error(`[INFO] 融合完成: ${ips.length} 行，写入 ${outPath}`);
  } else {
    process.stdout.write(tableContent);
  }
  process.exit(0);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main();
}
