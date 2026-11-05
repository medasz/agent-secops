#!/usr/bin/env node
/**
 * gen-xff-judgment.js - ids-fastReport 离线 XFF 研判（零 ES）
 *
 * 背景：父 skill 的 `judgment-xff` 子技能是 ES 直连脚本，无法用于本子技能的
 * 「零 ES / 离线 Excel」模式。本脚本从**事实基座**（parse-ids-excel.py 的
 * classification.xff_clients，数据来自 Excel 的 XFF代理 列）直接生成 judgment-xff
 * 同构的离线产物，供 render-skeleton 注入：
 *
 *   1) xff-ban-ip-table-{date}.md         → 4 列 XFF 封禁建议表（供 §5.1 --xff-ban-ip-table）
 *   2) xff-ban-ip-candidates-{date}.json  → 微步候选（供 external.js --batch 查询，格式同父）
 *   3) xff-victim-table-{date}.md         → 外部客户端 × 受害主机映射（供 §5.1 研判）
 *
 * 输出口径与父 skill `judgment-xff/gen-md-report-xff.js` **完全一致**：
 *   - 阈值：XFF_MIN_ATTACKS=10（严格大于，alerts > 10 才入选），与 §2.1 ban-ip-table 对齐。
 *   - 时间戳：yyyy/M/d H:mm:ss（上海，年/月/日/时无前导零，分/秒有前导零）。
 *   - 风险描述：{攻击类型}({次数}) 按次数降序取 top3，逗号连接（经 attack-type-mapping 映射）。
 *   - 地理：取自表格 `攻击IP地理信息` 字段（XFF 真实客户端与攻击IP一致时即为该值；缺失回退 `-`）。
 *   - 仅剔除 RFC1918 私网客户端（内网 XFF 源不封禁，但保留在 victim 表供研判）。
 *
 * 使用:
 *   node gen-xff-judgment.js --fact output/ids-fact-{date}.json --date {date}
 *       [--min-attacks N]
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function help() {
  console.log(`用法:
  node gen-xff-judgment.js --fact <fact.json> --date <YYYYMMDD> [--min-attacks N]

选项:
  --fact <path>        事实基座（parse-ids-excel.py 产物，必填）
  --date <YYYYMMDD>    报告日期（用于产物文件名，默认取 fact.meta.date 或今天）
  --min-attacks N      最小告警次数筛选（默认 10，严格大于，与父 judgment-xff 的 XFF_MIN_ATTACKS=10 一致）
  --help`);
}

function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--fact') a.fact = argv[++i];
    else if (argv[i] === '--date') a.date = argv[++i];
    else if (argv[i] === '--min-attacks') a.minAttacks = Number(argv[++i]);
    else if (argv[i] === '--help') a.help = true;
  }
  return a;
}

function isPrivate(ip) {
  if (typeof ip !== 'string') return true;
  const m = ip.split('.').map(Number);
  if (m.length !== 4 || m.some((n) => Number.isNaN(n))) return true;
  const [a, b] = m;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (/^局域网$/i.test(ip)) return true;
  return false;
}

function joinThreat(topThreat, max = 3) {
  if (!Array.isArray(topThreat)) return '未知攻击';
  return topThreat
    .slice(0, max)
    .map((t) => (Array.isArray(t) ? `${t[0]}(${t[1]})` : String(t)))
    .join(', ');
}

// 事实基座时间（本地上海字符串 "YYYY-MM-DD HH:MM:SS"）→ 父 judgment-xff 同款 "yyyy/M/d H:mm:ss"
// （年/月/日/时无前导零，分/秒有前导零），与 ban-ip-table.js 规则一致。
function formatAlertTimestamp(s) {
  if (!s) return '未知';
  const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{1,2}):(\d{2}):(\d{2})/.exec(String(s));
  if (!m) return s;
  return `${Number(m[1])}/${Number(m[2])}/${Number(m[3])} ${Number(m[4])}:${m[5]}:${m[6]}`;
}

function mdTable(header, rows) {
  const out = ['| ' + header.join(' | ') + ' |'];
  out.push('| ' + header.map(() => '---').join(' | ') + ' |');
  for (const r of rows) out.push('| ' + r.join(' | ') + ' |');
  return out.join('\n') + '\n';
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
  const date = args.date || (fact.meta && fact.meta.date) || new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const minAttacks = args.minAttacks != null ? args.minAttacks : 10;

  const xffClients = (fact.classification && fact.classification.xff_clients) || [];
  const xffVictims = (fact.classification && fact.classification.xff_victims) || [];

  // 1) 过滤公网客户端 + 阈值（严格大于，与父 judgment-xff 的 XFF_MIN_ATTACKS=10 对齐）
  const publicClients = xffClients
    .filter((c) => !isPrivate(c.ip))
    .filter((c) => (c.count || 0) > minAttacks)
    .sort((a, b) => (b.count || 0) - (a.count || 0));

  // 2) 4 列封禁建议表（攻防语义同父：风险IP=真实客户端IP，时间戳=该 client 最近发生时间，风险描述=攻击类型汇总，地理=取自表格字段，缺失回退 -）
  const banRows = [];
  for (const c of publicClients) {
    const ts = formatAlertTimestamp(c.last || c.first);
    const desc = joinThreat(c.top_threat, 3);
    const geo = c.geo && !/^(未知|--|-)$/.test(String(c.geo)) ? c.geo : '-';
    banRows.push([ts, c.ip, desc, geo]);
  }

  // 3) 受害映射表
  const victimRows = [];
  for (const v of xffVictims) {
    victimRows.push([`\`${v.ip}\``, String(v.count || 0), (v.clients || []).join(', ') || '—']);
  }

  // 4) 微步候选（对象形式，external.js 会归一为 IP 串）
  const candidates = publicClients.map((c) => ({ ip: c.ip, alerts: c.count || 0, victims: c.victims || [] }));

  const banMd = mdTable(['告警日期时间戳', '风险IP', '风险描述', '风险IP的地理位置'], banRows);
  const victimMd = mdTable(['受害IP', '次数', '外部客户端IP'], victimRows);

  // 写文件（路径相对 CWD）
  const base = path.resolve(process.cwd(), 'output');
  const banOut = path.join(base, `xff-ban-ip-table-${date}.md`);
  const candOut = path.join(base, `xff-ban-ip-candidates-${date}.json`);
  const victimOut = path.join(base, `xff-victim-table-${date}.md`);

  fs.writeFileSync(banOut, banMd, 'utf8');
  fs.writeFileSync(victimOut, victimMd, 'utf8');
  fs.writeFileSync(
    candOut,
    JSON.stringify(
      { candidates, total: candidates.length, date, whitelist_secondary_filtered_count: 0 },
      null,
      2
    ),
    'utf8'
  );

  console.log(`[OK] XFF 封禁表: ${banOut} (${banRows.length} 行)`);
  console.log(`[OK] XFF 受害映射: ${victimOut} (${victimRows.length} 行)`);
  console.log(`[OK] XFF 微步候选: ${candOut} (${candidates.length} 个公网客户端)`);
  console.log(JSON.stringify({ public_clients: candidates.length, total_xff_clients: xffClients.length, min_attacks: minAttacks }));
}

main();
