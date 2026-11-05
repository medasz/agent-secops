#!/usr/bin/env node
/**
 * selfcheck.js - 步骤0 本地自检批量探针
 *
 * 一次调用覆盖 11 项零 MCP 依赖自检项：
 *   A1 PF-ES-TCP         ES_HOST:ES_PORT TCP 连通（强制）
 *   B1 PF-DATE-VALID     日期合法性 + 非未来日期
 *   B3 PF-WHITELIST      白名单可解析
 *   B4 PF-ENV-CONFIG     scripts/.env 凭据存在性（不调 esQuery，只验凭据齐全）
 *   C1 PF-ENRICH-API     富化 API 密钥存在性检查（THREATBOOK_API_KEY 等）
 *   C2 PF-PORTAL-TOKEN   Portal Token 密钥 + Token 网关 TCP 连通
 *   C3 PF-THREATBOOK-TCP THREATBOOK_BASE_URL TCP 连通（替代原 C3 MCP + C4 REST）
 *   D1 PF-NODE-VER       node ≥ 22.5
 *   D2 PF-TZ             TZ=Asia/Shanghai
 *   D3 PF-OUTPUT-WRITE   output/ 可写
 *   D4 PF-TEMPLATES      templates/ 三文件存在
 *
 * 设计原则：自检 = .env 配置存在性 + IP:port TCP 连通性。不真实调取服务，不消耗 API 配额。
 *
 * 输出本地联合结论 local_verdict：A+B 全 PASS / A+B 失败项 / C/D 仅 WARN 不阻塞。
 *
 * 非阻塞退出码：子项 PASS/FAIL/WARN/SKIP 均退出 0（结论由 verdict 字段承载）；
 * 仅输入错误退出码 1。无退出码 2。
 *
 * 字段类型/查询动词约束以 SKILL.md 附录F「字段类型→查询动词对照」为依据。
 */
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';
import { URL } from 'url';
import { parseArgs, showHelp, validateRequired } from '../shared/cli-args.js';
import { toShanghaiTime, formatDate } from '../shared/time-utils.js';
import { loadWhitelist } from '../shared/whitelist.js';
import { getEsConfig } from '../shared/es-query.js';
import { getEnv, isFeatureEnabled } from '../shared/env.js';
import net from 'net';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DEFAULT_SKILL_DIR = join(__dirname, '..', '..');

// ============================================================
// TCP 连通探针工具
// ============================================================

/**
 * 从 URL 字符串提取 hostname 和 port。
 * @param {string} urlStr - URL 字符串（如 https://api.threatbook.cn/v3）
 * @param {number} defaultPort - URL 无端口时的默认端口
 * @returns {{ host: string, port: number } | null} 解析失败返回 null
 */
function parseHostPort(urlStr, defaultPort) {
  try {
    const url = new URL(urlStr.startsWith('http') ? urlStr : `https://${urlStr}`);
    const host = url.hostname;
    const port = url.port ? parseInt(url.port, 10) : defaultPort;
    return { host, port };
  } catch {
    return null;
  }
}

/**
 * TCP 连通性探针。
 * @param {string} host - 目标主机
 * @param {number} port - 目标端口
 * @param {number} timeoutMs - 超时毫秒（默认 5000）
 * @returns {Promise<{ ok: boolean, reason?: string }>}
 */
function tcpProbe(host, port, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      socket.destroy();
      resolve({ ok: true });
    });
    socket.once('error', (e) => {
      socket.destroy();
      resolve({ ok: false, reason: e.message });
    });
    socket.once('timeout', () => {
      socket.destroy();
      resolve({ ok: false, reason: `TCP 连接超时（>${timeoutMs}ms）` });
    });
    socket.connect(port, host);
  });
}

const SCHEMA = {
  date: { alias: 'd', type: 'string', required: true, description: '探测日期 YYYYMMDD（B1 校验合法性 + 非未来日期 Asia/Shanghai）' },
  format: { alias: 'f', type: 'string', default: 'text', description: '输出格式: json | markdown | text' },
  output: { alias: 'o', type: 'string', description: '输出文件路径（默认: stdout）' },
  'skip-c-network': { type: 'boolean', default: false, description: '跳过 C1/C2/C3 网络探活（离线测试/无外网环境用），C1/C2/C3 输出 SKIP verdict' },
  'skill-dir': { type: 'string', description: '技能根目录路径（默认: 脚本所在 skill 目录，测试隔离用）' },
  help: { alias: 'h', type: 'boolean', description: '显示帮助' },
};

const { flags } = parseArgs(process.argv, SCHEMA);
const skillDir = flags['skill-dir'] || DEFAULT_SKILL_DIR;

if (flags.help) {
  showHelp(
    'scripts/local_selfcheck.js',
    '--date YYYYMMDD [--format json|markdown|text] [--output <path>] [--skip-c-network] [--help]',
    SCHEMA
  );
}

// ============================================================
// 输入校验（contract 失败处理表：退出码 1）
// ============================================================
const VALID_FORMATS = ['json', 'markdown', 'text'];

function validateInputs(f) {
  const errors = [];

  const missing = validateRequired(f, SCHEMA);
  if (missing.length > 0) {
    errors.push(`缺少必填参数: ${missing.map((m) => `--${m}`).join(', ')}`);
  }

  const date = f.date;
  if (date) {
    if (!/^\d{8}$/.test(date)) {
      errors.push(`--date 格式非法（须 YYYYMMDD）: ${date}`);
    } else {
      const today = formatDate(toShanghaiTime(Date.now()), 'YYYYMMDD');
      if (date > today) {
        errors.push(`--date 不得为未来日期: ${date}（当前 ${today}）`);
      }
    }
  }

  if (f.format && !VALID_FORMATS.includes(f.format)) {
    errors.push(`--format 非法（须 json|markdown|text）: ${f.format}`);
  }

  return errors;
}

const validationErrors = validateInputs(flags);
if (validationErrors.length > 0) {
  for (const e of validationErrors) {
    console.error(`[错误] ${e}`);
  }
  console.error('用法: node scripts/local_selfcheck.js --date YYYYMMDD [--format json|markdown|text] [--skip-c-network]');
  process.exit(1);
}

// ============================================================
// 9 项子项判定
// 每项返回 { check_id, scope, verdict, sub_id, advice }
// verdict: PASS / FAIL / WARN / SKIP
// ============================================================

// --- A1 PF-ES-TCP（ES_HOST:ES_PORT TCP 连通，强制项）---
async function checkA1EsTcp() {
  const esHost = getEnv('ES_HOST', '');
  const esPort = getEnv('ES_PORT', '');
  if (!esHost || !esPort) {
    return {
      check_id: 'PF-ES-TCP', scope: 'A', verdict: 'FAIL', sub_id: 'PF-ES-TCP-NO-CONFIG',
      advice: `ES_HOST 或 ES_PORT 未配置于 scripts/.env。请确认 ES 连接配置后重试。`,
    };
  }
  const port = parseInt(esPort, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    return {
      check_id: 'PF-ES-TCP', scope: 'A', verdict: 'FAIL', sub_id: 'PF-ES-TCP-INVALID-PORT',
      advice: `ES_PORT 非法: ${esPort}（须 1-65535）。请确认配置后重试。`,
    };
  }
  const probe = await tcpProbe(esHost, port, 5000);
  if (probe.ok) {
    return {
      check_id: 'PF-ES-TCP', scope: 'A', verdict: 'PASS', sub_id: 'PF-ES-TCP-OK',
      advice: `ES ${esHost}:${port} TCP 连通。`,
    };
  }
  return {
    check_id: 'PF-ES-TCP', scope: 'A', verdict: 'FAIL', sub_id: 'PF-ES-TCP-UNREACHABLE',
    advice: `ES ${esHost}:${port} TCP 不可达: ${probe.reason}。请检查 ES 服务和 .env 配置。`,
  };
}

// --- B1 PF-DATE-VALID（日期合法性 + 非未来日期）---
function checkB1DateValid(date) {
  if (!/^\d{8}$/.test(date)) {
    return {
      check_id: 'PF-DATE-VALID', scope: 'B', verdict: 'FAIL', sub_id: 'PF-DATE-VALID-INVALID',
      advice: `日期 ${date} 格式非法，须为 YYYYMMDD。请确认日期参数后重试。`,
    };
  }
  const today = formatDate(toShanghaiTime(Date.now()), 'YYYYMMDD');
  if (date > today) {
    return {
      check_id: 'PF-DATE-VALID', scope: 'B', verdict: 'FAIL', sub_id: 'PF-DATE-VALID-FUTURE',
      advice: `日期 ${date} 为未来日期（当前 ${today}），不可探测未来日志。请确认日期后重试。`,
    };
  }
  return {
    check_id: 'PF-DATE-VALID', scope: 'B', verdict: 'PASS', sub_id: 'PF-DATE-VALID-OK',
    advice: `日期 ${date} 合法且非未来日期。`,
  };
}

// --- B3 PF-WHITELIST（白名单可解析）---
function checkB3Whitelist() {
  const whitelistPath = join(skillDir, 'references', 'ipWhite.md');
  if (!fs.existsSync(whitelistPath)) {
    return {
      check_id: 'PF-WHITELIST', scope: 'B', verdict: 'FAIL', sub_id: 'PF-WHITELIST-MISSING',
      advice: `白名单 references/ipWhite.md 缺失。请确认文件存在后重试。`,
    };
  }
  const entries = loadWhitelist(whitelistPath);
  if (!Array.isArray(entries) || entries.length === 0) {
    return {
      check_id: 'PF-WHITELIST', scope: 'B', verdict: 'FAIL', sub_id: 'PF-WHITELIST-EMPTY',
      advice: `白名单 references/ipWhite.md 为空或全不可解析（CIDR/区间/单 IP）。请确认格式后重试。`,
    };
  }
  return {
    check_id: 'PF-WHITELIST', scope: 'B', verdict: 'PASS', sub_id: 'PF-WHITELIST-OK',
    advice: `白名单 references/ipWhite.md 存在且可解析（${entries.length} 条）。`,
  };
}

// --- B4 PF-ENV-CONFIG（.env 凭据存在性，不调 esQuery）---
function checkB4EnvConfig() {
  const envPath = join(skillDir, 'scripts', '.env');
  if (!fs.existsSync(envPath)) {
    return {
      check_id: 'PF-ENV-CONFIG', scope: 'B', verdict: 'FAIL', sub_id: 'PF-ENV-CONFIG-MISSING',
      advice: `未找到 scripts/.env。建议参考宪法 III 配置管理，创建 scripts/.env（不含凭证提交），或通过环境变量注入 ES_HOST/ES_PORT/ES_USERNAME/ES_PASSWORD。`,
    };
  }
  // 复用 getEsConfig 读 .env（同源凭据路径，与 workflow/ban-ip-selfcheck.js 一致）
  let cfg;
  try {
    cfg = getEsConfig();
  } catch (e) {
    return {
      check_id: 'PF-ENV-CONFIG', scope: 'B', verdict: 'FAIL', sub_id: 'PF-ENV-CONFIG-INCOMPLETE',
      advice: `scripts/.env 读取异常: ${e.message}。请确认 ES_HOST/ES_PORT/ES_USERNAME/ES_PASSWORD 四键非空。`,
    };
  }
  const requiredKeys = [
    { env: 'ES_HOST', cfg: 'host' },
    { env: 'ES_PORT', cfg: 'port' },
    { env: 'ES_USERNAME', cfg: 'username' },
    { env: 'ES_PASSWORD', cfg: 'password' },
  ];
  // getEsConfig 有默认值（host/port），故须直接查 process.env 判断是否真实配置
  const missingKeys = requiredKeys.filter((k) => !process.env[k.env]);
  if (missingKeys.length > 0) {
    return {
      check_id: 'PF-ENV-CONFIG', scope: 'B', verdict: 'FAIL', sub_id: 'PF-ENV-CONFIG-INCOMPLETE',
      advice: `scripts/.env 缺少键: ${missingKeys.map((k) => k.env).join(', ')}。须含 ES_HOST/ES_PORT/ES_USERNAME/ES_PASSWORD 四键非空。`,
    };
  }
  return {
    check_id: 'PF-ENV-CONFIG', scope: 'B', verdict: 'PASS', sub_id: 'PF-ENV-CONFIG-OK',
    advice: `scripts/.env 含 ES_HOST/ES_PORT/ES_USERNAME/ES_PASSWORD。`,
  };
}

// --- C1 PF-ENRICH-API（富化 API 密钥存在性检查）---
// 检查 ThreatBook API Key 是否已配置（THREATBOOK_API_KEY）。
// ENABLE_THREATBOOK=false 时 C1 恒 WARN（功能未启用）。
function checkC1EnrichApi(skipNetwork) {
  if (skipNetwork) {
    return {
      check_id: 'PF-ENRICH-API', scope: 'C', verdict: 'SKIP', sub_id: 'PF-ENRICH-API-SKIP',
      advice: `C1 富化 API 探活被 --skip-c-network 跳过（离线模式）。`,
    };
  }
  const enrichKeys = ['THREATBOOK_API_KEY', 'VIRUSTOTAL_API_KEY', 'ENRICH_API_KEY'];
  const configured = enrichKeys.find((k) => process.env[k]);
  if (!configured) {
    return {
      check_id: 'PF-ENRICH-API', scope: 'C', verdict: 'WARN', sub_id: 'PF-ENRICH-API-NOT-CONFIGURED',
      advice: `富化 API 未配置，威胁情报集成待启用。本项为非阻塞诊断。`,
    };
  }
  return {
    check_id: 'PF-ENRICH-API', scope: 'C', verdict: 'PASS', sub_id: 'PF-ENRICH-API-OK',
    advice: `富化 API 密钥已配置（${configured}）。`,
  };
}

// --- C2 PF-PORTAL-TOKEN（Portal Token 密钥 + Token 网关 TCP 连通）---
// 只做 TCP 连通性检查，不真实调用 Token 接口
async function checkC2PortalToken(skipNetwork) {
  if (skipNetwork) {
    return {
      check_id: 'PF-PORTAL-TOKEN', scope: 'C', verdict: 'SKIP', sub_id: 'PF-PORTAL-TOKEN-SKIP',
      advice: `C2 Portal Token 探针被 --skip-c-network 跳过（离线模式）。`,
    };
  }
  const appid = getEnv('PORTAL_TOKEN_APPID', '');
  const secret = getEnv('PORTAL_TOKEN_SECRET', '');
  const tokenUrl = getEnv('PORTAL_TOKEN_URL', 'https://jk.teamshub.com/oncon-service/token');

  if (!appid || !secret) {
    return {
      check_id: 'PF-PORTAL-TOKEN', scope: 'C', verdict: 'WARN', sub_id: 'PF-PORTAL-TOKEN-MISSING-KEY',
      advice: `Portal Token 密钥缺失：PORTAL_TOKEN_APPID 或 PORTAL_TOKEN_SECRET 未配置于 scripts/.env。本项为非阻塞诊断。`,
    };
  }

  const parsed = parseHostPort(tokenUrl, 443);
  if (!parsed) {
    return {
      check_id: 'PF-PORTAL-TOKEN', scope: 'C', verdict: 'WARN', sub_id: 'PF-PORTAL-TOKEN-INVALID-URL',
      advice: `PORTAL_TOKEN_URL 解析失败: ${tokenUrl}。本项为非阻塞诊断。`,
    };
  }
  const probe = await tcpProbe(parsed.host, parsed.port, 5000);
  if (probe.ok) {
    return {
      check_id: 'PF-PORTAL-TOKEN', scope: 'C', verdict: 'PASS', sub_id: 'PF-PORTAL-TOKEN-OK',
      advice: `Portal Token 网关 ${parsed.host}:${parsed.port} TCP 连通，密钥齐全。`,
    };
  }
  return {
    check_id: 'PF-PORTAL-TOKEN', scope: 'C', verdict: 'WARN', sub_id: 'PF-PORTAL-TOKEN-UNREACHABLE',
    advice: `Portal Token 网关 ${parsed.host}:${parsed.port} TCP 不可达: ${probe.reason}。本项为非阻塞诊断，发布功能本就非阻塞。`,
  };
}

// --- C3 PF-THREATBOOK-TCP（Threatbook REST API TCP 连通，非阻塞）---
// 替代原 C3 (MCP tools/list) + C4 (REST API 真实查询探活)
// 只做 TCP 连通性检查，不真实调取服务，不消耗 API 配额
async function checkC3ThreatbookTcp(skipNetwork) {
  if (skipNetwork) {
    return {
      check_id: 'PF-THREATBOOK-TCP', scope: 'C', verdict: 'SKIP', sub_id: 'PF-THREATBOOK-TCP-SKIP',
      advice: `C3 Threatbook TCP 探针被 --skip-c-network 跳过（离线模式）。`,
    };
  }
  if (!isFeatureEnabled('THREATBOOK')) {
    return {
      check_id: 'PF-THREATBOOK-TCP', scope: 'C', verdict: 'SKIP', sub_id: 'PF-THREATBOOK-TCP-DISABLED',
      advice: `微步情报功能未启用 (ENABLE_THREATBOOK=false)，跳过 TCP 探针。`,
    };
  }
  const apiKey = getEnv('THREATBOOK_API_KEY', '');
  if (!apiKey) {
    return {
      check_id: 'PF-THREATBOOK-TCP', scope: 'C', verdict: 'WARN', sub_id: 'PF-THREATBOOK-TCP-NO-KEY',
      advice: `THREATBOOK_API_KEY 未配置，Threatbook TCP 探针跳过。本项为非阻塞诊断。`,
    };
  }
  let probeHost, probePort;
  if (isFeatureEnabled('PROXY')) {
    probeHost = getEnv('PROXY_HOST', '127.0.0.1');
    probePort = parseInt(getEnv('PROXY_PORT', '443'), 10);
  } else {
    const baseUrl = getEnv('THREATBOOK_BASE_URL', 'https://api.threatbook.cn/v3');
    const parsed = parseHostPort(baseUrl, 443);
    if (!parsed) {
      return {
        check_id: 'PF-THREATBOOK-TCP', scope: 'C', verdict: 'WARN', sub_id: 'PF-THREATBOOK-TCP-INVALID-URL',
        advice: `THREATBOOK_BASE_URL 解析失败: ${baseUrl}。本项为非阻塞诊断。`,
      };
    }
    probeHost = parsed.host;
    probePort = parsed.port;
  }
  const probe = await tcpProbe(probeHost, probePort, 5000);
  if (probe.ok) {
    return {
      check_id: 'PF-THREATBOOK-TCP', scope: 'C', verdict: 'PASS', sub_id: 'PF-THREATBOOK-TCP-OK',
      advice: `Threatbook ${probeHost}:${probePort} TCP 连通。`,
    };
  }
  return {
    check_id: 'PF-THREATBOOK-TCP', scope: 'C', verdict: 'WARN', sub_id: 'PF-THREATBOOK-TCP-UNREACHABLE',
    advice: `Threatbook ${probeHost}:${probePort} TCP 不可达: ${probe.reason}。本项为非阻塞诊断，Step 3c 将跳过情报查询。`,
  };
}

// --- D1 PF-NODE-VER（node ≥ 22.5）---
function checkD1NodeVer() {
  const major = parseInt(process.version.replace(/^v/, '').split('.')[0], 10);
  const minor = parseInt(process.version.replace(/^v/, '').split('.')[1], 10);
  if (major > 22 || (major === 22 && minor >= 5)) {
    return {
      check_id: 'PF-NODE-VER', scope: 'D', verdict: 'PASS', sub_id: 'PF-NODE-VER-OK',
      advice: `Node.js 版本 ${process.version} ≥ 22.5。`,
    };
  }
  return {
    check_id: 'PF-NODE-VER', scope: 'D', verdict: 'WARN', sub_id: 'PF-NODE-VER-LOW',
    advice: `Node.js 版本 ${process.version} < 22.5，建议升级至 ≥ 22.5。本项为非阻塞诊断。`,
  };
}

// --- D2 PF-TZ（TZ=Asia/Shanghai）---
function checkD2Tz() {
  if (process.env.TZ === 'Asia/Shanghai') {
    return {
      check_id: 'PF-TZ', scope: 'D', verdict: 'PASS', sub_id: 'PF-TZ-OK',
      advice: `时区 TZ=Asia/Shanghai。`,
    };
  }
  return {
    check_id: 'PF-TZ', scope: 'D', verdict: 'WARN', sub_id: 'PF-TZ-MISMATCH',
    advice: `当前 TZ 未设为 Asia/Shanghai（实际: ${process.env.TZ || '未设'}），报告时间可能偏差。建议设置 TZ=Asia/Shanghai。本项为非阻塞诊断。`,
  };
}

// --- D3 PF-OUTPUT-WRITE（output/ 可写）---
function checkD3OutputWrite() {
  const outputDir = join(process.cwd(), 'output');
  const testFile = join(outputDir, `.selfcheck-probe-${process.pid}.tmp`);
  try {
    if (!fs.existsSync(outputDir)) {
      return {
        check_id: 'PF-OUTPUT-WRITE', scope: 'D', verdict: 'WARN', sub_id: 'PF-OUTPUT-WRITE-FAIL',
        advice: `output/ 目录缺失（${outputDir}）。建议创建后重试。本项为非阻塞诊断。`,
      };
    }
    fs.writeFileSync(testFile, 'probe', 'utf-8');
    fs.unlinkSync(testFile);
    return {
      check_id: 'PF-OUTPUT-WRITE', scope: 'D', verdict: 'PASS', sub_id: 'PF-OUTPUT-WRITE-OK',
      advice: `output/ 目录可写。`,
    };
  } catch (e) {
    return {
      check_id: 'PF-OUTPUT-WRITE', scope: 'D', verdict: 'WARN', sub_id: 'PF-OUTPUT-WRITE-FAIL',
      advice: `output/ 目录不可写: ${e.message}。本项为非阻塞诊断。`,
    };
  }
}

// --- D4 PF-TEMPLATES（templates/ 三文件存在）---
function checkD4Templates() {
  const tplDir = join(skillDir, 'templates');
  const required = [
    'alert-report-template.md',
    'alert-report-template-v1.html',
    'trace-report-template.md',
  ];
  const missing = required.filter((f) => !fs.existsSync(join(tplDir, f)));
  if (missing.length === 0) {
    return {
      check_id: 'PF-TEMPLATES', scope: 'D', verdict: 'PASS', sub_id: 'PF-TEMPLATES-OK',
      advice: `templates/ 三文件齐全。`,
    };
  }
  return {
    check_id: 'PF-TEMPLATES', scope: 'D', verdict: 'WARN', sub_id: 'PF-TEMPLATES-MISSING',
    advice: `templates/ 缺失文件: ${missing.join(', ')}。本项为非阻塞诊断。`,
  };
}

// ============================================================
// 本地联合结论聚合（B 全 PASS / B 失败项 / C/D 仅 WARN）
// ============================================================
function aggregateLocalVerdict(items) {
  const abItems = items.filter((it) => it.scope === 'A' || it.scope === 'B');
  const bFailures = abItems.filter((it) => it.verdict === 'FAIL').map((it) => it.check_id);
  const bAllPass = abItems.every((it) => it.verdict === 'PASS');

  const cdWarnings = items
    .filter((it) => (it.scope === 'C' || it.scope === 'D') && it.verdict === 'WARN')
    .map((it) => it.check_id);
  const cdSkipped = items
    .filter((it) => it.scope === 'C' && it.verdict === 'SKIP')
    .map((it) => it.check_id);

  let summary;
  if (bAllPass) {
    const warnPart = cdWarnings.length > 0
      ? `；C/D 诊断项 ${cdWarnings.length} 项 WARN（${cdWarnings.join(', ')}），不阻塞`
      : '；C/D 诊断项全 PASS';
    summary = `A+B 前置项全 PASS${warnPart}`;
  } else {
    const warnPart = cdWarnings.length > 0
      ? `；C/D 诊断项 ${cdWarnings.length} 项 WARN（${cdWarnings.join(', ')}），不阻塞`
      : '';
    summary = `A+B 前置项失败：${bFailures.join(', ')}${warnPart}`;
  }

  return {
    b_all_pass: bAllPass,
    b_failures: bFailures,
    c_d_warnings: cdWarnings,
    c_d_skipped: cdSkipped,
    summary,
  };
}

// ============================================================
// 三格式输出（json / text / markdown）
// ============================================================
function renderJson(items, localVerdict, degradeHint, checkedAt, date) {
  const result = {
    checked_at: checkedAt,
    date,
    items,
    local_verdict: localVerdict,
    degrade_hint: degradeHint,
  };
  return JSON.stringify(result, null, 2);
}

function renderText(items, localVerdict) {
  const lines = items.map((it) => {
    const adviceSuffix = it.advice ? ` — ${it.advice}` : '';
    return `[步骤0 自检·本地批量] ${it.check_id}: ${it.verdict} (${it.sub_id})${adviceSuffix}`;
  });
  lines.push(`[步骤0 自检·本地批量·联合结论] ${localVerdict.summary}`);
  return lines.join('\n');
}

function renderMarkdown(items, localVerdict) {
  const descMap = {
    'PF-ES-TCP': 'ES TCP 连通',
    'PF-DATE-VALID': '日期合法性',
    'PF-WHITELIST': '白名单可解析',
    'PF-ENV-CONFIG': '.env 凭据',
    'PF-ENRICH-API': '富化 API',
    'PF-PORTAL-TOKEN': 'Portal Token TCP',
    'PF-THREATBOOK-TCP': '微步 TCP 连通',
    'PF-NODE-VER': 'node 版本',
    'PF-TZ': '时区',
    'PF-OUTPUT-WRITE': 'output 可写',
    'PF-TEMPLATES': 'templates',
  };
  const rows = items.map((it) => {
    const desc = descMap[it.check_id] || it.check_id;
    const adviceShort = it.advice ? it.advice.split('。')[0] : '';
    return `| 本地批量 | ${it.check_id} | ${desc} | ${it.verdict} | ${it.sub_id} | ${adviceShort} |`;
  });
  rows.push(`| 本地批量·联合 | — | B 全 PASS / C/D WARN | ${localVerdict.b_all_pass ? 'PASS' : 'FAIL'} | — | ${localVerdict.summary} |`);
  return rows.join('\n');
}

function renderOutput(items, localVerdict, degradeHint, checkedAt, date, format) {
  if (format === 'json') return renderJson(items, localVerdict, degradeHint, checkedAt, date);
  if (format === 'markdown') return renderMarkdown(items, localVerdict);
  return renderText(items, localVerdict);
}

function writeOutput(text) {
  if (flags.output) {
    fs.writeFileSync(flags.output, text + '\n', 'utf-8');
  } else {
    console.log(text);
  }
}

// ============================================================
// 主流程（脚本异常输出 degrade_hint 退出 0，SKILL.md 据此降级到逐条手工自检）
// ============================================================
async function main() {
  const date = flags.date;
  const skipNetwork = flags['skip-c-network'] === true;
  const checkedAt = formatDate(toShanghaiTime(Date.now()), 'YYYY-MM-DDTHH:mm:ssZ');

  // 11 项子项判定（A1 异步 TCP + B/C 同步项 + D 同步项 + C2/C3 异步 TCP 探活）
  // A1-B4 强制项（FAIL 触发 terminate，由 SKILL.md 据 local_verdict 判定）
  // C1-C3/D1-D4 诊断项（WARN 不阻塞）
  const items = [];

  items.push(await checkA1EsTcp());
  items.push(checkB1DateValid(date));
  items.push(checkB3Whitelist());
  items.push(checkB4EnvConfig());
  items.push(checkC1EnrichApi(skipNetwork));
  items.push(await checkC2PortalToken(skipNetwork));
  items.push(await checkC3ThreatbookTcp(skipNetwork));
  items.push(checkD1NodeVer());
  items.push(checkD2Tz());
  items.push(checkD3OutputWrite());
  items.push(checkD4Templates());

  const localVerdict = aggregateLocalVerdict(items);
  const text = renderOutput(items, localVerdict, null, checkedAt, date, flags.format);
  writeOutput(text);
  process.exit(0);
}

main().catch((e) => {
  // 脚本异常降级：输出 degrade_hint 退出 0（不阻断，SKILL.md 据此降级到逐条手工自检）
  const date = flags.date || 'unknown';
  const checkedAt = formatDate(toShanghaiTime(Date.now()), 'YYYY-MM-DDTHH:mm:ssZ');
  const degradeHint = `[DEGRADE] reason=local_selfcheck 异常: ${e.message} | ts=${checkedAt} | params={date=${date}} | mode=local-selfcheck→manual-preflight`;
  const fallback = {
    checked_at: checkedAt,
    date,
    items: [],
    local_verdict: { b_all_pass: false, b_failures: [], c_d_warnings: [], c_d_skipped: [], summary: `脚本异常: ${e.message}` },
    degrade_hint: degradeHint,
  };
  const text = flags.format === 'json'
    ? JSON.stringify(fallback, null, 2)
    : `${degradeHint}\n[步骤0 自检·本地批量·联合结论] 脚本异常: ${e.message}`;
  writeOutput(text);
  process.exit(0);
});
