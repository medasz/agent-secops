#!/usr/bin/env node
/**
 * post_to_portal.js - 发布HTML到公司门户
 *
 * 用法: node scripts/post_to_portal.js <html-file> [--title <标题>]
 *
 * 帖子标题默认从HTML的<title>标签解析，--title可覆盖。
 *
 * 配置来源：scripts/.env
 *   PORTAL_TOKEN_APPID      - Token 网关 appid (必填，用于自动获取 Token)
 *   PORTAL_TOKEN_SECRET     - Token 网关 secret (必填，用于自动获取 Token)
 *   PORTAL_TOKEN_GRANT_TYPE - 授权类型 (默认 sys_credential)
 *   PORTAL_TOKEN_URL        - Token 网关地址 (默认 https://jk.teamshub.com/oncon-service/token)
 *   PORTAL_GROUP_ID         - 组ID (默认 70011431)
 *   PORTAL_TYPE_ID          - 帖子类型ID (默认 71051517)
 *   PORTAL_EMP_ID           - 员工ID (默认 15570)
 *   PORTAL_TEMPLATE_ID      - 模板ID (默认 1)
 *   PORTAL_VIEW_RIGHT       - 查看权限: 1=完全公开 / 2=指定读者 (默认 2)
 *                            注: 3=设密码（需查看密码+编辑密码），当前脚本不支持，待后续支持
 *   PORTAL_VIEW_PRIV        - viewRight=2 时为指定读者ID列表（逗号分隔），必填
 *   PORTAL_EDIT_PRIV        - 编辑权限人员ID列表，逗号分隔 (默认空，仅作者可编辑)
 *   PORTAL_REPLY_RIGHT      - 回复权限: 0 不允许 / 1 允许 (默认 1)
 *   PORTAL_IS_GM_VISIBLE    - 圈友可见: true / false (默认 false)
 *   ENABLE_POST             - 是否启用发帖功能: true / false (默认 false)
 *   PORTAL_BASE_URL         - Portal API 主机 (默认 jk.teamshub.com)
 *   PORTAL_API_PATH         - Portal API 路径 (默认 /oncon-service/sys_credential/save_topic_info/v1.0)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * 成功/失败判定说明（重要）：
 *   契约文档（specs/021-fix-portal-posting/contracts/portal-api-contract.md）
 *   描述的响应 schema 与「真实服务端」并不一致。真实服务端使用：
 *     - 数字型 errcode：成功为 0，失败为 500 等
 *     - 顶层 ret / errcode / desc 字段
 *     - 成功时 data 可能是数字 topicId，也可能嵌套在 data.data 中
 *   故成功判定必须同时兼容「数字 errcode=0 / ret=0 / code=SUCCESS / code=200 /
 *   desc 含 success」，失败判定必须兼容「数字 errcode（如 500）/ 顶层 ret（如 5）」。
 *   相关逻辑集中在 interpretResponse() 中。
 * ─────────────────────────────────────────────────────────────────────────────
 */
import fs from 'fs';
import http from 'http';
import https from 'https';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { parseArgs, showHelp } from '../shared/cli-args.js';
import { getPortalConfig } from '../shared/env.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ===========================================================================
// 纯函数（可被单测直接调用，无副作用、无网络、无 process.exit）
// ===========================================================================

/**
 * 构建 save_topic_info/v1.0 请求信封。
 *
 * 仅负责构造请求体；成功/失败判定见 interpretResponse()。
 *
 * @param {object} cfg - 配置对象，字段见 main() 中组装
 *   { groupId, typeId, empId, templateId, viewRightNum, viewPrivValue,
 *     editPriv, isGMVisible, replyRight }
 * @param {string} html - 帖子 HTML 正文
 * @param {string} title - 帖子标题
 * @returns {object} 信封对象
 */
export function buildEnvelope(cfg, html, title) {
  const viewRightNum = cfg.viewRightNum;
  const viewPrivValue = cfg.viewPrivValue;
  // viewRight=2 时透传指定读者列表，否则留空
  const effectiveViewPriv = viewRightNum === 2 ? viewPrivValue : '';

  return {
    id: Date.now().toString(36),
    type: 'save_topic_info',
    action: 'request',
    version: '1.0',
    token: 'api',
    data: {
      viewPriv: effectiveViewPriv,
      editPriv: String(cfg.editPriv).trim(),
      isGMVisible: String(cfg.isGMVisible).trim(),
      topic: {
        groupId: Number(cfg.groupId),
        typeId: Number(cfg.typeId),
        userId: String(cfg.empId),
        topicTitle: title,
        topicContent: html,
        templateId: Number(cfg.templateId),
        viewRight: viewRightNum,
        replyRight: Number(cfg.replyRight),
        haveAttach: 0,
        isCopy: 1,
        isFrom: 0,
        isValid: 1,
        reqSource: 1,
        topicId: 0,
        modifyBy: null, // 契约要求保持 null（非字符串、非 0）
        orgNo: '10000',
        remark: 'eip',
      },
      attachList: [],
    },
  };
}

/**
 * 解析门户发布接口响应，给出成功/失败判定、topicId 与诊断信息。
 *
 * 适配真实服务端 schema：
 *   - 成功：数字 errcode=0 / 顶层 ret=0 / code='SUCCESS' / code='200' / desc 含 "success"
 *   - 失败：数字 errcode（如 500）/ 顶层 ret（如 5）
 *   - 失败时诊断信息带 HTTP 状态码与完整响应体，方便运维排查
 *
 * @param {number} statusCode - HTTP 状态码
 * @param {string} rawBody - 响应体原文
 * @returns {{ok: boolean, topicId: (number|string|null), diagnose: string, retryable: boolean}}
 */
export function interpretResponse(statusCode, rawBody) {
  let json;
  try {
    json = JSON.parse(rawBody);
  } catch (e) {
    // 响应体非 JSON：归为失败，保留 HTTP 状态码与原始片段
    return {
      ok: false,
      topicId: null,
      retryable: false,
      diagnose: `响应解析失败 (HTTP ${statusCode}): ${String(rawBody).slice(0, 500)}`,
    };
  }

  // 成功判定：兼容真实服务端（数字 errcode/ret）与旧契约（字符串 code）
  const isSuccess =
    json.errcode === 0 ||
    Number(json.errcode) === 0 ||
    json.ret === 0 ||
    json.code === 'SUCCESS' ||
    json.code === '200' ||
    /success/i.test(json.desc || '');

  if (isSuccess) {
    // 成功时 data 可能是数字 topicId，也可能嵌套在 data.data 中
    const topicId = json.data?.data ?? json.data;
    return { ok: true, topicId, retryable: false, diagnose: '' };
  }

  // 失败：带上 HTTP 状态码 + 完整响应体片段（运维可据此排查）
  const desc = json.desc || json.msg || '';
  const snippet = String(rawBody).slice(0, 500);
  const diagnose = `HTTP ${statusCode} | ${desc || '(无 desc/msg)'} | 响应体: ${snippet}`;

  // 服务端 500 / ret=5 视为可重试（疑似服务端瞬时故障）
  const retryable = Number(json.errcode) === 500 || json.ret === 5;

  return { ok: false, topicId: null, retryable, diagnose };
}

// ===========================================================================
// Token 获取辅助函数
// ===========================================================================

/**
 * 调用 Token 网关接口获取一次性 accessToken。
 * 使用原生 http/https.request（回调风格，Promise 化）。
 *
 * @param {string} tokenUrl - Token 网关基础 URL（不含 query 串）
 * @param {string} appid    - 应用 ID
 * @param {string} secret   - 应用密钥
 * @param {string} grantType- 授权类型
 * @returns {Promise<{token: string, expiresIn: number}>}
 */
export function getToken(tokenUrl, appid, secret, grantType) {
  return new Promise((resolve, reject) => {
    const qs = `appid=${encodeURIComponent(appid)}&secret=${encodeURIComponent(secret)}&grant_type=${encodeURIComponent(grantType)}`;
    const url = new URL(tokenUrl.startsWith('http') ? tokenUrl : `https://${tokenUrl}`);
    url.search = qs;

    // Parse the URL for http.get options
    const { hostname, port, pathname, search } = url;
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;

    const options = {
      hostname: hostname,
      port: port || (isHttps ? 443 : 80),
      path: pathname + search,
      method: 'GET',
      timeout: 30000, // 30-second timeout
    };

    const req = client.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        try {
          const data = Buffer.concat(chunks).toString('utf8');
          const json = JSON.parse(data);
          if (json.access_token) {
            resolve({ token: json.access_token, expiresIn: json.expires_in || 0 });
          } else {
            reject(new Error(json.msg || JSON.stringify(json)));
          }
        } catch (e) {
          reject(new Error(`Token 响应解析失败: ${data}`));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Token 接口 30 秒超时'));
    });

    req.on('error', (e) => {
      reject(e);
    });

    req.end();
  });
}

// ===========================================================================
// C2 探测：验证配置与依赖（失败直接 exit 1）
// ===========================================================================

/**
 * C2 探测：校验 Token 网关凭证并获取一次性有效 Token。
 * @param {object} cfg - 配置对象（需含 appid/secret/grantType/tokenUrl）
 * @returns {Promise<string>} accessToken
 */
async function c2Check(cfg) {
  // 1. 检查 Token 网关凭证是否就绪
  if (!cfg.appid || !cfg.secret) {
    console.error(`[C2] 门户Token获取失败: PORTAL_TOKEN_APPID 或 PORTAL_TOKEN_SECRET 未配置。请在 .env 中设置这两个变量。`);
    process.exit(1);
  }

  // 2. 尝试获取一次性的有效 Token
  try {
    const { token, expiresIn } = await getToken(cfg.tokenUrl, cfg.appid, cfg.secret, cfg.grantType);
    console.log(`[C2] Token 获取成功 (有效期 ${expiresIn}s)`);
    return token;
  } catch (err) {
    console.error(`[C2] 门户Token获取失败: ${err.message}`);
    process.exit(1);
  }
}

// ===========================================================================
// 执行单次 POST 请求（Promise 化，便于重试编排）
// ===========================================================================

/**
 * 向门户 save_topic_info 接口发起一次 POST 请求。
 * 网络异常/超时不会抛错，而是以结构化结果返回，交由上层决定是否重试。
 *
 * @param {object} cfg - 配置对象（需含 portalHost/portalPath）
 * @param {string} token - accessToken（作为查询参数传递）
 * @param {object} envelope - 由 buildEnvelope() 构造的请求体
 * @returns {Promise<{statusCode: number, rawBody: string, error: (Error|null), timedOut: boolean}>}
 */
export function doPost(cfg, token, envelope, transport = null) {
  return new Promise((resolve) => {
    const bodyBuffer = Buffer.from(JSON.stringify(envelope), 'utf-8');

    // 按 PORTAL_HOST 协议前缀选择 http/https 模块（无前缀默认 HTTPS）
    const host = cfg.portalHost.startsWith('http://') || cfg.portalHost.startsWith('https://')
      ? cfg.portalHost
      : `https://${cfg.portalHost}`;
    const url = new URL(host);
    const isHttps = url.protocol === 'https:';
    // transport 可注入（测试用，用于模拟网络异常/超时），默认按协议选择 http/https 模块
    const client = transport || (isHttps ? https : http);

    // access_token 作为查询参数传递（非请求头）
    const reqPath = `${cfg.portalPath}?access_token=${encodeURIComponent(token)}`;

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: reqPath,
      method: 'POST',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': bodyBuffer.length,
      },
    };

    const req = client.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const data = Buffer.concat(chunks).toString('utf8');
        resolve({ statusCode: res.statusCode || 0, rawBody: data, error: null, timedOut: false });
      });
    });

    req.on('error', (e) => {
      resolve({ statusCode: 0, rawBody: '', error: e, timedOut: false });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ statusCode: 0, rawBody: '', error: new Error('请求 30 秒超时'), timedOut: true });
    });

    req.write(bodyBuffer);
    req.end();
  });
}

/**
 * 简单的睡眠辅助函数。
 * @param {number} ms - 毫秒
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ===========================================================================
// 主流程（仅在作为入口脚本直接运行时执行，避免被测试 import 触发副作用）
// ===========================================================================

async function main() {
  // -------------------------------------------------------------------------
  // 配置读取（从 env.js 域配置函数获取）
  // -------------------------------------------------------------------------
  const portalConfig = getPortalConfig();
  const PORTAL_TOKEN_APPID   = portalConfig.tokenAppId;
  const PORTAL_TOKEN_SECRET  = portalConfig.tokenSecret;
  const PORTAL_TOKEN_GRANT   = portalConfig.tokenGrantType;
  const PORTAL_TOKEN_URL     = portalConfig.tokenUrl;
  const PORTAL_HOST          = portalConfig.baseUrl;
  const PORTAL_PATH          = portalConfig.apiPath;
  const GROUP_ID             = portalConfig.groupId;
  const TYPE_ID              = portalConfig.typeId;
  const EMP_ID               = portalConfig.empId;
  const TEMPLATE_ID          = portalConfig.templateId;
  const VIEW_RIGHT           = portalConfig.viewRight;
  const VIEW_PRIV            = portalConfig.viewPriv;
  const EDIT_PRIV            = portalConfig.editPriv;
  const REPLY_RIGHT          = portalConfig.replyRight;
  const IS_GM_VISIBLE        = portalConfig.isGmVisible;
  const ENABLE_POST          = portalConfig.enabled;

  // 发帖功能开关：ENABLE_POST=false 时仅输出提示，不执行实际发帖
  if (String(ENABLE_POST).trim().toLowerCase() !== 'true') {
    console.log('[SKIP] 发帖功能已禁用 (ENABLE_POST=false)。如需启用，请在 .env 中设置 ENABLE_POST=true。');
    process.exit(0);
  }

  // 早期校验：viewRight 只能为 1（完全公开）或 2（指定读者）
  // viewRight=2 时必须配置 viewPriv（读者ID列表），避免浪费 Token 网关调用
  const viewRightNum = Number(VIEW_RIGHT);
  if (viewRightNum !== 1 && viewRightNum !== 2) {
    console.error('[FATAL] PORTAL_VIEW_RIGHT 只能为 1（完全公开）或 2（指定读者），当前值: %s', VIEW_RIGHT);
    process.exit(1);
  }
  const viewPrivValue = String(VIEW_PRIV).trim();
  if (viewRightNum === 2 && !viewPrivValue) {
    console.error('[FATAL] PORTAL_VIEW_RIGHT=2（指定读者）需配合 PORTAL_VIEW_PRIV 读者ID列表（逗号分隔），');
    console.error('        当前 PORTAL_VIEW_PRIV 为空。请改设 PORTAL_VIEW_RIGHT=1（公开）或填写 PORTAL_VIEW_PRIV。');
    process.exit(1);
  }

  // 组装配置对象，供纯函数与各辅助函数复用
  const cfg = {
    appid: PORTAL_TOKEN_APPID,
    secret: PORTAL_TOKEN_SECRET,
    grantType: PORTAL_TOKEN_GRANT,
    tokenUrl: PORTAL_TOKEN_URL,
    portalHost: PORTAL_HOST,
    portalPath: PORTAL_PATH,
    groupId: GROUP_ID,
    typeId: TYPE_ID,
    empId: EMP_ID,
    templateId: TEMPLATE_ID,
    viewRightNum: viewRightNum,
    viewPrivValue: viewPrivValue,
    editPriv: EDIT_PRIV,
    isGMVisible: IS_GM_VISIBLE,
    replyRight: REPLY_RIGHT,
  };

  // 先跑 C2 探测，拿到有效 Token（失败会 exit 1）
  const firstToken = await c2Check(cfg);

  // -------------------------------------------------------------------------
  // 剩余参数解析 & 输入校验
  // -------------------------------------------------------------------------
  const SCHEMA = {
    title: { alias: 't', type: 'string', description: '帖子标题（默认从HTML <title>解析）' },
  };

  const { positional, flags } = parseArgs(process.argv, SCHEMA);

  if (flags.help) {
    showHelp('scripts/post_to_portal.js', '<html-file> [--title <标题>]', SCHEMA);
  }

  // 解析HTML文件路径（优先位置参数，其次 --file 标志）
  const htmlPath = positional[0] || flags.file;

  if (!htmlPath) {
    console.error('[ERROR] 请提供HTML文件路径');
    console.error('用法: node scripts/post_to_portal.js <html-file> [--title <标题>]');
    process.exit(1);
  }

  if (!fs.existsSync(htmlPath)) {
    console.error(`[ERROR] 文件不存在: ${htmlPath}`);
    process.exit(1);
  }

  const html = fs.readFileSync(htmlPath, 'utf-8');

  // 从HTML <title>标签解析标题，--title标志可覆盖
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  const topicTitle = flags.title || (titleMatch ? titleMatch[1].trim() : path.basename(htmlPath, '.html'));

  console.log(`[INFO] 标题: ${topicTitle}`);
  console.log(`[INFO] 文件: ${htmlPath} (${(html.length / 1024).toFixed(1)} KB)`);
  const viewRightLabel = viewRightNum === 1 ? '完全公开' : `指定读者 (${viewPrivValue})`;
  console.log(`[INFO] 查看权限: viewRight=${viewRightNum} (${viewRightLabel})`);
  console.log(`[INFO] 提交中...`);

  // -------------------------------------------------------------------------
  // 发送请求 + 重试策略
  //   对「网络异常 / 超时」以及「服务端 errcode=500 / ret=5」重试一次。
  //   重试间隔 1.8s；token 有效期 7200s，重试前重新取 token 以提升健壮性。
  // -------------------------------------------------------------------------
  const RETRIES = 1;
  const RETRY_DELAY_MS = 1800;

  let token = firstToken;
  let result = null;

  for (let attempt = 0; attempt <= RETRIES; attempt++) {
    const envelope = buildEnvelope(cfg, html, topicTitle);
    const { statusCode, rawBody, error, timedOut } = await doPost(cfg, token, envelope);

    if (error || timedOut) {
      // 网络层异常：超时归 exit 2，其它网络错误也归 exit 2
      const reason = timedOut ? '请求 30 秒超时' : error.message;
      if (attempt < RETRIES) {
        console.error(`[WARN] 第${attempt + 1}次发布请求异常: ${reason}，1.8s 后重试...`);
        await sleep(RETRY_DELAY_MS);
        // 重试前重新获取 token（失败则沿用旧 token）
        try {
          token = (await getToken(cfg.tokenUrl, cfg.appid, cfg.secret, cfg.grantType)).token;
        } catch (_) { /* keep old token */ }
        continue;
      }
      console.error(`[C2] 发布失败: 网络异常 (HTTP -): ${reason}`);
      process.exit(2);
    }

    result = interpretResponse(statusCode, rawBody);

    if (result.ok) {
      break;
    }

    if (result.retryable && attempt < RETRIES) {
      console.error(`[WARN] 第${attempt + 1}次发布返回可重试错误: ${result.diagnose}，1.8s 后重试...`);
      await sleep(RETRY_DELAY_MS);
      try {
        token = (await getToken(cfg.tokenUrl, cfg.appid, cfg.secret, cfg.grantType)).token;
      } catch (_) { /* keep old token */ }
      continue;
    }

    // 不可重试的失败：直接结束循环，交给下方统一出口处理
    break;
  }

  // -------------------------------------------------------------------------
  // 统一出口
  // -------------------------------------------------------------------------
  if (result && result.ok) {
    console.log(`[OK] 发布成功! 帖子ID: ${result.topicId}`);
    console.log(`[OK] 链接: https://eip.teamshub.com/t/${result.topicId}`);
    process.exit(0);
  } else {
    // 失败：打印带 HTTP 状态码与完整响应体的可读诊断（保持 [C2] 前缀，打到 stderr）
    console.error(`[C2] 发布失败: ${result ? result.diagnose : '未知错误'}`);
    process.exit(1);
  }
}

// 仅当本文件作为入口脚本直接运行时，才执行主流程（避免被测试 import 触发副作用）
const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  main().catch((e) => {
    console.error(`[C2] 发布失败: ${e && e.message ? e.message : String(e)}`);
    process.exit(2);
  });
}
