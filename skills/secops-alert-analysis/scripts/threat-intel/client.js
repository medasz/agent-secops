import { getThreatBookConfig, isFeatureEnabled } from '../shared/env.js';
import { createProxiedRequest } from '../shared/proxy.js';
import https from 'https';
import http from 'http';

let requestFn = null;

export function setRequestFn(fn) {
  requestFn = fn;
}

if (isFeatureEnabled('PROXY')) {
  setRequestFn(createProxiedRequest());
}

function defaultRequest(url, { timeout } = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        resolve({ statusCode: res.statusCode, body });
      });
    });
    req.on('error', (err) => {
      if (err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN') {
        reject(Object.assign(new Error('dns'), { code: 'DNS_FAILURE' }));
      } else if (err.code === 'ETIMEDOUT' || err.message.includes('timeout')) {
        reject(Object.assign(new Error('timeout'), { code: 'NETWORK_TIMEOUT' }));
      } else {
        reject(err);
      }
    });
    req.on('timeout', () => {
      req.destroy();
      reject(Object.assign(new Error('timeout'), { code: 'NETWORK_TIMEOUT' }));
    });
  });
}

async function doRequest(url, timeout) {
  if (requestFn) return await requestFn(url, { timeout });
  return await defaultRequest(url, { timeout });
}

function classifyError(responseCode, verboseMsg) {
  const msg = (verboseMsg || '').toLowerCase();
  if (msg.includes('apikey') || msg.includes('api key') || msg.includes('unauthorized') || msg.includes('auth')) {
    return 'IP_BINDING_MISMATCH';
  }
  if (msg.includes('quota') || msg.includes('limit') || msg.includes('exceed') || msg.includes('配额') || msg.includes('限制')) {
    return 'QUOTA_EXHAUSTED';
  }
  if (msg.includes('expire') || msg.includes('expired') || msg.includes('过期') || msg.includes('失效')) {
    return 'SUBSCRIPTION_EXPIRED';
  }
  return `API_ERROR_${responseCode}`;
}

function normalizeIpData(ip, raw) {
  const judgments = raw.judgments || [];
  const tagsClasses = raw.tags_classes || [];
  const tags = tagsClasses.flatMap(tc => tc.tags || []);
  const loc = raw.basic?.location || {};
  const geoParts = [loc.country, loc.province, loc.city].filter(Boolean);
  const isMalicious = raw.is_malicious === true;
  return {
    ip,
    found: isMalicious,
    is_malicious: isMalicious,
    threat_type: judgments.join(','),
    confidence: raw.confidence_level || 'low',
    severity: raw.severity || 'info',
    tags,
    scene: raw.scene || '',
    geo: geoParts.join(','),
    carrier: raw.basic?.carrier || '',
    permalink: raw.permalink || '',
    update_time: raw.update_time || '',
    reasoning: isMalicious
      ? `ThreatBook 判定恶意，威胁类型: ${judgments.join(',')}`
      : 'ThreatBook 判定非恶意'
  };
}

function normalizeGenericData(key, raw) {
  const judgments = raw.judgments || [];
  const tagsClasses = raw.tags_classes || [];
  const tags = tagsClasses.flatMap(tc => tc.tags || []);
  const isMalicious = raw.is_malicious === true;
  return {
    found: isMalicious,
    is_malicious: isMalicious,
    threat_type: judgments.join(','),
    confidence: raw.confidence_level || 'low',
    severity: raw.severity || 'info',
    tags,
    permalink: raw.permalink || '',
    update_time: raw.update_time || '',
    reasoning: isMalicious
      ? `ThreatBook 判定恶意，威胁类型: ${judgments.join(',')}`
      : 'ThreatBook 判定非恶意'
  };
}

function buildUrl(endpoint, params) {
  const config = getThreatBookConfig();
  const url = new URL(config.baseUrl + endpoint);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }
  return url.toString();
}

function getApiKey() {
  return getThreatBookConfig().apiKey;
}

function getTimeout() {
  return getThreatBookConfig().timeout;
}

function getBatchSize() {
  return getThreatBookConfig().batchSize;
}

function getLang() {
  return getThreatBookConfig().lang;
}

export async function queryIP(ipOrIpArray) {
  const apiKey = getApiKey();
  if (!apiKey) {
    return { found: false, error_code: 'API_KEY_MISSING', reasoning: 'THREATBOOK_API_KEY 未配置' };
  }

  const timeout = getTimeout();
  const batchSize = getBatchSize();
  const lang = getLang();

  let ips = Array.isArray(ipOrIpArray) ? [...ipOrIpArray] : [ipOrIpArray];
  let truncated = false;
  let truncatedCount = 0;
  if (ips.length > batchSize) {
    truncatedCount = ips.length - batchSize;
    ips = ips.slice(0, batchSize);
    truncated = true;
  }

  const resource = ips.join(',');
  const url = buildUrl('/scene/ip_reputation', { apikey: apiKey, resource, lang });

  let resp;
  try {
    resp = await doRequest(url, timeout);
  } catch (err) {
    const code = err.code === 'DNS_FAILURE' ? 'DNS_FAILURE' : 'NETWORK_TIMEOUT';
    return { found: false, error_code: code, reasoning: err.message || String(err) };
  }

  if (resp.statusCode < 200 || resp.statusCode >= 300) {
    return { found: false, error_code: `HTTP_${resp.statusCode}`, reasoning: `HTTP ${resp.statusCode}: ${resp.body?.slice(0, 200)}` };
  }

  let parsed;
  try {
    parsed = JSON.parse(resp.body);
  } catch {
    return { found: false, error_code: 'JSON_PARSE_ERROR', reasoning: '响应非合法 JSON' };
  }

  if (parsed.response_code !== 0) {
    const errorCode = classifyError(parsed.response_code, parsed.verbose_msg);
    return { found: false, error_code: errorCode, reasoning: parsed.verbose_msg || `response_code=${parsed.response_code}` };
  }

  const dataMap = parsed.data || {};
  const results = {};
  for (const ip of ips) {
    const raw = dataMap[ip];
    if (raw) {
      results[ip] = normalizeIpData(ip, raw);
    } else {
      results[ip] = { ip, found: false, is_malicious: false, reasoning: 'ThreatBook 无此 IP 数据' };
    }
  }

  if (!Array.isArray(ipOrIpArray)) {
    return results[ips[0]];
  }

  const returnObj = { results };
  if (truncated) {
    returnObj.truncated = true;
    returnObj.truncated_count = truncatedCount;
  }
  return returnObj;
}

export async function queryFile(hash) {
  const apiKey = getApiKey();
  if (!apiKey) {
    return { found: false, error_code: 'API_KEY_MISSING', reasoning: 'THREATBOOK_API_KEY 未配置' };
  }

  const timeout = getTimeout();
  const lang = getLang();
  const url = buildUrl('/file/report', { apikey: apiKey, resource: hash, lang });

  let resp;
  try {
    resp = await doRequest(url, timeout);
  } catch (err) {
    const code = err.code === 'DNS_FAILURE' ? 'DNS_FAILURE' : 'NETWORK_TIMEOUT';
    return { found: false, error_code: code, reasoning: err.message || String(err) };
  }

  if (resp.statusCode < 200 || resp.statusCode >= 300) {
    return { found: false, error_code: `HTTP_${resp.statusCode}`, reasoning: `HTTP ${resp.statusCode}` };
  }

  let parsed;
  try {
    parsed = JSON.parse(resp.body);
  } catch {
    return { found: false, error_code: 'JSON_PARSE_ERROR', reasoning: '响应非合法 JSON' };
  }

  if (parsed.response_code !== 0) {
    const errorCode = classifyError(parsed.response_code, parsed.verbose_msg);
    return { found: false, error_code: errorCode, reasoning: parsed.verbose_msg || '' };
  }

  const dataMap = parsed.data || {};
  const raw = dataMap[hash];
  if (raw) {
    return { hash, ...normalizeGenericData(hash, raw) };
  }
  return { hash, found: false, is_malicious: false, reasoning: 'ThreatBook 无此 Hash 数据' };
}

export async function queryDomain(domain) {
  const apiKey = getApiKey();
  if (!apiKey) {
    return { found: false, error_code: 'API_KEY_MISSING', reasoning: 'THREATBOOK_API_KEY 未配置' };
  }

  const timeout = getTimeout();
  const lang = getLang();
  const url = buildUrl('/domain/report', { apikey: apiKey, resource: domain, lang });

  let resp;
  try {
    resp = await doRequest(url, timeout);
  } catch (err) {
    const code = err.code === 'DNS_FAILURE' ? 'DNS_FAILURE' : 'NETWORK_TIMEOUT';
    return { found: false, error_code: code, reasoning: err.message || String(err) };
  }

  if (resp.statusCode < 200 || resp.statusCode >= 300) {
    return { found: false, error_code: `HTTP_${resp.statusCode}`, reasoning: `HTTP ${resp.statusCode}` };
  }

  let parsed;
  try {
    parsed = JSON.parse(resp.body);
  } catch {
    return { found: false, error_code: 'JSON_PARSE_ERROR', reasoning: '响应非合法 JSON' };
  }

  if (parsed.response_code !== 0) {
    const errorCode = classifyError(parsed.response_code, parsed.verbose_msg);
    return { found: false, error_code: errorCode, reasoning: parsed.verbose_msg || '' };
  }

  const dataMap = parsed.data || {};
  const raw = dataMap[domain];
  if (raw) {
    return { domain, ...normalizeGenericData(domain, raw) };
  }
  return { domain, found: false, is_malicious: false, reasoning: 'ThreatBook 无此域名数据' };
}

export default {
  queryIP,
  queryFile,
  queryDomain,
  setRequestFn
};
