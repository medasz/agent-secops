/**
 * es-query.js - ES query helper using native http module
 *
 * Reads connection config from scripts/.env file.
 * Follows the pattern established by es-tool/extract.js.
 *
 * Layered responsibilities (see design doc §1.1):
 *   - Low-level transport:   requestES(method, path, body, config)
 *   - Convenience search:    esQuery(index, body, config)
 *   - PIT adapter factory:   createEsRequest(config)  -> (method, path, body) => Promise
 *   - Declarative context:   CONTEXT_FILTERS + buildQuery(ctx, timeRange) + buildContextQuery(...)
 */
import http from 'http';
import { getEsConfig } from './env.js';

// Re-export getEsConfig from env.js for backward compatibility
export { getEsConfig };

/**
 * Execute an arbitrary ES HTTP request (low-level transport).
 * @param {string} method - HTTP method (GET/POST/PUT/DELETE)
 * @param {string} path - Request path (e.g. '/_pit', '/index/_search', '/')
 * @param {object|null} body - Optional JSON request body
 * @param {object} [config] - Optional ES config override
 * @returns {Promise<object>} Parsed ES response
 */
export function requestES(method, path, body = null, config = null) {
  const esConfig = config || getEsConfig();

  return new Promise((resolve, reject) => {
    const postData = body ? JSON.stringify(body) : '';
    const auth = Buffer.from(`${esConfig.username}:${esConfig.password}`).toString('base64');

    const options = {
      hostname: esConfig.host,
      port: esConfig.port,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        'Authorization': `Basic ${auth}`,
      },
    };

    const req = http.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const data = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 400) {
          reject(new Error(`ES error (${res.statusCode}): ${data}`));
          return;
        }
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`ES response parse error: ${e.message}`));
        }
      });
    });

    req.on('error', (err) => {
      reject(new Error(`ES connection error: ${err.message}`));
    });

    req.setTimeout(30000, () => {
      req.destroy();
      reject(new Error('ES request timeout (30s)'));
    });

    req.write(postData);
    req.end();
  });
}

/**
 * Execute an ES search query against an index.
 * @param {string} index - Index name
 * @param {object} body - Query body (will be JSON-stringified)
 * @param {object} [config] - Optional ES config override
 * @returns {Promise<object>} Parsed ES response
 */
export function esQuery(index, body, config = null) {
  return requestES('POST', `/${index}/_search`, body, config);
}

/**
 * Build a PIT-compatible ES request function (method, path, body) => Promise.
 *
 * Faithful port of the former extract.js `createEsRequest`: used by paginate.js
 * which calls it with ('GET','/',{}), ('POST','/_pit',{...}),
 * ('DELETE','/_pit',{id}), ('POST',`/${index}/_search`,body).
 *
 * @param {object} [config] - Optional ES config override
 * @returns {(method:string, path:string, body?:object) => Promise<object>}
 */
export function createEsRequest(config = null) {
  return (method, path, body) => requestES(method, path, body, config);
}

/**
 * Declarative context filters (eliminates if/else business branches in callers).
 * Each context maps to an array of ES filter clause objects.
 */
export const CONTEXT_FILTERS = {
  // 外部攻击：排除源地址为局域网的告警
  external: [
    { bool: { must_not: [{ term: { 'field_values.sip_addr': '局域网' } }] } },
  ],
  // 内部攻击：源地址为局域网
  internal: [
    { term: { 'field_values.sip_addr': '局域网' } },
  ],
  // 失陷/攻击成功：host_state ∈ {攻击成功, 失陷}
  compromised: [
    { terms: { 'field_values.host_state': ['攻击成功', '失陷'] } },
  ],
  // 全量（不过滤上下文）
  all: [],
};

/**
 * Data-driven query builder.
 * @param {('external'|'internal'|'compromised'|'all')} [ctx='all'] - Query context
 * @param {object} [timeRange] - { startMs, endMs } | { hours } (backwards compat)
 * @returns {{ bool: { filter: object[] } }}
 */
export function buildQuery(ctx = 'all', timeRange = {}) {
  const filters = [];

  if (timeRange.startMs != null && timeRange.endMs != null) {
    filters.push({ range: { timestamp: { gte: timeRange.startMs, lte: timeRange.endMs } } });
  } else if (timeRange.hours != null) {
    filters.push({ range: { timestamp: { gte: Date.now() - timeRange.hours * 3600_000 } } });
  }

  const ctxFilters = CONTEXT_FILTERS[ctx] || CONTEXT_FILTERS.all;
  return { bool: { filter: [...filters, ...ctxFilters] } };
}

/**
 * Build a full search body wrapping buildQuery with aggregations (for self-run CLI reuse).
 * @param {('external'|'internal'|'compromised'|'all')} [ctx='all'] - Query context
 * @param {object} [timeRange] - { startMs, endMs } | { hours }
 * @param {object} [aggs={}] - Aggregation DSL
 * @returns {object} ES search body
 */
export function buildContextQuery(ctx = 'all', timeRange = {}, aggs = {}) {
  return {
    query: buildQuery(ctx, timeRange),
    aggs,
    size: 0,
    track_total_hits: true,
  };
}
