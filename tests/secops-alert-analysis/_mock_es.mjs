/**
 * _mock_es.mjs - 测试用 mock Elasticsearch HTTP 服务
 *
 * 仅供 tests/secops-alert-analysis 下的单测使用。
 * 通过原生 http 模块起一个监听 127.0.0.1:0 的本地服务，
 * 由 handler(reqBody, req) 返回响应对象（会被 JSON 序列化并以 200 返回）。
 *
 * 设计要点：
 *  - handler 可读取 esQuery 实际发出的 query body，从而"聪明地"根据 DSL 字段
 *    返回不同聚合结果（用于验证字段映射修复）。
 *  - 返回合法 JSON 但缺少 aggregations，可触发上游 exit code 3（解析错误路径）。
 */
import http from 'http';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * 解析用于 spawnSync 的 node 可执行文件路径。
 * - 优先取 process.env.MANAGED_NODE（受控 node），缺省回退系统 'node'。
 * - Windows 下 Git Bash 传入的 /c/... 形式无法被 spawnSync 直接执行（ENOENT），
 *   需转为反斜杠形式。
 * @returns {string}
 */
export function nodeBin() {
  let raw = process.env.MANAGED_NODE || 'node';
  if (process.platform === 'win32') {
    // 将 Git Bash 的 /c/... 形式转为 C:\...（驱动盘符映射）
    raw = raw.replace(/^\/([a-zA-Z])\//, '$1:\\');
    raw = raw.replace(/\//g, '\\');
  }
  return raw;
}

// 测试统一引用路径前缀（tests/secops-alert-analysis → skills/secops-alert-analysis）
export const SKILL_ROOT = join(__dirname, '..', '..', 'skills', 'secops-alert-analysis');

/**
 * 启动 mock ES 服务
 * @param {(reqBody: object, req: IncomingMessage) => object} handler
 *   接收解析后的 ES query body，返回响应对象（默认 {}）
 * @returns {Promise<{ port: number, close: () => Promise<void>, server: http.Server, requests: Array<object> }>}
 */
export function startMockEs(handler) {
  return new Promise((resolve) => {
    const requests = [];
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        let parsed = {};
        try {
          parsed = body ? JSON.parse(body) : {};
        } catch {
          parsed = {};
        }
        requests.push(parsed);
        const responseObj = handler ? handler(parsed, req) : {};
        const payload = JSON.stringify(responseObj ?? {});
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(payload);
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        port,
        server,
        requests,
        close: () =>
          new Promise((r) => server.close(() => r())),
      });
    });
  });
}

/**
 * 构造 dns-agg.js 期望的聚合响应骨架
 * @param {object} opts
 * @param {Array<{key:string,doc_count:number,attack_types?:Array<{type:string,count:number}>,max_value?:number}>} [opts.alerts]
 * @param {Array<{key:string,doc_count:number}>} [opts.domains] 全量 DNS 域名（会被按 terms.size 截断）
 * @returns {object} ES 响应（含 aggregations）
 */
export function buildDnsAggResponse(opts = {}) {
  const alerts = opts.alerts || [];
  const domains = opts.domains || [];

  const alertBuckets = alerts.map((a) => ({
    key: a.key,
    doc_count: a.doc_count,
    by_attack_type: {
      buckets: (a.attack_types || []).map((t) => ({ key: t.type, doc_count: t.count })),
    },
    max_timestamp: { value: a.max_value ?? 1752000000000 },
  }));

  // dns_domains 子聚合尊重 DSL 中的 terms.size（Top N 截断）
  return {
    aggregations: {
      dns_alerts_by_ioc: { buckets: alertBuckets },
      dns_domains: {
        dns_traffic: {
          by_ioc: {
            // size 在 handler 中按 query 截取；此处返回全量，由调用方截断
            buckets: domains.map((d) => ({
              key: d.key,
              doc_count: d.doc_count,
              domain_max_timestamp: { value: 1752000000000 + d.doc_count },
            })),
          },
        },
      },
    },
  };
}
