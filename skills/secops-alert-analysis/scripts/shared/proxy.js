import https from 'https';
import http from 'http';
import { getProxyConfig } from './env.js';

export function createProxiedRequest() {
  return function proxiedRequest(url, { timeout } = {}) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const proxyConfig = getProxyConfig();
      const proxyHost = proxyConfig.host;
      const proxyPort = proxyConfig.port;
      const proxyTls = proxyConfig.tls;
      const mod = proxyTls ? https : http;

      const options = {
        hostname: proxyHost,
        port: proxyPort,
        path: parsed.pathname + parsed.search,
        method: 'GET',
        headers: {
          'Host': parsed.hostname,
        },
        rejectUnauthorized: false,
        timeout,
      };

      const req = mod.request(options, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          resolve({ statusCode: res.statusCode, body });
        });
        res.on('error', (err) => reject(err));
      });

      let timedOut = false;

      req.on('error', (err) => {
        if (timedOut) return;
        if (err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN') {
          reject(Object.assign(new Error('dns'), { code: 'DNS_FAILURE' }));
        } else if (err.code === 'ETIMEDOUT' || err.message.includes('timeout')) {
          reject(Object.assign(new Error('timeout'), { code: 'NETWORK_TIMEOUT' }));
        } else {
          reject(err);
        }
      });

      req.on('timeout', () => {
        timedOut = true;
        req.destroy();
        reject(Object.assign(new Error('timeout'), { code: 'NETWORK_TIMEOUT' }));
      });

      req.end();
    });
  };
}

export default { createProxiedRequest };
