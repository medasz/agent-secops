import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import http from 'node:http';

let capturedOptions = null;
let origHttpsRequest = null;
let origHttpRequest = null;

function mockRequest(statusCode, body) {
  return function (options, callback) {
    capturedOptions = options;
    const res = {
      statusCode,
      on(event, cb) {
        if (event === 'data') cb(body);
        else if (event === 'end') setTimeout(cb, 0);
      },
      setEncoding() {},
    };
    return {
      on() { return this; },
      setTimeout() { return this; },
      end() { if (callback) setTimeout(() => callback(res), 0); },
    };
  };
}

function mockErrorRequest(error) {
  return function (options, callback) {
    capturedOptions = options;
    return {
      on(event, cb) {
        if (event === 'error') setTimeout(() => cb(error), 0);
        return this;
      },
      setTimeout() { return this; },
      end() {},
    };
  };
}

describe('proxy.js - createProxiedRequest', () => {
  beforeEach(() => {
    process.env.PROXY_HOST = '192.0.2.34';
    process.env.PROXY_PORT = '443';
    process.env.PROXY_TLS = 'true';
    capturedOptions = null;
    origHttpsRequest = https.request;
    origHttpRequest = http.request;
  });

  afterEach(() => {
    delete process.env.PROXY_HOST;
    delete process.env.PROXY_PORT;
    delete process.env.PROXY_TLS;
    if (origHttpsRequest) https.request = origHttpsRequest;
    if (origHttpRequest) http.request = origHttpRequest;
  });

  it('createProxiedRequest 返回函数', async () => {
    const mod = await import('../../skills/secops-alert-analysis/scripts/shared/proxy.js?t=' + Date.now());
    const fn = mod.createProxiedRequest();
    assert.equal(typeof fn, 'function');
  });

  it('连接目标重写为 PROXY_HOST:PROXY_PORT', async () => {
    https.request = mockRequest(200, '{"response_code":0}');
    const mod = await import('../../skills/secops-alert-analysis/scripts/shared/proxy.js?t=' + Date.now());
    const proxiedRequest = mod.createProxiedRequest();

    await proxiedRequest('https://api.threatbook.cn/v3/scene/ip_reputation?apikey=xxx', { timeout: 5000 });

    assert.ok(capturedOptions, '请求应被捕获');
    assert.equal(capturedOptions.hostname, '192.0.2.34');
    assert.equal(capturedOptions.port, 443);
  });

  it('Host 头保留原始域名', async () => {
    https.request = mockRequest(200, '{"response_code":0}');
    const mod = await import('../../skills/secops-alert-analysis/scripts/shared/proxy.js?t=' + Date.now());
    const proxiedRequest = mod.createProxiedRequest();

    await proxiedRequest('https://api.threatbook.cn/v3/scene/ip_reputation?apikey=xxx', { timeout: 5000 });

    assert.equal(capturedOptions.headers['Host'], 'api.threatbook.cn');
  });

  it('路径和查询参数保持不变', async () => {
    https.request = mockRequest(200, '{"response_code":0}');
    const mod = await import('../../skills/secops-alert-analysis/scripts/shared/proxy.js?t=' + Date.now());
    const proxiedRequest = mod.createProxiedRequest();

    await proxiedRequest('https://api.threatbook.cn/v3/scene/ip_reputation?apikey=xxx', { timeout: 5000 });

    assert.equal(capturedOptions.path, '/v3/scene/ip_reputation?apikey=xxx');
  });

  it('rejectUnauthorized 设为 false（跳过 TLS 验证）', async () => {
    https.request = mockRequest(200, '{"response_code":0}');
    const mod = await import('../../skills/secops-alert-analysis/scripts/shared/proxy.js?t=' + Date.now());
    const proxiedRequest = mod.createProxiedRequest();

    await proxiedRequest('https://api.threatbook.cn/v3/scene/ip_reputation?apikey=xxx', { timeout: 5000 });

    assert.equal(capturedOptions.rejectUnauthorized, false);
  });

  it('返回 { statusCode, body } 格式', async () => {
    https.request = mockRequest(200, '{"response_code":0}');
    const mod = await import('../../skills/secops-alert-analysis/scripts/shared/proxy.js?t=' + Date.now());
    const proxiedRequest = mod.createProxiedRequest();

    const result = await proxiedRequest('https://api.threatbook.cn/v3/scene/ip_reputation?apikey=xxx', { timeout: 5000 });

    assert.equal(typeof result.statusCode, 'number');
    assert.equal(typeof result.body, 'string');
  });

  it('PROXY_TLS=false 时使用 http 模块', async () => {
    process.env.PROXY_TLS = 'false';

    let httpUsed = false;
    http.request = function (options, callback) {
      httpUsed = true;
      capturedOptions = options;
      const res = {
        statusCode: 200,
        on(event, cb) {
          if (event === 'data') cb('{"response_code":0}');
          else if (event === 'end') setTimeout(cb, 0);
        },
        setEncoding() {},
      };
      return {
        on() { return this; },
        setTimeout() { return this; },
        end() { if (callback) setTimeout(() => callback(res), 0); },
      };
    };

    const mod = await import('../../skills/secops-alert-analysis/scripts/shared/proxy.js?t=' + Date.now());
    const proxiedRequest = mod.createProxiedRequest();

    await proxiedRequest('https://api.threatbook.cn/v3/scene/ip_reputation?apikey=xxx', { timeout: 5000 });

    assert.ok(httpUsed, '应使用 http 模块');
  });

  it('网络错误返回 DNS_FAILURE 错误码', async () => {
    https.request = mockErrorRequest(Object.assign(new Error('dns'), { code: 'ENOTFOUND' }));
    const mod = await import('../../skills/secops-alert-analysis/scripts/shared/proxy.js?t=' + Date.now());
    const proxiedRequest = mod.createProxiedRequest();

    await assert.rejects(
      proxiedRequest('https://api.threatbook.cn/v3/scene/ip_reputation?apikey=xxx', { timeout: 5000 }),
      (err) => err.code === 'DNS_FAILURE'
    );
  });

  it('超时错误返回 NETWORK_TIMEOUT 错误码', async () => {
    https.request = mockErrorRequest(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }));
    const mod = await import('../../skills/secops-alert-analysis/scripts/shared/proxy.js?t=' + Date.now());
    const proxiedRequest = mod.createProxiedRequest();

    await assert.rejects(
      proxiedRequest('https://api.threatbook.cn/v3/scene/ip_reputation?apikey=xxx', { timeout: 5000 }),
      (err) => err.code === 'NETWORK_TIMEOUT'
    );
  });
});
