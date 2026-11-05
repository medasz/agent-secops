import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';

let httpClient = null;
let lastRequestUrl = null;
let lastRequestOptions = null;

beforeEach(() => {
  process.env.THREATBOOK_API_KEY = 'test-key-123';
  process.env.THREATBOOK_BASE_URL = 'https://api.threatbook.cn/v3';
  process.env.THREATBOOK_LANG = 'zh';
  process.env.THREATBOOK_TIMEOUT = '5000';
  process.env.THREATBOOK_BATCH_SIZE = '100';
  lastRequestUrl = null;
  lastRequestOptions = null;
  httpClient = null;
});

afterEach(() => {
  delete process.env.THREATBOOK_API_KEY;
  delete process.env.THREATBOOK_BASE_URL;
  delete process.env.THREATBOOK_LANG;
  delete process.env.THREATBOOK_TIMEOUT;
  delete process.env.THREATBOOK_BATCH_SIZE;
});

function setMockClient(mod) {
  httpClient = mod;
}

async function importClient() {
  const mod = await import('../../skills/secops-alert-analysis/scripts/threat-intel/client.js?t=' + Date.now());
  return mod;
}

function mockResponse(data) {
  return { __mock: true, data };
}

describe('client.js', () => {
  describe('queryIP', () => {
    it('单个 IP 成功查询（response_code=0）返回归一化结果', async () => {
      const apiResponse = {
        response_code: 0,
        verbose_msg: 'Ok',
        data: {
          '121.207.85.140': {
            is_malicious: true,
            confidence_level: 'high',
            severity: 'medium',
            judgments: ['Dynamic IP', 'Zombie', 'Spam'],
            tags_classes: [{ tags_type: 'gangs', tags: ['Mirai'] }],
            basic: {
              carrier: 'China Telecom',
              location: { country: 'China', province: 'Fujian', city: 'Quanzhou City' }
            },
            scene: 'Residence',
            update_time: '2024-10-17 14:29:48',
            permalink: 'https://x.threatbook.com/v5/ip/121.207.85.140'
          }
        }
      };
      process.env.__MOCK_RESPONSE = JSON.stringify(apiResponse);
      const { queryIP, setRequestFn } = await importClient();
      setRequestFn(async (url, opts) => {
        lastRequestUrl = url;
        lastRequestOptions = opts;
        return { statusCode: 200, body: JSON.stringify(apiResponse) };
      });

      const result = await queryIP('121.207.85.140');
      assert.equal(result.found, true);
      assert.equal(result.is_malicious, true);
      assert.equal(result.confidence, 'high');
      assert.equal(result.severity, 'medium');
      assert.equal(result.threat_type, 'Dynamic IP,Zombie,Spam');
      assert.deepEqual(result.tags, ['Mirai']);
      assert.equal(result.scene, 'Residence');
      assert.equal(result.geo, 'China,Fujian,Quanzhou City');
      assert.equal(result.carrier, 'China Telecom');
      assert.equal(result.permalink, 'https://x.threatbook.com/v5/ip/121.207.85.140');
      assert.equal(result.update_time, '2024-10-17 14:29:48');
      assert.ok(result.reasoning.includes('Zombie'));
    });

    it('批量 IP 查询（resource 逗号分隔）', async () => {
      const apiResponse = {
        response_code: 0,
        verbose_msg: 'Ok',
        data: {
          '1.1.1.1': { is_malicious: false, confidence_level: 'low', judgments: [], tags_classes: [] },
          '2.2.2.2': { is_malicious: true, confidence_level: 'medium', judgments: ['Spam'], tags_classes: [] }
        }
      };
      const { queryIP, setRequestFn } = await importClient();
      setRequestFn(async (url) => {
        lastRequestUrl = url;
        const u = new URL(url);
        assert.equal(u.searchParams.get('resource'), '1.1.1.1,2.2.2.2');
        return { statusCode: 200, body: JSON.stringify(apiResponse) };
      });

      const result = await queryIP(['1.1.1.1', '2.2.2.2']);
      assert.ok(result.results, 'should have results map');
      assert.equal(result.results['1.1.1.1'].found, false);
      assert.equal(result.results['2.2.2.2'].found, true);
      assert.equal(result.results['2.2.2.2'].is_malicious, true);
    });

    it('response_code=0 但 data map 缺少某 IP → 该 IP found:false', async () => {
      const apiResponse = {
        response_code: 0,
        verbose_msg: 'Ok',
        data: { '1.1.1.1': { is_malicious: false, confidence_level: 'low', judgments: [], tags_classes: [] } }
      };
      const { queryIP, setRequestFn } = await importClient();
      setRequestFn(async () => ({ statusCode: 200, body: JSON.stringify(apiResponse) }));

      const result = await queryIP(['1.1.1.1', '9.9.9.9']);
      assert.equal(result.results['1.1.1.1'].found, false);
      assert.equal(result.results['9.9.9.9'].found, false);
      assert.ok(result.results['9.9.9.9'].reasoning);
    });

    it('response_code!=0 + verbose_msg 含 "apikey" → IP_BINDING_MISMATCH', async () => {
      const apiResponse = { response_code: 1401, verbose_msg: 'apikey invalid or unauthorized' };
      const { queryIP, setRequestFn } = await importClient();
      setRequestFn(async () => ({ statusCode: 200, body: JSON.stringify(apiResponse) }));

      const result = await queryIP('8.8.8.8');
      assert.equal(result.found, false);
      assert.equal(result.error_code, 'IP_BINDING_MISMATCH');
    });

    it('response_code!=0 + verbose_msg 含 "quota" → QUOTA_EXHAUSTED', async () => {
      const apiResponse = { response_code: 1403, verbose_msg: 'API quota exceeded' };
      const { queryIP, setRequestFn } = await importClient();
      setRequestFn(async () => ({ statusCode: 200, body: JSON.stringify(apiResponse) }));

      const result = await queryIP('8.8.8.8');
      assert.equal(result.found, false);
      assert.equal(result.error_code, 'QUOTA_EXHAUSTED');
    });

    it('response_code!=0 + verbose_msg 含 "expire" → SUBSCRIPTION_EXPIRED', async () => {
      const apiResponse = { response_code: 1404, verbose_msg: 'subscription expired' };
      const { queryIP, setRequestFn } = await importClient();
      setRequestFn(async () => ({ statusCode: 200, body: JSON.stringify(apiResponse) }));

      const result = await queryIP('8.8.8.8');
      assert.equal(result.found, false);
      assert.equal(result.error_code, 'SUBSCRIPTION_EXPIRED');
    });

    it('response_code!=0 + 其他 → API_ERROR_{code}', async () => {
      const apiResponse = { response_code: 1500, verbose_msg: 'internal error' };
      const { queryIP, setRequestFn } = await importClient();
      setRequestFn(async () => ({ statusCode: 200, body: JSON.stringify(apiResponse) }));

      const result = await queryIP('8.8.8.8');
      assert.equal(result.found, false);
      assert.equal(result.error_code, 'API_ERROR_1500');
    });

    it('网络超时 → NETWORK_TIMEOUT', async () => {
      const { queryIP, setRequestFn } = await importClient();
      setRequestFn(async () => {
        throw new Error('timeout');
      });

      const result = await queryIP('8.8.8.8');
      assert.equal(result.found, false);
      assert.equal(result.error_code, 'NETWORK_TIMEOUT');
    });

    it('HTTP 4xx → HTTP_4xx', async () => {
      const { queryIP, setRequestFn } = await importClient();
      setRequestFn(async () => ({ statusCode: 403, body: 'Forbidden' }));

      const result = await queryIP('8.8.8.8');
      assert.equal(result.found, false);
      assert.equal(result.error_code, 'HTTP_403');
    });

    it('HTTP 5xx → HTTP_5xx', async () => {
      const { queryIP, setRequestFn } = await importClient();
      setRequestFn(async () => ({ statusCode: 502, body: 'Bad Gateway' }));

      const result = await queryIP('8.8.8.8');
      assert.equal(result.found, false);
      assert.equal(result.error_code, 'HTTP_502');
    });

    it('JSON 解析失败 → JSON_PARSE_ERROR', async () => {
      const { queryIP, setRequestFn } = await importClient();
      setRequestFn(async () => ({ statusCode: 200, body: 'not-json{' }));

      const result = await queryIP('8.8.8.8');
      assert.equal(result.found, false);
      assert.equal(result.error_code, 'JSON_PARSE_ERROR');
    });

    it('API Key 缺失 → API_KEY_MISSING', async () => {
      delete process.env.THREATBOOK_API_KEY;
      const { queryIP } = await importClient();

      const result = await queryIP('8.8.8.8');
      assert.equal(result.found, false);
      assert.equal(result.error_code, 'API_KEY_MISSING');
    });

    it('批量超过 100 IP → 自动截断为 100', async () => {
      const ips = Array.from({ length: 150 }, (_, i) => `${i}.${i}.${i}.${i}`.replace(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/, (m, a, b, c, d) => `${a % 256}.${b % 256}.${c % 256}.${d % 256}`));
      const apiResponse = { response_code: 0, verbose_msg: 'Ok', data: {} };
      const { queryIP, setRequestFn } = await importClient();
      let resourceParam = null;
      setRequestFn(async (url) => {
        const u = new URL(url);
        resourceParam = u.searchParams.get('resource');
        return { statusCode: 200, body: JSON.stringify(apiResponse) };
      });

      const result = await queryIP(ips);
      const resourceIps = resourceParam.split(',');
      assert.ok(resourceIps.length <= 100, 'should be truncated to 100');
      assert.equal(result.truncated, true);
      assert.equal(result.truncated_count, 50);
    });
  });

  describe('queryFile', () => {
    it('Hash 查询成功返回归一化结果', async () => {
      const apiResponse = {
        response_code: 0,
        verbose_msg: 'Ok',
        data: {
          'abc123hash': {
            is_malicious: true,
            confidence_level: 'high',
            severity: 'high',
            judgments: ['Trojan'],
            tags_classes: [{ tags_type: 'family', tags: ['Emotet'] }],
            update_time: '2024-10-17 14:29:48',
            permalink: 'https://x.threatbook.com/v5/file/abc123hash'
          }
        }
      };
      const { queryFile, setRequestFn } = await importClient();
      setRequestFn(async (url) => {
        assert.ok(url.includes('/file/report'), 'should use file report endpoint');
        return { statusCode: 200, body: JSON.stringify(apiResponse) };
      });

      const result = await queryFile('abc123hash');
      assert.equal(result.found, true);
      assert.equal(result.is_malicious, true);
      assert.equal(result.threat_type, 'Trojan');
      assert.equal(result.confidence, 'high');
      assert.deepEqual(result.tags, ['Emotet']);
    });

    it('Hash 查询未命中返回 found:false', async () => {
      const apiResponse = { response_code: 0, verbose_msg: 'Ok', data: {} };
      const { queryFile, setRequestFn } = await importClient();
      setRequestFn(async () => ({ statusCode: 200, body: JSON.stringify(apiResponse) }));

      const result = await queryFile('unknownhash');
      assert.equal(result.found, false);
    });
  });

  describe('queryDomain', () => {
    it('域名查询成功返回归一化结果', async () => {
      const apiResponse = {
        response_code: 0,
        verbose_msg: 'Ok',
        data: {
          'evil.com': {
            is_malicious: true,
            confidence_level: 'medium',
            severity: 'medium',
            judgments: ['Phishing'],
            tags_classes: [{ tags_type: 'gangs', tags: ['APT29'] }],
            update_time: '2024-10-17 14:29:48',
            permalink: 'https://x.threatbook.com/v5/domain/evil.com'
          }
        }
      };
      const { queryDomain, setRequestFn } = await importClient();
      setRequestFn(async (url) => {
        assert.ok(url.includes('/domain/report'), 'should use domain report endpoint');
        return { statusCode: 200, body: JSON.stringify(apiResponse) };
      });

      const result = await queryDomain('evil.com');
      assert.equal(result.found, true);
      assert.equal(result.is_malicious, true);
      assert.equal(result.threat_type, 'Phishing');
      assert.equal(result.confidence, 'medium');
      assert.deepEqual(result.tags, ['APT29']);
    });

    it('域名查询未命中返回 found:false', async () => {
      const apiResponse = { response_code: 0, verbose_msg: 'Ok', data: {} };
      const { queryDomain, setRequestFn } = await importClient();
      setRequestFn(async () => ({ statusCode: 200, body: JSON.stringify(apiResponse) }));

      const result = await queryDomain('unknown.com');
      assert.equal(result.found, false);
    });
  });

  describe('proxy auto-initialization', () => {
    afterEach(() => {
      delete process.env.ENABLE_PROXY;
      delete process.env.PROXY_HOST;
      delete process.env.PROXY_PORT;
      delete process.env.PROXY_TLS;
    });

    it('ENABLE_PROXY=true 时请求走代理（hostname 为 PROXY_HOST）', async () => {
      process.env.ENABLE_PROXY = 'true';
      process.env.PROXY_HOST = '192.0.2.34';
      process.env.PROXY_PORT = '443';
      process.env.PROXY_TLS = 'true';

      let capturedHostname = null;
      const origRequest = https.request;
      const origGet = https.get;

      const mockFn = function (...args) {
        const options = args[0];
        let callback;

        if (typeof options === 'string') {
          try {
            const parsed = new URL(options);
            capturedHostname = parsed.hostname;
          } catch {
            capturedHostname = options;
          }
          callback = args[2];
        } else if (options && typeof options === 'object') {
          capturedHostname = options.hostname;
          callback = args[1];
        }

        const res = {
          statusCode: 200,
          on(event, cb) {
            if (event === 'data') cb(JSON.stringify({ response_code: 0, verbose_msg: 'Ok', data: {} }));
            else if (event === 'end') setTimeout(cb, 0);
          },
          setEncoding() {},
        };

        if (callback) setTimeout(() => callback(res), 0);

        return {
          on() { return this; },
          setTimeout() { return this; },
          end() { return this; },
        };
      };

      https.request = mockFn;
      https.get = mockFn;

      try {
        const mod = await importClient();
        await mod.queryIP('8.8.8.8');
        assert.equal(capturedHostname, '192.0.2.34', '请求 hostname 应为代理地址');
      } finally {
        https.request = origRequest;
        https.get = origGet;
      }
    });

    it('ENABLE_PROXY=false 时请求走 defaultRequest（hostname 为原始域名）', async () => {
      process.env.ENABLE_PROXY = 'false';

      let capturedHostname = null;
      const origRequest = https.request;
      const origGet = https.get;

      const mockFn = function (...args) {
        const options = args[0];
        let callback;

        if (typeof options === 'string') {
          try {
            const parsed = new URL(options);
            capturedHostname = parsed.hostname;
          } catch {
            capturedHostname = options;
          }
          callback = args[2];
        } else if (options && typeof options === 'object') {
          capturedHostname = options.hostname;
          callback = args[1];
        }

        const res = {
          statusCode: 200,
          on(event, cb) {
            if (event === 'data') cb(JSON.stringify({ response_code: 0, verbose_msg: 'Ok', data: {} }));
            else if (event === 'end') setTimeout(cb, 0);
          },
          setEncoding() {},
        };

        if (callback) setTimeout(() => callback(res), 0);

        return {
          on() { return this; },
          setTimeout() { return this; },
          end() { return this; },
        };
      };

      https.request = mockFn;
      https.get = mockFn;

      try {
        const mod = await importClient();
        await mod.queryIP('8.8.8.8');
        assert.notEqual(capturedHostname, '192.0.2.34', '请求 hostname 不应为代理地址');
        assert.ok(capturedHostname, '请求应被发出');
      } finally {
        https.request = origRequest;
        https.get = origGet;
      }
    });
  });
});
