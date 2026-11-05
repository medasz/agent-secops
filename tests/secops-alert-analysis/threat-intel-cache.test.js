import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { getCache, setCache, cleanup, closeCache } from '../../skills/secops-alert-analysis/scripts/threat-intel/cache.js';
import fs from 'fs';
import path from 'path';
import os from 'os';

const TEST_DB = path.join(os.tmpdir(), `test-threatbook-cache-${Date.now()}.sqlite`);

beforeEach(() => {
  process.env.THREATBOOK_CACHE_PATH = TEST_DB;
  process.env.THREATBOOK_CACHE_TTL = '2';
});

afterEach(() => {
  closeCache();
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
});

describe('cache.js', () => {
  describe('setCache + getCache', () => {
    it('写入后立即读取返回相同数据', () => {
      const data = { is_malicious: true, confidence: 'high' };
      setCache('threatbook', 'ip', '8.8.8.8', data);
      const result = getCache('threatbook', 'ip', '8.8.8.8');
      assert.deepEqual(result, data);
    });

    it('不同 source/type/value 互不干扰', () => {
      setCache('threatbook', 'ip', '1.1.1.1', { a: 1 });
      setCache('threatbook', 'ip', '2.2.2.2', { a: 2 });
      setCache('threatbook', 'domain', 'evil.com', { a: 3 });
      assert.deepEqual(getCache('threatbook', 'ip', '1.1.1.1'), { a: 1 });
      assert.deepEqual(getCache('threatbook', 'ip', '2.2.2.2'), { a: 2 });
      assert.deepEqual(getCache('threatbook', 'domain', 'evil.com'), { a: 3 });
    });

    it('覆盖写入相同 key 替换旧值', () => {
      setCache('threatbook', 'ip', '8.8.8.8', { v: 1 });
      setCache('threatbook', 'ip', '8.8.8.8', { v: 2 });
      const result = getCache('threatbook', 'ip', '8.8.8.8');
      assert.deepEqual(result, { v: 2 });
    });
  });

  describe('getCache 未命中', () => {
    it('不存在的 key 返回 null', () => {
      assert.equal(getCache('threatbook', 'ip', '10.10.10.10'), null);
    });

    it('过期后返回 null', async () => {
      setCache('threatbook', 'ip', '8.8.8.8', { ok: true });
      await new Promise(r => setTimeout(r, 2100));
      const result = getCache('threatbook', 'ip', '8.8.8.8');
      assert.equal(result, null);
    });

    it('未过期返回数据', () => {
      setCache('threatbook', 'ip', '8.8.8.8', { ok: true });
      const result = getCache('threatbook', 'ip', '8.8.8.8');
      assert.deepEqual(result, { ok: true });
    });
  });

  describe('cleanup', () => {
    it('清理过期记录', async () => {
      setCache('threatbook', 'ip', '8.8.8.8', { old: true });
      await new Promise(r => setTimeout(r, 2100));
      setCache('threatbook', 'ip', '9.9.9.9', { fresh: true });
      cleanup();
      assert.equal(getCache('threatbook', 'ip', '8.8.8.8'), null);
      assert.deepEqual(getCache('threatbook', 'ip', '9.9.9.9'), { fresh: true });
    });
  });

  describe('边界', () => {
    it('data 为 null → getCache 返回 null（不报错）', () => {
      setCache('threatbook', 'ip', '0.0.0.0', null);
      assert.equal(getCache('threatbook', 'ip', '0.0.0.0'), null);
    });

    it('data 为复杂嵌套对象保持完整', () => {
      const data = {
        is_malicious: true,
        tags: ['spam', 'botnet'],
        nested: { a: { b: { c: 1 } } },
        arr: [1, 2, 3]
      };
      setCache('threatbook', 'ip', '1.2.3.4', data);
      assert.deepEqual(getCache('threatbook', 'ip', '1.2.3.4'), data);
    });
  });
});
