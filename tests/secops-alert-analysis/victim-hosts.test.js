/**
 * victim-hosts.test.js — 集成级回归测试
 *
 * 背景：victim-hosts.js 的 `main()` 是「数据生产者」一环，被 gen-md-report-xff.js
 * 的 XFF 4 列封禁表（{{xff_ban_ip_table}}）依赖其产出的 `max_timestamp`。
 *
 * 此前有两处缺陷：
 *   1) queryVictimsForClient 的 ES 聚合 `aggs` 漏加 `max_timestamp` 子聚合
 *      → resp.aggregations?.max_timestamp 恒为 undefined → 返回 null
 *      → XFF 4 列表「告警日期时间戳」整列渲染成「未知」。
 *   2) main() 解构未取 max_timestamp → `ReferenceError: max_timestamp is not defined`
 *      → main().catch 捕获后 process.exit(2)，真实 ES 流程下整段崩溃。
 *
 * 这两处缺陷都被「预置 --victims JSON 直接绕过 main()」的 mock 自测掩盖。
 * 本测试用真实形态（本地 stub ES + 真实执行 main()）跑一遍，避免再次被掩盖：
 *   - stub 返回含 max_timestamp.value 的真实聚合形状；
 *   - 捕获发往 ES 的线查询体，断言 aggs 确实含 max_timestamp 子聚合（即修复已落到请求上）；
 *   - 断言产出的 clients[].max_timestamp 为真实值（非 null），且 main() 未崩溃。
 *
 * 运行：node --test 会自动发现本文件（*.test.js）。
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCRIPT_PATH = resolve(
  __dirname,
  '../../skills/secops-alert-analysis/scripts/judgment-xff/victim-hosts.js',
);

// 真实形态：ES max 聚合返回的 @timestamp 是 epoch millis（数字）
const STUB_MAX_TS = 1753225391000;

const STUB_RESPONSE = {
  hits: { total: { value: 42 } },
  aggregations: {
    max_timestamp: { value: STUB_MAX_TS },
    by_victim: {
      buckets: [
        {
          key: '10.0.0.5',
          doc_count: 25,
          attack_types: { buckets: [{ key: 'webshell上传', doc_count: 25 }] },
          host_states: { buckets: [{ key: '攻击成功', doc_count: 25 }] },
        },
      ],
    },
  },
};

/**
 * 轮询等待文件出现（main() 为 fire-and-forget，导入即解析，但写文件在其后）。
 * @param {string} p - 文件路径
 * @param {number} timeoutMs - 超时（毫秒）
 * @returns {Promise<void>}
 */
function waitForFile(p, timeoutMs) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      if (fs.existsSync(p)) return resolve();
      if (Date.now() - start > timeoutMs) {
        return reject(new Error(`等待输出文件超时（${timeoutMs}ms）：${p}（main() 可能崩溃未写出）`));
      }
      setTimeout(tick, 50);
    };
    tick();
  });
}

describe('victim-hosts.js main() 集成回归（真实形态，stub ES）', () => {
  let server = null;
  let capturedBody = null; // 发往 ES 的线查询体
  let exitCode = null; // 若 main() 崩溃调用 process.exit 则记录
  let origExit = null;
  let origArgv = null;
  let origEnv = null;
  let outPath = null;

  before(async () => {
    // 1) 起 stub ES，捕获线查询体
    capturedBody = null;
    server = http.createServer((req, res) => {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        try {
          capturedBody = JSON.parse(raw);
        } catch {
          capturedBody = null;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(STUB_RESPONSE));
      });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;

    // 2) 指向 stub ES（系统 env 优先于 .env，见 env.js）
    origEnv = { ...process.env };
    process.env.ES_HOST = '127.0.0.1';
    process.env.ES_PORT = String(port);
    process.env.ES_USERNAME = 'test';
    process.env.ES_PASSWORD = 'test';
    process.env.ES_INDEX_PREFIX = 'testlog_';

    // 3) 守卫 process.exit，避免 main() 崩溃时杀死测试运行器
    origExit = process.exit;
    exitCode = null;
    process.exit = (code) => {
      exitCode = code;
    };

    // 4) 准备 main() 入参（用 --ips 直接指定客户端，触发真实 queryVictimsForClient）
    outPath = resolve(__dirname, '.tmp-victim-hosts-out.json');
    origArgv = process.argv;
    process.argv = [
      'node',
      'victim-hosts.js',
      '--ips', '1.2.3.4',
      '--start-date', '20260723',
      '--end-date', '20260723',
      '--output', outPath,
    ];

    // 5) 动态导入（main() 在导入时自动运行；main 为 fire-and-forget，需等待其写出文件）
    await import(pathToFileURL(SCRIPT_PATH).href);
    await waitForFile(outPath, 5000);
  });

  after(() => {
    // 恢复环境，清理 stub 与临时产物
    process.exit = origExit;
    process.argv = origArgv;
    process.env = origEnv;
    if (server) server.close();
    if (outPath && fs.existsSync(outPath)) fs.unlinkSync(outPath);
  });

  it('main() 未崩溃（process.exit 未被异常路径调用，输出文件已生成）', () => {
    assert.equal(exitCode, null, `main() 不应以异常码退出，实际 exit(${exitCode})`);
    assert.ok(fs.existsSync(outPath), 'main() 应成功写出归因 JSON');
  });

  it('发往 ES 的查询 aggs 确实含 max_timestamp 子聚合（修复落到线查询）', () => {
    assert.ok(capturedBody, '应捕获到发往 ES 的查询体');
    assert.ok(capturedBody.aggs, '查询体应含 aggs');
    assert.ok(capturedBody.aggs.max_timestamp, 'aggs 应含 max_timestamp 子聚合');
    assert.deepEqual(
      capturedBody.aggs.max_timestamp,
      { max: { field: '@timestamp' } },
      'max_timestamp 子聚合定义应为 { max: { field: "@timestamp" } }',
    );
  });

  it('clients[].max_timestamp 为真实值（非 null），数据生产者链路贯通', () => {
    const data = JSON.parse(fs.readFileSync(outPath, 'utf8'));
    assert.ok(Array.isArray(data.clients) && data.clients.length === 1, '应产出 1 个客户端');
    const client = data.clients[0];
    assert.equal(client.client_ip, '1.2.3.4');
    assert.equal(client.alerts, 42, 'alerts 应来自 hits.total.value');
    assert.equal(client.victims.length, 1, '应解析出 1 个受害主机');
    // 关键：max_timestamp 必须是 stub 返回的真实 epoch millis，而非 null/undefined
    assert.equal(client.max_timestamp, STUB_MAX_TS, 'max_timestamp 应为 stub 返回的真实值（修复前为 null）');
    assert.equal(typeof client.max_timestamp, 'number', 'max_timestamp 应为数字（epoch millis）');
  });
});
