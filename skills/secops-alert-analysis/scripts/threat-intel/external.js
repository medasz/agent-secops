import { getThreatBookConfig, isFeatureEnabled } from '../shared/env.js';
import { queryIP, queryFile, queryDomain } from './client.js';
import { getCache, setCache, cleanup, closeCache, resetCache } from './cache.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function showHelp() {
  console.log(`ThreatBook 威胁情报查询 CLI

用法:
  node external.js --ip <IP>              单 IP 查询
  node external.js --hash <HASH>          文件 Hash 查询
  node external.js --domain <DOMAIN>      域名查询
  node external.js --batch <FILE> --date <YYYYMMDD>   批量查询（enrich 输出按告警日期命名）
  node external.js --reset-cache          清空 SQLite 缓存
  node external.js --help                 显示帮助

选项:
  --ip <IP>          查询的 IP 地址
  --hash <HASH>      查询的文件 Hash（sha256/sha1/md5）
  --domain <DOMAIN>  查询的域名
  --batch <FILE>     ban-ip-candidates JSON 文件路径
  --date <YYYYMMDD>  告警日期，用于 enrich 默认输出文件命名（与全流水线同一 {date}；缺省且无 --output 时明确报错）
  --output <PATH>    批量查询结果输出文件路径（仅 --batch 模式有效，默认: <cwd>/output/threatbook-enrich-<date>.json，需配合 --date）
  --reset-cache      清空缓存数据库
  --help             显示帮助信息

环境变量:
  ENABLE_THREATBOOK  功能总开关（必须为 true 才能执行）
  THREATBOOK_API_KEY 微步 API Key
  THREATBOOK_*       其他配置见 .env
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') { args.help = true; }
    else if (arg === '--ip') { args.ip = argv[++i]; }
    else if (arg === '--hash') { args.hash = argv[++i]; }
    else if (arg === '--domain') { args.domain = argv[++i]; }
    else if (arg === '--batch') { args.batch = argv[++i]; }
    else if (arg === '--output') { args.output = argv[++i]; }
    else if (arg === '--date') { args.date = argv[++i]; }
    else if (arg === '--reset-cache') { args.resetCache = true; }
  }
  return args;
}

async function handleSingleIp(ip) {
  const cached = getCache('threatbook', 'ip', ip);
  if (cached) {
    console.log(JSON.stringify({ ...cached, cached: true }));
    return;
  }
  const result = await queryIP(ip);
  if (result.found !== undefined || result.error_code) {
    if (!result.error_code) {
      setCache('threatbook', 'ip', ip, result);
    }
    console.log(JSON.stringify({ ...result, cached: false }));
  } else {
    console.log(JSON.stringify({ ...result, cached: false }));
  }
}

async function handleHash(hash) {
  const cached = getCache('threatbook', 'file', hash);
  if (cached) {
    console.log(JSON.stringify({ ...cached, cached: true }));
    return;
  }
  const result = await queryFile(hash);
  if (!result.error_code) {
    setCache('threatbook', 'file', hash, result);
  }
  console.log(JSON.stringify({ ...result, cached: false }));
}

async function handleDomain(domain) {
  const cached = getCache('threatbook', 'domain', domain);
  if (cached) {
    console.log(JSON.stringify({ ...cached, cached: true }));
    return;
  }
  const result = await queryDomain(domain);
  if (!result.error_code) {
    setCache('threatbook', 'domain', domain, result);
  }
  console.log(JSON.stringify({ ...result, cached: false }));
}

async function handleBatch(batchFile, outputFlag, dateFlag) {
  const tbConfig = getThreatBookConfig();
  const batchSize = tbConfig.batchSize;
  const dailyQuota = tbConfig.dailyQuota;
  const rateLimit = tbConfig.rateLimit;
  const rateIntervalMs = Math.ceil(60000 / rateLimit);

  const resolved = path.isAbsolute(batchFile)
    ? batchFile
    : path.resolve(process.cwd(), batchFile);
  const raw = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  // 候选文件两种形态需兼容：扁平字符串数组（如 ban-ip-candidates），
  // 或对象数组（如 XFF candidates 的 {ip,alerts,...}）。统一归一化为 IP 字符串，
  // 否则对象被当作 entry_value 传入 SQLite 会触发「cannot be bound to parameter 3」。
  const rawCandidates = raw.candidates || raw.ips || [];
  const candidates = rawCandidates
    .map(c => {
      if (typeof c === 'string') return c;
      if (c && typeof c === 'object') return c.ip || c.value || c.entry_value || c.ip_addr || null;
      return null;
    })
    .filter(Boolean);
  if (candidates.length === 0) {
    console.log(JSON.stringify({ source: 'threatbook', results: [], cache_stats: { hits: 0, misses: 0 }, quota_stats: { daily_quota: dailyQuota, api_calls_made: 0 }, errors: {} }));
    return;
  }

  const cached = [];
  const uncached = [];
  for (const ip of candidates) {
    const hit = getCache('threatbook', 'ip', ip);
    if (hit) {
      cached.push({ ...hit, cached: true });
    } else {
      uncached.push(ip);
    }
  }

  let truncated = false;
  let truncationReason = null;
  if (uncached.length > dailyQuota) {
    truncated = true;
    truncationReason = `未命中 ${uncached.length} 个超过日配额 ${dailyQuota}，仅查询前 ${dailyQuota} 个`;
    uncached.splice(dailyQuota);
  }

  const batches = [];
  for (let i = 0; i < uncached.length; i += batchSize) {
    batches.push(uncached.slice(i, i + batchSize));
  }

  const results = [...cached];
  let apiCallsMade = 0;
  let terminatedEarly = false;
  let terminationReason = null;
  const failedIps = [];

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    apiCallsMade++;
    const batchResult = await queryIP(batch);

    if (batchResult.error_code) {
      const fatalErrors = ['IP_BINDING_MISMATCH', 'SUBSCRIPTION_EXPIRED', 'QUOTA_EXHAUSTED', 'API_KEY_MISSING', 'DNS_FAILURE'];
      if (fatalErrors.includes(batchResult.error_code)) {
        terminatedEarly = true;
        terminationReason = batchResult.error_code;
        for (const ip of batch) {
          failedIps.push(ip);
        }
        for (let j = i + 1; j < batches.length; j++) {
          for (const ip of batches[j]) {
            failedIps.push(ip);
          }
        }
        break;
      }
      for (const ip of batch) {
        const errResult = { ip, found: false, error_code: batchResult.error_code, reasoning: batchResult.reasoning, cached: false };
        results.push(errResult);
        failedIps.push(ip);
      }
    } else if (batchResult.results) {
      for (const ip of Object.keys(batchResult.results)) {
        const r = batchResult.results[ip];
        if (!r.error_code) {
          setCache('threatbook', 'ip', ip, r);
        }
        results.push({ ...r, cached: false });
      }
    }

    if (i < batches.length - 1 && !terminatedEarly) {
      await new Promise(r => setTimeout(r, rateIntervalMs));
    }
  }

  closeCache();

  const now = new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
  const output = {
    source: 'threatbook',
    queried_at: now,
    mode: 'script',
    results,
    cache_stats: {
      hits: cached.length,
      misses: uncached.length,
    },
    quota_stats: {
      daily_quota: dailyQuota,
      api_calls_made: apiCallsMade,
      api_calls_remaining: dailyQuota - apiCallsMade,
      truncated,
      truncation_reason: truncationReason,
    },
    errors: {
      terminated_early: terminatedEarly,
      termination_reason: terminationReason,
      failed_count: failedIps.length,
      failed_ips: failedIps,
    },
  };

  // enrich 文件名使用「告警日期」而非当前日期：取 --date 显式参数（与全流水线同一 {date} 事实源）。
  // 仅当未显式给出 --output 时才需要 --date；若两者都缺，明确报错（fail loud），
  // 避免静默回退到今天、导致 Step 8 fuse.js 按告警日期找不到文件。
  let date = dateFlag;
  if (!outputFlag && !date) {
    console.error('[ERROR] 缺少 --date 参数（告警日期 YYYYMMDD），无法确定 enrich 默认输出文件名。请传入 --date {YYYYMMDD}（或显式 --output）。');
    process.exit(2);
  }
  const outputPath = outputFlag
    ? (path.isAbsolute(outputFlag) ? outputFlag : path.resolve(process.cwd(), outputFlag))
    : path.resolve(process.cwd(), 'output', `threatbook-enrich-${date}.json`);
  const outputDir = path.dirname(outputPath);
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));
  console.log(JSON.stringify(output, null, 2));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    showHelp();
    return;
  }

  if (args.resetCache) {
    resetCache();
    closeCache();
    console.log('缓存已清空');
    return;
  }

  if (!isFeatureEnabled('THREATBOOK')) {
    process.stderr.write('功能未启用: 设置 ENABLE_THREATBOOK=true 以启用微步威胁情报\n');
    process.exit(1);
  }

  if (args.ip) {
    await handleSingleIp(args.ip);
  } else if (args.hash) {
    await handleHash(args.hash);
  } else if (args.domain) {
    await handleDomain(args.domain);
  } else if (args.batch) {
    await handleBatch(args.batch, args.output, args.date);
  } else {
    showHelp();
    process.exit(1);
  }

  closeCache();
}

main().catch(err => {
  process.stderr.write(`[ERROR] ${err.message}\n`);
  closeCache();
  process.exit(1);
});
