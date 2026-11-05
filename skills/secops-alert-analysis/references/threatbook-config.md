# ThreatBook 威胁情报配置

> 本文件从 SKILL.md 附录H外迁，为 ThreatBook 集成的配置参考。

## H.1 环境变量（scripts/.env）

| 变量                         | 说明                                      | 默认值                                   |
| ---------------------------- | ----------------------------------------- | ---------------------------------------- |
| `ENABLE_THREATBOOK`        | 功能开关，`true` 启用，`false` 禁用   | `false`                                |
| `THREATBOOK_API_KEY`       | 微步 API Key（MCP URL 与 REST 回退共用）  | —                                       |
| `THREATBOOK_BASE_URL`      | REST API 基础地址                         | `https://api.threatbook.cn/v3`         |
| `THREATBOOK_CACHE_PATH`    | SQLite 缓存文件路径（相对 scripts/ 目录） | `cache/threatbook.sqlite`              |
| `THREATBOOK_CACHE_TTL`     | 缓存生效秒数                              | `86400`                                |
| `THREATBOOK_RATE_LIMIT`    | 每分钟最大请求数（客户端侧限频）          | `10`                                   |
| `THREATBOOK_TIMEOUT`       | 单次请求超时毫秒数                        | `10000`                                |
| `THREATBOOK_DAILY_QUOTA`   | IP信誉 API 日配额上限                     | `150`                                  |
| `THREATBOOK_BATCH_SIZE`    | 单次批量查询 IP 数上限                    | `100`                                  |
| `THREATBOOK_BOUND_IP`      | API Key 绑定的固定出口 IP                 | `203.0.113.200`                        |
| `THREATBOOK_CONFIRM_LEVEL` | 情报确认阈值（high/medium/low）           | `high`                                 |
| `THREATBOOK_LABEL_MAP`     | severity/confidence 中文映射表路径        | `references/threatbook-label-map.json` |

## H.2 ENABLE_THREATBOOK 开关行为

| 环节                 | `false`                     | `true`            |
| -------------------- | ----------------------------- | ------------------- |
| Step 0 C3 (TCP 连通) | SKIP + "功能未启用"           | 正常执行            |
| Step 6 (情报查询)    | 跳过，不调公网                | 正常执行            |
| Step 7 (情报融合)    | 输出"威胁情报查询结果不可用"  | 正常执行            |
| Path B (IP溯源)      | 脚本入口拒绝执行 + 不提示 MCP | MCP 优先 + 脚本回退 |
| `external.js` CLI  | 拒绝执行（退出码 1 + stderr） | 正常执行            |

> **无豁免路径**: `external.js` 脚本入口在顶部硬性检查 `ENABLE_THREATBOOK`，`false` 时 `--ip` 和 `--batch` 均拒绝执行。`--reset-cache` 和 `--help` 不受限。

## H.3 脚本路径（threat-intel/ 目录）

| 脚本                                 | 职责                                             | CLI                                                             |
| ------------------------------------ | ------------------------------------------------ | --------------------------------------------------------------- |
| `scripts/threat-intel/client.js`   | REST API 客户端（queryIP/queryFile/queryDomain） | 内部模块，无 CLI                                                |
| `scripts/threat-intel/cache.js`    | SQLite 缓存（node:sqlite）                       | 内部模块，无 CLI                                                |
| `scripts/threat-intel/external.js` | CLI 入口（单 IP/批量/Hash/域名查询）             | `--ip / --hash / --domain / --batch / --reset-cache / --help` |
| `scripts/threat-intel/fuse.js`     | Step 7 生成独立情报表格                          | `--ban-ip-table / --enrich / --output / --label-map / --help` |

## H.4 输出文件格式

**ban-ip-candidates-{date}.json**（Step 4 副产物）:

```jsonc
{
  "date": "20260624",
  "generated_at": "2026-06-24T12:00:00+08:00",
  "candidates": ["198.51.100.200", "198.51.100.201"],
  "total": 2,
  "summary": { "total_risk_ips": 2, "query_window": "..." }
}
```

**threatbook-enrich-{date}.json**（Step 6 产物）:

```jsonc
{
  "source": "threatbook",
  "queried_at": "2026-06-24 12:00:00",
  "mode": "script",
  "results": [
    { "ip": "198.51.100.200", "found": true, "is_malicious": true, "confidence": "high", "severity": "high", "threat_type": "Zombie,Spam", "permalink": "https://threatbook.io/ip/198.51.100.200", "cached": false }
  ],
  "cache_stats": { "hits": 0, "misses": 2 },
  "quota_stats": { "daily_quota": 150, "api_calls_made": 1, "api_calls_remaining": 149, "truncated": false, "truncation_reason": null },
  "errors": { "terminated_early": false, "termination_reason": null, "failed_count": 0, "failed_ips": [] }
}
```
