---
name: secops-alert-analysis-judgment-xff
description: |
  XFF 代理攻击研判子技能（路径A 纯脚本、零 MCP）。当用户分析 X-Forwarded-For 代理链、提取真实外部客户端 IP、排查经 CDN 进来的攻击源、生成「外部客户端 × 微步恶意标签 × 受害主机」封禁建议时，按本工作流执行。
output:
  files:
    - pattern: "output/judgment-xff-ban-recommendation-{end}.md"
      description: "XFF 封禁建议 MD 报告"
      template: "templates/judgment-xff-ban-template.md"
    - pattern: "output/judgment-xff-ban-recommendation-{end}.json"
      description: "XFF 封禁建议机读 JSON（含 judgment 块）"
  terminal:
    summary: true
---

# XFF 代理攻击研判（路径A 纯脚本，零 MCP）

> 本子技能由父 skill `secops-alert-analysis` 的 router 经 `Read` 显式加载，**不设 triggers**。

XFF（X-Forwarded-For）是客户端可控的请求头，链形如 `真实客户端,中间代理1,CDN边缘`。本子技能的核心是：**取链最左端公网 IP 作为真实外部客户端**，排除 CDN 中转跳与 `127.0.0.1`/私网伪造占位，再结合微步情报与受害主机生成封禁建议。

> ⚙️ **运行环境（统一口径）**：本子技能所有脚本以 `node` 直接运行。若执行报 ES 连接错误（退出码 2），确认 ES 服务可达后重跑。

---

## 执行流程

### Step 0：获取报告时间

```bash
TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S'
```

将返回值作为 `--report-time`（gen-md-report-xff.js）；禁止 LLM 编造时间。

### Step 1：查询外部 XFF 告警 + 解析真实客户端

```bash
node skills/secops-alert-analysis/scripts/judgment-xff/query-xff.js \
    --start-date {start} --end-date {end}
```

- 产出：`output/judgment-xff-{start}-{end}.json`（聚合 + 外部客户端排名）+ `output/judgment-xff-candidates-{start}-{end}.json`（微步候选）
- 关键逻辑见 §附录A（致命 DSL 教训）与 `references/judgment-xff-analysis.md`

### Step 2：（可选）微步威胁情报

```bash
node skills/secops-alert-analysis/scripts/threat-intel/external.js \
    --batch output/judgment-xff-candidates-{start}-{end}.json --date {end}
```

- 产出：`output/threatbook-enrich-{end}.json`
- `ENABLE_THREATBOOK != true` 时跳过，gen-md-report-xff 标注「未提供微步情报」

### Step 3：受害主机归因

```bash
node skills/secops-alert-analysis/scripts/judgment-xff/victim-hosts.js \
    --input output/judgment-xff-{start}-{end}.json --start-date {start} --end-date {end}
```

- 产出：`output/judgment-xff-victimhosts-{start}-{end}.json`（每个外部客户端的受害主机 dip + 攻击类型 + host_state）

### Step 4：（按需）主机失陷核验

针对可疑受害主机（如落 webshell/代码执行/RCE 的主机），回答「是否已攻击成功/失陷」：

```bash
node skills/secops-alert-analysis/scripts/judgment-xff/check-host-state.js \
    --hosts 192.0.2.31,192.0.2.32 --start-date {start} --end-date {end}
```

- 产出：`output/xff-host-state-{host}.json`（host_state 分布 + 全局攻击成功/失陷计数 + verdict）
- **关键**：`webshell上传`/`代码执行` 类告警 ≠ 已失陷，须看 `host_state`。`total=0` 即无失陷迹象。

### Step 5：合并生成封禁建议

```bash
node skills/secops-alert-analysis/scripts/judgment-xff/gen-md-report-xff.js \
    --xff output/judgment-xff-{start}-{end}.json \
    --victims output/judgment-xff-victimhosts-{start}-{end}.json \
    --threatbook output/threatbook-enrich-{end}.json \
    --start-date {start} --end-date {end} --report-time "{Step 0 时间}" \
    --ban-ip-append output/ban-ip-table-{end}.md
```

- 产出：`output/judgment-xff-ban-recommendation-{end}.md`（按 `templates/judgment-xff-ban-template.md`）+ `.json`（含 `judgment` 权威块，其中 `report_tables.xff_ban_ip_table_md` 为 §5.1 新增的 4 列 XFF 封禁表：`告警日期时间戳|风险IP|风险描述|风险IP的地理位置`）
- `--ban-ip-append output/ban-ip-table-{end}.md`：将同一张 4 列 XFF 封禁表**并入**主报告 §2.1 的 `ban-ip-table-{end}.md` 的同一张 4 列表（不再带独立「## XFF-IP 封禁建议表（追加）」小节，fuse.js 下游按同布局抽取 IP，安全且有益）；文件不存在则新建。
- 优先级：P0=微步确认恶意；P1=告警数≥20 或命中核心暴露面；P2=低频未标记
- 受害主机优先级：检测到攻击成功/失陷 → P1；命中数≥50 → P2；其余 P3

---

## 附录A：⚠️ 致命 DSL 教训（必读）

`must_not` **不能**嵌进 `must` 数组（会触发 ES `400 Bad Request`）。正确写法（`must` 与 `must_not` 同级）：

```json
"query": { "bool": {
  "must": [ { "exists": { "field": "field_values.x_forwarded_for" } } ],
  "must_not": [
    { "term": { "field_values.x_forwarded_for": "" } },
    { "term": { "field_values.sip_addr": "局域网" } }
  ]
} }
```

完整字段语义、CDN 段、公网 IP 判定、XFF 伪造陷阱、规范查询体见 **`references/judgment-xff-analysis.md`**（本子技能唯一事实来源）。

## 附录B：CDN / 中转跳（不可封禁）

真实源取链最左端公网 IP；链中后续 IP 多为中转：

| 网段前缀 | 归属 |
| --- | --- |
| `175.12.90.` / `183.60.227.` / `47.105.` | 腾讯 CDN |
| `172.64.` / `172.69.` / `162.158.` | Cloudflare |

## 附录C：路径与产物规范

- **CWD 必须为项目根目录**（agent-secops/），命令 `scripts/...` 相对项目根，`output/...` 相对 CWD（宪法 VII）。
- 脚本内部引用（`shared/es-query.js`、模板）经 `__dirname` 自动定位，无需显式传参。
- 多日查询索引名用逗号拼接 `logfmt_746_20260712,...,logfmt_746_20260718`，避免通配符跨月误匹配。

### 脚本工具链

| 脚本 | 路径 | 用途 |
| --- | --- | --- |
| query-xff.js | `scripts/judgment-xff/query-xff.js` | Step 1 外部 XFF 查询 + 真实客户端解析 |
| victim-hosts.js | `scripts/judgment-xff/victim-hosts.js` | Step 3 受害主机归因 |
| check-host-state.js | `scripts/judgment-xff/check-host-state.js` | Step 4 主机失陷核验 |
| gen-md-report-xff.js | `scripts/judgment-xff/gen-md-report-xff.js` | Step 5 合并封禁建议（MD+JSON） |
| external.js | `scripts/threat-intel/external.js` | Step 2 微步情报（复用） |
| es-query.js | `scripts/shared/es-query.js` | ES 直连（共享） |

### 产物

| 文件 | 路径 | 说明 |
| --- | --- | --- |
| XFF 聚合+客户端排名 | `output/judgment-xff-{start}-{end}.json` | Step 1 |
| 微步候选 | `output/judgment-xff-candidates-{start}-{end}.json` | 供 external.js --batch |
| 受害主机 | `output/judgment-xff-victimhosts-{start}-{end}.json` | Step 3 |
| 主机失陷核验 | `output/xff-host-state-{host}.json` | Step 4（按需） |
| 封禁建议 | `output/judgment-xff-ban-recommendation-{end}.md` / `.json` | Step 5 终产物 |

*本子技能遵循：路由加载（无 triggers） → SKILL.md（执行手册 + 知识附录） → references/judgment-xff-analysis.md（唯一事实来源） → scripts/templates（固化实现）*
