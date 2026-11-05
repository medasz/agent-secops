---
name: secops-alert-analysis-judgment
description: |
  路径A 告警研判分析（纯脚本、零 MCP）。当用户进行告警研判、封禁建议、失陷主机、横向渗透、内网横移、ESG日志、入侵检测告警、安全事件分析、攻击IP分析、威胁IP封禁时，按本工作流执行。
output:
  files:
    - pattern: "output/alert-report-{date}.md"
      description: "MD报告（Markdown格式）"
      template: "templates/alert-report-template.md"
    - pattern: "output/alert-report-{date}.html"
      description: "HTML报告（深色模式+打印友好）"
      template: "templates/alert-report-template-v1.html"
  terminal:
    summary: true
    template: "templates/terminal-summary-template.md"
    max_lines: 50
---
# 路径A：告警研判分析（纯脚本，零 MCP）

> **⚠️ 本路径不使用任何 MCP 工具。** 所有 ES 查询（聚合 / 详情 / 溯源 / 计数 / DNS 聚合）一律经共享脚本库（`scripts/es-tool/extract.js`、`scripts/es-tool/dns-agg.js`、`scripts/shared/es-query.js` 等）**直连 ES** 完成，不调用任何 `elasticsearch-sse` / ThreatBook 工具。详见宪法 VI（路径分离原则：路径A 纯脚本，路径B 保留原策略）。

本 skill 用于从 Elasticsearch 大数据提取 IDS 告警日志，比对白名单，查询威胁情报【可选】，生成分析报告，自动发帖【可选】。

流水线概览：脚本主路径（外部+内部+失陷三次查询 + DNS 全局聚合）→ 白名单 → IP封禁表 → Domain封禁表 → 情报查询 → 情报融合 → 渲染（含横向攻击分析）→ 发布 portal

---

## 执行流程

> **本流程按报告模板 `alert-report-template.md` 的章节（§1–§7）组织**：先准备与提取（§1 元信息 + §2/§3/§4 数据源），再逐章准备数据（§2 外部 → §3 失陷 → §4 内部 → §5 专项），最后在 Step 9 汇总渲染（§6 附录 + §7 建议）并发布。各 Step 标题标注其产出的报告章节。

**报告章节 ← 步骤 映射**：

| 报告章节         | 来源 Step                                                                     | 说明                                |
| ---------------- | ----------------------------------------------------------------------------- | ----------------------------------- |
| §1 报告概述     | Step 0、Step 3                                                                | 报告时间 + 统计汇总表               |
| §2 外部攻击研判 | Step 4（§2.1）、Step 5（§2.2）、Step 6（§2.3）、Step 9 渲染（§2.4/§2.5） | IP/Domain 封禁 + 情报 + 趋势        |
| §3 失陷IP研判   | Step 2（`--compromised`）、Step 9 渲染                                      | analyzeCompromised 补全「攻击来源」 |
| §4 内部攻击研判 | Step 2（`--internal`）、Step 7（横向）、Step 9 渲染                         | §4.1–§4.5                        |
| §5 专项研判     | Step 8（§5.1 XFF，内嵌流水线）、Step 9 渲染（§5.2–§5.4）                  | XFF + 弱口令/远控/挖矿              |
| §6 详细数据附录 | Step 3（§6.1 过滤）、Step 9 渲染（§6.2 完整列表）                           |                                     |
| §7 安全建议     | 模板静态内容                                                                  | 无需步骤                            |

### Step 0：准备 — 报告时间（→ §1 报告概述元信息）

**处理**：

执行系统命令获取精确时间：

```bash
TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S'
```

将返回值作为 `report_time`，后续 Step 9 和 Step 10 必须直接使用此值。

> **禁止**: LLM不得自行猜测或编造报告时间，必须使用上述命令返回的值。

### Step 1：准备 — 环境自检

#### 执行自检

> **一次调用，零 MCP 依赖。** Step 0 不再调用任何 MCP 工具。
> 仅运行 `selfcheck.js` 一次，通过 TCP 连通性 + .env 配置存在性完成 11 项自检。

```bash
node skills/secops-alert-analysis/scripts/workflow/selfcheck.js --date YYYYMMDD [--format json|text|markdown] [--skip-c-network]
```

> ⚙️ **运行环境（统一口径）**：本子技能后续脚本一律以 `node` 直接运行，以本自检 `A1 PF-ES-TCP` 探测 ES 服务是否可达为准（可达即继续，不可达即阻断并提示排查 ES 服务）。

- `--date`：必填，YYYYMMDD 格式
- `--format`：输出格式，默认 json
- `--skip-c-network`：跳过 C1/C2/C3 网络探活（离线测试用）

#### 自检项

| ID | check_id          | scope | 检查内容                          | 阻塞 |
| -- | ----------------- | ----- | --------------------------------- | ---- |
| A1 | PF-ES-TCP         | A     | ES_HOST:ES_PORT TCP 连通          | 是   |
| B1 | PF-DATE-VALID     | B     | 日期合法性 + 非未来日期           | 是   |
| B3 | PF-WHITELIST      | B     | 白名单可解析                      | 是   |
| B4 | PF-ENV-CONFIG     | B     | scripts/.env 凭据存在性           | 是   |
| C1 | PF-ENRICH-API     | C     | 富化 API 密钥存在性               | 否   |
| C2 | PF-PORTAL-TOKEN   | C     | Portal Token 密钥 + 网关 TCP 连通 | 否   |
| C3 | PF-THREATBOOK-TCP | C     | THREATBOOK_BASE_URL TCP 连通      | 否   |
| D1 | PF-NODE-VER       | D     | node ≥ 22.5                      | 否   |
| D2 | PF-OUTPUT-WRITE   | D     | output/ 可写                      | 否   |
| D3 | PF-TEMPLATES      | D     | templates/ 三文件存在             | 否   |

#### 判定逻辑

- **A+B 项**为强制项：任一 FAIL → `local_verdict.b_all_pass = false`
- **C+D 项**为非阻塞诊断项：WARN 不影响 b_all_pass，仅记录在 `c_d_warnings` 中
- 退出码：子项 PASS/FAIL/WARN/SKIP 均退出 0；仅输入错误退出 1

#### 解读输出

**JSON 输出结构：**

```json
{
  "checked_at": "2026-07-13T...",
  "date": "20260713",
  "items": [
    { "check_id": "PF-ES-TCP", "scope": "A", "verdict": "PASS", "sub_id": "PF-ES-TCP-OK", "advice": "..." }
  ],
  "local_verdict": {
    "b_all_pass": true,
    "b_failures": [],
    "c_d_warnings": [],
    "summary": "A+B 前置项全 PASS；C/D 诊断项全 PASS"
  },
  "degrade_hint": null
}
```

**分支判断：**

- `b_all_pass = true` → 进入 Step 2
- `b_all_pass = false` → 按以下优先级修复：
  1. **B4 PF-ENV-CONFIG FAIL** → 检查 `scripts/.env` 文件是否存在且含 `ES_HOST`、`ES_PORT`、`ES_USERNAME`、`ES_PASSWORD`、`THREATBOOK_BASE_URL`、`THREATBOOK_API_KEY`、`PORTAL_TOKEN_URL`、`PORTAL_TOKEN_APPID`、`PORTAL_TOKEN_SECRET`
  2. **A1 PF-ES-TCP FAIL** → 检查 ES 服务是否运行、ES_HOST:ES_PORT 是否正确、网络是否可达
  3. **B1 PF-DATE-VALID FAIL** → 检查 --date 参数格式和值
  4. **B3 PF-WHITELIST FAIL** → 检查白名单配置文件
  5. **C/D 项 WARN** → 不阻塞，继续 Step 2；但记录 degrade_hint 供后续降级参考

### Step 2：提取 — 外部/内部/失陷三查询 + DNS 聚合（→ §2/§3/§4 数据源）

> **A3/B2 隐式覆盖：** Step 0 已不再单独检查 A3（ES 搜索权限）和 B2（ES 连通性）。
> 这两项由本步骤的**首次脚本 ES 查询**（外部查询 `extract.js` / `dns-agg.js` 经 `es-query.js` 直连）自然覆盖：
>
> - 如果 ES 不可达或凭据无效，首次脚本 ES 查询会失败（退出码 2）
> - 失败时直接报错终止（纯脚本路径，ES 不可用时直接终止，不混用其他数据路径，宪法 VI）
> - 无需额外自检调用，节省 1-2 次查询

> **三层架构（详见 `docs/superpowers/plans/2026-07-21-secops-report-refactor-design.md`）**：查询层（`scripts/shared/es-query.js` 的 `CONTEXT_FILTERS`+`buildQuery(ctx)`）→ 分析层（`scripts/analysis/{analyze-external,analyze-internal,analyze-compromised}.js` + `scripts/shared/threat-categories.js`）→ 渲染层（`scripts/reporting/sections/{render-external,render-internal,render-compromised,render-special}-section.js`）→ 编排层（`gen-md-report.js`）。`gen-md-report.js` 仅做薄编排：读 parsed → 调 analyze* → `deriveThreatTopics` → 调 render* → 注入模板块占位符，**不再内联任何表行生成或逐行正则 replace**。

> **三次查询 + 一次 DNS 聚合策略**：外部查询 + 内部查询 + 失陷主机查询，分别产出 `parsed-external-{date}.json`、`parsed-internal-{date}.json` 和 `parsed-compromised-{date}.json`（含 `compromised_hosts[].sip_addrs`，用于判定失陷主机「攻击来源」）；DNS 全局聚合产出 `dns-domains-{date}.json`（替代原 `dns_domains` 全局聚合能力，覆盖全量 DNS 流量）。

**脚本主路径（全部经共享脚本库直连 ES，零 MCP）：**

```bash
# —— 单日简写（等价于 --start {date}000000 --end {date}235959）——
# 外部攻击聚合（排除局域网）
node skills/secops-alert-analysis/scripts/es-tool/extract.js -d {date} -x --parsed-output output/parsed-external-{date}.json

# 内部攻击聚合（sip_addr = 局域网）
node skills/secops-alert-analysis/scripts/es-tool/extract.js -d {date} --internal --parsed-output output/parsed-internal-{date}.json

# 失陷主机聚合（host_state = 攻击成功|失陷）
node skills/secops-alert-analysis/scripts/es-tool/extract.js -d {date} --compromised --parsed-output output/parsed-compromised-{date}.json

# —— 跨天窗口形式（推荐用于"今日/跨自然日"报告，避免日期写死成当天）——
# 三处 extract 查询须传同一 {start}/{end}（YYYYMMDDHHmmss）；-s/-e 与 -d 互斥，不可混用
node skills/secops-alert-analysis/scripts/es-tool/extract.js -s {start} -e {end} -x --parsed-output output/parsed-external-{date}.json
node skills/secops-alert-analysis/scripts/es-tool/extract.js -s {start} -e {end} --internal --parsed-output output/parsed-internal-{date}.json
node skills/secops-alert-analysis/scripts/es-tool/extract.js -s {start} -e {end} --compromised --parsed-output output/parsed-compromised-{date}.json

# DNS 全局聚合（覆盖全量 DNS 流量 + 内部 DNS 服务风险域名）
# dns-agg.js 同样支持 --start/--end 跨天窗口（与 extract.js -s/-e 同源），须与上面三处传同一窗口
node skills/secops-alert-analysis/scripts/es-tool/dns-agg.js -d {date} --start {start} --end {end} --output output/dns-domains-{date}.json
```

> **🔑 跨天窗口统一约定（务必遵守）**：报告真实查询窗口由 `--start`/`--end`（YYYYMMDD 或 YYYYMMDDHHmmss）指定，`extract.js`（`-s/-e`）、`dns-agg.js`、`ban-domain-table.js` **三者必须传同一套 `{start}`/`{end}`**，否则 §2/§4 与 §2.2 的窗口会对不上。
> - `-d {date}` 是单日简写，等价于 `--start {date}000000 --end {date}235959`；单日报告可用，跨天（如 21:00→次日 09:00）**必须**用 `-s/-e`（或对应脚本的 `--start/--end`）。
> - `extract.js` 的 `-s/-e` 与 `-d` **互斥（同传会报错退出）**，跨天请只用 `-s/-e` 不带 `-d`；`dns-agg.js` / `ban-domain-table.js` 的 `--start/--end` 可与 `-d` 同传（start/end 窗口优先，date 仅用于输出文件名）。无论哪种写法，三者传入的窗口值必须一致。
> - `gen-md-report.js`（Step 9）从 Step 2 的 parsed JSON 读取窗口，**无需**重复传 `-s/-e`。

**输出**：

- `output/parsed-external-{date}.json`（外部攻击聚合数据，shape 与 `extract.js --parsed-output` 一致）
- `output/parsed-internal-{date}.json`（内部攻击聚合数据，含 lateral 字段）
- `output/parsed-compromised-{date}.json`（失陷主机聚合数据，host_state = 攻击成功|失陷）
- `output/dns-domains-{date}.json`（`stats.dns_domains`：Top 域名覆盖全量 DNS 流量；`dns_alerts`：内部 DNS 服务风险域名列表，供 Step 5）

> **字段说明**：`extract.js` 已自动完成聚合（`computeAggregations`），输出 shape 与历史聚合解析器 `parse-mcp.js` 完全一致，本路径由 `extract.js` 直出相同 shape，无需再经该解析器。

### Step 3：处理 — 白名单过滤 + 统计汇总（→ §1 概述表 + §6.1 过滤结果）

**处理**：

1. 白名单比对:

   ```
   FOR each ip IN external_ips:
     IF ip NOT in whitelist:
       add to valid_external_ips
     ELSE:
       LOG: "[白名单过滤] 排除内部可信IP: {ip}"
     END
    END
   ```

   ⚠️ **约束**：任何涉及白名单过滤的阶段 MUST 调 `shared/whitelist.js isExternal()`，禁止自实现正则。违反此约束会导致 CIDR/range 白名单漏匹配（ISS-019）。
2. 统计汇总:

   > **🚫 确定性取数铁律（防上下文爆炸）**：本步骤统计**严禁**用 `Read` 工具直接读取 `parsed-external-{date}.json` / `parsed-internal-{date}.json` / `parsed-compromised-{date}.json` 原始文件（单文件可达数 MB，且 opencode/glm-5.2 上下文窗口仅 ≅100k tokens，整文件 Read 必触发 `maximum context length` 报错导致分析失败）。
   >
   > **必须**通过脚本只取 `stats` 子对象（脚本已 `computeAggregations`，`.stats` 即权威统计，无需加载全文）：
   >
   > ```bash
   > node -e "const fs=require('fs');const e=JSON.parse(fs.readFileSync('output/parsed-external-{date}.json','utf8'));console.log('external.total_alerts=',e.stats.total_alerts);"
   > node -e "const fs=require('fs');const i=JSON.parse(fs.readFileSync('output/parsed-internal-{date}.json','utf8'));console.log('internal.total_alerts=',i.stats.total_alerts,'lateral=',i.stats.lateral_alerts);"
   > node -e "const fs=require('fs');const c=JSON.parse(fs.readFileSync('output/parsed-compromised-{date}.json','utf8'));console.log('compromised_hosts=',c.compromised_hosts.length);"
   > ```
   >
   > 若需攻击类型 / Top 目标等明细，同样只 `JSON.parse(...).stats.attack_types` 等，绝不大文件整读。本路径 Step 4–10 的表格/报告生成均已由脚本经 `--input` 消费，不依赖 LLM 读取原文。
   >

   全部取自 Step 2 两个 JSON 的 `stats` 对象：

   - **权威总数**: `total_alerts` = `parsed-external.stats.total_alerts` + `parsed-internal.stats.total_alerts`（外部 + 内部，两份 JSON 之和）
   - `total_alerts`: parsed-external.stats.total_alerts + parsed-internal.stats.total_alerts
   - `external_alerts`: parsed-external.stats.total_alerts（外部查询已过滤局域网）
   - `unique_external_ips`: Set.size（精确值）
   - `compromised_alerts`: 失陷主机数（parsed-compromised-{date}.json 的 compromised_hosts.length）
   - `attack_types`: parsed-external.stats.attack_types，shape `[{type, count}]`
   - `hazard_ratings`: parsed-external.stats.hazard_ratings，shape `[{type, count}]`
   - `top_targets`: parsed-external.stats.top_targets，shape `[{type, count}]`
   - `top_external_ips`: ips[]（含 attack_types/max_timestamp/sip_addr，供 ban-ip-table.js --input 直接消费）
   - `hourly_distribution`: [{hour, count}]（客户端归桶，已填充空桶）
   - `internal_alerts`: parsed-internal.stats.total_alerts（内部查询 sip_addr = "局域网"）
   - `lateral_alerts`: parsed-internal.stats.lateral_alerts（横向移动告警数）
   - `unique_internal_sources`: parsed-internal.stats.unique_internal_sources
   - `unique_internal_targets`: parsed-internal.stats.unique_internal_targets

   > **边界差异说明**: `date_histogram` 桶求和可能与权威总数存在差异（源于 `timestamp` 字段缺失文档不参与聚合、时区边界归桶偏差等）。报告中任何"按小时分布总计"类数字仅供趋势展示，**不作为权威总数**。报告第4节须附带脚注：
   > *注：按小时分布总计为 date_histogram 桶求和，与 count 查询存在边界差异（可能由于 timestamp 缺失/时区边界归桶导致）。权威总数以 count 查询为准。*
   >

**输出**: 结构化统计数据、白名单过滤后的IP列表

### Step 4：§2.1 生成 IP 封禁建议表

**处理**：

1. 读取模板: `templates/alert-report-template.md`
2. **生成封禁表格块（脚本生成，禁止LLM即兴填写，可复现）**:

   ```bash
   node skills/secops-alert-analysis/scripts/reporting/ban-ip-table.js \
     --input output/parsed-external-{date}.json \
     --format markdown \
     --output output/ban-ip-table-{date}.md \
     --candidates-output output/ban-ip-candidates-{date}.json
   ```

   - 从 `output/parsed-external-{date}.json`（Step 2 脚本输出）读取数据生成封禁表（零 MCP）
   - 该脚本生成四列封禁表格 `告警日期时间戳 | 风险IP | 风险描述 | 风险IP的地理位置`，已二次白名单过滤
   - 三列数据值全部取自ES数据源该IP查询时段真实告警记录
   - 同时输出 `output/ban-ip-candidates-{date}.json`（封禁候选 IP 列表，供 Step 7 `--batch` 消费）
   - **禁止**: LLM不得自行填写封禁表格四列，必须使用脚本输出

**输出**: `output/ban-ip-table-{date}.md`（封禁表）、`output/ban-ip-candidates-{date}.json`（候选 IP 列表）

### Step 5：§2.2 生成 Domain 封禁建议表

**处理**：

1. **生成Domain封禁表格块（脚本生成，禁止LLM即兴填写，可复现）**:

   ```bash
   node skills/secops-alert-analysis/scripts/reporting/ban-domain-table.js \
     --input output/dns-domains-{date}.json \
     --start {start} --end {end} \
     --format markdown \
     --output output/ban-domain-table-{date}.md \
     --candidates-output output/ban-domain-candidates-{date}.json
   ```

   - 输入源为 Step 2 的 `dns-agg.js` 输出 `output/dns-domains-{date}.json`（本路径纯脚本，不再经 `parse-mcp.js`）
   - `{start}`/`{end}` 为报告真实查询窗口（YYYYMMDD 或 YYYYMMDDHHmmss，与 `extract.js -s/-e` 同源），跨天场景必须传，供 ban-domain-table.js 做窗口级行过滤确保 §2.2 不含窗口外域名；单日场景可省略（回退为 `--date` 单日范围）
   - 该脚本生成四列Domain封禁表格 `最近告警时间 | 风险域名 | 风险描述 | 告警次数`，数据取自内部DNS服务（192.0.2.10/11/12）查询时段真实告警记录
   - 风险域名取自ES `field_values.ioc`（经格式规整，排除规则描述型条目）
   - 同时输出 `output/ban-domain-candidates-{date}.json`（封禁候选域名列表）
   - **禁止**: LLM不得自行填写Domain封禁表格，必须使用脚本输出

   > 备注：`ban-domain-table.js` 仍保留 `--date` 直连 ES 模式作为独立脚本回退（纯脚本直连，不依赖外部工具），但本路径A 主流程统一经 `--input` 消费 `dns-agg.js` 输出，保证数据源单一、可复现。
   >

**输出**: `output/ban-domain-table-{date}.md`（Domain封禁表）、`output/ban-domain-candidates-{date}.json`（候选域名列表）

### Step 6：§2.3 威胁情报查询与情报表融合

**前置**: `ENABLE_THREATBOOK !== 'true'` → 跳过本步骤（情报表在 Step 9 渲染为"威胁情报查询结果不可用"），记 INFO 日志，不调公网

**输入**: `output/ban-ip-candidates-{date}.json`（Step 4 副产物，封禁候选 IP 列表）、`output/ban-ip-table-{date}.md`（Step 4 封禁表）

**C3 TCP verdict 分支**（由 Step 1 自检结论驱动）：

- `PF-THREATBOOK-TCP` verdict=PASS → 正常执行微步威胁情报查询
- verdict=WARN/SKIP/FAIL（C 项非阻塞）→ 跳过微步查询，在输出中标注「微步 TCP 不可达，威胁情报降级」

**处理**：

1. **情报查询**（`external.js`）——逐 IP 查 SQLite 缓存 → 配额预检（>150 截断+WARN）→ 按 100 个一批调 `client.queryIP` → 错误分类（绑定不匹配/过期/配额耗尽终止；网络/HTTP/JSON 失败续批）→ 写入缓存 + 累积；批次间隔 60/限频 秒（默认 6s）

   ```bash
   node skills/secops-alert-analysis/scripts/threat-intel/external.js --batch output/ban-ip-candidates-{date}.json --date {date}
   ```

   **输出**: `output/threatbook-enrich-{date}.json`（results + cache_stats + quota_stats + errors）
2. **情报表融合**（`fuse.js`）——读取 ban-ip-table md 的 IP 列表 + enrich JSON，生成 5 列情报表（`风险IP | 是否恶意 | 可信度 | 威胁类型 | 情报标签`）；字段映射：是否恶意 `is_malicious===true→是`、可信度经 `references/threatbook-label-map.json` 映射（high→高/medium→中/low→低）、威胁类型原值或 `—`、情报标签 tags 数组逗号拼接或 `—`；无情报数据 IP 四项均 `—`

   ```bash
   node skills/secops-alert-analysis/scripts/threat-intel/fuse.js \
     --ban-ip-table output/ban-ip-table-{date}.md \
     --enrich output/threatbook-enrich-{date}.json \
     --output output/threat-intel-table-{date}.md
   ```

   **可用性判定**（任一满足 → 输出"威胁情报查询结果不可用"）：`ENABLE_THREATBOOK=false` / ban-ip-table md 不存在 / enrich JSON 不存在 / `errors.terminated_early=true` / `results` 为空或全部 IP 有 `error_code`
   **输出**: `output/threat-intel-table-{date}.md`（情报查询结果表格，→ §2.3）

**降级**：API Key 缺失→跳过查询输出空 results+warning；IP 绑定不匹配/订阅过期→终止+提示；日配额耗尽→终止剩余+WARN；网络全失败→跳过+降级日志（四要素 reason/ts/params/mode）；部分失败→标注 found:false+error_code 不整体退出；缓存读写失败→无缓存模式全量走 API。

### Step 7：§4 内部攻击与横向移动分析（→ §4.1–§4.5）

**输入**: `output/parsed-internal-{date}.json`（Step 2 产出）

**处理**：

> **主路径**: 内部攻击统计与横向移动分析已内嵌至报告模板 `alert-report-template.md` 第 4 章，由 Step 9 `gen-md-report.js` 直接读取 `parsed-internal-{date}.json` 的 `lateral` 字段渲染（§4.1–§4.5），无需单独运行脚本。

**独立工具（调试/离线分析可选）**:

```bash
node skills/secops-alert-analysis/scripts/reporting/lateral-analysis.js \
  --input output/parsed-internal-{date}.json \
  --date {date} \
  --output output/lateral-analysis-{date}.md
```

- 读取内部攻击聚合数据，生成独立的横向攻击分析 MD 章节
- 包含: 内部攻击统计/攻击类型分布/源IP Top10/目标IP Top10/小时分布
- 空数据时输出"未检测到横向移动行为"
- 不生成封禁建议（R7），不做白名单过滤（R8）

**输出**: `output/lateral-analysis-{date}.md`（独立横向攻击分析 MD，可选）

### Step 8：§5.1 XFF 代理攻击专项（默认执行，含关闭开关）

> **开关**：检查 `scripts/.env` 中 `ENABLE_XFF_PROXY` 值。
> - `true`（默认）→ 执行本 Step，§5.1 始终有真实内容
> - `false` → 跳过本 Step，Step 9 不传 `--xff` / `--xff-judgment`，§5.1 渲染器降级显示"未提供 XFF 预跑产物"

本 Step 在路径A 内嵌执行，不依赖独立子技能路由。**单日分析固定 `start = end = {date}`**。

**Step 8a — 查询外部 XFF 告警 + 解析真实客户端：**

```bash
node skills/secops-alert-analysis/scripts/judgment-xff/query-xff.js \
  --start-date {date} --end-date {date}
```

- 产出：`output/judgment-xff-{date}-{date}.json`（聚合 + 外部客户端排名）+ `output/judgment-xff-candidates-{date}-{date}.json`（微步候选 IP）
- 关键逻辑见 `references/judgment-xff-analysis.md`（XFF 子技能唯一事实来源）与附录A（致命 DSL 教训）

**Step 8b — 微步威胁情报（可选，复用 Step 6 逻辑）：**

前置：`ENABLE_THREATBOOK = 'true'` 且 Step 1 自检 `C3 PF-THREATBOOK-TCP` verdict=PASS。

```bash
node skills/secops-alert-analysis/scripts/threat-intel/external.js \
  --batch output/judgment-xff-candidates-{date}-{date}.json --date {date}
```

- 产出：`output/threatbook-enrich-{date}.json`（若 Step 6 已查询，此为追加覆盖，不影响 Step 6 结果）
- `ENABLE_THREATBOOK != true` 或 C3 FAIL → 跳过，`gen-md-report-xff.js` 标注"未提供微步情报"

**Step 8c — 受害主机归因：**

```bash
node skills/secops-alert-analysis/scripts/judgment-xff/victim-hosts.js \
  --input output/judgment-xff-{date}-{date}.json \
  --start-date {date} --end-date {date}
```

- 产出：`output/judgment-xff-victimhosts-{date}-{date}.json`（每个外部客户端的受害主机 dip + 攻击类型 + host_state）

**Step 8d — 合并生成封禁建议（MD + JSON）：**

```bash
node skills/secops-alert-analysis/scripts/judgment-xff/gen-md-report-xff.js \
  --xff output/judgment-xff-{date}-{date}.json \
  --victims output/judgment-xff-victimhosts-{date}-{date}.json \
  --threatbook output/threatbook-enrich-{date}.json \
  --start-date {date} --end-date {date} \
  --report-time "{Step 0 获取的时间值}" \
  --ban-ip-append output/ban-ip-table-{date}.md
```

- 产出：`output/judgment-xff-ban-recommendation-{date}.json`（含 `report_tables` 四张表 Markdown，供 Step 9 §5.1 注入）+ `.md`（独立 XFF 报告，可选阅读）

**产物与 Step 9 对齐**：Step 9 的 `gen-md-report.js` 必须传入 `--xff` + `--xff-judgment`（见 Step 9），§5.1 三项指标 + 四张表自然填充（含 `{{xff_ban_ip_table}}` 4列封禁表）。当无 XFF 告警时（total=0），指标显示 0，四张表为"—"。

**无 XFF 数据降级**：若 Step 8a 产出 `total_xff_alerts = 0`，Step 8c/8d 仍执行（脚本会产出空但合法的 JSON），无需人工跳过。

### Step 9：生成 Markdown 报告（汇总 §1–§5 内容 + §6 附录 + §7 建议）

**处理**：

1. **主路径：脚本生成（统一，可复现）**:
   ```bash
   node skills/secops-alert-analysis/scripts/reporting/gen-md-report.js \
     --date {date} \
     --ban-ip output/ban-ip-table-{date}.md \
     --ban-domain output/ban-domain-table-{date}.md \
     --threat-intel output/threat-intel-table-{date}.md \
     --stats output/parsed-external-{date}.json \
     --internal-stats output/parsed-internal-{date}.json \
     --compromised output/parsed-compromised-{date}.json \
     --xff output/judgment-xff-{date}-{date}.json \
     --xff-judgment output/judgment-xff-ban-recommendation-{date}.json \
     --report-time "{Step 0 获取的时间值}" \
     --output output/alert-report-{date}.md
   ```

   - 作用: 读取三份 parsed JSON + 表格文件 + XFF 产物，经**分析层 + 渲染层**生成 MD 报告。内部流程（薄编排）：
     1. `analyzeExternal(parsed-external)` → 外部攻击类型分布 / 按小时分布 / 高峰时段
     2. `analyzeInternal(parsed-internal)` → 内部统计 / 横向移动
     3. `analyzeCompromised(compromised_hosts)` → 失陷主机补全「攻击来源」列（`外部`/`内网`/`未知`，基于 `sip_addrs` 判定）
     4. `deriveThreatTopics({attackTypes,ips,domains,compromised})` → §5 专项（弱口令/远控C2/挖矿勒索）
     5. `renderExternalSection` / `renderInternalSection` / `renderCompromisedSection` / `renderSpecialSection` → 各子节内容体（**仅表格/列表，不含 ### 标题**；标题由模板提供）
     6. 将章节作为占位符注入模板：§2 用 `{{external_section}}`/`{{external_time_section}}`；§3 用 `{{compromised_section}}`；§4 用 `{{internal_4_1}}`–`{{internal_4_5}}` 五节独立占位符；§5.1 用 `{{xff_metrics}}`（指标）+ `{{xff_real_client_investigate_table}}`/`{{xff_victim_investigate_table}}`/`{{xff_ban_ip_table}}`/`{{xff_threat_intel_table}}`（四张表，xff_ 前缀隔离 §2.3 撞名），§5.2–§5.4 用 `{{special_5_2}}`–`{{special_5_4}}`。渲染器返回按子节 keyed 的内容体对象，模板拥有全部 ### / #### 标题与表占位符，实现「模板拥有标题、渲染器只渲染内容体、每节单独渲染」。
   - **PASS**（路径就绪）→ parsed-external-{date}.json 和表格文件均存在，直接生成
   - **FAIL**（parsed-external-{date}.json 不存在 / 脚本异常）→ 降级到 LLM 模板注入:
     LOG: "[DEGRADE] reason=gen-md-report.js失败: {错误详情} | ts=<ISO8601></iso8601> | params={stats=output/parsed-external-{date}.json} | mode=Step9:script→LLM"
     LLM 读取表格 MD 片段，手工注入模板占位符
     填充统计变量（从 Step 3 统计汇总数据）
     填充时间变量: {{report_time}} → Step 0 时间值, {{start_time}} → {date} 00:00:00, {{end_time}} → stats.last_timestamp 或 {date} 23:59:59
   - **禁止**: LLM不得自行填写表格，必须使用脚本输出
2. 写入: `output/alert-report-{date}.md`

**变量填充说明（三层拆分后）**：

- 模板已**重排**为 §2–§5 四章 + §6 附录 + §7 建议；旧逐行占位符（`{{attack_type}}`/`{{hourly_data_table}}`/`{{lat_src_*}}` 等）已被**块占位符**取代：
  - `{{external_section}}` → §2.4 外部攻击类型分布 + §2.5 按小时分布与攻击高峰（由 `renderExternalSection` 预渲染）
  - `{{compromised_section}}` → §3 失陷主机表（含 7 列：`最近告警时间|主机IP|攻击次数|攻击结果|风险描述|攻击来源|研判意见`）
  - `{{internal_4_1}}`–`{{internal_4_5}}` → §4.1 内部攻击统计 / §4.2 内部攻击类型分布 / §4.3 横向移动源IP Top10 / §4.4 横向移动目标IP Top10 / §4.5 横向移动攻击小时分布（renderInternalSection 返回的内容体，标题在模板）
  - §5.1 XFF 代理攻击：三项指标由 `{{xff_metrics}}`（renderSpecialSection 返回）注入；四张表（`{{xff_real_client_investigate_table}}`/`{{xff_victim_investigate_table}}`/`{{xff_ban_ip_table}}`/`{{xff_threat_intel_table}}`）标题与占位符在模板 §5.1 正文，数据来自子技能 report_tables（单源，禁止主报告重算）。§5.2/§5.3/§5.4 用 `{{special_5_2}}`–`{{special_5_4}}`（renderSpecialSection 返回内容体，标题在模板）
- `{{end_time}}` → 数据实际截止时间（gen-md-report.js 从 parsed-external-{date}.json 的 stats.last_timestamp 读取）
- `{{internal_alerts}}` → parsed-internal-{date}.json 的 stats.total_alerts（内部攻击数）；未执行内部查询时显示 `N/A（内部查询未执行）`
- `{{compromised_alerts}}` → 失陷主机数（analyzed compromised_hosts.length）
- **攻击来源字段（§3 新增列）**：由 `analyzeCompromised` 基于 `compromised_hosts[].sip_addrs` 判定每个受害主机的攻击来源——`sip_addrs` 含任一非「局域网」且非空的值 → `外部`；全部为「局域网」→ `内网`；缺失/非数组/全空 → `未知`（避免把未知误标为确证内网）。`sip_addrs` 由 `extract.js`/`parse-mcp.js` 的 `victim_sip_addrs` 子聚合提供。

**输出**: `output/alert-report-{date}.md`（Markdown报告文件）

### Step 10：生成 HTML 报告（渲染 §1–§7 为 HTML）

**处理**：

1. **主路径：脚本转换（统一，可复现）**:
   ```bash
   node skills/secops-alert-analysis/scripts/reporting/gen-html-report.js \
     --input output/alert-report-{date}.md \
     --output output/alert-report-{date}.html
```

- 作用: 将 Step 9 生成的 MD 报告转换为 HTML，使用 alert-report-template-v1.html 作为外壳
- 支持: 表格解析、代码块、折叠段落、白名单IP过滤、ECharts图表
- **PASS**（路径就绪）→ MD 报告存在，直接转换
- **FAIL**（MD报告不存在/脚本异常）→ 降级到 LLM 渲染:
  LOG: "[DEGRADE] reason=gen-html-report.js失败: {错误详情} | ts=<ISO8601></iso8601> | params={input=output/alert-report-{date}.md} | mode=Step10:script→LLM"
  LLM 读取封禁表格 MD 片段，手工渲染为 HTML
  使用 alert-report-template-v1.html 作为外壳，填入 {{content}}
  填充元数据变量 {{title}}/{{date_range}}/{{analyst}}/{{report_time}}
- **SKIP**（Step 1 已 terminate）→ 无下游

2. 写入: `output/alert-report-{date}.html`

### Step 11：发布报告

**输入**: `output/alert-report-{date}.html`（Step 10 产物）

**处理**：

1. 前置验证:

   - 检查HTML文件存在且非空 → 不存在则跳过发布，LOG: `[WARN] HTML报告不存在，跳过发布`
2. 执行发布:

   ```bash
   node skills/secops-alert-analysis/scripts/portal/post.js output/alert-report-{date}.html
   ```

   - 支持 `--title` 参数覆盖默认标题（默认从HTML `<title>` 标签解析）
3. 后置验证:

   - 检查退出码 = 0 → 成功
   - 退出码 = 1 → 输入错误（文件缺失/API业务错误）
   - 退出码 = 2 → 网络超时（非内网环境）
   - 验证输出中URL格式匹配 `https://eip.teamshub.com/t/{topicId}`

**输出**: 帖子链接URL

**降级策略**: 发布失败不阻断整体分析流程，记录降级日志后继续。降级日志格式:

```
[FALLBACK] 发布降级: portal_publish → skipped
[FALLBACK] 原因: {error_message}
[FALLBACK] 时间: {ISO 8601 timestamp}
```

---

## 前端风格规范

生成 HTML 页面时必须严格遵守以下规范：

### 图标规范

- **禁止使用 emoji 或任何计算机符号**作为视觉元素
- 必须使用 SVG 矢量图形替代

（图标 SVG 表与现状一致，略；详见 `templates/alert-report-template-v1.html` 与现状主 SKILL.md 前端风格规范）

### 样式/脚本放置规范

- **所有 `<style>` 标签必须放入 `<body>` 内部**，不允许放在 `<head>` 中
- **所有 `<script>` 标签必须放入 `<body>` 内部**
- 禁止使用外部 CDN 脚本（除公司内网支持的库外）
- 涉及图表时，**仅允许使用**公司内网支持的 ECharts：https://yi.teamshub.com/temp/c-ui/c-plugin/echarts/echarts.min.js
- **禁止使用**：TypeScript、CoffeeScript、ES6 模块以外的任何脚本语言

### HTML 渲染规范

- 主路径使用 `gen-html-report.js` 脚本转换 MD → HTML（可复现、格式一致）
- LLM 直接渲染仅作为脚本失败的降级方案
- 严格按照 `alert-report-template-v1.html` 的CSS样式，只使用模板已有的class
- 表格使用 `<table>` 结构，表头使用 `<th>`，行使用 `<tr><td>`
- 代码块使用 `<pre><code>`，列表使用 `<ul><li>` 或 `<ol><li>`，引用使用 `<blockquote>`
- 重点强调使用 `class="badge"`（badge-danger/success/warning）

---

## 输出规范

### 终端摘要

> **模板文件**: `templates/terminal-summary-template.md`
>
> 所有步骤执行完毕后，Agent 必须按模板输出三段式完成总结：
>
> 1. **执行流程表** — 按本 SKILL.md 中定义的 Step 逐行生成 `| Step N | 状态 | 说明 |`（表头 + 数据行），状态使用 ✅/⏭️/⚠️/❌，说明列填关键产出摘要（如告警数、候选数、文件路径等）
> 2. **关键发现** — 核心指标、Top攻击类型、攻击高峰、高危IP/Domain
> 3. **输出文件表** — 产物文件路径与说明

### **状态标记**

- `✅` — 步骤成功完成
- `⏭️` — 步骤被跳过（如 ENABLE_POST=false、ENABLE_THREATBOOK=false、无候选IP等）
- `⚠️` — 步骤完成但有警告（如 ThreatBook 配额截断、部分查询失败等）
- `❌` — 步骤失败（流水线应在此终止）

### 文件输出

| 文件         | 路径                                | 说明              |
| ------------ | ----------------------------------- | ----------------- |
| Markdown报告 | `output/alert-report-{date}.md`   | 完整分析报告      |
| HTML报告     | `output/alert-report-{date}.html` | 深色模式+打印友好 |

### 路径规范

- **工作目录（CWD）必须为项目根目录**（即 `agent-secops/`），所有命令均从项目根目录执行
- **禁止将 workdir 设为 skill 目录或其子目录**：skill 目录可能是符号链接，shell 会解析为物理路径，导致相对路径计算偏移
- `output/` 路径相对于 CWD（项目根目录），如 `output/alert-report-{date}.md`
- `scripts/`、`references/`、`templates/` 路径相对于 skill base directory，Agent 调用时用 `skills/secops-alert-analysis/` 前缀拼接（见上方命令示例）
- **skill 内部引用文件（白名单、标签映射等）不作为 CLI 参数传递**——脚本已通过 `__dirname` 自动定位，无需显式传参

### 质量门控

- 验证 MD 文件写入成功
- 验证 HTML 文件写入成功
- 验证白名单已检查（已记录日志）

---

## 脚本工具链（路径A 相关）

> 本路径A 全程使用脚本直连 ES，不调用任何 MCP 工具。以下为关键脚本（位于 `skills/secops-alert-analysis/scripts/`）：

| 脚本                   | 路径                                        | 用途                                                                                                    |
| ---------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| selfcheck.js           | `scripts/workflow/selfcheck.js`           | Step 1 自检（TCP + .env）                                                                               |
| extract.js             | `scripts/es-tool/extract.js`              | Step 2 外部/内部/失陷聚合查询（`-x` / `--internal` / `--compromised` + `--parsed-output`）      |
| dns-agg.js             | `scripts/es-tool/dns-agg.js`              | Step 2 DNS 全局聚合（覆盖全量 DNS 流量，产出`dns-domains-{date}.json`）                               |
| analyze-external.js    | `scripts/analysis/analyze-external.js`    | 分析层：外部攻击类型分布 / 按小时分布（由 gen-md-report.js 调用，亦支持`--self-run --date` 独立查询） |
| analyze-internal.js    | `scripts/analysis/analyze-internal.js`    | 分析层：内部攻击统计 + 横向移动（由 gen-md-report.js 调用）                                             |
| analyze-compromised.js | `scripts/analysis/analyze-compromised.js` | 分析层：失陷主机补全「攻击来源」列（classifyAttackSource，由 gen-md-report.js 调用）                    |
| ban-ip-table.js        | `scripts/reporting/ban-ip-table.js`       | Step 4 IP封禁表（`--input parsed-external`）                                                          |
| ban-domain-table.js    | `scripts/reporting/ban-domain-table.js`   | Step 5 Domain封禁表（`--input dns-domains`）                                                          |
| lateral-analysis.js    | `scripts/reporting/lateral-analysis.js`   | Step 7 §4 内部攻击/横向分析（独立工具，可选）                                                          |
| external.js            | `scripts/threat-intel/external.js`        | Step 6 §2.3 威胁情报（`--batch` / `--ip`）                                                         |
| fuse.js                | `scripts/threat-intel/fuse.js`            | Step 6 §2.3 情报表融合                                                                                 |
| gen-md-report.js       | `scripts/reporting/gen-md-report.js`      | Step 9 MD报告编排（读 parsed → analyze* → deriveThreatTopics → render* → 注入模板）                 |
| gen-html-report.js     | `scripts/reporting/gen-html-report.js`    | Step 10 HTML报告渲染                                                                                    |
| post.js                | `scripts/portal/post.js`                  | Step 11 发布                                                                                            |

> `parse-mcp.js` 为路径B 专属解析器，本路径A 不使用（由 `extract.js --parsed-output` 直出相同 shape）。`scripts/analyzer/`（使用 `@timestamp` 字段）为另一套遗留工具，与本重构的 `scripts/analysis/`（使用 `timestamp`）**无关**，勿混淆。

### 共享库模块

| 模块                 | 路径                                    | 功能                                                                                                |
| -------------------- | --------------------------------------- | --------------------------------------------------------------------------------------------------- |
| whitelist.js         | `scripts/shared/whitelist.js`         | 白名单解析与IP分类（CIDR/范围/单IP）                                                                |
| es-query.js          | `scripts/shared/es-query.js`          | 查询层：ES HTTP 直连 + 声明式`CONTEXT_FILTERS` + `buildQuery(ctx)` + `buildContextQuery`      |
| threat-categories.js | `scripts/shared/threat-categories.js` | 专项研判派生：`THREAT_CATEGORIES` 配置 + `deriveThreatTopics`（纯函数，弱口令/远控C2/挖矿勒索） |
| time-utils.js        | `scripts/shared/time-utils.js`        | 时区转换（Asia/Shanghai）                                                                           |
| report-renderer.js   | `scripts/shared/report-renderer.js`   | `renderTemplate`（块占位符全局正则替换 + 未替换 WARN）/ Markdown 表格渲染                         |
| cli-args.js          | `scripts/shared/cli-args.js`          | CLI参数解析工具                                                                                     |

### 测试

```bash
# 运行白名单测试
node --test tests/secops-alert-analysis/whitelist.test.js
# 运行解析器测试
node --test tests/secops-alert-analysis/parser.test.js
# 运行渲染器测试
node --test tests/secops-alert-analysis/renderer.test.js
# 运行所有测试
node --test tests/secops-alert-analysis/
```

### 终端输出

- 最多50行
- 包含：关键指标、高危IP Top 5、失陷主机、文件路径
- 报告文件路径突出显示

---

## 附录B：ES字段说明（通用，脚本直连 ES 适用）

| 字段路径                       | 说明                                         |
| ------------------------------ | -------------------------------------------- |
| `field_values.sip`           | 源IP地址（可能是内网IP）                     |
| `field_values.sip_addr`      | 源IP地理地址（值为"局域网"表示内网）         |
| `field_values.dip`           | 目标IP地址                                   |
| `field_values.dip_addr`      | 目标IP地理地址                               |
| `field_values.host_state`    | 攻击结果（攻击成功/失陷/企图等）             |
| `field_values.attack_type`   | 攻击类型                                     |
| `field_values.hazard_rating` | 危险等级（高危/中危/低危/危急）              |
| `field_values.proto`         | 协议（http/mysql/redis等）                   |
| `field_values.dport`         | 目标端口                                     |
| `timestamp`                  | 时间戳（date 类型，不带 field_values. 前缀） |

> **查询动词规则（通用，适用于本路径脚本直连 ES）**：`field_values.*` 为 keyword 类型 → 必须用 `term` 精确匹配；`timestamp` 为 date 类型 → 用 `range`；`message` 为 text 类型 → 用 `match`。索引 mapping 为 `dynamic: false`，**禁止查询未在 mapping 中的字段**。所有需要精确计数的查询必须包含 `track_total_hits: true`。ES 版本 7.16.3，不支持 ESQL（`_query` 端点）。

## 附录C：白名单格式

文件: `references/ipWhite.md`

支持格式:

- 单IP: `192.168.1.1`
- CIDR: `10.0.0.0/8`
- IP范围: `203.0.113.0-63`

## 附录F：报告模板变量

- 外部攻击告警数 = 源IP为非局域网（sip_addr != "局域网"）的告警数
- 内部攻击告警数 = 源IP为局域网（sip_addr = "局域网"）的告警数
- 横向攻击告警数 = 源和目的都是内网（sip_addr = "局域网" AND dip_addr = "局域网"）的告警数，属于内部攻击告警数的子集

### alert-report-template.md 变量

| 变量                                                   | 说明                                                                                             |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| `{{report_time}}`                                    | 报告生成时间（必须使用 Step 0 获取的值）                                                         |
| `{{start_time}}`                                     | 分析开始时间                                                                                     |
| `{{end_time}}`                                       | 分析结束时间                                                                                     |
| `{{analyst}}`                                        | SecOps Agent                                                                                     |
| `{{total_alerts}}`                                   | 告警总数（外部告警数 + 内部攻击数）                                                              |
| `{{external_alerts}}`                                | 外部攻击告警数                                                                                   |
| `{{internal_alerts}}`                                | 内部攻击数（parsed-internal.stats.total_alerts；未执行则 N/A）                                   |
| `{{compromised_alerts}}`                             | 攻击成功/失陷数（analyzed compromised_hosts.length）                                             |
| `{{unique_external_ips}}`                            | 涉及外部IP数                                                                                     |
| `{{unique_internal_hosts}}`                          | 涉及内部主机数                                                                                   |
| `{{lateral_alerts}}`                                 | 横向移动告警数（parsed-internal.stats.lateral_alerts）                                           |
| `{{external_section}}`                               | **块占位符**：§2.4 外部攻击类型分布 + §2.5 按小时分布与攻击高峰（renderExternalSection） |
| `{{compromised_section}}`                            | **块占位符**：§3 失陷主机表（7 列含「攻击来源」，renderCompromisedSection）               |
| `{{internal_4_1}}`                                   | **块占位符**：§4.1 内部攻击统计（renderInternalSection）                                  |
| `{{internal_4_2}}`                                   | **块占位符**：§4.2 内部攻击类型分布（renderInternalSection）                              |
| `{{internal_4_3}}`                                   | **块占位符**：§4.3 横向移动源IP Top10（renderInternalSection）                            |
| `{{internal_4_4}}`                                   | **块占位符**：§4.4 横向移动目标IP Top10（renderInternalSection）                          |
| `{{internal_4_5}}`                                   | **块占位符**：§4.5 横向移动攻击小时分布（renderInternalSection）                          |
| `{{xff_metrics}}`                                    | **块占位符**：§5.1 XFF 三项指标（告警总数/客户端IP数/伪造XFF数，renderSpecialSection 返回） |
| `{{xff_real_client_investigate_table}}` / `{{xff_victim_investigate_table}}` / `{{xff_ban_ip_table}}` / `{{xff_threat_intel_table}}` | §5.1 XFF 四张表（标题+占位符在模板 §5.1 正文，数据来自子技能 report_tables 单源；xff_ 前缀隔离 §2.3 `{{threat_intel_table}}` 撞名） |
| `{{special_5_2}}`                                    | **块占位符**：§5.2 弱口令攻击（renderSpecialSection）                                     |
| `{{special_5_3}}`                                    | **块占位符**：§5.3 远控木马/C2 外联攻击（renderSpecialSection）                           |
| `{{special_5_4}}`                                    | **块占位符**：§5.4 挖矿/勒索攻击（renderSpecialSection）                                  |
| `{{ban_ip_table}}`                                   | IP封禁建议表格（ban-ip-table.js 生成）                                                           |
| `{{ban_domain_table}}`                               | Domain封禁建议表格（ban-domain-table.js 生成）                                                   |
| `{{threat_intel_table}}`                             | IP威胁情报表格（fuse.js 生成）                                                                   |
| `{{full_ip_list}}`                                   | 附录：完整外部攻击IP列表（保留，gen-md-report.js 渲染）                                          |
| `{{detected_external_ips}}` / `{{filter_summary}}` | 附录：IP 过滤结果（保留，白名单 + 阈值对比）                                                     |

### alert-report-template-v1.html 变量

| 变量                | 说明                                     |
| ------------------- | ---------------------------------------- |
| `{{title}}`       | 报告标题                                 |
| `{{date_range}}`  | 分析日期                                 |
| `{{analyst}}`     | SecOps Agent                             |
| `{{report_time}}` | 报告生成时间（必须使用 Step 0 获取的值） |
| `{{content}}`     | Markdown转换后的HTML内容                 |

## 附录G：ThreatBook 威胁情报配置

> **完整配置参考见 `references/threatbook-config.md`**（环境变量表/开关行为表/脚本路径表/输出文件格式）。
>
> 核心开关行为（`ENABLE_THREATBOOK`）：
>
> - `false`：Step 7 跳过（不调公网），Step 8 输出"威胁情报查询结果不可用"
> - `true`：Step 7/8 正常执行
> - 无豁免路径：`external.js` 入口硬性检查，`--ip`/`--batch` 均拒绝；`--reset-cache`/`--help` 不受限

---

*本 skill 遵循三元结构：元数据 + 执行手册（纯脚本/零 MCP）+ 知识附录（B/C/F/G 共享）*
