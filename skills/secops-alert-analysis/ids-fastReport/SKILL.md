---
name: secops-alert-analysis-ids-fastreport
description: |
  IDS 导出 Excel 快速研判子技能（纯脚本 + LLM 研判、零 MCP/零 ES）。当用户提供「流量传感器」/ IDS 平台导出的「告警列表-流量传感器_列表导出*.xlsx」告警 Excel，要求快速做告警研判、攻击链还原、失陷判定、IOC 提取并按 alert-report-template.{md,html} 输出报告时，按本工作流执行。数据源为 Excel 文件而非 ES，全程离线可跑（威胁情报/发布等公网环节可降级跳过）；报告渲染完成后可选复用父 skill 的 `scripts/portal/post.js` 发布到公司 EIP 门户（受 `ENABLE_POST` 开关控制）。
output:
  files:
    - pattern: "output/ids-fastreport-{date}.md"
      description: "IDS 告警研判 MD 报告（按 alert-report-template.md 结构）"
      template: "templates/alert-report-template.md"
    - pattern: "output/ids-fastreport-{date}.html"
      description: "IDS 告警研判 HTML 报告（深色模式+打印友好）"
      template: "templates/alert-report-template-v1.html"
    - pattern: "output/ban-ip-candidates-{date}.json"
      description: "非白名单公网攻击源，供微步批量查询（复用 reporting/ban-ip-table.js 产出）"
    - pattern: "output/ban-ip-table-{date}.md"
      description: "IP 封禁建议表（复用 reporting/ban-ip-table.js 产出，已二次白名单过滤）"
    - pattern: "output/ban-domain-candidates-{date}.json"
      description: "可疑域名候选（复用 reporting/ban-domain-table.js 产出）"
    - pattern: "output/ids-infra-report-{date}.md"
      description: "失陷主机基础设施角色修正清单（fact-to-enrich.js 产出，复用 shared/infra-exclude.js）"
    - pattern: "output/ids-fact-{date}.json"
      description: "ids告警事实（parse-ids-excel.py 产出）"
  terminal:
    summary: true
---

# IDS 导出 Excel 快速研判（ids-fastReport）

> 本子技能由父 skill `secops-alert-analysis` 按需加载，**不设 triggers**。用于**离线快速研判** IDS/流量传感器导出的告警 Excel，生成与主报告同构的 `alert-report-template.{md,html}` 报告。

**与路径A（judgment）的区别**：

| 维度 | 路径A（judgment）                    | 本子技能（ids-fastReport）                          |
| ---- | ------------------------------------ | ------------------------------------------------------------ |
| 数据源 | Elasticsearch（脚本直连，需内网）   | **IDS 平台导出的 Excel 文件**（离线，自包含）                |
| MCP/ES | 纯脚本直连 ES                        | **零 ES、零 MCP**，仅解析 Excel                              |
| 典型场景 | 按日期从 ES 拉全量告警做日报        | 收到 IDS / 流量传感器**导出清单**（含「成功失陷告警」过滤）  |
| 报告 | alert-report-{date}.{md,html}        | ids-fastreport-{date}.{md,html}                              |

---

## 输入输出

**输入**：一个或多个 `告警列表-流量传感器_列表导出*.xlsx`（68 列标准表头，见附录A）。平台导出的文件可能是「全量告警」或「成功失陷告警」过滤子集，本子技能均可处理，并在报告中标注数据口径。

**输出**：
- `output/ids-fastreport-{date}.md` — Markdown 报告（章节与 `alert-report-template.md` 对齐）
- `output/ids-fastreport-{date}.html` — 使用 `gen-html-report.js` + `alert-report-template-v1.html` 外壳渲染
- （可选）发帖到公司 EIP 门户：复用父 skill `scripts/portal/post.js`，受 `ENABLE_POST` 控制（Step 7）

> CWD 必须为项目根 `agent-secops/`；命令用 `skills/secops-alert-analysis/ids-fastReport/scripts/` 前缀；产物写 `output/`。

---

## 执行流程

### Step 0：获取报告时间

```bash
TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S'
```

将返回值作为 `report_time`，写入事实基座与报告头部。禁止 LLM 编造时间。

### Step 1：输入处理 — 定位 / 核对 Excel

1. 确认 xlsx 文件路径（支持全路径或相对项目根的路径）。
2. 核对文件是否为本子技能所识别的 IDS 导出格式（表头含 `受害IP`/`攻击IP`/`威胁名称`/`攻击结果` 等列）。若不是，询问用户确认来源。
3. 若提供了多个 xlsx（同一时段多次导出，如「全量」+「成功失陷告警」），告知用户将**分别解析**，并推荐以口径最全的一份为主报告依据。
4. 确定 `date`：从文件名时间范围（如 `…2026-08-13T00_00_00.000至2026-08-13T18_33_52.000…`）或 `最近发生时间` 结尾推断，格式 `YYYYMMDD`。

### Step 2：解析 Excel → 事实基座 JSON

```bash
python skills/secops-alert-analysis/ids-fastReport/scripts/parse-ids-excel.py \
    --input "<xlsx路径>" \
    --output output/ids-fact-{date}.json \
    --report-time "{Step 0 时间}"
```

- 产出 `output/ids-fact-{date}.json`（规范化 JSON 事实基座，UTF-8）：`meta` / `stats`（含 `external_by_lv2`/`external_hourly`/`lateral_hourly`）/ `classification`（external/lateral/tunnel/other，含 `lateral_sources`/`lateral_targets`/`xff_clients`/`xff_victims`）/ `compromised` / `ioc` / `rows`（精简逐行）。
- 确定性聚合由脚本完成：总数、威胁级别、攻击结果、一级/二级类型、威胁名称 Top、按小时分布、外部攻击源 Top、受害主机 Top、失陷主机、IOC（域名/公网源/URI）。
- **失败**：
  - `无法加载 openpyxl` → `pip install openpyxl`。
  - `表中无数据行`（退出码 3）→ 核对工作表名，可用 `--sheet` 指定。
  - 输入不存在（退出码 2）→ 检查路径。

> ⚠️ **确定性取数铁律**：统计与清单**严禁**用 Read 直接读取整个 xlsx 或大 JSON 原文。统计一律以 `parse-ids-excel.py` 的 `stats`/`classification`/`ioc` 为准。`rows` 逐行数据仅供 LLM 做**攻击链推理**（按威胁/主机/时间过滤后小段查阅），避免整读导致上下文爆炸。

### Step 2B（新增）：白名单剔除 + 封禁表 + 基础设施 enrich（复用父 skill 机制，不重复开发）

> 本步骤**最大化复用父 skill 既有模块**，不再自行实现白名单剔除/微步候选逻辑。仅用一个薄适配器 `fact-to-enrich.js` 把事实基座转成父 skill 模块能消费的输入形状，再逐级调用既有 CLI。

**① 适配器：事实基座 → 父 skill enrich 输入形状 + 基础设施角色修正**

```bash
node skills/secops-alert-analysis/ids-fastReport/scripts/fact-to-enrich.js \
    --fact output/ids-fact-{date}.json \
    --out-ip output/enrich-ip-{date}.json \
    --out-domain output/enrich-domain-{date}.json \
    --infra-report output/ids-infra-report-{date}.md \
    --out-mapping output/merged-mapping-{date}.json
```

- `enrich-ip-{date}.json`：`{ips:[{ip,total_alerts,attack_types,max_timestamp,sip_addr}]}` → 喂下列 `reporting/ban-ip-table.js `--input``。
- `enrich-domain-{date}.json`：`{domains:[{ioc,total_alerts,attack_types,max_timestamp}]}` → 喂 `reporting/ban-domain-table.js --input`。
- `ids-infra-report-{date}.md`：命中 `ipInfra.md` 的失陷主机**角色修正清单**（复用 `shared/infra-exclude.js` 的 `isInfrastructure`）。
- `merged-mapping-{date}.json`：父 `attack-type-mapping.json` 与 skill-local `lv2-attack-type-mapping.json` 的**合并映射**（父表只读）→ 喂下方两个 ban 脚本的 `--attack-type-mapping`。
- **攻击类型（attack_types）统一取自 `二级告警类型`（LV2）**：适配器**透传原始 LV2 短 token**（不再预替换），由 ban 脚本经合并映射统一映射为可读名。父表缺失的 LV2（配置不当/错误、其他攻击利用等）由 skill-local 兜底补齐，因此**对该数据集零 FR-011 回退**。CVE 级细节仍保留在报告正文/URI 与 `rows` 中。所需封禁 IP/域名集合与次数不变（仅 `风险描述` 更可读）。

**② 复用 `reporting/ban-ip-table.js`：二次白名单过滤（FR-013）+ 封禁表 + 微步候选**

```bash
node skills/secops-alert-analysis/scripts/reporting/ban-ip-table.js \
    --input output/enrich-ip-{date}.json \
    --format markdown \
    --output output/ban-ip-table-{date}.md \
    --candidates-output output/ban-ip-candidates-{date}.json \
    --attack-type-mapping output/merged-mapping-{date}.json
```

- 复用 `shared/whitelist.js` 对 `ipWhite.md` 做二次过滤，排除公司/内网/合法源（实际报告流中该数通常为 0：`parse-ids-excel.py` 已在事实基座阶段预剔除白名单源）。
- **白名单排除量为确定性指标，从 `ids-fact-{date}.json` 的 `stats.whitelist_excluded` 机器可读读取**（`parse-ids-excel.py` 在事实基座阶段用 `ipWhite.md` 对外部源预剔除时统计的 unique 源 IP 数，**真实反映被过滤的合法源数量**）。注意：`reporting/ban-ip-table.js` 的二次复查（FR-013）读出的 `whitelist_secondary_filtered_count` 通常为 0，**不要**用它替代真实过滤数。将其作为「排除的公司/内网/合法源数量」指标写入报告 §1 表格与终端摘要，与封禁表分开呈现——这些是被正确过滤的合法源，**不计入封禁建议、不视为恶意**。
- `ban-ip-candidates-{date}.json`：**仅非白名单公网攻击源** + 确定性指标 `whitelist_secondary_filtered_count`，格式与父 skill ban-ip 机制兼容，直接供 Step 2C `external.js --batch` 消费。
- `ban-ip-table-{date}.md`：四列封禁表 `告警日期时间戳|风险IP|风险描述|风险IP的地理位置`（父 skill 同构，供报告 §2 引用）。

**③ 复用 `reporting/ban-domain-table.js`：域名封禁表 + 域名候选**（外联可疑域名）

```bash
node skills/secops-alert-analysis/scripts/reporting/ban-domain-table.js \
    --input output/enrich-domain-{date}.json \
    --format markdown \
    --output output/ban-domain-table-{date}.md \
    --candidates-output output/ban-domain-candidates-{date}.json \
    --attack-type-mapping output/merged-mapping-{date}.json \
    --min-attacks 1
```

> 注：事实基座 `ioc.domains` 仅聚合 **`协议=dns`** 的 DNS 查询域名（真实 DNS C2/隧道 IOC），并携带逐域名 `attack_types`（取自 `二级告警类型`）与 `max_timestamp`。故域名表 `风险描述`/`最近告警时间` 为真实值，且天然排除了 HTTP Host/SNI 与 `ip:port` 噪音——**不要**把 HTTP 行的 `域名` 列（其为被攻击的公司 Web 资产 Host，非攻击者 C2）当作 IOC。

**研判要点（复用父 skill 语义）**：
- **白名单 ≠ 忽视**：`ipWhite.md` 用于判定「外部攻击源是否公司/内网」，命中不封禁、不微步查询（由 `ban-ip-table.js` 过滤）。
- **基础设施 ≠ 一刀切剔除**：`ipInfra.md` 只提示**人工复核**是否真失陷，底层告警保留。
- `compromised` 中命中 infra 的（如 DNS 服务器 192.0.2.10/12、网关 198.51.100.1、198.51.100.3、203.0.113.2 等）在报告 §5 以「角色修正」呈现，勿直接当作普通业务主机被控。

### Step 2C：微步威胁情报 enrich（**必选**）

> **直接复用父 skill 既有 `threat-intel/` 脚本**（见 threatbook-config.md），不重复实现。
> `.env` 已配 `ENABLE_THREATBOOK=true` + `THREATBOOK_API_KEY`，微步查询**本应可用**，**禁止**因单次网络抖动直接降级跳过。

```bash
# 批量查 IP（消费 Step 2B 的 ban-ip-candidates）：
node skills/secops-alert-analysis/scripts/threat-intel/external.js \
    --batch output/ban-ip-candidates-{date}.json \
    --date {date} \
    --output output/threatbook-enrich-{date}.json

# 逐个查域名（可选）：
node skills/secops-alert-analysis/scripts/threat-intel/external.js --domain <域名>

# 融合成情报表（输入 ban-ip-table，与父 skill judgment 的 fuse 用法一致）：
node skills/secops-alert-analysis/scripts/threat-intel/fuse.js \
    --ban-ip-table output/ban-ip-table-{date}.md \
    --enrich output/threatbook-enrich-{date}.json \
    --output output/threat-intel-table-{date}.md
```

- 依赖 `scripts/.env`：`ENABLE_THREATBOOK=true` + `THREATBOOK_API_KEY`。
- **先验证再断言降级**：运行前用 `node external.js --ip 8.8.8.8` 探测；只有确认 `C3 PF-THREATBOOK-TCP=FAIL`（网关配置/凭据问题）才可降级，并记录 `[FALLBACK] threatbook → unavailable` 日志。**网络超时≠不可用**：重试一次，仍 `NETWORK_TIMEOUT` 才降级为报告注明「威胁情报查询结果不可用」。
- 在报告 §2/§5 引用：非白名单公网源已微步确认的（is_malicious + severity=high/危急）优先封禁与高亮；未确认但高危的标注「待情报确认」。

### Step 2D（新增）：离线 XFF 研判（**必选**，零 ES）

> 父 skill 的 `judgment-xff` 子技能依赖 ES，无法用于本子技能的「零 ES 离线」模式。本步骤用**离线脚本 `gen-xff-judgment.js`** 从事实基座直接生产与 judgment-xff **口径完全一致**的产物，不依赖 ES。

```bash
node skills/secops-alert-analysis/ids-fastReport/scripts/gen-xff-judgment.js \
    --fact output/ids-fact-{date}.json \
    --date {date}
```

- 产出：
  - `output/xff-ban-ip-table-{date}.md` — **4 列 XFF 封禁建议表**（`告警日期时间戳|风险IP|风险描述|风险IP的地理位置`），供 §5.1 `--xff-ban-ip-table` 注入。
  - `output/xff-ban-ip-candidates-{date}.json` — XFF 公网客户端微步候选，供 Step 2C `external.js --batch` 查询恶意性。
  - `output/xff-victim-table-{date}.md` — 外部客户端 × 受害主机映射，供 §5.1 研判。
- **输出口径与父 `judgment-xff` 完全一致**：`gen-xff-judgment.js` **默认 `--min-attacks 10`（严格大于，alerts>10 才入选）**，与父 judgment-xff 的 `XFF_MIN_ATTACKS=10` 及 §2.1 主 `ban-ip-table.js` 对齐；时间戳 `yyyy/M/d H:mm:ss`（上海）、风险描述 `{类型}({次数})` 逗号连接（top3 降序）均与父 judgment-xff 同构。**地理**：父 judgment-xff 因 ES 数据模型无客户端地理而固定「未知」；本子技能从表格字段 `攻击IP地理信息` 直接取值（XFF 真实客户端与攻击IP一致时为该值，缺失回退「未知」），更精准。
- **接入微步**：对 `xff-ban-ip-candidates-{date}.json` 执行 Step 2C 的 `external.js --batch`，再用 `fuse.js --ban-ip-table output/xff-ban-ip-table-{date}.md` 融合出 `output/xff-threat-intel-table-{date}.md`（供 §5.1 `--xff-threat-intel-table`）。
- **判定**：XFF 客户端中微步 `is_malicious=true` 的（尤其 P0 傀儡机/垃圾邮件/webshell 类）**必须列入封禁建议**，并以 §5.1 情报表高亮；同时交叉核对该客户端告警次数是否达封禁阈值。

### Step 3：渲染确定性 MD 骨架

```bash
python skills/secops-alert-analysis/ids-fastReport/scripts/render-skeleton.py \
    --input output/ids-fact-{date}.json \
    --output output/ids-fastreport-{date}.md \
    --ban-ip-table output/ban-ip-table-{date}.md \
    --ban-domain-table output/ban-domain-table-{date}.md \
    --threshold-filtered-count <N> \
    --valid-external-count <N> \
    --min-attacks 10 \
    --threat-intel-table output/threat-intel-table-{date}.md \
    --xff-ban-ip-table output/xff-ban-ip-table-{date}.md \
    --xff-threat-intel-table output/xff-threat-intel-table-{date}.md
```
> **`--title` 缺省自动生成**（无需传）：由导出文件名窗口（`export_window_*`）推导为与 ES 版一致的标题格式 `安全运营研判告警分析报告 {start} ~ {end}`（如 `安全运营研判告警分析报告 2026-08-16-21:00:00 ~ 2026-08-17-09:00:00`）；文件名窗口缺失时回退告警首末时间（`window_*`）；仍需自定义才显式传 `--title`。
> `--threat-intel-table`/`--xff-ban-ip-table`/`--xff-threat-intel-table` 为**必填**（由 Step 2C/2D 产出）；仅当微步网关/凭据确认不可达（见 Step 2C 降级判定）时才留空，骨架以降级说明占位。
> `--output` 直接指向 `ids-fastreport-{date}.md` 即可（骨架即完整报告壳，LLM 仅补写 §7）。若沿用两文件流程，可先写 `ids-skeleton-{date}.md` 再由 Step 5 落 `ids-fastreport-{date}.md`。

- `--whitelist-count N`：白名单过滤排除 IP **总数**（**不区分一次/二次**）。**默认自动取** `parse-ids-excel.py` 产出的 fact JSON 的 `stats.whitelist_excluded`（解析层用 `ipWhite.md` 剔除外部源的真实 unique IP 数）；仅在需要覆盖时才显式传值。勿再取 `ban-ip-candidates-{date}.json` 的 `whitelist_secondary_filtered_count`（那只是封禁表生成时的二次复查，通常为 0，会低估真实过滤数）。
- `--threshold-filtered-count N`：阈值过滤 IP 数（`ban-ip-candidates-{date}.json` 的 `threshold_filtered_count`，攻击次数≤`--min-attacks`）。
- `--valid-external-count N`：有效外部攻击 IP 数（阈值过滤后剩余候选数，即候选 `total`）。
- `--min-attacks`：阈值下限（默认 10，与 §2.1 封禁表口径一致）。
- §6.1 与 ES 版同构（**不区分一次/二次白名单**，只报过滤总数，且满足 ES 恒等式 `检出 = 白名单 + 阈值 + 有效`）：`本次检出外部攻击IP：N`(=剔除白名单前的外部源数 `len(ext)+wl`) + `经白名单过滤X个IP(=stats.whitelist_excluded)，阈值过滤Y个IP（攻击次数≤Z），有效外部攻击IP：W个`。
- `--ban-ip-table` / `--ban-domain-table`：Step 2B 的封禁表，确定性注入报告正文 §2.4/§2.5（对齐模板「建议立即封禁」高亮），处置人员无需翻到附录。
  - 产出 `output/ids-fastreport-{date}.md`（**确定性渲染章节，严格对齐 `alert-report-template.md`**）：
    - **§1 报告概述**：概述表（告警总数 / 外部·内部·外联攻击告警数 / 攻击成功·失陷IP数 / 涉及外部·内部主机数 / 精确总数 / ES计数查询总数=N/A / 白名单排除IP数(=stats.whitelist_excluded) / 威胁级别·攻击结果分布）
    - **§2 外部攻击研判**：2.1 IP 封禁建议（注入 `ban-ip-table`，高亮） / 2.2 Domain 封禁建议（注入 `ban-domain-table`） / 2.3 IP 威胁情报（可选注入 `threat-intel-table`） / 2.4 外部按类型分布（`external_by_lv2`） / 2.5 外部按时间分布（`external_hourly`）
    - **§3 攻击成功/失陷IP研判**：`compromised` 表（受害IP / 攻击结果 / 来源 / 主要威胁 / 最近时间）
    - **§4 内部攻击研判**：4.1 内部攻击统计 / 4.2 内部按类型分布（`lateral_by_lv2`） / 4.3 横向源 Top10 / 4.4 横向目标 Top10 / 4.5 横向按时间分布（`lateral_hourly`）
    - **§5 专项研判**：5.1 XFF 代理攻击（真实客户端 / 受害映射 + 可选封禁·情报表） / 5.2 弱口令暴力猜解 / 5.3 远控木马C2 / 5.4 挖矿勒索（均由外部源按关键词确定性派生）
    - **§6 详细数据附录**：6.1 IP 过滤结果（ES 版同构，报过滤总数）/ 6.2 外部攻击IP完整列表（`外部攻击IP完整列表` 标题，供 HTML 折叠；5 列与 ES 版同构：最近告警时间/攻击IP/攻击次数/归属地/攻击类型(次数)）
    - **§7 攻击链还原与研判结论（保留，LLM 补写）**：7.1 研判概述 / 7.2 核心事件还原 / 7.3 IOC 提炼 / 7.4 失陷·攻击成功主机分级 / 7.5 应急响应优先级（占位标记）
    - **§8 安全建议**：模板固定四项

> ⚠️ **确定性铁律不变**：除 §7 攻击链还原与研判结论（LLM 补写）外，以上统计与表格**全部由脚本渲染**，LLM **不得**重造或删改脚本数字。LLM 仅需在 §7 补写攻击链叙事、失陷研判与应急优先级，且可直接引用 §2.4/§2.5、§4.3–§4.5、§5.1 的既有确定性数据，**无需手工重算/重排**。
> ⚠️ **换行铁律**：`render-skeleton.py` 以 `newline="\n"` 写出 LF；若误产 CRLF，`gen-html-report.js` 的标题正则 `^(#{1,4})\s+(.+)$` 会失效（`.` 不匹配 `\r`），导致所有章节变成 `<p>` 而非 `<h2>/<h3>`。

### Step 4：LLM 研判 — 攻击链还原 + 失陷判定 + 应急优先级（核心）

基于事实基座（`stats`/`classification`/`compromised`/`ioc` + 按需小段查阅 `rows`），做专业研判，写入骨架 §7：

1. **识别高价值威胁**：远控木马（AsyncRAT/SilverFox/Tinba/Farfli 等）、webshell 上传、反弹 SHELL、内网穿透隧道（CPolar/Tailscale/WireGuard/OpenVPN/ToDesk/Socks）、未授权访问（Nacos/Eureka/Swagger/Consul 等）、命令执行（Java/ThinkPHP/PHP/Python/Shell）等。
2. **攻击链还原**：按「侦察→利用→植入→命令控制→横向/外联」组织叙事；对每条核心事件给出受害主机、疑似来源、URI/载荷特征、次数、时间线。
3. **角色修正（重要）**：注意 `10.x` 网段中可能混入**交换机/网络设备**（仅作五元组源目的展示，不代表失陷、也不是横向传播源）；`VPN 网段`主机是隧道/外联告警的**主动发起方**，需区分「员工个人灰色使用」与「被攻陷后植入后门」。
4. **失陷/攻击成功判定**：以 `攻击结果 ∈ {攻击成功, 失陷}` 的受害主机为准（`compromised` 已聚合）；webshell 上传/代码执行类告警 ≠ 已失陷，须看 `攻击结果`。
5. **IOC 提炼**：外联/隧道/恶意域名（区分合法公网 DNS 如 223.5.5.5 与恶意 C2）、公网攻击源、恶意 URI 特征。
6. **处置状态核对**：不同导出可能带「处置状态」列，梳理未处置项。

> 参考标杆：`output/alert-report-20260812-ids-export.md`（成功失陷告警导出研判范例，含核心事件①②③…、IOC 汇总、P0/P1/P2 应急建议）。

### Step 5：生成 MD 报告（骨架 + 研判合并）

1. 将 Step 4 研判内容**替换骨架 §7 占位标记**（7.1–7.5），并确认全文结构严格对齐 `alert-report-template.md`（§1–§6 同构，§7 攻击链还原为保留章节，§8 安全建议）。
2. 若骨架 §3–§6 清单量过大，按研判需要保留 Top + 关键行，其余折叠到「完整列表见附录」；**不得改动 §1–§6 的脚本数字**。
3. 写入 `output/ids-fastreport-{date}.md`（若 Step 3 已直接落盘此文件，则仅补写 §7 占位）。
4. **禁止**：LLM 不得重造或臆造统计数字——凡可脚本算出的指标一律以事实基座为准；研判叙事可推理，但不得虚构不存在的记录。

### Step 6：生成 HTML 报告（复用主报告渲染器）

```bash
node skills/secops-alert-analysis/scripts/reporting/gen-html-report.js \
    --input output/ids-fastreport-{date}.md \
    --output output/ids-fastreport-{date}.html \
    --date-range "{window_start} ~ {window_end}" \
    --report-time "{Step 0 时间}" \
    --analyst "SecOps Agent"
```

- 复用 `alert-report-template-v1.html` 外壳与深色主题/打印布局。
- **`--title` 缺省**：`gen-html-report.js` 自动从 MD 的 `# H1` 抽取（即 Step 3 由导出窗口自动生成的标题），保证 HTML `<title>` 与 MD/ES 版本一致；仅需自定义时才显式传 `--title`。
- 失败→降级由 LLM 按 `alert-report-template-v1.html` 外壳手工渲染（填入 `{{title}}/{{date_range}}/{{analyst}}/{{report_time}}/{{content}}`）。

### Step 7：发布报告（复用父 skill 发帖能力，可选）

> **直接复用父 skill 既有 `scripts/portal/post.js`**（发布 HTML 到公司 EIP 门户），不重复实现。发布为可选环节，**默认受 `scripts/.env` 的 `ENABLE_POST` 开关控制**（默认 `false` 不发帖）。

**输入**：`output/ids-fastreport-{date}.html`（Step 6 产物）

**处理**：

1. 前置验证：检查 HTML 文件存在且非空 → 不存在则跳过发布，LOG: `[WARN] HTML报告不存在，跳过发布`。
2. 执行发布（CWD 为项目根，直接调用父脚本）：

   ```bash
   node skills/secops-alert-analysis/scripts/portal/post.js \
       output/ids-fastreport-{date}.html
   ```

   - 复用父 `shared/env.js` 读取 `scripts/.env` 的 `PORTAL_*` 配置（`PORTAL_TOKEN_APPID/SECRET`、`PORTAL_GROUP_ID/TYPE_ID`、`PORTAL_VIEW_RIGHT` 等），**无需传参**。
   - **帖子标题缺省继承 HTML `<title>`**（即 Step 3/6 自动生成的 ES 版标题格式，保证 MD/HTML/帖子三处一致）；`--title` 仅需自定义时覆盖。
3. 开关与降级：
   - `ENABLE_POST=false`（默认）→ 父脚本打印 `[SKIP] 发帖功能已禁用` 并 `exit 0`，子技能标记 Step ⏭️。
   - 网络异常（exit 2，非内网）或凭证缺失（exit 1）→ 记录降级日志后继续，不阻断整体流程：

     ```
     [FALLBACK] 发布降级: portal_publish → skipped
     [FALLBACK] 原因: {error_message}
     [FALLBACK] 时间: {ISO 8601 timestamp}
     ```

4. 成功判定：退出码 `0` 且输出链接匹配 `https://eip.teamshub.com/t/{topicId}` → ✅，记录帖子链接。

**输出**：帖子链接 URL（如有）。

---

### Step 8：终端摘要

按 `templates/terminal-summary-template.md` 三段式输出：执行流程表（✅/⏭️/⚠️/❌）、关键发现（核心指标/高危威胁/失陷主机/关键 IOC）、输出文件表。Step 7 发布状态（✅/⏭️）须在流程表中体现。

---

## 输出规范

- `output/ids-fastreport-{date}.md` / `output/ids-fastreport-{date}.html`
- 中间产物：`output/ids-fact-{date}.json`、`output/ids-skeleton-{date}.md`、`output/enrich-ip-{date}.json`、`output/enrich-domain-{date}.json`
- 状态标记与文件输出规则同父 skill。

### 质量门控

- 事实基座 JSON 与骨架 MD 写入成功。
- 报告统计与事实基座一致（不臆造）。
- 失陷/攻击成功主机均已在报告中体现。
- HTML 渲染成功且非空。

---

## 附录A：IDS 导出 Excel 标准表头（68 列，关键列）

| 列号 | 列名 | 用途 |
| ---- | ---- | ---- |
| 1 | 首次发生时间 | 事件开始 |
| 2 | 最近发生时间 | 汇总/时间桶 |
| 3 | 受害IP | 受害主机 |
| 4 | 攻击IP | 攻击源 |
| 5 | 资产IP | 资产归属 |
| 6/7 | 一级/二级告警类型 | 分类分布 |
| 8 | 威胁名称 | 核心威胁聚合 |
| 10 | 攻击结果 | **企图/攻击成功/失陷**（失陷判定依据） |
| 11 | 威胁级别 | 低危/中危/高危/危急 |
| 12 | 次数 | 去重聚合计数 |
| 13 | 攻击阶段 | 命令控制/横向渗透等 |
| 15 | 攻击维度 | **外部攻击/横向攻击/外联攻击/其他**（内外分类依据） |
| 16 | XFF代理 | 代理链 |
| 19 | 域名 | IOC 域名 |
| 26 | 载荷内容 | 攻击载荷 |
| 36 | 攻击IP地理信息 | **局域网** 或 地理位置 |
| 42–47 | 源/目的IP、端口、协议 | 五元组 |
| 51 | 告警ID | 关联 |

> 完整 68 列见实际导出文件。子技能解析器按列名（非列号）取值，具备表头顺序鲁棒性。

## 附录B：内外/外联判定

- 权威依据 = `攻击维度` 列：`外部攻击`→external、`横向攻击`→lateral、`外联攻击`→tunnel（受害主机主动外联公网）、`其他`→other。
- 兜底 = `攻击IP` 是否私网（RFC1918 / 10./172.16-31./192.168./127./局域网）。`攻击IP地理信息=局域网` 视为内网。
- ⚠️ 注意：`成功失陷告警` 导出中，`横向攻击` 记录的 `攻击IP地理信息` 可能仍显示真实地理（如 `中国--四川省--成都市`），此时以 `攻击维度` 为准，勿误判为外部。

## 附录C：IOC 甄别要点

- 合法公网 DNS（223.5.5.5/223.6.6.6/119.29.29.29/180.76.76.76 等）**不应**作为恶意源封禁——真正的风险是内网主机主动外联解析恶意域名。
- 隧道/穿透工具域名（`*.cpolar.cn`、Tailscale、`*.mlcrosft.vip` 等仿冒域）为高价值 C2 IOC。
- 结合`域名`列与负载中的 URI/SNI 特征交叉提炼，避免单列误报。

## 附录D：白名单 / 基础设施机制（复用父 skill，勿混用）

| 机制 | 参考文件 | 复用模块 | 用途 | 语义 |
| ---- | ---- | ---- | ---- | ---- |
| 外部源白名单 | `references/ipWhite.md`（CIDR/单IP/范围） | `reporting/ban-ip-table.js` → `shared/whitelist.js` | 判定外部攻击源是否公司/内网资产，并产出封禁表与微步候选 | 命中 → 二次白名单过滤排除（FR-013），不封禁 / 不进微步候选；**不等于忽视告警** |
| 基础设施清单 | `references/ipInfra.md` | `shared/infra-exclude.js` | 失陷主机角色修正（DNS 转发/网关/交换机误标） | 命中 → 提示人工复核是否真失陷；只剔除「协议=DNS 转发误标」，底层告警保留 |
| 微步威胁情报 | `threatbook-config.md` / `scripts/.env` | `threat-intel/external.js`、`fuse.js` | 公网源/域名信誉查询 | `ENABLE_THREATBOOK=true`；公网不通则降级 |

> ⚠️ **切勿混用**：`ipWhite.md` 含整段私网（10.x/172.16-31/192.168 等），只可用于「外部源判定」（由 `reporting/ban-ip-table.js` 处理）；**不可**复用它做失陷主机剔除（会误伤真实内网失陷主机）。失陷主机的角色修正必须以 `ipInfra.md` 为准（由 `fact-to-enrich.js` 区分处理）。

---

*本子技能遵循：父 skill router 加载 → 执行手册（纯脚本 + LLM 研判，零 ES/零 MCP）+ 附录（输入格式）
由 SecOps Agent Skill 生成，AI 内容请核实关键细节*
