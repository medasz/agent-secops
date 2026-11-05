# IDS 告警分析 Skill — 任务清单

> **统一分类**：功能扩展 / Bug 修复 / 效率优化 / 代码重构/工程化 / 测试。每项标注优先级（P0/P1/P2）与完成状态，关联 `docs/issues.md`（ISS-xxx）。
> **状态约定**：`[x]` 已完成、`[ ]` 未完成。未完成项在各分类内按优先级排序。
> **来源**：ISS-001~008（2026-06-28 执行复盘）+ 原 `docs/general/TODO`（已合并删除）。

---

## 一、功能扩展（Tier 分级路线）

- [X] [P0] **Tier1 告警提取**：从 Elasticsearch 查询 IDS 告警数据
- [X] [P0] **Tier1 告警分析**：比对白名单/资产清单/漏扫结果，归纳攻击类型/等级/源
- [ ] [P1] **Tier2 情报集成**：接入 x.threatbook.com、abuse.ch、VirusTotal (ISS-012)
- [X] [P1] **Tier2 威胁研判**：结合外部情报深度研判，溯源时间序列行为轨迹
- [ ] [P2] **Tier3 威胁处置**：防火墙封禁IP、公司帖子通知资产归属人员 (ISS-013)
- [ ] [P2] **Tier3 复盘总结**：总结全过程与态势，邮件通知安全运营团队 (ISS-014)

---

## 二、Bug 修复

- [X] [P0] **修复 parse_mcp_output.js 与 MCP 输出格式脱节** (ISS-005)

  - 问题：脚本期望 `{type:"text",text:"<JSON>"}` 信封，MCP 实际返回扁平 `[{field_values:{}}]`，导致步骤1.3/1.4 持久化+解析流水线跑不通
  - 任务：
    1. 明确输入契约（MCP 直接输出 vs 经包装信封）
    2. 支持"扁平数组"输入模式，移除或放宽外层 `item.type === 'text'` 校验
    3. 验证持久化+解析流水线能跑通
  - 验证：用真实 MCP 输出跑 `node scripts/parse_mcp_output.js <file> --format json`，输出含 `total_records/records/grouped_by_victim/compromised_hosts`
  - 完成：2026-06-28 — 改写 Phase 2 循环逻辑，分三路处理：信封格式走 JSON.parse → hitArray 提取；扁平格式直接提取 field_values；均不符合则 warn 跳过。测试 9/9 通过
- [X] [P0] **修复 post_to_portal.js 发布失败（Client-Token 解析有误）** (ISS-003)

  - 问题：发布失败"Client-Token解析有误"，退出码 1，报告无法自动发布
  - 任务：

    1. 定位 Token 读取来源（环境变量/配置文件）
    2. 增加 token 自动获取逻辑，确保每次请求都带有效 token，参考：docs\dev\DEV-portal-API.md
    3. 步骤0 C2 探测阶段给出更明确失败原因
  - 验证：`node scripts/post_to_portal.js <html> --title "test"` 退出码 0 且返回 `https://eip.teamshub.com/t/{topicId}`
  - 完成：2026-06-28 — 新增 `getToken()` 函数（原生 http.get 调用 Token 网关），集成动态 Token 到 `Client-Token` 头；Token 网关凭证（PORTAL_TOKEN_APPID/SECRET）迁移至 .env；步骤0 前置 C2 探测（校验凭证可用性 + 预获取有效 Token），失败输出 `[C2] 门户Token获取失败: {原因}`；发布错误信息升级为 `[C2] 发布失败: {原因}`；`.env` + `.env.template` 已同步更新
- [X] [P0] **修复 post_to_portal.js 发布接口返回 Client-Token 解析有误** (ISS-010) ✅ 已解决：Feature 021

  - 问题：Token 网关获取成功（`access_token` 7200s 有效），但发布接口 `createCommonTopic` 返回 `{"msg":"Client-Token解析有误","code":"FAIL"}`
  - 已修复的脚本侧问题（3 项，Token 获取链路已通）：
    1. `require('https')` → `import https from 'https'`（ESM 兼容）
    2. `new URL(`/${qs}`, base)` → `new URL(base); url.search = qs`（URL 构建）
    3. `json.data.accessToken` → `json.access_token`（Token 响应格式）
  - 待排查的服务端问题：
    1. 联系门户接口人（xuyy/张德胜）确认 `fromCode` 渠道编码确切值（文档标注"MBOS接口自动化平台"但无数值）
    2. 确认 Token 网关 appid `yx_8fjv2c3ivi0wxdr8` 是否已与 `createCommonTopic` 渠道绑定
    3. 确认发布接口是否升级 Token 校验逻辑，需额外 header 或参数
    4. 参考 https://eip.teamshub.com/t/7694556 获取最新接口变更
  - 验证：`node scripts/post_to_portal.js <html> --title "test"` 退出码 0 且返回 `https://eip.teamshub.com/t/{topicId}`
  - 完成：2026-07-01 — Feature 021 `021-fix-portal-posting` 切换到 `save_topic_info/v1.0` 端点（JSON 信封 + `access_token` 查询参数），废弃 `createCommonTopic`；首次发布验证成功（帖子 ID 8132157）；响应解析器已兼容新端点扁平响应结构（commit `8eefc85`，见 ISS-016）
- [X] [P1] **修复 time_distribution.js 与报告需求错配** (ISS-006)

  - 问题：脚本输出全量告警分布，报告第5节要求"仅统计外部攻击IP"
  - 任务：
    1. ✅ 增加 `--external` 标志（别名 `-x`）
    2. ✅ 查询加 `must_not: {term: {field_values.sip_addr: "局域网"}}`
    3. ✅ 修正 timestamp 字段从 `@timestamp` → `timestamp`（与 AGENTS.md 经验一致）
  - 验证：82/82 tests pass，`--help` 输出已更新
  - 完成：2026-06-28 — 三项修复：external 标志、must_not 推送、timestamp 字段修正
- [X] [P1] **修复报告总数边界差异未说明** (ISS-008)

  - 问题：第5节按小时分布求和 3696 与第1节 count 查询 3690 不一致，未说明
  - 任务：
    1. 统一以 count 查询值为权威总数
    2. 第5节 `date_histogram` 仅作趋势展示，标注"桶求和与总数存在边界差异"
    3. 或排查 `timestamp` 缺失/时区边界文档归桶问题
  - 验证：报告中无互相矛盾的总数，或有明确脚注说明
  - 完成：2026-06-28 — SKILL.md 步骤2 统计汇总增加"权威总数"定义与边界差异脚注；附录A 聚合查询 DSL 增加边界差异注释；报告中 date_histogram 展示须附带脚注说明
- [X] [P1] **硬编码敏感信息提取到 .env**

  - 问题：数据库连接信息、API 密钥等硬编码在脚本中
  - 任务：提取为 `.env` 配置变量，参考宪法 III 配置管理
  - 验证：脚本中无明文密钥，`.env` 不入 git
  - 完成：2026-06-28 — `post_to_portal.js` JWT Token、Portal API URL/端口/表单参数已全部迁移到 `.env` 变量；`.env.template` 模板已创建；`es-tool/.env` 密码已清空；TDD 测试 6/6 通过
- [X] [P0] 告警提取分页数据不完整
- [X] [P0] UTC 与本地时间转换
- [X] [P0] 日期边界索引名 bug（凌晨时区计算导致查错索引）
- [X] [P1] **更新 save_topic_info 契约文档响应结构** (ISS-016) ✅ 已解决：2026-07-13

  - 问题：`specs/021-fix-portal-posting/contracts/portal-api-contract.md` §4/§5 与 `data-model.md` 实体2 描述成功响应为双层包裹 `{msg, code, data:{errcode, data, ...}}`，实际为扁平 `{errcode, data, status, desc, ...}`，导致 T010 "保留解析不变" 误报失败
  - 任务：
    1. 更新 `portal-api-contract.md` §4 响应示例与 §5 解析规则（基于实际集成响应） ✅
    2. 同步更新 `data-model.md` 实体2 字段表（`errcode`/`data`/`status`/`desc` 提升为顶层） ✅
    3. 记录流程改进：speckit 契约应来自实际集成验证而非文档示例 ✅
  - 验证：契约文档响应示例与 `post_to_portal.js` 实际收到的响应一致；speckit analyze 无不一致告警
  - 完成：2026-07-13 — `portal-api-contract.md` §4/§5 和 `data-model.md` 实体2 更新为扁平结构（commit `eb8ae82`）
- [X] [P1] **viewRight=2 指定读者模式补充 viewPriv 配置与校验** (ISS-020)

  - 问题：`post_to_portal.js` 硬编码 `viewPriv: ''`，`.env` 配 `viewRight=2`（指定读者）但未配 viewPriv → 帖子圈子成员不可见
  - 任务：
    1. 新增 `PORTAL_VIEW_PRIV` 环境变量，脚本从 env 读取 ✅
    2. 早期校验：`viewRight=2 + viewPriv 空` → FATAL（避免浪费 Token 网关调用）✅
    3. `viewRight=1` 时 viewPriv 忽略；`viewRight=2` 时 viewPriv 必填 ✅
    4. 启动日志打印实际 viewRight 语义 + viewPriv 值 ✅
    5. `.env.template` 补充 `PORTAL_VIEW_PRIV` 配置项 ✅
  - 验证：viewRight=2+viewPriv=15570 发布成功（帖子 8132364）；viewRight=2+viewPriv 空 FATAL；viewRight=1 正常发布
  - 完成：2026-07-01
- [X] [P2] **attack_type 编码异常在丰富化阶段清洗** (ISS-018) ✅ 已解决：2026-07-13

  - 问题：ES `attack_type` 存在编码异常变体（`暴力猜解` vs `暴力\ufffd解`，`代码执行` vs `\ufffd码执行`），导致攻击类型分布表重复
  - 任务：
    1. `ip_enrichment.js` 丰富化阶段统一清洗 `attack_type` 编码（归一化函数） ✅（在 `parse-mcp.js` 数据入口处实现 `normalizeAttackType()`）
    2. 归一化映射表纳入 `references/` 或脚本配置 ✅（内联到 `parse-mcp.js`，单函数单消费者）
    3. 报告生成移除手动 `cleanTypes()`，消费清洗后数据 ✅（归一化在解析阶段完成）
  - 验证：`ip_enrichment.js` 输出无重复 attack_type；报告分布表无需手动合并
  - 完成：2026-07-13 — `parse-mcp.js` 新增 `normalizeAttackType()` + `extractTerms()` 合并同类型 bucket（commit `6f882c5`）；5 测试覆盖

---

## 三、效率优化

- [X] [P1] **合并 MCP 聚合查询，减少调用次数** (ISS-004)

  - 问题：步骤1 发起 6 次 search，3 次为补查（外部总数、cardinality、date_histogram）
  - 任务：
    1. 附录A 聚合查询 DSL 增加 `cardinality`（唯一外部IP）与 `date_histogram`（按小时）agg ✅
    2. 确认 `track_total_hits: true` 下 `hits.total.value` 即外部攻击总数，免去补查 ✅
    3. 流程文档标注"一次聚合拿全统计" ✅
  - 目标：步骤1 从 6 次降至 3 次 ✅
  - 验证：步骤1 聚合查询一次返回 unique_external_ips、hourly_distribution、hits.total.value，仅需 3 次 search
  - 完成：2026-06-28 — 附录A 聚合DSL 已追加 cardinality + date_histogram agg；步骤1 说明已标注"一次聚合拿全统计"；步骤2 统计汇总更新为取自聚合 agg；附录F 新增第12条说明 cardinality 精度误差
- [x] [P1] **list_indices 大输出分页/过滤** (ISS-001) — 部分：2026-06-28 Feature 020 已将 B2 改为轻量定向探针（get_mappings/search size:0），消除 B2 维度截断；A1 全量枚举分页/过滤留后续

  - 问题：811 索引输出 54KB 被截断，需 grep 确认索引存在
  - 任务：
    1. 评估 MCP 工具是否支持 `size`/`prefix_filter` 参数
    2. 步骤0 B2 改用单索引探针（轻量 search 或 get_mappings）替代全量 list_indices
  - 验证：步骤0 B2 一次工具调用内确认 `logfmt_746_{date}` 存在性，无需 shell grep
- [x] [P1] **自检阶段低效：简化过程 + 配套脚本提效** (ISS-009) — 完成：2026-06-28 Feature 020 `020-selfcheck-batch-dedup` 交付 `local_selfcheck.js`（9 项批量 + local_verdict）、SKILL.md B2 轻量探针/A1 职责分离/A2 复用 E1/自检结论读 local_verdict；本地项 9→1、A1+B2 去重、A2/E1 复用、判定下沉均落地，32 测试全绿

  - 问题：步骤0 共 13 项自检，仅 E1 有专用脚本（`ban_table_selfcheck.js`），其余 12 项全靠 Agent 逐条读 SKILL.md、逐条调工具、逐条判结论，存在三处低效：
    1. **本地可脚本化项手工执行**：B1（日期解析）/B3（白名单可解析）/B4（.env 存在）/C1（密钥存在）/D1-D4（node 版本、TZ、output 可写、templates 存在）共 8 项均为本地文件/环境/进程检查、零 MCP 依赖，却每次由 Agent 逐个探测 + 推理，重复且易错
    2. **跨项重复探测**：A1 与 B2 都调 `list_indices`（且 A1 全量枚举 811 索引 54KB 截断，见 ISS-001）；A2（es-query.js 直连）与 E1（ban_table 自检复用同一直连路径）对脚本路径重复探一次
    3. **结论判定逻辑全靠 Agent 推理**：A1/A2 联合判定 4 分支 + A3 条件执行 + B 全 PASS 判定 + C/D/E 仅 WARN，每次重新推理，易遗漏分支
  - 边界约束（017 R-004 / 019 先例）：MCP 项 A1/A3 无法从 Node 调用，**不得**做覆盖全 13 项的通用 orchestrator 脚本（017 已否决 `preflight.js`）；配套脚本只能覆盖"纯 HTTP 直连 + 本地文件"项，沿用 019 单用途探针 + PF-xxx/scope-group/降级日志契约模式
  - 任务：
    1. 新增 `scripts/local_selfcheck.js`（或并入现有 selfcheck 系列）：批量覆盖 8 项零 MCP 依赖项（B1/B3/B4/C1/D1-D4），一次调用输出各子项 `verdict/sub_id` + 联合结论 + 可操作中文建议，复用 019 的 PF-xxx 命名与降级日志契约
    2. 合并跨项重复探测：A1+B2 索引存在性合并为单索引探针（联动 ISS-001，改轻量 search/get_mappings）；评估 A2 与 E1 直连探测合并或复用（E1 已有 `ban_table_selfcheck.js`，A2 可复用同模式）
    3. 将 A1/A2 联合判定、B 全 PASS、C/D/E 仅 WARN 等结论逻辑下沉到脚本/校验表，SKILL.md 仅保留"读脚本 verdict 决定走向"，减少 Agent 重复推理
    4. 保持 A1/A3 为纯 MCP 文字项不动（017 边界），仅在 SKILL.md 标注其不可脚本化原因
  - 验证：
    - `node scripts/local_selfcheck.js --date {date} --format json` 一次返回 8 项子结论 + 联合 verdict，无需 Agent 逐条调工具
    - 步骤0 MCP 项（A1/A3）调用次数不增；本地项工具调用从 8 次降至 1 次
    - 联合判定结论与现 SKILL.md 4 分支逻辑一致（A1/A2 矩阵、B 全 PASS、C/D/E 仅 WARN）
    - 017 R-004 边界未被突破：无通用 orchestrator，A1/A3 仍由 Agent 经 MCP 执行
- [ ] [P1] **使用 subagent 重构执行工作流，提升执行效率（先评估后按需改进）** (ISS-015)

  - 思路：**先评估后按需改进**——第一阶段只读评估当前 `SKILL.md` 工作流的可并行化空间与 subagent 适用性；第二阶段仅对评估确认收益明确、风险可控的阶段按需落地，不预设全量改造
  - 背景：步骤0 本地项经 Feature 020 已批量化（ISS-009），但 MCP 项 A1/A3 仍只能由主 Agent 经 MCP 逐条串行执行——这正是 017 R-004 否决 Node 通用 orchestrator 的根因（Node 无法调用 MCP）。subagent 能并行驱动 MCP 工具，是绕过 R-004 限制、进一步提效的可行方向
  - 与 017 R-004 的边界区分：R-004 否决的是"Node 通用 orchestrator 脚本"（Node 无法调 MCP + 与 SKILL.md 逻辑重复）；subagent 由主 Agent 调度、可经 MCP 执行 A1/A3、调度逻辑写在 SKILL.md 指令层——**不违背 R-004**，落地时须在 spec 显式标注此区分
  - 任务（第一阶段·只读评估）：
    1. 逐阶段产出「可并行性矩阵」：标独立性 / MCP 依赖 / 输入输出契约 / 上下文成本 / 并行收益；候选阶段至少覆盖步骤0 A1/A3（MCP 自检并行）、封禁表 vs 报告主体（脚本与渲染并行）、Tier2 多 IP 情报富化（联动 ISS-012）、脚本回退诊断（MCP 失败时不阻塞主 Agent）
    2. 评估 subagent 适用性：是否保留会话级 MCP 连接、结果回传合并、上下文/token 成本 vs 串行耗时取舍、失败/降级处理
    3. 对每个候选阶段给"是否值得 subagent 化"结论 + 理由，避免无收益并行化（上下文成本 > 耗时收益的阶段保持串行）
    4. 产出可并行性矩阵 + 改进项清单 + 取舍依据文档（spec 目录），无代码改动
  - 任务（第二阶段·按需落地，非全量）：
    1. 仅对第一阶段确认收益明确、风险可控的阶段落地，如步骤0 A1/A3 改并行 subagent、封禁表与报告主体并行生成
    2. 每项落地后验证：现有测试套件全绿；SKILL.md 所有脚本调用按原入口跑通；串行耗时 vs 并行耗时确认收益
  - 约束：不得破坏既有对外契约（脚本入口 / CLI 形态 / 输出 JSON 结构不变）；不得引入 Node 通用 orchestrator（017 R-004），调度逻辑写在 SKILL.md 指令层
  - 验证：第一阶段产出评估文档无代码改动；第二阶段每项落地后测试全绿 + 脚本入口跑通 + 耗时收益对比
- [ ] [P2] **详情查询按需返回字段** (ISS-007)

  - 问题：返回 100 条完整文档（694KB），仅用 host_state 统计
  - 任务：
    1. 若只需统计，改 `size:0 + aggs`（按 host_state 聚合 + terms 取失陷IP）
    2. 若需详情，加 `_source: ["field_values.sip","field_values.dip","field_values.host_state","field_values.attack_type","field_values.access_time","field_values.sip_addr","field_values.dip_addr"]`
  - 验证：详情查询输出 < 50KB
- [X] [P2] **消除 MODULE_TYPELESS_PACKAGE_JSON 告警** (ISS-002)

  - 修复：在 `skills/secops-alert-analysis/package.json` 声明 `"type": "module"`
  - 验证：执行 `ban_table_generator.js` 无告警；测试 76 pass / 0 fail
  - 完成时间：2026-06-28
- [X] [P2] **白名单过滤逻辑收敛，消除分散重复** (ISS-019) ✅ 已解决：2026-07-13

  - 问题：白名单过滤分散 4 处（extract_es_ids / ip_enrichment / ban_table_generator / 报告生成），报告生成阶段无脚本化入口，Agent 易绕过 `isExternal()` 自实现正则（2026-07-01 漏 CIDR 导致统计偏差 92 vs 88）
  - 任务：
    1. 报告生成脚本化（联动 ISS-017），过滤统一走 `lib/whitelist.js isExternal()` ✅（`gen_html_report.js` 内置 `filterWhitelistIps()`）
    2. 或 `extract_es_ids.js` 产物直接输出已过滤 `valid-ips-{date}.txt` 供下游消费 ✅（`gen_html_report.js` CLI `--whitelist` 参数）
    3. SKILL.md 明确：任何白名单过滤阶段 MUST 调 `isExternal()`，禁止自实现正则 ✅
  - 验证：白名单过滤仅经 `isExternal()` 单一实现；报告统计与 `ban_table_generator` 口径一致
  - 完成：2026-07-13 — `gen_html_report.js` 内置白名单过滤 + SKILL.md 约束行（commits `5361e73` + `8c621ae`）

---

## 四、测试

- [X] [P0] **修复 tests/secops-alert-analysis/ 路径引用失效**
  - `tests/parse_mcp_output.js` 路径错误 → 应引用 `skills/secops-alert-analysis/scripts/parse_mcp_output.js`
  - `lib/*.js` 路径错误 → 应引用 `skills/secops-alert-analysis/scripts/lib/*.js`
  - `renderer.test.js` 和 `whitelist.test.js` 的 import 路径需要更新

---

## 五、代码重构 / 工程化

- [ ] [P2] **整理聚合 `scripts/` 目录，对齐模块化 / 高内聚低耦合工程实践** (ISS-011)

  - 背景：`scripts/` 现为"顶层平铺脚本 + `es-tool/` 分层子包"双轨结构，横切逻辑分散在两套 `lib/`，存在反向依赖与职责重叠，不符合高内聚低耦合最佳实践。执行待办时先逐文件梳理真实依赖图，再定具体合并/迁移步骤，不预设方案。
  - 现状（待治理的信号）：
    1. **两套并行 `lib/`，职责重叠**：`scripts/lib/`（cli-args / es-query / whitelist / time-utils / report-renderer）与 `scripts/es-tool/lib/`（env / loader / logger / retry）并存，env 加载、ES 连接配置/查询、日志等能力各有一份，重复且易漂移
    2. **反向依赖（子包内部向顶层泄露）**：顶层 `post_to_portal.js` 直接 `import './es-tool/lib/env.js'`，子包内部工具被顶层脚本跨层引用，破坏分层边界
    3. **目录组织不一致**：顶层脚本平铺（CLI 参数 + 业务逻辑 + 渲染混写在单文件），`es-tool/` 却按 extractor/analyzer/lib 三层分目录，缺统一分层约定
    4. **配置/环境读取多源**：`lib/es-query.js` 自行读取 `es-tool/.env`，`es-tool/lib/env.js` 又提供 `loadEnv/getEnv`，两套 env 读取路径未统一
  - 思路方向（执行时细化为具体步骤，此处仅列方向）：
    1. 先画清"谁依赖谁"的真实依赖图（顶层脚本 ↔ 两套 lib ↔ es-tool 子包），标出重复能力与跨层/反向依赖点
    2. 按高内聚低耦合确立单一分层约定（如 core 基础设施 / domain 业务 / entry 脚本入口），明确每层职责边界与可引用方向
    3. 消除重复的横切能力（env、ES 配置/查询、日志、CLI 参数）——收敛到单一实现，单一职责
    4. 拆解"CLI + 逻辑 + 渲染"混写的顶层脚本，按职责分离（参数解析 / 业务逻辑 / 输出渲染各归其位）
    5. 修正反向依赖，确立子包/底层不得被顶层跨层直引的边界规则
    6. 同步更新引用方（脚本 import 路径、SKILL.md 步骤中的脚本调用、测试路径）与 `.env` 读取约定
  - 约束与验证（执行时落地）：
    - **不得破坏既有对外契约**：SKILL.md 步骤中调用的脚本入口、`--date/--format/--help` 等 CLI 形态、输出 JSON 结构须保持不变（017/019 边界：脚本是被 SKILL.md 契约驱动的）
    - **不得引入通用 orchestrator**：沿用 017 R-004 边界，重构仅做模块整理聚合，不趁机新增覆盖全流程的编排脚本
    - 验证：现有测试套件全绿（含路径已修复的 `tests/secops-alert-analysis/`）；SKILL.md 中所有脚本调用按原入口跑通；无跨层/反向 import；两套 `lib/` 重复能力收敛为单一实现
- [X] [P2] **HTML 报告生成脚本 gen_html_report.mjs 纳入 spec** (ISS-017) ✅ 已解决：2026-07-13

  - 问题：2026-07-01 新增 `scripts/gen_html_report.mjs` 程序化生成 HTML 报告（替代 LLM 即兴渲染），但未经过 speckit 流程，模板占位符契约与数据注入接口未形式化，当日数据内联硬编码
  - 任务：
    1. 纳入后续 spec（如 `022-html-report-generator`） ✅（通过 `docs/superpowers/specs/2026-07-13-p0-p1-bugfix-design.md` 覆盖）
    2. 定义模板占位符契约（`{{title}}`/`{{date_range}}`/`{{report_time}}`/`{{content}}` 等，`replaceAll` 语义） ✅
    3. 定义数据 JSON 输入接口（从 `extract-*.json`/`enrichment-*.json`/`ban-ip-table-*.html` 自动读取，无需内联硬编码） ✅（MD 报告作为输入，`extractMetadata()` 解析内联元数据）
    4. 对齐 `ban_table_generator.js`（已 spec 化先例）的契约模式 ✅
  - 验证：`gen_html_report.js --input <md> --template <html> --output <out>` 生成报告，无需手动改数据；模板占位符全部替换无残留
  - 完成：2026-07-13 — 新建 `scripts/reporting/gen_html_report.js`（commit `5361e73`）；14 测试覆盖

---

*创建时间：2026-06-28 18:25 (Asia/Shanghai)*
*最后更新：2026-07-13 ISS-016/017/018/019 标记完成（P0+P1 bugfix 20260713）*
*关联文件：`docs/issues.md`*
