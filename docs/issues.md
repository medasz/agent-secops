# IDS 告警分析 Skill — 问题记录

> 来源：2026-06-28 执行"分析今日告警"时发现。对应修复任务见 `docs/TODO.md`。

## ISS-001 list_indices MCP 工具对大输出缺乏分页（报错/低效）【部分解决：Feature 020 B2 轻量探针】

- **状态**：🔶 部分解决（Feature 020 `020-selfcheck-batch-dedup` 已将 B2 改为轻量定向探针 `get_mappings`/`search size:0`，消除 B2 维度的截断与 grep 依赖；A1 全量枚举分页/过滤优化仍留后续）
- **分类**：报错 + 低效
- **严重度**：中
- **复现**：`elasticsearch-sse_list_indices` 以 `logfmt_746_*` 模式查询，返回 811 个索引，输出 54131 bytes 被截断，需写入临时文件后用 grep 确认目标索引存在。
- **影响**：
  - A1 连通性探测与 B2 索引存在性校验被迫分两步，且需借助 shell grep
  - 截断后无法在一次工具调用内完成索引枚举
- **证据**：本次执行首条 `list_indices` 输出提示 "...54131 bytes truncated"，结果保存至 `tool-output/tool_f0dbccd8e001tTw0wSdtYD2Iqv`
- **建议方向**：
  - MCP 工具增加分页/过滤参数（如 `size`、`prefix_filter`）
  - 或在 skill 步骤0 B2 改用针对单索引的 `get_mappings`/轻量 `search` 探针替代全量 `list_indices`

## ISS-002 所有 Node 脚本反复触发 MODULE_TYPELESS_PACKAGE_JSON 告警（低效）✅ 已修复

- **分类**：低效（日志污染 + 性能开销）
- **严重度**：低
- **状态**：已于 2026-06-28 修复（TODO-007）
- **复现**：执行 `es-query.js`、`ban_table_generator.js`、`whitelist_filter.js`、`time_distribution.js`、`post_to_portal.js` 等 ES 模块脚本，均输出：
  ```
  (node:xxxx) [MODULE_TYPELESS_PACKAGE_JSON] Warning: Module type of file ... is not specified and it doesn't parse as CommonJS.
  Reparsing as ES module because module syntax was detected. This incurs a performance overhead.
  ```
- **影响**：
  - 每个脚本启动时多一次"重新解析为 ES module"的开销
  - 告警信息反复出现在工具输出中，干扰关键信息识别
- **根因**：项目根 `agent-secops/` 与 skill 目录 `skills/secops-alert-analysis/` 均无 `package.json`，Node 沿目录树向上查找直至 `/mnt/c/Users/Leion/T/` 也未命中，遂默认按 CJS 解析；发现 `import` 语法后回退重解析为 ESM，产生告警。（原记录"根 package.json 未声明 type"不准确——实为根本不存在 package.json）
- **修复**：在 `skills/secops-alert-analysis/package.json` 声明 `"type": "module"`，作用域覆盖 `scripts/`、`templates/` 等子目录，不污染 `ai-connector/` 等其他子项目
- **验证**：执行 `ban_table_generator.js` 无 `[MODULE_TYPELESS_PACKAGE_JSON]` 告警；测试套件 76 pass / 0 fail

## ISS-003 post_to_portal.js 发布失败：Client-Token 解析有误（报错）

- **分类**：报错（非阻塞，属 C2 诊断项预知可能失败）
- **严重度**：中
- **复现**：`node scripts/post_to_portal.js output/alert-report-20260628.html --title "..."` 返回：
  ```
  [ERROR] 发布失败: Client-Token解析有误，请确认入参是否正确！
  EXIT=1
  ```
- **影响**：报告无法自动发布到 portal，需手工上传或修复 Token
- **已处理**：按 skill 降级策略记录 `[FALLBACK]` 日志，未阻断主流程
- **建议方向**：
  - 校验 `post_to_portal.js` 读取 Client-Token 的来源（环境变量？配置文件？）
  - 确认 Token 是否过期或格式损坏
  - 在步骤0 C2 探测阶段给出更明确的失败原因

## ISS-004 MCP 查询次数偏多，可合并（低效）

- **分类**：低效
- **严重度**：中
- **复现**：本次步骤1 共发起 6 次 `elasticsearch-sse_search`：
  1. mapping 探针（A3）
  2. 聚合查询（攻击IP/类型/危害/目标）
  3. 攻击成功/失陷详情查询
  4. 补查外部攻击总数（`hits.total`，首次聚合未直接可用）
  5. 补查 `cardinality`（唯一外部IP数）
  6. 补查 `date_histogram`（外部攻击按小时分布，因 `time_distribution.js` 输出全量而非外部）
- **影响**：MCP 调用次数翻倍，增加延迟与上下文占用
- **可优化点**：
  - 第 4、5 次可合并进第 2 次聚合查询：加 `cardinality` agg，且 `track_total_hits: true` 已能给出 `hits.total.value`（本次漏读）
  - 第 6 次可合并进第 2 次：加 `date_histogram` agg（限定 `must_not sip_addr=局域网`）
  - 优化后步骤1 可从 6 次降至 3 次（mapping 探针 + 1 次聚合 + 1 次详情）
- **根因**：附录A 的 DSL 模板未包含 `cardinality` 与 `date_histogram`，skill 流程也未提示"一次聚合拿全统计"

## ISS-005 parse_mcp_output.js 与 MCP 实际输出格式脱节（数据一致性）

- **分类**：数据一致性 / 脚本缺陷
- **严重度**：高
- **复现**：
  - `parse_mcp_output.js` 期望输入为 `[{type:"text", text:"<嵌套JSON字符串>"}]` 的 MCP 原始信封格式（脚本第 70-76 行显式校验 `item.type === 'text'`）
  - 但 `elasticsearch-sse_search` 工具实际返回的是 `[{field_values:{...}}]` 扁平结构（已解包）
  - 两者格式不匹配，脚本无法直接消费 MCP 输出
- **影响**：
  - 本次执行绕过了 `parse_mcp_output.js`，用内联 `node -e` 直接解析详情数据
  - 持久化的 `output/mcp-output-20260628.json` 是手工构造的摘要，而非 MCP 原始返回
  - skill 步骤1.3/1.4 描述的"持久化 + 解析"流水线实际未跑通
- **建议方向**：
  - 明确 `parse_mcp_output.js` 的输入契约：是 MCP 工具直接输出，还是经包装的 `{type:"text",text:JSON.stringify(...)}` 信封
  - 若 MCP 已返回解包结构，脚本应支持"扁平数组"输入模式（`hit._source || hit` 分支已存在，但外层信封校验阻断）
  - 或在持久化阶段补一层信封包装，使脚本契约稳定

## ISS-006 time_distribution.js 与报告需求错配（低效）

- **分类**：低效 / 脚本缺陷
- **严重度**：中
- **复现**：
  - 报告模板第5节明确要求"仅统计外部攻击IP的告警，已排除白名单IP"
  - 但 `time_distribution.js --date 20260628` 输出的是**全量告警**时间分布（总计 14663），包含内部IP
  - 脚本无 `--external-only` 或 `--exclude-lan` 选项
- **影响**：
  - 脚本输出无法直接用于报告第5节
  - 被迫用 MCP 补查 1 次 `date_histogram`（ISS-004 第 6 次查询）
- **建议方向**：
  - `time_distribution.js` 增加 `--external-only` 标志，查询时加 `must_not: {term: {field_values.sip_addr: "局域网"}}`
  - 或在 skill 流程中明确：时间分布数据取自 MCP 聚合查询的 `date_histogram` agg，而非单独脚本

## ISS-007 详情查询数据利用率低（低效）

- **分类**：低效
- **严重度**：低
- **复现**：攻击成功/失陷详情查询返回 100 条文档（截断后仍 694KB），但本次只用到 `host_state` 状态统计（92 攻击成功 + 8 失陷）和失陷主机IP列表
- **影响**：
  - 传输了完整 `_source`（含 `detail_info`、`bulletin` 等长文本字段），占用大量上下文
  - 694KB 输出被截断，需写文件处理
- **建议方向**：
  - 若只需统计，改用 `size:0 + aggs`（按 `host_state` 聚合 + `terms` agg 取失陷主机IP）
  - 若需详情列表，加 `_source` 过滤只取 `sip/dip/host_state/attack_type/access_time`，避免长文本字段

## ISS-008 时间分布总计与外部攻击总数不一致（数据一致性）

- **分类**：数据一致性
- **严重度**：中
- **复现**：
  - 外部攻击总数（count 查询）= 3690
  - 外部攻击按小时 `date_histogram` 桶求和 = 3696（差 6）
  - 危害等级桶求和 = 3687（差 3）
- **影响**：报告中两个数字并存（第1节 3690、第5节 3696），未说明偏差来源，影响数据严谨性
- **可能原因**：
  - `date_histogram` 与 `terms` agg 在文档无 `timestamp` 或 `hazard_rating` 字段时的处理差异
  - 时区边界文档归桶差异
- **建议方向**：
  - 报告中明确标注"按小时分布总计为 date_histogram 桶求和，与 count 查询存在边界差异"
  - 或统一以 `count` 查询值为准，`date_histogram` 仅用于趋势展示不求和

## ISS-009 自检阶段低效：本地项手工逐条执行 + 跨项重复探测 + 结论靠推理（低效）【已解决：Feature 020】

- **状态**：✅ 已解决（Feature 020 `020-selfcheck-batch-dedup`，2026-06-28）
- **分类**：低效（流程复杂度 + 重复调用 + 认知负担）
- **严重度**：中
- **复现**：步骤0 共 13 项自检，仅范围 E（`ban_table_selfcheck.js`）有专用脚本，其余 12 项每次执行均由 Agent 逐条读 SKILL.md → 逐条调工具 → 逐条判结论。具体三处低效：
  1. **本地可脚本化项仍手工执行**：B1（日期解析）/B3（白名单 CIDR/区间/单 IP 可解析）/B4（.env 含 ES_HOST/ES_PORT/ES_USERNAME/ES_PASSWORD）/C1（富化 API 密钥存在）/D1（node ≥18）/D2（TZ=Asia/Shanghai）/D3（output/ 可写）/D4（templates/* 存在）共 8 项均为本地文件/环境/进程检查、零 MCP 依赖，却每次逐个探测 + 推理
  2. **跨项重复探测**：A1（list_indices 全量枚举）与 B2（list_indices 确认索引存在）对同一 MCP 工具重复调用，且 A1 全量返回 811 索引 54KB 截断（见 ISS-001）；A2（es-query.js 直连探测）与 E1（ban_table 自检复用同一直连路径）对脚本路径重复探一次
  3. **结论判定逻辑全靠 Agent 推理**：A1/A2 联合判定 4 分支 + A3 条件执行（仅 A1 PASS 时）+ B 全 PASS 判定 + C/D/E 仅 WARN 不阻塞，每次重新推理，易遗漏分支或判错矩阵
- **影响**：
  - 本地项从 8 次工具调用（每项一次）增至认知开销，重复且易错
  - 跨项重复探测使 MCP/脚本调用次数虚高，与 ISS-001/ISS-004 的减调用目标冲突
  - 联合判定靠人工推理，分支多时存在判错风险，影响后续走 MCP 主路径/脚本回退/终止的决策正确性
- **边界约束**：
  - **017 R-004 否决通用 orchestrator**：MCP 项 A1/A3 无法从 Node 调用，覆盖全 13 项的通用 `preflight.js` 会与 SKILL.md 逻辑重复（DRY/YAGNI）且无法覆盖 MCP 项——不得做
  - **019 先例**：单用途探针脚本（`ban_table_selfcheck.js`）覆盖"纯 HTTP 直连 + 零 MCP 依赖"项是被允许的模式，沿用 PF-xxx 命名 / scope-group / 降级日志契约
- **建议方向**：
  - 新增 `scripts/local_selfcheck.js`：批量覆盖 8 项零 MCP 依赖项（B1/B3/B4/C1/D1-D4），一次调用输出各子项 `verdict/sub_id` + 联合结论 + 可操作中文建议，复用 019 探针契约
  - 合并跨项重复探测：A1+B2 索引存在性合并为单索引探针（联动 ISS-001）；A2 与 E1 直连探测评估合并或复用
  - 将联合判定逻辑（A1/A2 矩阵、B 全 PASS、C/D/E 仅 WARN）下沉到脚本/校验表，SKILL.md 仅保留"读脚本 verdict 决定走向"
  - A1/A3 保持纯 MCP 文字项不动，SKILL.md 标注其不可脚本化原因（017 边界）
- **关联**：ISS-001（list_indices 截断）、ISS-004（MCP 查询次数）、017 R-004（通用 orchestrator 否决）、019（单用途探针先例）

## ISS-010 post_to_portal.js 发布接口持续返回 Client-Token 解析有误（报错/服务端）✅ 已解决：Feature 021

- **状态**：已于 2026-07-01 解决（Feature 021 `021-fix-portal-posting`，切换到 `save_topic_info/v1.0` 端点，废弃 `createCommonTopic`）
- **分类**：报错（服务端/接口侧，非脚本侧）
- **严重度**：中
- **复现**：`node scripts/post_to_portal.js output/alert-report-20260628.html --title "..."` 输出：
  ```
  [C2] Token 获取成功 (有效期 7200s)
  [INFO] 提交中...
  [C2] 发布失败: Client-Token解析有误，请确认入参是否正确！
  ```
- **影响**：报告无法自动发布到 portal，降级为手工上传
- **已排查排除项**（确认非脚本侧问题）：
  1. **`require('https')` ESM 报错**（ISS-010 子项 a，已修复）：`package.json` 声明 `"type": "module"` 后 ESM 模式下 `require` 不可用，`getToken()` 第 73 行 `require('https')` 抛 `ReferenceError` → 已改为 `import https from 'https'`，Token 获取恢复
  2. **URL 构建错误**（ISS-010 子项 b，已修复）：`new URL(`/${qs}`, base)` 将 query 串当作 path 覆盖原 path → 改为 `new URL(base); url.search = qs`，Token 网关正常返回 `access_token`
  3. **Token 响应格式不匹配**（ISS-010 子项 c，已修复）：代码期望 `{code:"SUCCESS", data:{accessToken}}`，Token 网关实际返回顶层 `{access_token, expires_in}` → 改为读 `json.access_token`，Token 获取成功
  4. **curl 等价验证排除脚本嫌疑**：用 `curl` 直接调发布接口（绕过 Node 脚本），同样返回 `"Client-Token解析有误"`，确认非脚本 HTTP 客户端问题
  5. **多认证方式均失败**：分别测试 `Client-Token` 头、`Authorization: Bearer` 头、`access_token` query 参数，发布接口均返回同一错误
  6. **旧 JWT Token 同样失败**：从 git 历史提取 ISS-003 修复前的硬编码 JWT（无 `exp` 字段，iss=adevops.si-tech.com.cn），发布接口同样拒绝
  7. **`fromCode` 取值无关**：`fromCode: 0` / `fromCode: 1` / 不传 fromCode 三种情况错误一致
- **根因推断**：Token 网关返回的 `access_token`（非 JWT，184 字符 opaque token）能被获取但被发布接口拒绝解析；旧 JWT 也被拒绝，说明发布接口服务端对 Token 校验逻辑有变更或依赖额外参数（如 `fromCode` 的渠道编码未注册、Token 网关 appid 与发布接口渠道未绑定），需联系门户接口人（张德胜，见 docs/dev/DEV-portal-API.md）确认
- **建议方向**：
  1. 联系门户接口人确认 `fromCode` 渠道编码是否为 `1`（文档标注"MBOS接口自动化平台"但未给出确切数值）
  2. 确认 Token 网关 appid（`yx_8fjv2c3ivi0wxdr8`）是否已与发布接口的 `createCommonTopic` 渠道绑定
  3. 确认发布接口是否升级了 Token 校验逻辑，需额外的 header（如 `Content-Type: application/json` 而非 `multipart/form-data`）或参数
  4. 可参考公司门户帖子 https://eip.teamshub.com/t/7694556（DEV-portal-API.md 引用来源）获取最新接口变更
- **降级**：发布失败不阻断主流程，已记录 `[FALLBACK]` 日志至 `output/degrade-20260628.log`
- **解决**：2026-07-01 Feature 021 切换到新端点 `save_topic_info/v1.0`（JSON 信封 + `access_token` 查询参数），废弃 `createCommonTopic`。首次发布验证成功（帖子 ID 8132157）。注：新端点实际响应结构与契约文档示例不符（见 ISS-016），代码已兼容两种结构（commit `8eefc85`）。

## ISS-011 `scripts/` 目录双轨结构，违反高内聚低耦合（代码重构/工程化）

- **分类**：代码重构 / 工程化
- **优先级**：P2
- **背景**：`skills/secops-alert-analysis/scripts/` 现为"顶层平铺脚本 + `es-tool/` 分层子包"双轨结构，横切逻辑分散在两套 `lib/`，存在反向依赖与职责重叠
- **现状（待治理信号）**：
  1. **两套并行 `lib/`，职责重叠**：`scripts/lib/`（cli-args / es-query / whitelist / time-utils / report-renderer）与 `scripts/es-tool/lib/`（env / loader / logger / retry）并存，env 加载、ES 连接配置/查询、日志等能力各有一份，重复且易漂移
  2. **反向依赖（子包内部向顶层泄露）**：顶层 `post_to_portal.js` 直接 `import './es-tool/lib/env.js'`，子包内部工具被顶层脚本跨层引用，破坏分层边界
  3. **目录组织不一致**：顶层脚本平铺（CLI 参数 + 业务逻辑 + 渲染混写在单文件），`es-tool/` 却按 extractor/analyzer/lib 三层分目录，缺统一分层约定
  4. **配置/环境读取多源**：`lib/es-query.js` 自行读取 `es-tool/.env`，`es-tool/lib/env.js` 又提供 `loadEnv/getEnv`，两套 env 读取路径未统一
- **影响**：横切能力重复易漂移；反向依赖使分层失效、改动易牵连；理解成本高；与高内聚低耦合最佳实践相悖
- **思路方向**（执行待办时细化为具体步骤，此处仅列方向）：
  1. 逐文件梳理真实依赖图（顶层脚本 ↔ 两套 lib ↔ es-tool 子包），标出重复能力与跨层/反向依赖点
  2. 确立单一分层约定（如 core 基础设施 / domain 业务 / entry 脚本入口），明确每层职责与可引用方向
  3. 消除重复横切能力（env、ES 配置/查询、日志、CLI 参数），收敛到单一实现、单一职责
  4. 拆解"CLI + 逻辑 + 渲染"混写的顶层脚本，按职责分离
  5. 修正反向依赖，确立子包/底层不得被顶层跨层直引的边界规则
  6. 同步更新引用方（脚本 import 路径、SKILL.md 步骤中的脚本调用、测试路径）与 `.env` 读取约定
- **约束**：不得破坏既有对外契约（SKILL.md 调用的脚本入口、`--date/--format/--help` 等 CLI 形态、输出 JSON 结构须不变）；不得引入通用 orchestrator（沿用 017 R-004 边界，仅做模块整理聚合）
- **关联**：对应 TODO「五、代码重构/工程化」；017 R-004（通用 orchestrator 否决）；019（单用途探针先例）；ISS-002（package.json type:module 已修，属本目录工程化前提）

## ISS-012 Tier2 情报集成：自动接入外部威胁情报源（功能扩展）

- **分类**：功能扩展
- **优先级**：P1
- **背景**：Tier2 威胁研判已具备"结合外部情报深度研判、溯源时间序列行为轨迹"能力，但情报获取仍依赖手工查询，未自动接入情报源 API
- **目标**：接入 x.threatbook.com、abuse.ch、VirusTotal 三大威胁情报源，实现 IP/IOC 自动富化，支撑 Tier2 研判与 Tier3 处置
- **思路方向**（执行待办时细化）：
  1. 梳理三大情报源 API 接入方式（认证、配额、限频、字段差异）
  2. 评估与现有 `ip_enrichment.js` 富化能力的整合方式（复用 / 扩展 / 新建）
  3. 设计情报缓存与配额管理，避免重复查询与超限
  4. 定义情报结果的数据结构与落库/落文件方式，供报告与研判消费
  5. 凭证（API key）按宪法 III 配置管理纳入 `.env`，不入 git
- **关联**：对应 TODO「一、功能扩展」Tier2 情报集成；与已完成的 Tier2 威胁研判衔接；复用 `ip_enrichment.js`；ISS-003/010（凭证 .env 化先例）

## ISS-013 Tier3 威胁处置：防火墙封禁 + 通知资产归属人员（功能扩展）

- **分类**：功能扩展
- **优先级**：P2
- **背景**：当前流程止于分析与报告产出，无自动处置闭环；封禁与通知仍靠人工
- **目标**：对研判确认的恶意 IP 自动生成防火墙封禁动作，并通过公司帖子通知资产归属人员
- **思路方向**（执行待办时细化）：
  1. 确认防火墙封禁接口/方式（API 对接 or 生成封禁配置下发清单），评估权限与审批流程
  2. 资产归属查询：明确"资产清单 → 归属人员"的查询路径与数据源
  3. 通知发布：评估复用 `post_to_portal.js`（已有门户发布能力，受 ISS-010 发布接口问题阻塞）发布通知帖子的可行性
  4. 处置范围控制：封禁须有白名单/误报保护，避免封禁内部或合规 IP（联动白名单能力）
  5. 处置结果记录与回执，纳入复盘
- **约束**：封禁属高风险外向动作，须人工确认或审批后再执行，不得全自动封禁
- **关联**：对应 TODO「一、功能扩展」Tier3 威胁处置；依赖 Tier2 研判产出；复用 `post_to_portal.js`（ISS-010）；白名单能力（`lib/whitelist.js`）

## ISS-014 Tier3 复盘总结：全过程态势总结 + 邮件通知安全运营团队（功能扩展）

- **分类**：功能扩展
- **优先级**：P2
- **背景**：当前流程产出单次告警分析报告，缺少周期性态势总结与对安全运营团队的结构化通知
- **目标**：总结全过程与整体态势，邮件通知安全运营团队
- **思路方向**（执行待办时细化）：
  1. 定义复盘总结的内容结构（告警概况 / 研判结论 / 处置动作 / 遗留风险 / 趋势态势）
  2. 评估邮件通知通道（SMTP 配置 or 公司邮件 API），凭证纳入 `.env`
  3. 与现有报告渲染能力（`lib/report-renderer.js`）的复用关系
  4. 触发方式（单次复盘 vs 周期性汇总）与收件人配置
- **关联**：对应 TODO「一、功能扩展」Tier3 复盘总结；依赖前序 Tier1/Tier2/Tier3 产出；复用 `lib/report-renderer.js`

## ISS-015 使用 subagent 重构执行工作流，提升执行效率（效率优化 / 工作流架构）

- **分类**：效率优化 / 工作流架构
- **优先级**：P1
- **思路**：**先评估后按需改进**——第一阶段只读评估当前 `SKILL.md` 工作流的可并行化空间与 subagent 适用性，产出"可并行性矩阵 + 改进项清单 + 取舍依据"；第二阶段仅对评估确认收益明确、风险可控的阶段按需落地，不预设全量改造。
- **背景**：当前 `SKILL.md` 工作流由主 Agent 串行执行各阶段（步骤0 自检 → 步骤1 MCP 提取 → 白名单/富化/渲染/发布）。步骤0 经 Feature 020 已将本地可脚本化项收敛为 `local_selfcheck.js` 单调用（ISS-009），但 **MCP 项 A1/A3 仍只能由 Agent 经 MCP 逐条串行执行**——这正是 017 R-004 否决 Node 通用 orchestrator 的根因（Node 无法调用 MCP）。subagent 能并行驱动 MCP 工具，是绕过 R-004 限制、进一步提效的可行方向。
- **与 017 R-004 的边界区分**：
  - 017 R-004 否决的是"Node 通用 orchestrator 脚本"（`preflight.js` 之类覆盖全流程的脚本），原因：Node 无法调用 MCP（A1/A3 覆盖不到）且与 SKILL.md 逻辑重复（DRY/YAGNI）
  - subagent 重构**不违背 R-004**：subagent 由主 Agent 调度、可经 MCP 工具执行 A1/A3 类项，不引入 Node 编排脚本；调度逻辑写在 SKILL.md（指令层）而非脚本层
  - 落地时须在 spec 文档显式标注此区分，避免与 R-004 先例冲突
- **评估范围（第一阶段产出）**：
  1. **可并行性矩阵**：逐阶段标注「独立性 / MCP 依赖 / 输入输出契约 / 上下文成本 / 并行收益」，候选阶段至少覆盖：
     - 步骤0 MCP 自检项 A1（索引连通性）/A3（mapping 探针）——两项独立、均经 MCP，可由两个 subagent 并行
     - 封禁表生成（`ban_table_generator.js`，脚本侧）与报告主体生成（LLM 渲染）——独立可并行
     - Tier2 单 IP 情报富化（联动 ISS-012，多 IP 可并行查询）
     - 脚本回退诊断（MCP 失败时由 subagent 排查脚本回退路径，主 Agent 不阻塞）
  2. **subagent 适用性评估**：subagent 是否保留会话级 MCP 连接（elasticsearch-sse 等）、结果如何回传合并、上下文/token 成本与串行耗时的取舍、失败/降级处理
  3. **取舍依据**：对每个候选阶段给出"是否值得 subagent 化"的结论 + 理由，避免无收益的并行化（如上下文成本 > 耗时收益的阶段保持串行）
- **改进候选（第二阶段按需落地，非全量）**：
  - 步骤0 A1/A3 改为并行 subagent 探测，结果合并后主 Agent 判走向
  - 封禁表与报告主体并行生成，主 Agent 汇总注入
  - 其余阶段视评估结论决定是否落地
- **约束**：
  - **不得破坏既有对外契约**：SKILL.md 中脚本调用入口、`--date/--format/--help` 等 CLI 形态、输出 JSON 结构不变（017/019 边界）
  - **不得引入 Node 通用 orchestrator**（017 R-004），调度逻辑写在 SKILL.md 指令层
  - 第一阶段评估为只读，不改代码与 SKILL.md 行为
- **验证**：
  - 第一阶段：产出可并行性矩阵 + 改进项清单 + 取舍依据文档（spec 目录），无代码改动
  - 第二阶段（按需）：每项落地后现有测试套件全绿；SKILL.md 所有脚本调用按原入口跑通；串行耗时对比 subagent 并行耗时，确认收益
- **关联**：对应 TODO「三、效率优化」；017 R-004（Node orchestrator 否决，subagent 边界区分）；ISS-009（步骤0 本地项已批量化，本次聚焦 MCP 项）；ISS-001/ISS-004（MCP 调用次数与效率目标）；ISS-012（Tier2 情报富化并行候选）

## ISS-016 门户 save_topic_info 契约文档响应结构与实际不符（文档/契约一致性）✅ 已解决

- **状态**：已于 2026-07-13 解决
- **分类**：文档 / 契约一致性
- **优先级**：P1
- **发现**：2026-07-01 Feature 021 集成验证
- **问题**：`specs/021-fix-portal-posting/contracts/portal-api-contract.md` §4/§5 与 `data-model.md` 实体2 描述成功响应为双层包裹 `{msg, code, data:{errcode, data, status, desc}}`，但 `save_topic_info/v1.0` 实际返回扁平结构 `{errcode, data, status, desc, ...}`（无外层 `code`/`msg` 包裹）
- **影响**：
  - `tasks.md` T010 指令"保留响应解析逻辑不变（`code === 'SUCCESS'`）"基于错误假设
  - 首次发布误报失败：实际响应 `"保存成功！"` 且 topicId 8132157 已创建，但脚本判定为失败
  - 契约来源 `docs/dev/DEV-portal-API-门户发帖测试用例-chenghf.md` 出参示例与实际不符
- **已修复（代码侧）**：commit `8eefc85` 兼容两种结构——`isSuccess = code==='SUCCESS' || code==='200' || errcode==='0' || status==='0'`；`topicId = json.data?.data || json.data`
- **修复（文档侧）**：2026-07-13 更新 `portal-api-contract.md` §4 响应示例为扁平结构 + §5 解析规则（含兼容说明）；`data-model.md` 实体2 字段表提升为顶层（commit `eb8ae82`）
- **关联**：Feature 021；ISS-010（同源问题，旧端点已废弃）

## ISS-017 HTML 报告生成脚本 gen_html_report.mjs 未纳入 spec（工程化/契约化）✅ 已解决

- **状态**：已于 2026-07-13 解决
- **分类**：工程化 / 契约化
- **优先级**：P2
- **背景**：2026-07-01 新增 `scripts/gen_html_report.mjs`，程序化生成 HTML 报告（读模板 + 注入数据），替代之前 LLM 读 MD + 套模板即兴渲染的方式
- **问题**：脚本解决了渲染一致性，但未经过 speckit 流程，模板占位符契约与数据注入接口未形式化
- **现状**：
  - 当日数据（hourly/atkTypes/victims 等数组）内联硬编码在脚本中，每次运行需手动改数据
  - 模板占位符 `{{title}}`/`{{content}}` 等替换逻辑散在脚本，`{{title}}` 出现两次首次 `replace` 只改一个（已改 `replaceAll`）
  - 与 `ban_table_generator.js`（已 spec 化的封禁表生成）形成对比，报告主体生成仍无契约
- **修复**：2026-07-13 新建 `scripts/reporting/gen_html_report.js`（commit `5361e73`）——MD→HTML 转换器，支持 CLI `--input/--template/--output/--title/--whitelist`；模板占位符 `replaceAll` 语义；内联元数据提取（`extractMetadata()`）；14 测试覆盖
- **关联**：Feature 021 旁路产物；SKILL.md 步骤3c；`ban_table_generator.js`（已 spec 化先例）

## ISS-018 attack_type 字段编码异常未在丰富化阶段清洗（数据质量）✅ 已解决

- **状态**：已于 2026-07-13 解决
- **分类**：数据质量
- **优先级**：P2
- **发现**：2026-07-01 报告生成
- **问题**：ES `attack_type` 字段存在编码异常变体：`暴力猜解` vs `暴力\ufffd解`，`代码执行` vs `\ufffd码执行`，导致攻击类型分布表出现重复项（如"暴力猜解 637"与"暴力\ufffd解 1"实为同一类型）
- **影响**：
  - 报告生成需手动 `cleanTypes()` 合并去重（正则 `暴力[^解]*解`→`暴力猜解`），否则分布表重复
  - `ip_enrichment.js` 丰富化阶段未兜底清洗，异常编码直通到下游
  - `ban_table_generator.js` 风险描述也受影响
- **根因**：ES 数据源编码问题（非脚本问题），但丰富化阶段应兜底归一化
- **修复**：2026-07-13 在 `parse-mcp.js` 数据入口处新增 `normalizeAttackType()` 函数（commit `6f882c5`）——处理 U+FFFD 编码变体（`暴力\ufffd解`→`暴力猜解`、`\ufffd码执行`→`代码执行`）；`extractTerms()` 归一化后合并相同 type 的 bucket（count 相加）；5 测试覆盖
- **关联**：`ip_enrichment.js`；`ban_table_generator.js`；`lib/whitelist.js`（归一化先例）

## ISS-019 白名单过滤逻辑分散多处，存在重复与不一致风险（低效/数据一致性）✅ 已解决

- **状态**：已于 2026-07-13 解决
- **分类**：低效 / 数据一致性
- **优先级**：P2
- **发现**：2026-07-01 报告生成
- **现状**：白名单过滤分散 4 处执行：
  1. `extract_es_ids.js -x`（ES 端 `must_not: sip_addr:"局域网"`，粗过滤）
  2. `ip_enrichment.js`（脚本端 `isExternal()`，精过滤）
  3. `ban_table_generator.js`（二次兜底过滤，FR-013）
  4. 报告生成（Agent 端，手动调 `isExternal()` 或自实现正则）
- **问题**：
  - 报告生成阶段无脚本化过滤入口，依赖 Agent 手动调用
  - 2026-07-01 执行时 Agent 首次用简单正则自实现过滤（只匹配单 IP），漏了 CIDR 范围 → 统计 92 个（应为 88 个），后改用 `isExternal()` 才正确
  - 多处过滤易漂移，过滤口径不一致会导致下游统计偏差
- **根因**：虽有 `lib/whitelist.js isExternal()` 统一函数，但报告生成阶段无脚本化入口，且 Agent 易绕过统一函数自实现
- **修复**：2026-07-13 双管齐下（commits `5361e73` + `8c621ae`）：
  1. `gen_html_report.js` 内置白名单过滤 `filterWhitelistIps()`，调 `shared/whitelist.js isExternal()` 移除含白名单 IP 的表格行
  2. SKILL.md 新增约束行："任何涉及白名单过滤的阶段 MUST 调 `shared/whitelist.js isExternal()`，禁止自实现正则"
- **关联**：ISS-011（目录重构，`lib/whitelist.js` 归属）；ISS-017（报告生成 spec 化）；`lib/whitelist.js`

---

## ISS-020 viewRight=2 指定读者模式未配置 viewPriv，导致帖子圈子成员不可见（配置/契约语义）

- **分类**：配置错误 / 契约语义理解偏差
- **优先级**：P1
- **发现**：2026-07-01 Feature 021 合并后复查
- **现状**：`post_to_portal.js` 硬编码 `viewPriv: ''`（空字符串），`.env` 配置 `PORTAL_VIEW_RIGHT=2`（指定读者）
- **问题**：
  - 契约语义（`DEV-portal-API.md:139`）：`viewRight=1` 完全公开 / `viewRight=2` 指定读者（**viewPriv 必填**，逗号分隔读者ID）/ `viewRight=3` 设密码（需查看密码+编辑密码，4-8位字母数字组合）
  - 注：契约文档描述 viewRight=3 为"草稿"，但实际门户行为是需要密码才能查看，与文档不符（同 ISS-016 契约漂移）
  - `viewRight=2 + viewPriv=""` = 指定读者模式但未指定任何读者 → 帖子发布成功但圈子成员不可见，仅作者可见
  - Feature 021 spec.md:115 假设"viewRight=2 与圈子权限策略一致"有误，契约文档说 viewRight 默认 1（公开）
- **影响**：20260701 报告帖子 ID 8132157 圈子成员不可见，需手动删除补发
- **根因**：
  1. 021 spec 对 viewRight 语义理解偏差，未识别 viewPriv 的必填约束
  2. 代码硬编码 `viewPriv: ''`，未从 env 读取
  3. 缺少 viewRight=2 时 viewPriv 必填的启动校验
- **修复**（2026-07-01）：
  1. 新增 `PORTAL_VIEW_PRIV` 环境变量，`post_to_portal.js` 从 env 读取
  2. 早期校验：`viewRight=2 + viewPriv 空` → FATAL 退出（避免浪费 Token 网关调用）
  3. `viewRight=1` 时 viewPriv 忽略；`viewRight=2` 时 viewPriv 必填
  4. 启动日志打印实际 viewRight 语义 + viewPriv 值，避免"以为生效但没生效"
  5. `.env.template` 补充 `PORTAL_VIEW_PRIV` 配置项 + 语义说明
- **验证**：viewRight=2+viewPriv=15570 发布成功（帖子 8132364，指定读者 15570 可见）
- **关联**：ISS-016（契约文档响应结构漂移，同属 021 契约一致性问题）；`DEV-portal-API.md:139`

---

*记录时间：2026-06-28 18:25 (Asia/Shanghai)*
*最后更新：2026-07-13 ISS-016/017/018/019 标记已解决（P0+P1 bugfix 20260713）*
*记录人：安全运营告警分析研判Skill 执行复盘*


