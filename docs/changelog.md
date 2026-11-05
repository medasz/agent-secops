# Changelog


Changelog — 2026.9.15

  简版包纳入定时入口，部署收敛为「投放两件 + 一条 install」

- feat(release): release-maker.sh lite 引入白名单 LITE_KEEP_SCRIPTS —— scripts/ 顶层保留 .env 与 auto-patrol.sh
- feat(cron): install-cron.sh 将 scripts/auto-patrol.sh 列为包内必需件（缺件即拒绝部署、不落树），部署后补执行位；取消「手工投放启动脚本」前置
- refactor(cron): 选件优先部署根（工件平铺投放即可），部署根缺失时自动创建，--dry-run 不再因空部署根误报失败
- docs(ops): ops/secops-cron-deploy/README.md 收敛为两件工件 + 一条 install，全文去掉 cd 跳转
- chore: 发布 secops-alert-analysis-2026.9.15 简版包（含 auto-patrol.sh）
- feat(cron): install-cron.sh 新增 uninstall-all —— 整套回收 crontab 条目 + skill 软链 + 部署根（不带 --yes 只打印计划，软链指向开发仓或实体目录一律跳过）
- docs(ops): README 里 install-cron.sh 指令统一写脚本短名（命令在部署根执行），不再逐条写绝对路径
- feat(cron): 默认调度由每小时一次改为每天 09:00（CRON_SCHEDULE 默认 0 9 * * *；重跑 install 会按目标值重写条目）
- feat(cron): 默认部署根由 /opt/agent-secops 改为 $HOME/agent-secops —— 建根、部署、软链、写 crontab 全程普通用户，不再需要 sudo
- docs(ops): README 部署段去掉 sudo mkdir/chown，改为 mkdir -p ~/agent-secops + cd；并说明别用 sudo 跑脚本（HOME=/root 会把 crontab、skill 软链、.env 挂到 root 名下）
- fix(cron): uninstall-all 删部署根失败不再被 set -e 掐掉 —— 父目录不可写时先 WARN、给出 sudo 收尾命令，收尾核对照跑并报残留（退出码 1）
- fix(cron): 「巡检在跑」判定改读 output/auto-patrol.lock 里的 PID 判活，不再用 pgrep -f（命令行里出现过脚本名会误命中）
- docs(spec): specs/015-auto-ids-patrol/quickstart.md 收敛为速查表，部署命令统一指向 ops/secops-cron-deploy/README.md（去掉重复的 /opt 旧路径与 5 * * * * 旧调度）
- docs: 新增 docs/公开化改造清单.md —— 公开化前须处理的敏感面（入库 zip 内含 .env 与 ipWhite、包密码硬编码、内网清单与 320 处内网地址、git 历史），含发布前复扫命令
- chore: 删除 releases/152（0 字节误建文件，无任何引用）


Changelog — 2026.9.14

  Linux cron 定时巡检就绪性加固与部署指南

- feat(cron): auto-patrol.sh 适配 cron 最小环境 —— TZ 归一化、PATH 兜底（nvm / ~/.local/bin / /usr/local/bin）、opencode 缺失即以 127 退出（skills/secops-alert-analysis/scripts/auto-patrol.sh）
- feat(cron): 无人值守默认参数 —— 默认 --auto、显式固定模型（PATROL_MODEL）、超时/提示词/轮转阈值均可环境变量覆盖（同上）
- feat(cron): 日志按大小轮转并保留最近 N 份；成功时记录当日报告路径；启动行回显模型与超时上限（同上）
- docs(ops): 新增 Linux cron 部署指南与幂等安装脚本（ops/secops-cron-deploy/README.md、install-cron.sh）
- docs(spec): 015 规格、计划、速查、任务、数据模型、研究全面对齐 opencode 调用形态与真实路径（specs/015-auto-ids-patrol/*）
- fix(spec): 015 中残留的 claude -p、skills/ids-alert-analysis 路径与 auto-ids-patrol.log 日志名统一更正（同上）
- chore(windows): 删除 auto-patrol.bat（LF + UTF-8 无 BOM 在 ACP=936 cmd 下解析错乱，实测 rc=255）；Windows 侧改由任务计划程序调用 wsl.exe 执行同一 auto-patrol.sh（skills/secops-alert-analysis/scripts/、ops/secops-cron-deploy/README.md 附录 B）

Changelog — 2026.9.1

  告警/威胁计数口径修正与运维部署自动化

- fix(解析): 告警类型/威胁计数改用真实攻击次数（`+= r["count"]`）而非记录条数 — `parse-ids-excel.py` 五处聚合（threat/lv2：src_agg / XFF 客户端 / 失陷主机 / ioc_domains）与 count 口径对齐，修复 Excel 行合并导致风险描述括号内次数被低估的问题
- feat(ops): 新增 `secops-skill-deploy` 部署自动化 — `deploy-to-librechat.sh` / `status.sh` 部署、体检与回滚脚本 + `README.md` 运维文档
- chore(secops): 更新 IP 白名单（`ipWhite.md`）并调整报告标签（`render-skeleton.py`）
- chore: 发布 `secops-alert-analysis-2026.9.1` 版本包（full/lite）

Changelog — 2026.8.17

  新增 ids-fastReport 子技能（IDS 离线快速研判）

- feat: 新增 `ids-fastReport` 子技能 — IDS 告警 Excel 导出离线快速研判全流程（SKILL.md + `parse-ids-excel.py` / `render-skeleton.py` / `gen-xff-judgment.js` / `fact-to-enrich.js` 脚本 + `lv2-attack-type-mapping.json` 攻击类型映射）
- feat: `render-skeleton` 报告骨架 — 标题自动推导 + §6.1 过滤口径 + §6.2 五列对齐 ES
- feat: `parse-ids-excel` — 解析 IDS 导出的告警 Excel，增加白名单剔除 IP 统计与导出窗口解析
- fix: ban-ip 阈值对齐 ES 版本、XFF 微步融合、§1/§7 修正
- fix: 离线 XFF 研判 + 微步情报必选
- docs: 新增 router 设计文档 `docs/superpowers/specs/2026-08-17-ids-fastreport-router-design.md`

  脚本口径对齐与执行环境分级降级

- fix(ids-fastReport): XFF 研判对齐 ES 口径（阈值 >10 / 时间格式 / geo 取自表格）与报告数据来源显示
- docs(ids-fastReport): SKILL 对齐脚本新口径（标题自动推导 / §6.1 过滤 / 白名单统计数据源 / XFF 判定 ES 口径 + WSL 清理 + 工具链精简）
- refactor(secops): 执行环境改为「依赖探测 + 分级降级」，零 ES 路径不再被阻断 + wsl-node 触发条件收敛
- refactor(secops): 子技能去除 WSL 启动器 `wsl-node` 引用，统一 node 直接运行
- docs(secops): 父 Router 修正 ids-fastReport 死路名并补齐 A-XFF 路径
- docs(plans): 统一告警综述中「本日」的表述为「当日」
- chore: gitignore 忽略 `export/` 输出目录、IDS 原始告警 Excel 与 Python 缓存
- chore(skills): 移除 `.claude` / `.agents/.workbuddy` 下的技能副本与硬链接副本
- chore(workbuddy): 清理历史记忆文件（2026-06-28 至 2026-08-04）
- chore(secops-alert-analysis): 简化 wsl-node.sh 中的注释描述
- fix(release): 打包脚本排除 `__pycache__/` Python 缓存目录（full/lite 统一走 staging 减法）

Changelog — 2026.7.30
  快捷方式与发布包维护

- chore: 添加 `AISecOps.lnk` 桌面快捷方式
- chore(secops): 移除一次性 bugfix 验证脚本 `_verify_bugfix.mjs`（离线验证已固化进测试套件）
- chore: 更新 `secops-alert-analysis-2026.7.24` 发布包

Changelog — 2026.7.28

  WSL 启动器与白名单加固

- fix(script): `wsl-node.sh` 动态查找 WSL 中的 Node.js 路径并优化错误提示
- chore(secops): 更新 IP 白名单（`ipWhite.md`）与基础设施参考清单（`ipInfra.md`）

Changelog — 2026.7.24

  XFF 子技能重命名与报告增强

- refactor(xff): 子技能 `judgment-xff-proxy` → `judgment-xff`（目录 / SKILL.md / references / templates / 脚本头注释 / 父 router 引用全链路同步，output 历史产物一并改名）
- feat(xff-report): XFF 报告多项增强 — H1 与标题自动追加研判时间窗；§5.1「攻击IP」改名「外部真实客户端IP」；`xff_ban_ip_table` 封禁表与 §2.1 单表合并且判断逻辑对齐；§5.1.1/§5.1.2 攻击类型列统一 `type(count)` 全量格式
- docs(secops): 更正 XFF 模板 IP 描述术语

  模板与发布

- refactor(templates): HTML 模板 `report-template-v1.html` → `alert-report-template-v1.html`（git mv + 全链路裸引用同步 + selfcheck D4 判定一致 + 还原 .claude 符号链接）
- fix(release): lite 包打包排除规则误伤修复 + zip 前置检查
- chore: 发布 `secops-alert-analysis-2026.7.24` 版本包

Changelog — 2026.7.23

  跨天报告缺陷修复

- fix(secops-alert): 修复跨天报告 7 处缺陷 — §5.2 攻击类型计数补全（含非授权访问/权限绕过）+ 受害/失陷标签语义；§2.3 威胁情报三态（是/否/未知）；HTML 概览空元数据解析；小时分布按真实窗口裁剪；§2.2 窗口外域名行级过滤 + 跨日索引合并；`dns-agg.js` 支持 `--start/--end` 跨天窗口；SKILL.md 跨天参数与窗口约定同步

---

Changelog — 2026.7.22



  XFF 代理攻击研判子技能完善（Feature 025）



- feat: `judgment-xff` 子技能完善 — 双表产出（外部客户端 × 微步标签 × 受害主机 + 封禁建议），取消威胁情报/研判占位符

- feat: XFF 专项流程内嵌主路由并增加执行开关（`ENABLE_XFF_PROXY`）

- refactor: XFF §5.1 三表统一 `xff_` 前缀，模板驱动单源

- docs: 主路由 SKILL.md 与 judgment 子技能说明更新



  报告渲染模板化重构



- refactor: 报告渲染拆分为模板驱动 section + §5 双表设计 + §6 标题规范

- refactor: 共享层与威胁情报/ES 工具重构

- refactor: 报告生成器脚本连字符重命名 + 全量引用同步

- feat: `gen-md-report` 加防呆警告，杜绝漏传参数静默降级

- fix: `full_ip_list` 重构至渲染层，HTML 折叠仅包裹表格

- style: 简化外部 IP 列表折叠提示文案



  白名单与自检加固



- fix: 白名单 CIDR 基址对齐修正并加固完整性测试

- test: `local-selfcheck` 加环境感知（ES 不可达自动转 WSL node）

- test: 补充 section/analysis/threat-categories 测试并修正渲染断言



  打包发布脚本



- feat: 添加打包发布脚本 `make-release`（全量包 + lite 包）

- fix: lite 包保留子目录文件，恢复 zip 加密

- chore: 移动 `package.json` 位置

- chore: 移除 IP 信誉查询示例脚本

- chore: 发布 `secops-alert-analysis-2026.7.22` 版本包



---



Changelog — 2026.7.18



  报告乱码根因修复（HTTP 分块解码）



- fix: 报告 `attack_type` / `hazard_rating` 出现 U+FFFD 乱码 — 根因为 HTTP 响应按 chunk 逐块 `data += chunk`（Buffer 被隐式按块解码）切断多字节 UTF-8 → 统一改为 Buffer 累积 + 收尾一次性 `Buffer.concat(chunks).toString('utf8')`

- fix: 6 处 HTTP 响应处理修复 — `shared/es-query.js`、`es-tool/extract.js`（esRequest + makeRequest 两处）、`threat-intel/client.js`、`shared/proxy.js`、`portal/post.js`（token / submit 两处）

- fix: `shared/logger.js` 补 `errorWithStack(message, error)` 方法（此前缺失，TypeError 掩盖真实 ENETUNREACH）



  ThreatBook 缓存 TTL 调整（12h → 24h）



- chore: `THREATBOOK_CACHE_TTL` 由 43200（12h）改为 86400（24h）；`.env`、`shared/env.js` fallback、`references/threatbook-config.md` 及统一化设计/计划文档代码样例全量对齐



Changelog — 2026.7.15



  ThreatBook 威胁情报集成（Feature 022）



- feat: `threat-intel/cache.js` — SQLite 缓存层（node:sqlite），避免重复查询消耗 API 配额

- feat: `threat-intel/client.js` — 微步 ThreatBook REST API 客户端，支持批量 IP 查询

- feat: `threat-intel/external.js` — CLI 入口脚本，`ENABLE_THREATBOOK=false` 时硬阻断（exit 1 + stderr）

- feat: `threat-intel/fuse.js` — Step 3d 报告融合，将威胁情报合并进封禁表/独立章节

- feat: `shared/env.js` 新增 `isFeatureEnabled()` 通用特性开关函数

- feat: ThreatBook 配置文件 + `.env` 变量（API Key / lang / cache_path / probe_ip / confirm_level / label_map）

- feat: `ban-table.js` 新增 `--candidates-output` 输出封禁候选 JSON

- chore: Node.js 要求从 18 升级至 22.5（支持 node:sqlite）

- specs: 新增 022-threatbook-integration 全套规格（设计/实测数据/错误处理/.env 抽取/特性开关/实现计划 4 阶段 20 任务）



  Proxy 反向代理模块（Feature 023）



- feat: `shared/proxy.js` — Nginx 反向代理模块，支持 ThreatBook API 代理转发

- feat: `client.js` 集成 proxy 自动初始化（`ENABLE_PROXY=true` 时生效）

- feat: selfcheck C3 适配代理探测（`ENABLE_PROXY=true` 时探测代理主机）

- fix: proxy `res.on('error')` 错误处理 + 超时防双重 reject

- test: proxy 模块单元测试 + 自动初始化行为验证



  自检系统 TCP 化重构（Feature 024）



- refactor: C2 HTTP + C4 REST 探针替换为 TCP 探针，删除 `probePortalToken`/`probeThreatbookRest`

- feat: `tcpProbe` + `parseHostPort` 通用工具函数

- feat: A1 ES TCP + C3 Threatbook TCP 探针新增

- feat: scope A 纳入 `aggregateLocalVerdict` 强制校验

- refactor: 删除 `ban-ip/domain-selfcheck.js`，合并进 `selfcheck.js`（11 项单调用自检）

- docs: SKILL.md 步骤0 重写为单调用 TCP 自检，移除 ban-selfcheck 引用



  脚本目录重构与 .env 统一



- refactor: 9 个工具文件从 `lib/` 和 `es-tool/lib/` 迁移至 `shared/`

- refactor: `es-tool/extractor/` 扁平化至 `es-tool/` 根目录

- refactor: analyzer / portal / reporting / workflow 脚本迁移至 `scripts/` 子目录

- refactor: `.env` 统一至 `scripts/` 根目录，修正相对路径

- refactor: auto-patrol 脚本更新，校验边界规则



  Skill 重命名与定位调整



- refactor: `ids-alert-analysis` → `secops-alert-analysis`（目录+全链路重命名）

- refactor: SKILL.md 标题「IDS告警分析」→「安全运营告警分析研判」，溯源模板改用 JSON DSL

- feat: `ban-table` → `ban-ip-table` 全链路重命名 + 新增 Domain 封禁建议

- refactor: 封禁表首列标题改为「告警日期时间戳」



  报告模板优化



- refactor: 告警报告模板优化（排版与结构调整）

- feat: 威胁情报拆分为独立报告章节（§2.3 IP威胁情报）

- feat: `fuse.js` 重写为 4 列独立 `threat-intel-table` 输出

- feat: 终端摘要模板 + 报告标题清理 + 巡检日志路径修正

- fix: 统一步骤编号、交叉引用与终端摘要模板

- test: fuse 测试重写适配独立 threat-intel-table 输出



  ISS 批量修复（ISS-016 ~ ISS-019）



- fix: ISS-016 — Portal API 契约更新为扁平响应结构

- fix: ISS-017/019 — 新增 `gen_html_report.js` 实现 MD→HTML 转换

- fix: ISS-018 — `parse_mcp_output.js` 新增 `normalizeAttackType` + bucket 合并

- fix: DSL `size:0`→`size:1` 修正 MCP 路径 + 白名单约束

- docs: `issues.md` + `TODO.md` 标记 ISS-016/017/018/019 已解决



  宪法更新 — Principle VII. Path Safety



- feat: 新增 Principle VII. Path Safety（路径安全原则）

- fix: 路径规范新增符号链接警告 + 脚本自解析规则

- fix: `fuse.js` 示例删除 `--label-map` 参数

- docs: 路径安全设计文档与实现计划

- chore: 宪法版本号 1.2.0 → 1.3.0，更新 Sync Impact Report



  SKILL.md 文档更新



- docs: 工作流新增 Step 3c/3d/3e/3f + C3/C4 自检说明

- docs: 附录 H（ThreatBook 配置 / 脚本路径 / 输出格式）

- docs: 步骤 3b/3b'/3c 重写为 try-then-fallback 策略

- docs: 步骤 1 新增 A3/B2 隐式覆盖说明

- docs: 附录 H C4 REST 引用替换为 C3 TCP



  基础设施与清理



- chore: SpecKit 切换集成至 Codex 并添加技能

- chore: 清理旧备份输出文件 + 扩展构建输出目录忽略规则

- chore: 删除未使用的 `secops-alert-analysis-workspace` 目录

- chore: 添加 AISecOpsAgent 并更新忽略规则

- chore: 删除 3 个一次性硬编码脚本

- chore: 寻回 `specs/` 目录

- fix: 修复 3 个既有测试失败 + 测试路径 CWD 无关化



---



Changelog — 2026.7.3



  .env 解析器增强与配置规范化



- fix: `env.js` + `es-query.js` 支持 .env 行内注释（`key=value # comment`）与带引号值（`key="value"`）的正确解析

- feat: `post_to_portal.js` 新增 `ENABLE_POST` 开关（默认 false），防止误发帖；`PORTAL_IS_GM_VISIBLE` 可配置化

- chore: `.env.template` 全量重写注释 + 新增 ENABLE_POST / PORTAL_IS_GM_VISIBLE / PORTAL_REPLY_RIGHT / PORTAL_GROUP_ID 等参数说明

- chore: `.env.prd` 加入 `.gitignore`，杜绝凭证泄露风险

- chore: `SKILL.md` 步骤3b/3c 封禁表注入路径统一为文件读写（`--output output/ban-ip-table-{date}.md`）

- docs: 新增 `docs/general/ip-whitelist-parsing.md`，记录白名单解析流程与 4 种格式匹配逻辑



  新脚本工具



- feat: `scripts/gen_report.js` — 从 extract_es_ids 输出自动生成 Markdown 报告

- feat: `scripts/md_to_html.js` — 从生成的 Markdown 报告渲染为 HTML 报告



  凭证安全



- fix: `.env.prd` 配置含 ES 密码与 Portal 凭证，加入 `.gitignore` 禁止提交



---



Changelog — 2026.7.1



  Portal 发布修复（Feature 021）



- fix: `post_to_portal.js` 响应解析器适配 `save_topic_info/v1.0` 成功格式，修复发布成功但无响应的解析失败

- fix: `post_to_portal.js` viewRight 限制为 1（完全公开）或 2（指定读者），拒绝非法值提前退出

- fix: `post_to_portal.js` viewRight=2 时补充 viewPriv 早期校验，避免浪费 Token 网关调用

- fix: 移除未使用的 `PORTAL_GROUP_NAME` 配置变量（旧契约残留）

- docs: 补充 viewRight=3 密码语义及契约漂移说明（契约文档称"草稿"，实际门户行为为设密码查看）

- docs: `issues.md` 记录 ISS-020（viewPriv 配置缺失导致圈子成员不可见）



  凭证安全



- chore: `es-tool/.env.template` 更新 PORTAL_VIEW_RIGHT/VIEW_PRIV 注释说明



  发布



- chore: 打包发布 `releases/secops-alert-analysis-2026.7.1.zip`



---



Changelog — 2026.6.29



  ES MCP 查询约束强化（Feature 017）



- docs(secops-alert-analysis): SKILL.md 步骤0 环境自检 + DSL 合规 + SoT 对齐大改（+261 行）

- feat: 步骤0 增加 A1 索引连通性 / A3 mapping 探针 / B2 索引存在性校验前置

- feat: 附录A 聚合查询 DSL 对齐权威总数（SoT），消除多源计数漂移

- feat: 新增查询契约与前置探针契约文档 `specs/017-es-mcp-query-constraints/contracts/query-and-preflight-contracts.md`

- specs: 新增 017-es-mcp-query-constraints 全套规格（spec/plan/tasks/research/quickstart/data-model/checklist），**R-004 否决通用 Node orchestrator**（Node 无法调 MCP + 与 SKILL.md 重复，DRY/YAGNI）



  封禁IP表格脚本化与比对验证（Feature 018）



- feat: `ban_table_generator.js` — 封禁IP表格脚本化生成（484 行），四列数据全部取自 ES 真实告警，非 LLM 即兴填写

- feat: `references/attack-type-mapping.json` — 攻击类型映射表；`ip_enrichment.js` 扩展富化字段

- feat: SKILL.md 集成封禁表生成步骤；报告模板第3节注入 `{{ban_ip_table}}` + 时间戳语义说明

- feat: 封禁表与告警比对验证（`tests/secops-alert-analysis/ban-ip-table.test.js` + fixtures）

- specs: 新增 018-ban-ip-table-verify 全套规格（含 ban-ip-table-contract 契约）



  封禁表 ES 直连自检（Feature 019）



- feat: `ban_table_selfcheck.js` — 单用途探针脚本，纯 HTTP 直连 ES 验证封禁表数据（零 MCP 依赖）

- feat: SKILL.md 步骤0 范围 E 自检改走专用探针，复用 PF-xxx 命名 / scope-group / 降级日志契约

- specs: 新增 019-ban-ip-es-selfcheck 全套规格（含 ban-ip-selfcheck-contract 契约）；**先例确立"单用途探针"是被允许的模式**（区别于 017 否决的通用 orchestrator）

- test: 4 组 fixture（empty / fields-missing / no-aggregations / ok）+ 自检契约测试



  自检批量化与去重（Feature 020）



- feat: `local_selfcheck.js` — 批量覆盖 9 项零 MCP 依赖自检（B1/B3/B4/C1/D1-D4），单调用输出各子项 verdict + 联合结论 + 中文建议（523 行）

- feat: B2 改轻量定向探针（`get_mappings`/`search size:0`）消除 ISS-001 截断；A1 职责分离 / A2 复用 E1 直连路径；自检结论读 local_verdict 下沉脚本

- feat: ISS-009 解决 — 本地项 9→1 调用、A1+B2 去重、A2/E1 复用、判定逻辑下沉，32 测试全绿

- specs: 新增 020-selfcheck-batch-dedup 全套规格（含 local-selfcheck-contract 契约）



  ISS 批量修复（ISS-001 ~ ISS-009）



- fix: ISS-002 — `package.json` 声明 `"type":"module"`，消除所有脚本 MODULE_TYPELESS_PACKAGE_JSON 告警

- fix: ISS-003 — `post_to_portal.js` 动态 Token 自动获取（新增 `getToken()` 调 Token 网关），前置 C2 探测校验凭证

- fix: ISS-004 — 合并 MCP 聚合查询（追加 cardinality + date_histogram agg），步骤1 从 6 次降至 3 次

- fix: ISS-005 — `parse_mcp_output.js` 兼容信封与扁平两种 MCP 输出格式，步骤1.3/1.4 持久化+解析流水线跑通

- fix: ISS-006 — `time_distribution.js` 新增 `--external-only`/`-x` 标志 + 修正 timestamp 字段 `@timestamp`→`timestamp`

- fix: ISS-008 — SKILL.md 步骤2 + 附录A 增加权威总数定义与边界差异脚注（count vs date_histogram 桶求和差异）

- fix: whitelist_filter.js stdin 管道顶层 return 语法错误



  凭证安全加固



- feat: 硬编码敏感信息迁移到 `.env`（JWT Token、Portal API URL/端口/表单参数）— 宪法合规

- feat: `es-tool/.env.template` 模板（36 行）；`es-tool/.env` 密码清空

- test: TDD 测试先行，`env-credentials.test.js` 6/6 通过

- feat: Token 网关凭证 PORTAL_TOKEN_APPID/SECRET 迁移至 .env



  es-tool 目录扁平化重构



- refactor: `es-tool/scripts/` 上移到 `es-tool/` 扁平化（extractor/analyzer/lib/config.json）

- refactor: 删除顶层 `scripts/lib/` 4 个孤儿文件（env/loader/logger/retry，−433 行），消除双轨 lib 重复

- fix: `lib/es-query.js` 修正 .env 读取路径（真实凭据位置 `es-tool/.env`）

- docs: SKILL.md 脚本路径 + AGENTS.md/CLAUDE.md 同步



  文档重组与目录结构



- docs: 重组文档目录为 `docs/dev/` + `docs/diagram/` + `docs/general/` 三分

- docs: 新增 `docs/TODO.md`（统一任务清单，5 分类 + P0/P1/P2 优先级）合并删除原 `docs/general/TODO`

- docs: 新增 `docs/issues.md`（ISS-001~015 问题记录，含 Tier2/3 路线与 subagent 评估）

- docs: 清理根配置文件（删 AGENTS.md 82 行 / CLAUDE.md 130 行旧内容），更新 portal API 文档

- docs: 新增奇安信天眼 IDS SYSLOG 说明、SOC API、IP 信誉查询、黑名单规则、封禁IP处置数据样例

- docs: spec-coding toolset 说明文档更新；skill 快捷方式创建指南



  报告模板优化（6/29）



- docs: 报告模板第1节增加"数据来源"声明（ES 数据源 + 时间范围 + 分析对象）

- docs: 封禁表时间戳语义说明合并进表格注释；各章节表格格式对齐

- docs: 移除 report 模板末尾冗余的"时间戳语义说明"独立段



  未解决项（记录于 issues.md）



- ISS-010: post_to_portal.js 发布接口服务端返回"Client-Token 解析有误"（脚本侧 3 项已修，疑似 fromCode 渠道编码未绑定，待联系门户接口人）

- ISS-011: scripts/ 双轨结构深度重构（P2，待办）

- ISS-012~014: Tier2 情报自动接入 / Tier3 封禁处置 / Tier3 复盘邮件通知（功能扩展路线）

- ISS-015: subagent 重构执行工作流评估（P1，绕过 017 R-004，第一阶段只读评估）



  文档 & 规格



- specs: 新增 4 个功能规格（017 ES MCP 查询约束、018 封禁表脚本化验证、019 封禁表 ES 直连自检、020 自检批量化去重），总计 18 个

- docs: ES-MCP 服务环境文档新增封禁IP处置数据样例



  基础设施



- chore: 同步 017 spec-context 状态；合并 018-ban-ip-table-verify 分支

- chore: 清理根配置文件 + 更新 portal API 文档

- feat: workbuddy 记忆 — 2026-06-28 安全加固配置记录



---



Changelog — 2026.6.4



  文档与外部资料



- docs: 奇安信天眼威胁监测与分析系统（天眼-分析平台）IDS 官方 SYSLOG 说明文档

- feat: 新增多个文档 — IDS 告警字段、SOC API 接口、黑名单规则



  Skill 工具链



- feat: 新增 SpecKit 与 OpenSpec skill（specify/clarify/plan/tasks/implement 全链路）



---



Changelog — 2026.5.26



  Portal 发布集成（增强）



- feat: post_to_portal.js 重构 — 支持位置参数传入HTML路径，自动从 `<title>` 标签解析帖子标题

- fix: 将请求协议从 HTTPS 切换为 HTTP

- feat: 移除硬编码 Client-Token，改为 PORTAL_CLIENT_TOKEN 环境变量（Constitution 安全合规）

- feat: 步骤4集成到SKILL.md — 自动发布HTML报告到公司门户，含前置验证、后置验证、降级策略



  MCP 数据流优化



- feat: SKILL.md 步骤1新增MCP输出持久化步骤 — 查询结果保存为 `output/mcp-output-{date}.json`

- feat: 显式声明 parse_mcp_output.js 的调用时机、输入格式、输出结构

- docs: 脚本工具链章节更新 — 用法示例与执行流程路径一致



  定时巡检



- feat: auto-patrol.bat — Windows定时巡检wrapper脚本

- feat: auto-patrol.sh — Linux定时巡检wrapper脚本，含锁文件防并发、5分钟超时、timeout退出码处理

- docs: 自动巡检方案设计文档 (auto-ids-patrol-plan.md)



  报告时间修复



- fix: 报告"生成时间"始终不准确 — 根因是LLM无法访问系统时钟

- feat: SKILL.md步骤3重编号 — 3a(获取时间) → 3b(生成MD) → 3c(生成HTML)

- feat: 步骤3a强制执行 `TZ=Asia/Shanghai date` 获取系统时间，3b/3c禁止自行猜测



  文档 & 规格



- docs: CLAUDE.md 增强 — MCP回退策略、常见陷阱

- specs: 新增2个功能规格（015自动巡检、016时间注入），总计16个



  基础设施



- chore: SpecKit 工作流 — specify/clarify/plan/tasks/implement 全链路实践



---



Changelog — 2026.5.20



  IDS 告警分析 Skill (skills/secops-alert-analysis/)



- feat: 初始 IDS 告警分析 skill，支持 MCP 优先 + ES 脚本降级的双路径数据提取

- feat: extract_es_ids.js — ES PIT 分页查询，支持多日期索引范围

- feat: parse_mcp_output.js — MCP 输出解析，兼容 flat document 格式

- feat: whitelist_filter.js — IP 白名单过滤（CIDR / 短范围 / 完整范围 / 单 IP）

- feat: ip_enrichment.js — 外部 IP 威胁情报查询与标记

- feat: time_distribution.js — 告警时间分布统计

- feat: calculate_total.js — 汇总计算

- feat: 共享库 scripts/lib/ — whitelist.js、es-query.js、report-renderer.js、time-utils.js、cli-args.js、logger.js、retry.js

- fix: parse_mcp_output 支持 MCP flat document 格式

- fix: ES 查询分页、时区转换、日期边界 bug

- refactor: 移除旧 MCP 模块（mcp-client.js、fallback-manager.js），统一为 Direct ES Engine

- refactor: 将 lib/ 合并至 scripts/lib/，tests/ 移至项目根目录

- chore: 删除 ids-patrol-tool，迁移至 skills/secops-alert-analysis/scripts/es-tool



  报告生成



- feat: 报告模板 — Markdown 模板、HTML 暗色模板（v1）、IP 溯源模板

- feat: report-renderer.js — 统一报告渲染引擎



  Portal 发布集成



- feat: post_to_portal.js — 自动发布 HTML 报告至公司门户，集成到分析流程 Step 4

- fix: 将请求协议从 HTTPS 切换为 HTTP

- feat: 移除对 PORTAL_CLIENT_TOKEN 环境变量的硬编码依赖



  测试



- feat: Parser 测试 — MCP flat 格式、合法/畸形输入

- feat: Renderer 测试 — 报告渲染验证

- feat: Whitelist 测试 — 白名单过滤覆盖（CIDR、范围、单 IP）

- test: 测试 fixture 文件（valid-mcp.json、flat-mcp.json、malformed-mcp.json）



  文档 & 规格



- docs: AGENTS.md — 综合架构指南

- docs: docs/general/ — ARCHITECTURE、CONFIGURATION、QUICKSTART、EXTRACT_ES_IDS

- docs: 自动巡检方案设计文档 (auto-ids-patrol-plan.md)

- docs: 架构图（SVG + PNG）

- docs: 项目宪法 constitution.md v1.0.0 → v1.1.0

- specs: 14 个功能规格（001–014），涵盖 AI 分析增强、OpenAI 兼容、MCP ES 查询、.env 配置、配置统一、告警提取工作流、Skill

  重构、报告脚本、Portal 发布、MCP 解析优化



  基础设施



- chore: 初始化 Spec Coding 工具集成（SpecKit + OpenSpec）

- chore: .gitignore 重组

- feat: 移动 secops-alert-analysis 至 skills/ 目录并创建符号链接



