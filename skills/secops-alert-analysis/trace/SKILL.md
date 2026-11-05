---
name: secops-alert-analysis-trace
description: |
  路径B 深度溯源分析（保留 MCP 优先）。当用户进行 IP 溯源、查一下这个IP、查询IP、攻击路径、深度溯源时，按本工作流执行。
output:
  files:
    - pattern: "output/trace-report-{target_ip}.md"
      description: "溯源分析报告（Markdown格式）"
      template: "templates/trace-report-template.md"
  terminal:
    summary: true
    template: "templates/terminal-summary-template.md"
    max_lines: 50
---
# 路径B：深度溯源分析（保留 MCP 优先）

> **本路径保留 MCP 优先策略**（宪法 VI：路径B 保留 MCP 优先）。
>
> - 威胁情报经微步 ThreatBook MCP（`ip_query` / `ip_attribution`）主路径、脚本 `external.js --ip` 回退；
> - 溯源 ES 检索经 `elasticsearch-sse` MCP 主路径、脚本回退；
> - MCP 与脚本在路径B 内为两条独立自包含子路径，**禁止同次运行交叉调用**；仅当 MCP 完全不可用时**整体切换**到脚本路径并记降级日志。
>
> **参考文件**：
>
> - `references/mcp-es-notes.md` — ES MCP 注意事项（附录A/E/D 选择表，本路径B 专属）
> - `references/dsl-examples.md` — ES DSL（溯源查询章节）
> - `references/MCP-ES-index-logfmt_746_Ref.md` — ES MCP logfmt_746_ 索引参考指南（含适用范围小节）
> - 宪法 VI / VII（路径分离 / CWD 锁定）

适用于"查一下这个IP"、"溯源某个IP"、"查询某IP的攻击路径"等场景。

ES index name prefix: logfmt_746_

## 溯源流程

### 第一步：双向日志检索

对目标IP查询最近30天关联日志，内部IP额外查横向移动：

| IP类型                | 查询条件                                                                                                  |
| --------------------- | --------------------------------------------------------------------------------------------------------- |
| 外部IP（攻击源）      | `field_values.sip = 目标IP` AND `field_values.sip_addr != '局域网'`                                   |
| 内部IP（受害）        | `field_values.dip = 目标IP`                                                                             |
| 内部IP（作为源/横向） | `field_values.sip = 目标IP` AND `field_values.dip_addr = '局域网'`                                    |
| 内部IP（双向）        | `field_values.dip = 目标IP` OR (`field_values.sip = 目标IP` AND `field_values.dip_addr = '局域网'`) |

### 第二步：日志推断

统计日志结果后判断：

- 日志条数 = 0：该IP无告警记录，输出"未发现关联告警"
- 日志条数少（<5）：输出简略日志列表即可
- 日志条数多（≥5）：需要深度溯源

### 第三步：深度溯源（当需要时）

调用外部威胁情报（默认不自动执行，询问用户是否执行）:

**主路径 — MCP 工具（交互式单 IP 查询**）:

1. 使用微步 ThreatBook MCP 工具查询 IP 情报:
   - `ip_query` — IP 基础情报（标签、解析IP、WHOIS、证书、子域名等）
   - `ip_attribution` — IP 情报溯源
2. MCP 查询不经本地 SQLite 缓存，单次查询无需缓存

**回退路径 — 脚本 CLI（MCP 不可用时**）:

```
RUN: node skills/secops-alert-analysis/scripts/threat-intel/external.js --ip <目标IP>
```

- 脚本入口检查 `ENABLE_THREATBOOK`，`false` 时退出码 1 + stderr 提示
- 查询结果经 SQLite 缓存，命中缓存不消耗 API 配额

> **功能开关**: `ENABLE_THREATBOOK=false` 时，不主动推荐微步溯源路径，脚本回退硬阻断（退出码 1），全链路无豁免。

### 第四步：生成溯源报告

按溯源报告模板输出，模板路径：`templates/trace-report-template.md`

> **ES MCP DSL 与查询注意事项**：详见 `references/mcp-es-notes.md`（附录A/E/D 选择表）与 `references/dsl-examples.md`（溯源查询章节）。查询动词必须用 `term`（keyword 字段），`timestamp` 用 `range`，`dynamic: false` 不查未索引字段，`track_total_hits: true`（详见 `references/mcp-es-notes.md` 附录E 第8条）。