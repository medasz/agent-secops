# ES MCP 查询注意事项（路径B 专属参考）

> 本文件从主 `SKILL.md` 附录 A / E / D（MCP 相关部分）外迁，**仅供路径B（深度溯源分析）引用**。
> 路径A（告警研判分析）为纯脚本路径，**不引用本文件、不调用任何 MCP 工具**（宪法 VI）。

---

## 附录A：MCP查询DSL参考

> **完整 DSL 查询示例见 `references/dsl-examples.md`**（扩展聚合查询/文本时间范围查询/溯源查询）。
>
> 核心要点：
>
> - Step 1 两次查询：外部扩展聚合查询 + 内部攻击聚合查询（各一次 search），`compromised_hosts` 用 filter agg，`dns_domains` 用 global agg（仅外部查询），`lateral_movement` 用 filter agg（仅内部查询）
> - MCP 路径 `size:1`（获取 hits.total），脚本路径 `size:0 + track_total_hits:true`；两路径不可混用（宪法 VI），详见附录E 第5条
> - 边界差异脚注须在报告中展示（date_histogram 桶求和与权威总数存在差异），详见路径B 主流程统计汇总说明
> - 字段映射：attack_ips 子聚合供 parse-mcp.js → ban-ip-table.js 消费；compromised_hosts 按 `by_victim` 分桶（terms.field = `field_values.alarm_sip`，即受害 IP / 被攻击方，非 `dip`）；dns_domains 覆盖全量 DNS 流量

---

## 附录E：MCP查询注意事项

1. **`query_body` 必须是 JSON 对象**：MCP search 工具的 `query_body` 参数类型是 object，传入字符串会报 `invalid type: string, expected a map` 错误。
2. **字段必须加 `field_values.` 前缀**：原始日志字段存储在 `field_values` 命名空间下。直接使用 `sip` 或 `host_state` 无法匹配到数据。
3. **使用 `term` 而非 `match`**：`field_values.*` 为 keyword 类型，必须用 `term` 精确匹配（`match` 会分词导致空结果）。详见第8条对照表。
4. **`_source` 和 `fields` 参数**：指定返回字段时，`_source` 需要传入带 `field_values.` 前缀的路径数组。如不指定，默认返回所有字段。
5. **聚合查询中 `size`**：MCP 路径用 `size: 1`（MCP 在 `size:0 + aggs` 时不返回 `hits.total`，需 `size:1` 获取外部攻击总数）；脚本路径用 `size: 0`（直连 ES 原生返回 `hits.total.value`）。两者均搭配 `track_total_hits: true`。
6. **索引命名格式**：`logfmt_746_YYYYMMDD`，如 `logfmt_746_20260404`。可用 `list_indices` 工具配合 `logfmt_746_*` 模式确认索引是否存在。
7. **必须设置 `track_total_hits: true`**：ES 默认 `track_total_hits` 上限为 10,000。当日志量超过 10,000 条时，不设置此参数会导致 `hits.total.value` 返回 10,000 而非真实总数，影响告警总数等关键指标的准确性。所有需要精确计数的查询（扩展聚合查询、溯源查询）都必须包含此参数。
8. **字段类型 → 查询动词对照**：索引 `logfmt_746_YYYYMMDD` 的 mapping 为 `dynamic: false`，字段类型与可用查询方式如下：

   | 字段                                                                                    | ES 类型 | 合法查询动词 | 非法动词                                     |
   | --------------------------------------------------------------------------------------- | ------- | ------------ | -------------------------------------------- |
   | `field_values.*`（sip/dip/host_state/attack_type/hazard_rating/sip_addr/dip_addr 等） | keyword | `term`     | `match`                                    |
   | `message`                                                                             | text    | `match`    | `term`                                     |
   | `timestamp`                                                                           | date    | `range`    | `match` / `term`                         |
   | 未在 mapping 中的字段                                                                   | —      | —           | 全部禁止（`dynamic: false`，未索引不可查） |

   可用查询方式对照表：

   | 查询类型                    | 状态      | 示例                                                            |
   | --------------------------- | --------- | --------------------------------------------------------------- |
   | `match_all`               | ✅ 可用   | `{"query": {"match_all": {}}}`                                |
   | `term`（keyword 字段）    | ✅ 可用   | `{"query": {"term": {"field_values.hazard_rating": "高危"}}}` |
   | `range`（date 字段）      | ✅ 可用   | `{"query": {"range": {"timestamp": {"gte": "2026-06-25"}}}}`  |
   | `match`（text 字段）      | ✅ 可用   | `{"query": {"match": {"message": "告警"}}}`                   |
   | `aggs` 聚合               | ✅ 可用   | 按攻击类型/危害等级分组统计                                     |
   | `_source` 过滤            | ✅ 可用   | 只返回需要的字段                                                |
   | `esql`（`_query` 端点） | ❌ 不可用 | ES 7.x 不支持（见第 9 条）                                      |

   **总结**：ES 7.16.3 只支持 `_search` DSL 查询，不支持 ESQL；对 keyword 字段只能用 `term` 精确匹配。
9. **`esql` 工具不可用**：当前 ES 版本为 **7.16.3**，ESQL 需要 ES **8.11+**。`esql` 工具调用 `_query` 端点会返回 **405 Method Not Allowed**（`http://203.0.113.10:9200/_query`），调用必然失败。**禁止调用 `esql` 工具**；数据提取仅使用 `search` 工具（`match_all`/`term`/`range`/`match`/`aggs`/`_source`）。若未来 ES 升级到 8.11+ 使 `esql` 可用，以本附录更新后的结论为准。
10. **`dynamic: false` 不得查询未在 mapping 中的字段**：索引 `logfmt_746_YYYYMMDD` 为 `dynamic: false`，未在 mapping 中的字段不会被索引、查询必然空结果。仅可查询 mapping 中已存在的 `field_values.*`、`message`、`timestamp` 字段。
11. **数据真实性原则**：所有计数（告警总数、外部攻击数、命中数等）必须取自 `track_total_hits: true` 的 `hits.total.value` 或聚合桶的真实值，**不得用 `size`、聚合桶数或 `sum_other_doc_count` 推断**；报告中任何真实数据指标必须来自统计汇总的 ES 真实值，**LLM 绝不允许对真实数据猜测、估算、四舍五入或篡改**。
12. **聚合合并优化**：Step 1 扩展聚合查询一次 search 获取全部数据（外部攻击总数/唯一IP/小时分布/攻击IP/失陷主机/DNS域名），共需 2 次 search（mapping 探针 + 扩展聚合）。详见 `references/dsl-examples.md` 和附录A。
13. **MCP 查询结果必须立即持久化到文件（强制）**：MCP `elasticsearch-sse_search` 返回的聚合 JSON 体积通常为 50KB–500KB+，直接保留在对话上下文中会导致 context 溢出和压缩丢失。Agent 必须遵守：
    - 每次 MCP 查询返回后，立即使用 `write` 工具将完整结果写入指定文件（如 `output/mcp-output-external-{date}.json`）
    - 不得在对话中展示或引用完整 JSON
    - 仅提取关键指标（如 `hits.total.value`、唯一IP数）作为对话摘要，不超过 3 行
    - 所有后续处理从持久化文件读取，需要时用 Grep 或 Read（带 offset/limit）定向检索
    - 禁止在对话回复中回显完整 MCP 查询结果 JSON

> **字段类型约束声明**：附录E 第8-10 条是本 skill MCP 查询约束的**权威依据**。Step 1-3 的所有字段类型说明、查询动词映射、`esql` 可用性结论必须与附录E **零矛盾**；当 ES mapping / 版本演进时，应先更新附录E，再同步全文，不硬编码于不可变更之处。

---

## 附录D（MCP 相关部分）：MCP vs 脚本选择

> 路径B 保留 MCP 优先策略；以下选择表仅用于路径B 内部决策，与路径A 无关。

| 场景             | 推荐 | 原因                                  |
| ---------------- | ---- | ------------------------------------- |
| MCP服务器正常    | MCP  | 可定制查询，两次查询获取外部+内部统计 |
| MCP查询失败      | 脚本 | 兜底保障                              |
| 需要批量处理多日 | 脚本 | 更稳定                                |
| 需要实时交互     | MCP  | 可分步查询                            |

> **路径B 混用约束**：MCP 与脚本在路径B 内为两条独立自包含子路径，**禁止同次运行交叉调用**；仅当 MCP 完全不可用时**整体切换**到脚本路径并记降级日志（宪法 IV / VI）。
