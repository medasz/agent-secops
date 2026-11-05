# ES MCP logfmt_746_ 索引参考指南（全字段版）

基于真实样本（`logfmt_746_20260601`，当日 27599 条）与产品静态文档 `docs/dev/DEV-API-IDS-static-help-docs/`（高级检索字段 `zh-cn_search_fields_README.html` / `zh-cn_adv-search_fields_README.html`）梳理的威胁检测日志索引结构与**全字段**查询参考。

> 说明：`get_mappings` 当前对单索引返回 "error decoding response body"（服务端瞬时/序列化问题），本指南字段清单由真实样本并集 + 产品 help-docs 交叉核对得出，覆盖本索引（`sys_qax_01` 流量传感器 / webids）实际出现并可查询的全部字段。

## 0. 适用范围（必读）

本指南的边界与 `docs/dev/DEV-SOC-API-MCP-安全运营大数据查询.md`（下称"API 文档"）逐条对齐，请先确认您要查的是哪一类数据：

| 场景 | 是否适用本指南 | 说明 |
|------|---------------|------|
| **ES MCP / `_search` DSL 查询 `logfmt_746_YYYYMMDD`**（IDS 告警 / 安全事件运营数据，inKey `sys_qax_01`） | ✅ **完全适用** | 本指南的全部字段表、DSL 模板、查询规范均针对此类。API 文档实证的 ES 7.16.3、`field_values.*` 全 keyword→`term`、`timestamp` date→`range`、`dynamic:false`、禁用 ESQL `_query`，与本指南 §5.3/§7 完全一致 |
| **经 ULMP 封装接口 `queryLogFROMEs` 查询 `logfmt_746`** | ⚠️ **仅字段语义共享，接口不通用** | 该接口用 `inKey` / `beginTime-endTime` / `fields[{key,value,relation}]` / `pageSize` 另一套参数（非 ES DSL/MCP）；本指南的 `term/range` DSL 模板**不能直接套**，但 `field_values.*` 字段名、值域（如 `sip_addr=局域网` 表内网）可复用 |
| **`logfmt_761`（易信VPN风险应用运营数据）** | ❌ **不适用** | 不同索引族，`field_values` 是风险应用 schema（`app_id` / `risk_app_*` / `device_id` / `user` …），与本指南 IDS 告警字段表无交集，请勿混用 |

> 补充（避免误判）：API 文档中的 `/_sql` 示例走的是 SQL 插件端点（`/_sql`，ES 7.16.3 支持），与 ESQL 的 `_query`（不支持、本指南 §7 已禁用）是两回事，本指南按 DSL 表述、与之无冲突。

## 1. 索引命名规范

| 类型 | 格式 | 示例 |
|-----|-----|-----|
| 单日索引 | `logfmt_746_YYYYMMDD` | `logfmt_746_20260601` |
| 时间范围索引 | `logfmt_746_*` | 跨日查询 |

## 2. 文档顶层结构

一条文档的顶层字段（非 `field_values.*` 命名空间）：

| 顶层字段 | ES 类型 | 说明 |
|---------|--------|------|
| `id` | keyword | 文档唯一 ID（ES `_id`） |
| `timestamp` | date（epoch_millis，如 `1784341656806`） | **时间范围查询唯一可用字段**，用 `range` |
| `message` | text | 完整日志 JSON 字符串（含 `_origin` 原始字段），用 `match` 全文检索 |
| `org_length` | long | 原始 message 长度 |
| `zip_message` | text | 压缩原始消息（通常空） |
| `sys` | object | 采集端元数据：`sys.client.hostname/ip`（采集主机）、`sys.dir.path`（原始日志路径）、`sys.java` |
| `ulmp` | object | 日志框架元数据：`ulmp.inkey`（数据源标识，如 `sys_qax_01`）、`ulmp.logfmt`（格式码 `746`）、`ulmp.node_lv1/2/3`（节点层级/设备）、`ulmp.offset`、`ulmp.type`（如 `filebeat 7.6.1`） |
| `field_values` | object | **核心结构**，所有告警/事件字段均在此命名空间下，查询须加 `field_values.` 前缀 |

> 查询铁律：所有业务字段都在 `field_values.*` 下 → 查询必须写 `field_values.sip` 而非 `sip`；时间用顶层 `timestamp`；全文用 `message`。

## 3. field_values.* 全字段表（核心可查询字段）

**类型约定**：本索引 `field_values.*` 全部为 **keyword**（`dynamic:false`，仅索引已声明字段），查询一律用 `term` 精确匹配；其中 `access_time` / `first_access_time` 为日期格式字符串（时间范围请改用顶层 `timestamp`）；`sport/dport/hazard_level/repeat_count/update_time` 等数值在 ES 中以 keyword 存储，查询值仍按字符串（如 `"53"`、`"6"`）。

| ES 路径 | 类型 | 中文名 | 说明 / 示例 | 来源 |
|---------|------|--------|------------|------|
| `field_values._origin` | keyword(text) | 原始日志 | 协议级原始 JSON 字符串（含 `xff/uri/sip/dip/sport/dport/...`，详见第 4 节） | 实测 |
| `field_values.access_time` | keyword(date串) | 审计时间 | `2026-06-01T23:59:37.000+0800` | 实测 |
| `field_values.first_access_time` | keyword(date串) | 首次访问时间 | 同源首次出现时间 | 实测 |
| `field_values.update_time` | keyword(num串) | 更新时间 | Unix 秒，如 `1780329580` | 实测 |
| `field_values.alarm_id` | keyword | 告警 ID | `20260601_90d0b3011cab8e93cae6d0806a379954` | 实测 |
| `field_values.alarm_sample` | keyword | 告警样本标记 | `1` / `0` | 实测 |
| `field_values.alarm_source` | keyword | 告警来源 | `1` | 实测 |
| `field_values.alarm_sip` | keyword | 受害 IP | 被攻击方 IP（`dip` 的镜像） | help-docs |
| `field_values.sip` | keyword | 源 IP | 直连源 IP（经代理时通常为代理/CDN 出口，非真实攻击者） | help-docs |
| `field_values.dip` | keyword | 目的 IP | 受害/目标 IP | help-docs |
| `field_values.sport` | keyword | 源端口 | `38076` | 实测 |
| `field_values.dport` | keyword | 目的端口 | `8848`(Nacos) / `53`(DNS) / `3335`(MySQL) | 实测 |
| `field_values.src_mac` | keyword | 源 MAC | `14:84:77:ab:d2:01` | help-docs |
| `field_values.dst_mac` | keyword | 目的 MAC | `58:b3:8f:db:51:95` | help-docs |
| `field_values.vlan_id` | keyword | VLAN | `0x68` | help-docs |
| `field_values.sip_addr` | keyword | 源 IP 地址分类 | `局域网` / `中国--四川省--成都市(30.658529/104.075546)` | 实测 |
| `field_values.dip_addr` | keyword | 目的 IP 地址分类 | `局域网` / `中国--四川省--成都市(30.658529/104.075546)` | 实测 |
| `field_values.sip_group` | keyword | 源资产组 | `未分配资产组` / 空 | 实测 |
| `field_values.dip_group` | keyword | 目的资产组 | `未分配资产组` | 实测 |
| `field_values.asset_group` | keyword | 资产组 | `未分配资产组` | help-docs |
| `field_values.proto` | keyword | 协议 | `http` / `mysql` / `oracle` / `dns` / `redis` / `ftp` | help-docs |
| `field_values.is_web_attack` | keyword | WEB 攻击标记 | `1` / `0` | help-docs |
| `field_values.host` | keyword | 域名/主机 | `192.0.2.50:8848` 或域名（Web 类） | help-docs |
| `field_values.uri` | keyword | URI | 见 `_origin.uri`（部分场景上提） | help-docs |
| `field_values.rsp_status` | keyword | 响应状态码 | `200` / `404` / 空 | 实测 |
| `field_values.status_http` | keyword | HTTP 状态码 | help-docs 检索条件别名 | help-docs |
| `field_values.attack_type` | keyword | 攻击类型 | `暴力猜解` / `代码执行` / `非授权访问/权限绕过` / `信息泄露` / `文件上传` / `代理工具` | 实测 |
| `field_values.type` | keyword | 类型（可读标签） | 与 `attack_type` 同源人类可读值 | 实测 |
| `field_values.attack_sip` | keyword | 攻击 IP | 真实攻击 IP（XFF 场景为 `198.51.100.200`，与直连 `sip` `192.0.2.40` 不同） | 实测 |
| `field_values.attack_org` | keyword | 攻击组织 | 空 / APT 组织名 | 实测 |
| `field_values.attack_chain` | keyword | 攻击链编码 | `0x02020000` | 实测 |
| `field_values.super_attack_chain` | keyword | 上级攻击链 | `0x02000000` | 实测 |
| `field_values.super_type` | keyword | 上级类型 | `攻击利用` | 实测 |
| `field_values.type_chain` | keyword | 类型链 | `16040000` | 实测 |
| `field_values.att_ck` | keyword | ATT&CK 战术/技术 | `初始访问:TA0001\|利用面向公众的应用程序:T1190` | 实测 |
| `field_values.vuln_type` | keyword | 漏洞类型 | `Alibaba Nacos 未授权访问漏洞` / `MYSQL数据库账号暴力猜解` | 实测 |
| `field_values.ioc` | keyword | 威胁指标 IOC | `268570099-Alibaba Nacos 未授权访问漏洞` | help-docs |
| `field_values.host_state` | keyword | 攻击结果 | `企图` / `攻击成功` / `失陷` | help-docs |
| `field_values.hazard_rating` | keyword | 风险等级（标签） | `高危` / `中危` / `低危` / `危急` | 实测 |
| `field_values.hazard_level` | keyword | 威胁级别（数值） | `6`(高危)/`4`(中危)/`2`(低危) | help-docs |
| `field_values.confidence` | keyword | 可信度 | `高` / `中` / `低` | 实测 |
| `field_values.payload` | keyword | 载荷 | `null` / 实际载荷串 | 实测 |
| `field_values.rule_id` | keyword | 规则 ID | `0x10020df3` | help-docs |
| `field_values.rule_key` | keyword | 规则键 | `webids` | 实测 |
| `field_values.rule_desc` | keyword | 规则描述 | `网页漏洞利用` / `网络攻击` | 实测 |
| `field_values.rule_state` | keyword | 规则状态 | `green` | 实测 |
| `field_values.rule_labels` | keyword | 规则标签 | JSON 串，如 `{"0x110A02":{"parent_name":"资产识别","name":"UA指纹识别"}}` | 实测 |
| `field_values.serial_num` | keyword | 告警设备 | 设备序列号 `QnMLEHHVk` | help-docs |
| `field_values.branch_id` | keyword | 级联单位 | `QnMLEKhRV` | help-docs |
| `field_values.repeat_count` | keyword | 重复次数 | `1` | 实测 |
| `field_values.is_white` | keyword | 白名单标记 | `0` / `1` | help-docs |
| `field_values.is_delete` | keyword | 删除标记 | `0` | 实测 |
| `field_values.white_id` | keyword | 白名单 ID | `null`（字符串） | 实测 |
| `field_values.nid` | keyword | 网段/标识 | 空 | 实测 |
| `field_values.file_md5` | keyword | 文件 MD5 | WebShell/上传文件 MD5（空则无） | help-docs |
| `field_values.file_name` | keyword | 文件名 | `agent-tools-1.0.0-20260601.112731-10.jar`（上传文件名） | 实测 |
| `field_values.host_md5` | keyword | 主机 MD5 | 目标主机指纹 | 实测 |
| `field_values.sip_ioc_dip` | keyword | sip+ioc+dip 哈希 | 关联三元组哈希，用于去重/关联 | 实测 |
| `field_values.skyeye_id` | keyword | skyeye 标识 | 空 / 标识 | 实测 |
| `field_values.skyeye_index` | keyword | skyeye 索引 | 空 | 实测 |
| `field_values.skyeye_serial_num` | keyword | skyeye 设备序列 | `QnMLEHHVk` | 实测 |
| `field_values.skyeye_type` | keyword | skyeye 日志类型 | `webids-webattack_dolog` / `webids-ids_dolog` | 实测 |
| `field_values.x_forwarded_for` | keyword | **XFF 代理** | 真实客户端 IP 链，如 `198.51.100.200,198.51.100.200,198.51.100.201`；空串表示无代理 | 实测 |

> 其他设备类型字段（来自 help-docs 高级检索，本索引 `sys_qax_01` 流量传感器一般不含，列出供跨设备参考）：`asset_mark`/`marks`/`threat_type`/`user_label`/`focus_label`/`staff_name`/`status`（通用）；`alert_rule`/`attack_dimension`/`attack_stage`/`attck`（流量传感器）；`asset_ip`/`threat_name`（资产/威胁名）；`file_size`/`file_type`/`is_dynamic`（文件威胁鉴定器）；`mail_from`/`mail_to`/`sender_ip`/`subject`/`att_md5`/`att_name`（邮件）；`event_stage`（服务器安全）；`name_honeypot`（蜜罐）。

## 4. _origin 原始网络日志字段（message 内）

`field_values._origin` 是**单字段文本**，存协议级原始 JSON（一个字符串，不可按子字段单独 `term` 查询；如需检索其中的 `uri`/`xff` 等，用顶层 `message` 的 `match` 或在 `field_values` 上提的对应字段）。常见子键：

| _origin 子键 | 说明 |
|--------------|------|
| `xff` | X-Forwarded-For 原始值（与 `field_values.x_forwarded_for` 同源） |
| `uri` | 请求 URI（含参数，常含攻击载荷，如 `/nacos/v1/cs/configs?tenant=...&accessToken=`） |
| `sip` / `dip` / `sport` / `dport` | 五元组成员（与 field_values 镜像） |
| `write_date` | 原始写入 Unix 秒 |
| `rsp_status` | 响应状态码 |
| `detail_info` / `vuln_desc` / `vuln_harm` / `vuln_name` | 漏洞/攻击详细描述 |
| `solution` | 修复建议 |
| `rule_name` / `sig_id` / `appid` / `protocol_id` / `attack_method` | 规则名/签名 ID/应用 ID/协议 ID/攻击方法 |
| `hit_start` / `hit_end` / `hit_field` | 命中位置（请求体/响应体等） |
| `packet_size` | 包大小 |
| `cnnvd_id` / `public_date` / `affected_system` / `code_language` / `site_app` | 漏洞编号/公开日期/影响系统/代码语言/站点应用 |
| `req_body` / `rsp_body` | 请求/响应体（命中字段） |

> **完整按协议字段说明**见 `docs/dev/DEV-API-IDS-static-help-docs/static/help-docs/zh-cn_search_fields_README.html`，分节包括：TCP流量、Web访问日志、域名解析、文件传输、登录动作、LDAP行为、SSL加密协商、邮件行为、数据库行为、FTP控制通道、UDP流量、网络异常报文、telnet行为、网络阻断、MQ流量、Radius行为。

## 5. 查询规范

### 5.1 时间范围查询
```bash
# 单日查询（用顶层 timestamp，date 类型用 range）
timestamp >= 2026-06-01T00:00:00 && timestamp <= 2026-06-01T23:59:59
```

### 5.2 协议 / 状态过滤
```bash
# 数据库攻击
field_values.proto IN (mysql, oracle, redis, mongodb)
# Web 攻击
field_values.proto = http && field_values.is_web_attack = 1
# 攻击结果
field_values.host_state IN (攻击成功, 失陷)
# XFF 代理（非空）
exists field_values.x_forwarded_for && field_values.x_forwarded_for != ""
```

### 5.3 字段类型 → 查询动词（权威）

| 字段 | ES 类型 | 合法动词 | 非法 |
|------|--------|---------|------|
| `field_values.*`（sip/dip/attack_type/host_state/hazard_rating/sip_addr/x_forwarded_for 等） | keyword | `term` | `match` |
| `message` | text | `match` | `term` |
| `timestamp` | date | `range` | `match`/`term` |
| 未声明字段（`dynamic:false`） | — | — | 全部禁止 |

### 5.4 风险等级映射
| hazard_rating | hazard_level | 描述 |
|--------------|-------------|------|
| 危急 | 8(20260601 实测确认) | 需立即响应 |
| 高危 | 6 | 需立即响应 |
| 中危 | 4 | 需要关注 |
| 低危 | 2 | 常规处理 |

## 6. DSL 查询模板

### 6.1 弱口令攻击查询
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"field_values.attack_type": "暴力猜解"}},
        {"range": {"timestamp": {"gte": "2026-06-01T00:00:00", "lte": "2026-06-01T23:59:59"}}}
      ]
    }
  },
  "aggs": {
    "by_sip": {"terms": {"field": "field_values.sip"}},
    "by_target": {"terms": {"field": "field_values.dip"}}
  }
}
```

### 6.2 失陷主机查询
```json
{
  "query": {"terms": {"field_values.host_state": ["攻击成功", "失陷"]}},
  "sort": [{"timestamp": "desc"}],
  "size": 100
}
```

### 6.3 XFF 代理查询（非空 XFF 告警，溯源真实客户端 IP）
```json
{
  "index": "logfmt_746_20260601",
  "query_body": {
    "size": 1,
    "track_total_hits": true,
    "query": {
      "bool": {
        "must": [{"exists": {"field": "field_values.x_forwarded_for"}}],
        "must_not": [{"term": {"field_values.x_forwarded_for": ""}}]
      }
    },
    "aggs": {
      "by_xff": {"terms": {"field": "field_values.x_forwarded_for", "size": 25}},
      "by_sip": {"terms": {"field": "field_values.sip", "size": 25}},
      "by_attack_type": {"terms": {"field": "field_values.attack_type", "size": 25}},
      "by_host_state": {"terms": {"field": "field_values.host_state", "size": 10}},
      "by_target": {"terms": {"field": "field_values.dip", "size": 20}}
    }
  }
}
```
> 研判要点：`sip` 是直连源（常是内网代理/负载出口），**真实客户端 IP 在 `x_forwarded_for` 链最左端**；封禁/溯源应取 XFF 最左端 IP，避免误伤代理出口。示例：XFF 链 `198.51.100.200,198.51.100.200,198.51.100.201`，真实客户端最左端 `198.51.100.200`，直连 `sip` 为内网代理 `192.0.2.40`；另有内网 XFF 场景客户端 `192.0.2.41`、`192.0.2.42`。

## 7. MCP 查询限制

- ES 版本 7.16.3，**不支持 ESQL**（`_query` 端点，调用必 405）→ 禁用 `esql` 工具，仅用 `search`。
- `field_values.*` 为 keyword，**必须用 `term`** 精确匹配（值按字符串，如 dport `"53"`、hazard_level `"6"`）。
- `timestamp` 为 date，**必须用 `range`**。
- 索引 `dynamic:false`，**禁止查询未声明字段**（未索引、必空结果）。
- 需启用 `track_total_hits: true` 精确计数（默认上限 10,000）。
- MCP `search` 在 `size:0 + aggs` 时不返回 `hits.total`，故 MCP 路径用 `size:1` 取总数；`get_mappings` 当前对单索引可能返回解码错误，字段清单改由样本并集 + help-docs 获取。

## 8. 字段查询速记

| 场景 | 查询字段 | 值 |
|------|---------|-----|
| 外部攻击 | `field_values.sip_addr` | 非局域网（含地理串） |
| 内部攻击 | `field_values.sip_addr` | 局域网 |
| 横向移动 | `sip_addr = 局域网` AND `dip_addr = 局域网` | — |
| 失陷主机 | `host_state` IN [攻击成功, 失陷] | — |
| 弱口令 | `attack_type` = 暴力猜解 | — |
| 高危 IP | `hazard_rating` = 高危 | — |
| XFF 代理/真实客户端 | `x_forwarded_for` 非空 | `exists` + `must_not term ""` |
| Web 攻击 | `is_web_attack` = 1 | — |
| 按时间 | 顶层 `timestamp` | `range` |
| 全文/URI/载荷 | `message` | `match` |
