# XFF 代理攻击研判参考



> 本文件是 `judgment-xff/` 子技能的唯一事实来源（知识层）。覆盖：字段语义、致命 DSL 教训、CDN 中转跳判定、公网 IP 识别、XFF 伪造陷阱、完整工作流与规范查询体。

> 执行步骤见 `judgment-xff/SKILL.md`；脚本见 `scripts/judgment-xff/`。



---



## 1. 字段语义（logfmt_746_*）



| 字段路径 | 类型 | 说明 |

| --- | --- | --- |

| `field_values.x_forwarded_for` | keyword | XFF 代理链，逗号分隔，如 `206.189.202.53,47.105.158.255`；空字符串 `""` 表示无代理；`127.0.0.1` 等为伪造占位 |

| `field_values.sip` | keyword | 触发告警的**直连源 IP**（即最外层代理/客户端出口，非真实客户端） |

| `field_values.sip_addr` | keyword | 直连源 IP 地理；值为 `局域网` 表示内网源 |

| `field_values.dip` | keyword | 受害目标内网 IP |

| `field_values.host_state` | keyword | 攻击结果：`企图` / `攻击成功` / `失陷` / `失败` 等 |

| `field_values.attack_type` | keyword | 攻击类型（如 `webshell上传` / `SQL注入` / `代码执行`） |

| `field_values.hazard_rating` | keyword | 危害等级：`高危` / `中危` / `低危` / `危急` |

| `timestamp` | date | 事件时间（不带 `field_values.` 前缀，用 `range`） |



**核心判定**：真实外部客户端 = XFF 链**最左端（第一个）公网 IP**。`sip` 只是直连出口，经 CDN 时它永远是 CDN 边缘 IP，看不到真实源——这是 XFF 分析区别于普通外部攻击分析的根本点。



---



## 2. ⚠️ 致命 DSL 教训（必读，已踩坑）



**错误写法（触发 ES `400 Bad Request`）**：把 `must_not` 嵌进 `must` 数组。



```json

{ "query": { "bool": { "must": [

    { "exists": { "field": "field_values.x_forwarded_for" } },

    { "must_not": [ { "term": { "field_values.x_forwarded_for": "" } } ] }   // ❌ 错：must_not 不是合法 query 子句

] } } }

```



ES 的 `bool.must` 数组每个元素必须是合法 query 子句，`must_not` 不是查询类型 → 直接 `400`。



**正确写法（`must` 与 `must_not` 同级，参考 §6.3）**：



```json

{

  "query": {

    "bool": {

      "must": [

        { "exists": { "field": "field_values.x_forwarded_for" } }

      ],

      "must_not": [

        { "term": { "field_values.x_forwarded_for": "" } },

        { "term": { "field_values.sip_addr": "局域网" } }

      ]

    }

  }

}

```



- `must[exists]`：只取带 XFF 字段的文档（空字符串 `""` 也满足 exists，故用 must_not 排除）。

- `must_not[term ""]`：排除空 XFF（无代理的正常直连）。

- `must_not[term sip_addr=局域网]`：排除内网源（内部互打不算外部代理攻击）。

- 三条关系为「与」，即：有 XFF 且 非空 且 源非局域网。



> 此查询用脚本路径（`scripts/judgment-xff/query-xff.js` 经 `shared/es-query.js` 直连 ES）时 `size:0` + `track_total_hits:true` 即可拿到 `hits.total.value`；**不要**用 MCP 路径的 `size:1` 变通（宪法 VI：路径 A 纯脚本）。



---



## 3. CDN / 中转跳判定（不可封禁）



真实源永远取链**最左端公网 IP**；链中后续 IP 多为 CDN/反向代理中转，**封禁会误伤业务**。



| 网段（前缀） | 归属 | 处理 |

| --- | --- | --- |

| `175.12.90.` / `183.60.227.` / `47.105.` | 腾讯 CDN | 标注 `TencentCDN`，不封 |

| `172.64.` / `172.69.` / `162.158.` | Cloudflare | 标注 `Cloudflare`，不封 |



> 这是基于实测流量的启发式前缀，非穷举。新增 CDN 段时在此补充；脚本 `cdnTag()` 同步更新。



---



## 4. 公网 IP 识别（脚本 `isPublic`）



取「最左端公网 IP」时跳过以下（即不视为真实外部客户端）：



- `127.0.0.0/8` 回环（含 `127.0.0.1`）

- `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 私网

- `169.254.0.0/16` 链路本地

- `100.64.0.0/10` CGNAT（运营商级 NAT）

- `224.0.0.0/4` 多播、`240.0.0.0/4` 保留、`0.0.0.0/8`



一条链若**所有 token 都不是公网 IP**（如纯 `127.0.0.1` 或私网占位）→ 归入 `spoofed_or_internal_xff`（伪造/内网 XFF），不计入外部真实客户端排名。



---



## 5. XFF 伪造陷阱（研判必看）



XFF 是**客户端可控的请求头**，上游可任意注入。实战证据：



- 链 `127.0.0.1,185.177.72.12,175.12.90.54`：链首 `127.0.0.1` 是伪造占位，真实源是 `185.177.72.12`。解析时应**跳过 127/私网**，取首个公网 IP。

- 若前端 CDN 为**我方可信前置**且会重写/校验 XFF，则「最左端公网 IP = 真实源」成立。

- 若存在**不可信直连端**可伪造 XFF，则本口径可能被绕过——此时应回退到 `sip`（直连公网 IP）交叉验证，并优先处置「直连 + 高频」源。



**封禁落地要点**：经 CDN 进来的真实源，边界防火墙（L3/4）看到的是 CDN 边缘 IP，**只能在 WAF（L7，能读 XFF）上按「XFF 最左端公网 IP」规则拦截**，否则封禁不生效。直连真实源不受此限。



---



## 6. 「攻击成功/失陷」核验口径



告警里有 `webshell上传` / `代码执行` **不等于已失陷**。须看 `host_state`：



- 单链核验：`field_values.x_forwarded_for` 命中某链 AND `dip` = 目标主机 → 看该批 `host_state` 分布。

- 主机整体核验：`dip` = 目标主机 AND `host_state IN [攻击成功, 失陷]` 的全局计数。`total = 0` 即「无失陷迹象」（IDS/IPS 强信号，理论存在漏报可能）。

- 仅 `企图`/`失败` → 攻击被拦/未落地，主机按「已核实未失陷、维持监控」处理，**不得**排到取证最高位。



---



## 7. 完整工作流



```

Step 0  取报告时间（TZ=Asia/Shanghai）

Step 1  query-xff.js      → 外部 XFF 告警聚合 + 真实客户端排名 + 微步候选

Step 2  external.js --batch（复用 threat-intel）→ 微步恶意标签

Step 3  victim-hosts.js   → 各客户端命中的受害主机 + 攻击类型

Step 4  check-host-state.js（按需）→ 核验可疑主机是否失陷

Step 5  gen-md-report-xff.js → 合并 → 封禁建议 MD + JSON（含 judgment 块）

```


所有 ES 脚本以 `node` 直接运行（宪法 VI：路径 A 纯脚本）。



---



## 8. 规范查询体（脚本直连 ES 版）



**外部 XFF 聚合（query-xff.js 默认查询）**：



```json

{

  "size": 0,

  "track_total_hits": true,

  "query": {

    "bool": {

      "must": [ { "exists": { "field": "field_values.x_forwarded_for" } } ],

      "must_not": [

        { "term": { "field_values.x_forwarded_for": "" } },

        { "term": { "field_values.sip_addr": "局域网" } }

      ]

    }

  },

  "aggs": {

    "daily_trend": { "date_histogram": { "field": "timestamp", "calendar_interval": "day", "time_zone": "Asia/Shanghai" } },

    "by_xff": { "terms": { "field": "field_values.x_forwarded_for", "size": 1000 } },

    "by_attack_type": { "terms": { "field": "field_values.attack_type", "size": 30 } },

    "by_host_state": { "terms": { "field": "field_values.host_state", "size": 10 } },

    "by_target": { "terms": { "field": "field_values.dip", "size": 20 } },

    "by_sip": { "terms": { "field": "field_values.sip", "size": 50 } }

  }

}

```



**按客户端链过滤受害主机（victim-hosts.js 单客户端查询）**：用该客户端所有 XFF 链做 `terms` 过滤（ES 无「最左端公网 IP」存储字段，必须按链过滤再聚合 dip）。



```json

{

  "size": 0,

  "track_total_hits": true,

  "query": {

    "bool": {

      "must": [

        { "terms": { "field_values.x_forwarded_for": ["<chain1>", "<chain2>", "..."] } },

        { "exists": { "field": "field_values.x_forwarded_for" } }

      ],

      "must_not": [ { "term": { "field_values.sip_addr": "局域网" } } ]

    }

  },

  "aggs": {

    "by_victim": { "terms": { "field": "field_values.dip", "size": 50 },

      "aggs": {

        "attack_types": { "terms": { "field": "field_values.attack_type", "size": 10 } },

        "host_states": { "terms": { "field": "field_values.host_state", "size": 5 } }

      } }

  }

}

```



**主机失陷核验（check-host-state.js）**：



```json

{

  "size": 0,

  "track_total_hits": true,

  "query": {

    "bool": {

      "must": [

        { "term": { "field_values.dip": "<目标主机>" } },

        { "exists": { "field": "field_values.x_forwarded_for" } }

      ],

      "must_not": [ { "term": { "field_values.sip_addr": "局域网" } } ]

    }

  },

  "aggs": {

    "host_states": { "terms": { "field": "field_values.host_state", "size": 10 } },

    "by_client": { "terms": { "field": "field_values.sip", "size": 50 } }

  }

}

```



> 多日查询：索引名用逗号拼接 `logfmt_746_20260712,logfmt_746_20260713,...,logfmt_746_20260718`（ES 支持多索引同查），避免通配符跨月误匹配。



---



## 9. 产物命名约定



| 产物 | 路径 | 说明 |

| --- | --- | --- |

| XFF 聚合+客户端排名 | `output/judgment-xff-{start}-{end}.json` | Step 1 主产物 |

| 微步候选 | `output/judgment-xff-candidates-{start}-{end}.json` | `{ips:[...], candidates:[{ip,alerts}]}`，供 `external.js --batch` |

| 受害主机 | `output/judgment-xff-victimhosts-{start}-{end}.json` | Step 3 |

| 主机失陷核验 | `output/xff-host-state-{host}.json` | Step 4（按需） |

| 封禁建议 | `output/judgment-xff-ban-recommendation-{end}.md` / `.json` | Step 5 终产物 |

