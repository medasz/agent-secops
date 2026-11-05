# MCP查询DSL参考

> 本文件从 SKILL.md 附录A外迁，为所有 ES DSL 查询的唯一事实来源。

## 扩展聚合查询（Step 1）

> **一次查询获取全部数据**：合并原聚合查询 + 详情查询，MCP 2→1，ES direct 2→0。`compromised_hosts` 使用 `filter` agg 在查询上下文内筛选攻击成功/失陷文档；`dns_domains` 使用 `global` agg 脱离查询上下文，覆盖全量 DNS 流量。
>
> 此为**外部查询**（`must_not sip_addr = "局域网"`），内部查询见下方「内部攻击聚合查询」章节。

> **MCP 路径 `size:1` 说明**：MCP `elasticsearch-sse_search` 在 `size:0 + aggs` 时不返回 `hits.total`，需用 `size:1` 获取 `hits.total.value`（外部攻击总数）。脚本路径（直连 ES）保持 `size:0 + track_total_hits:true`，`hits.total.value` 原生可用。两条路径不可在同一次运行中混用（宪法 VI）。详见 SKILL.md 附录F 第5条。

> **边界差异脚注（须在报告中展示）**: `date_histogram` 桶求和与 `terms` 聚合总和可能与 `hits.total.value`（count 查询权威总数）存在边界差异，原因包括：某些文档缺少 `timestamp` 字段或未设置 `hazard_rating` 而不参与对应聚合、时区边界归桶偏差等。**报告中任何分布/总计类数字仅供趋势展示，权威总数以 count 查询（`hits.total.value`）为准。**

```json
{
  "index": "logfmt_746_{date}",
  "query_body": {
    "size": 1,
    "track_total_hits": true,
    "query": {
      "bool": {
        "must_not": [
          {"term": {"field_values.sip_addr": "局域网"}}
        ]
      }
    },
    "aggs": {
      "attack_ips": {
        "terms": {"field": "field_values.sip", "size": 50},
        "aggs": {
          "max_timestamp": {"max": {"field": "timestamp"}},
          "geo_locations": {"terms": {"field": "field_values.sip_addr", "size": 1}},
          "ip_attack_types": {"terms": {"field": "field_values.attack_type", "size": 10}}
        }
      },
      "attack_types": {"terms": {"field": "field_values.attack_type", "size": 30}},
      "hazard_ratings": {"terms": {"field": "field_values.hazard_rating", "size": 10}},
      "top_targets": {"terms": {"field": "field_values.dip", "size": 20}},
      "unique_external_ips": {"cardinality": {"field": "field_values.sip"}},
      "hourly_distribution": {
        "date_histogram": {
          "field": "timestamp",
          "calendar_interval": "hour",
          "min_doc_count": 0,
          "time_zone": "Asia/Shanghai"
        }
      },
      "compromised_hosts": {
        "filter": {
          "bool": {
            "should": [
              {"term": {"field_values.host_state": "攻击成功"}},
              {"term": {"field_values.host_state": "失陷"}}
            ]
          }
        },
        "aggs": {
          "by_victim": {
            "terms": {"field": "field_values.alarm_sip", "size": 100},
            "aggs": {
              "victim_attack_types": {"terms": {"field": "field_values.attack_type", "size": 10}},
              "victim_states": {"terms": {"field": "field_values.host_state", "size": 5}},
              "victim_proto": {"terms": {"field": "field_values.proto", "size": 5}},
              "victim_ioc": {"terms": {"field": "field_values.ioc", "size": 5}},
              "victim_sip_addrs": {"terms": {"field": "field_values.sip_addr", "size": 10}},
              "first_seen": {"min": {"field": "timestamp"}},
              "last_seen": {"max": {"field": "timestamp"}}
            }
          }
        }
      },
      "dns_domains": {
        "global": {},
        "aggs": {
          "dns_traffic": {
            "filter": {
              "bool": {
                "must": [
                  {"term": {"field_values.proto": "dns"}},
                  {"term": {"field_values.dport": "53"}}
                ]
              }
            },
            "aggs": {
              "by_ioc": {
                "terms": {"field": "field_values.ioc", "size": 50},
                "aggs": {
                  "domain_max_timestamp": {"max": {"field": "timestamp"}},
                  "domain_attack_types": {"terms": {"field": "field_values.attack_type", "size": 10}}
                }
              }
            }
          }
        }
      }
    }
  }
}
```

> **聚合结构说明**：
>
> - `attack_ips` 子聚合 `max_timestamp`/`geo_locations`/`ip_attack_types` 供 parse-mcp.js 填充 ban-ip-table.js 所需字段（`max_timestamp`/`sip_addr`/`attack_types`）
> - `compromised_hosts` 的 `filter` agg 在查询上下文（外部攻击）内筛选，`by_victim` 按**受害 IP（`field_values.alarm_sip`）**分桶（失陷主机=被攻击方；改自原 `dip`，避免把仅作为外联目的地的 DNS/网关误列为失陷主机）。子聚合 `victim_proto`/`victim_ioc` 供 `parse-mcp.js` 做「按协议特征研判」：`协议=DNS 且命中 ipInfra → 判 DNS 转发设备误标剔除`，其余保留并附 `风险描述`(复用 attack-type-mapping)+`研判意见`。
> - `dns_domains` 的 `global` agg 脱离查询上下文，覆盖全量文档（含内网），再用 `filter` 缩窄至 DNS 流量（`proto=dns` + `dport=53`）

## 文本/时间范围查询（message / timestamp 例外字段）

> `message`（text）与 `timestamp`（date）不在 `field_values.` 命名空间，**不带前缀**；分别用 `match` 与 `range`（见 SKILL.md 附录F 第8条对照表）。

**按告警内容模糊检索（message，text → match）**:

```json
{
  "index": "logfmt_746_{date}",
  "query_body": {
    "track_total_hits": true,
    "query": {
      "match": {"message": "告警"}
    }
  }
}
```

**按当日时间范围收窄（timestamp，date → range）**:

```json
{
  "index": "logfmt_746_{date}",
  "query_body": {
    "track_total_hits": true,
    "query": {
      "range": {"timestamp": {"gte": "{date}T00:00:00+08:00", "lte": "{date}T23:59:59+08:00"}}
    }
  }
}
```

## 溯源查询（外部攻击源IP）

```json
{
  "index": "logfmt_746_{date}",
  "query_body": {
    "size": 100,
    "track_total_hits": true,
    "query": {
      "bool": {
        "must": [
          {"term": {"field_values.sip": "目标IP"}}
        ],
        "must_not": [
          {"term": {"field_values.sip_addr": "局域网"}}
        ]
      }
    },
    "sort": [{"timestamp": {"order": "desc"}}]
  }
}
```

## 溯源查询（内部IP受害）

```json
{
  "index": "logfmt_746_{date}",
  "query_body": {
    "size": 100,
    "track_total_hits": true,
    "query": {
      "bool": {
        "must": [
          {"term": {"field_values.dip": "目标IP"}}
        ]
      }
    },
    "sort": [{"timestamp": {"order": "desc"}}]
  }
}
```

## 内部攻击聚合查询（Step 1）

> **内部查询**: 过滤 `sip_addr = "局域网"`，获取内部攻击数据。`lateral_movement` 子聚合在内部查询上下文内再 `filter` `dip_addr = "局域网"`，得到横向移动子集（源和目的都是内网）。

> **与外部查询对称**: 外部查询使用 `must_not`（排除局域网），内部查询使用 `must`（仅局域网）。两条查询的 `aggs` 结构基本相同，但内部查询额外包含 `lateral_movement` 和 `host_states` 聚合，不包含 `unique_external_ips` 和 `dns_domains`。

```json
{
  "index": "logfmt_746_{date}",
  "query_body": {
    "size": 1,
    "track_total_hits": true,
    "query": {
      "bool": {
        "must": [
          {"term": {"field_values.sip_addr": "局域网"}}
        ]
      }
    },
    "aggs": {
      "attack_ips": {
        "terms": {"field": "field_values.sip", "size": 50},
        "aggs": {
          "max_timestamp": {"max": {"field": "timestamp"}},
          "ip_attack_types": {"terms": {"field": "field_values.attack_type", "size": 10}}
        }
      },
      "attack_types": {"terms": {"field": "field_values.attack_type", "size": 30}},
      "hazard_ratings": {"terms": {"field": "field_values.hazard_rating", "size": 10}},
      "host_states": {"terms": {"field": "field_values.host_state", "size": 10}},
      "top_targets": {"terms": {"field": "field_values.dip", "size": 20}},
      "hourly_distribution": {
        "date_histogram": {
          "field": "timestamp",
          "calendar_interval": "hour",
          "min_doc_count": 0,
          "time_zone": "Asia/Shanghai"
        }
      },
      "lateral_movement": {
        "filter": {"term": {"field_values.dip_addr": "局域网"}},
        "aggs": {
          "lateral_sources": {
            "terms": {"field": "field_values.sip", "size": 20},
            "aggs": {
              "max_timestamp": {"max": {"field": "timestamp"}},
              "source_attack_types": {"terms": {"field": "field_values.attack_type", "size": 10}}
            }
          },
          "lateral_targets": {
            "terms": {"field": "field_values.dip", "size": 20},
            "aggs": {
              "max_timestamp": {"max": {"field": "timestamp"}},
              "target_attack_types": {"terms": {"field": "field_values.attack_type", "size": 10}}
            }
          },
          "lateral_hourly": {
            "date_histogram": {
              "field": "timestamp",
              "calendar_interval": "hour",
              "min_doc_count": 0,
              "time_zone": "Asia/Shanghai"
            }
          },
          "lateral_host_states": {
            "terms": {"field": "field_values.host_state", "size": 10}
          },
          "lateral_pairs": {
            "terms": {"field": "field_values.sip", "size": 20},
            "aggs": {
              "target_ips": {
                "terms": {"field": "field_values.dip", "size": 20},
                "aggs": {
                  "pair_attack_types": {"terms": {"field": "field_values.attack_type", "size": 10}},
                  "pair_max_timestamp": {"max": {"field": "timestamp"}}
                }
              }
            }
          }
        }
      },
      "compromised_hosts": {
        "filter": {
          "bool": {
            "should": [
              {"term": {"field_values.host_state": "攻击成功"}},
              {"term": {"field_values.host_state": "失陷"}}
            ]
          }
        },
        "aggs": {
          "by_victim": {
            "terms": {"field": "field_values.alarm_sip", "size": 100},
            "aggs": {
              "victim_attack_types": {"terms": {"field": "field_values.attack_type", "size": 10}},
              "victim_states": {"terms": {"field": "field_values.host_state", "size": 5}},
              "victim_proto": {"terms": {"field": "field_values.proto", "size": 5}},
              "victim_ioc": {"terms": {"field": "field_values.ioc", "size": 5}},
              "victim_sip_addrs": {"terms": {"field": "field_values.sip_addr", "size": 10}},
              "first_seen": {"min": {"field": "timestamp"}},
              "last_seen": {"max": {"field": "timestamp"}}
            }
          }
        }
      }
    }
  }
}
```

> **聚合结构说明**：
>
> - `lateral_movement` 的 `filter` agg 在内部查询上下文内再筛选 `dip_addr = "局域网"`，得到横向移动子集
> - `lateral_pairs` 嵌套 `terms` 聚合（sip → dip），用于生成源→目的 IP 对
> - `host_states` 在顶层聚合，统计内部攻击的攻击结果分布
> - `compromised_hosts` 与外部查询结构相同（按 `alarm_sip` 受害 IP 分桶，含 `victim_proto`/`victim_ioc` 子聚合供按协议特征研判），但在内部查询上下文内
> - 不包含 `dns_domains`（内部攻击不涉及 DNS 域名封禁）和 `unique_external_ips`（内部查询无此概念）
