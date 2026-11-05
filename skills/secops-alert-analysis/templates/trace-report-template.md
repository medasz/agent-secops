# IP溯源分析报告

**报告生成时间**：{{report_time}}
**目标IP**：{{target_ip}}
**IP类型判定**：{{ip_role}}（攻击源/受害目标/横向跳板）
**分析时间范围**：{{start_time}} 至 {{end_time}}

---

## 1. IP概览

| 属性       | 值               |
| ---------- | ---------------- |
| IP地址     | {{target_ip}}    |
| 地理区域   | {{geo_location}} |
| 运营商     | {{isp}}          |
| IP类型     | {{ip_type}}      |
| 威胁判定   | {{threat_type}}  |
| 置信度     | {{confidence}}   |
| 首次出现   | {{first_seen}}   |
| 最近活动   | {{last_seen}}    |
| 关联告警数 | {{alert_count}}  |

---

## 2. 日志时间线

> 最近24小时该IP关联的所有告警，按时间倒序排列

| 时间     | 方向          | 对端IP      | 对端地区        | 攻击类型        | 攻击结果   | 危害等级  |
| -------- | ------------- | ----------- | --------------- | --------------- | ---------- | --------- |
| {{time}} | {{direction}} | {{peer_ip}} | {{peer_region}} | {{attack_type}} | {{result}} | {{level}} |

**统计**：共 {{total_count}} 条告警，攻击成功 {{success_count}} 次

---

## 3. 深度分析

### 3.1 如果是外部攻击源

**被攻击目标列表**：

| 目标IP        | 地区       | 攻击次数  | 主要攻击类型    | 成功率           |
| ------------- | ---------- | --------- | --------------- | ---------------- |
| {{target_ip}} | {{region}} | {{count}} | {{attack_type}} | {{success_rate}} |

**攻击类型分布**：

| 攻击类型        | 次数      | 占比           |
| --------------- | --------- | -------------- |
| {{attack_type}} | {{count}} | {{percentage}} |

**威胁情报补充**（来自微步 ThreatBook）：

- 威胁类型：{{threat_type}}
- 历史攻击记录：{{vt_history}}
- 相关样本：{{related_malware}}

### 3.2 如果是内部受害IP

**攻击来源列表**：

| 攻击源IP   | 地区       | 攻击次数  | 主要攻击类型    | 成功率           |
| ---------- | ---------- | --------- | --------------- | ---------------- |
| {{src_ip}} | {{region}} | {{count}} | {{attack_type}} | {{success_rate}} |

**失陷评估**：

- 攻击成功次数：{{compromised_count}}
- 可能被控服务：{{exposed_services}}
- 建议操作：{{recommended_action}}

### 3.3 如果是横向跳板嫌疑

**横向渗透指标**：

- 作为源IP发起内网攻击次数：{{lateral_count}}
- 攻击目标均为内网IP：{{all_internal}}
- 同攻击链关联的其他内网IP：{{related_internal_ips}}

**分析结论**：
{{lateral_analysis}}

---

## 4. 关联分析

### 4.1 同网段关联IP

{{same_subnet_ips}}

### 4.2 相似攻击手法关联

{{similar_tactic_ips}}

---

## 5. 封禁/处置建议

| 建议类型        | 具体操作          | 优先级       |
| --------------- | ----------------- | ------------ |
| {{action_type}} | {{action_detail}} | {{priority}} |

---

## 6. 详细数据附录

### ES查询语句

> 完整 DSL 见 `references/dsl-examples.md`（溯源查询章节）。查询动词必须用 `term`（keyword字段），见附录E 第8条。

```json
// 攻击源查询（外部IP）
{"query": {"bool": {"must": [{"term": {"field_values.sip": "{{target_ip}}"}}], "must_not": [{"term": {"field_values.sip_addr": "局域网"}}]}}, "sort": [{"timestamp": {"order": "desc"}}]}

// 受害目标查询（内部IP）
{"query": {"bool": {"must": [{"term": {"field_values.dip": "{{target_ip)"}}]}}, "sort": [{"timestamp": {"order": "desc"}}]}

// 横向移动查询（内部IP作为源）
{"query": {"bool": {"must": [{"term": {"field_values.sip": "{{target_ip}}"}}, {"term": {"field_values.dip_addr": "局域网"}}]}}, "sort": [{"timestamp": {"order": "desc"}}]}
```

### 原始日志

{{raw_logs}}

---

※ Powered by SecOps Agent Skill ※
内容由 AI 生成，请核实关键细节
