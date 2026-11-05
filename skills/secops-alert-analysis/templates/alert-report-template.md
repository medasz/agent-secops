# 安全运营研判告警分析报告{{title_window}}

**报告生成时间**：{{report_time}}
**研判时间范围**：{{start_time}} 至 {{end_time}}
**研判人员**：{{analyst}}

---

## 1. 报告概述

| 指标                   | 数值                      |
| ---------------------- | ------------------------- |
| 告警总数               | {{total_alerts}}          |
| 外部攻击告警数         | {{external_alerts}}       |
| 内部攻击告警数         | {{internal_alerts}}       |
| 攻击成功/失陷IP数      | {{compromised_alerts}}    |
| 涉及外部IP数           | {{unique_external_ips}}   |
| 涉及内部主机数         | {{unique_internal_hosts}} |
| 精确总数（含分桶余数） | {{exact_total}}           |
| ES计数查询总数         | {{count_query_total}}     |

---

## 2. 外部攻击研判

### 2.1 IP封禁建议（建议立即封禁）

{{ban_ip_table}}

---

### 2.2 Domain封禁建议（建议立即封禁）

{{ban_domain_table}}

---

### 2.3 IP威胁情报

{{threat_intel_table}}

---

### 2.4 外部攻击趋势-按类型分布

{{external_section}}

---

### 2.5 外部攻击趋势-按时间分布

{{external_time_section}}

---

## 3. 攻击成功/失陷IP研判

> 以下IDC主机/办公终端已被攻击成功或确认失陷（按 `alarm_sip` 受害 IP 聚合），建议立即进行应急响应

{{compromised_section}}

---

## 4. 内部攻击研判

> 以下数据统计源IP为局域网的内部攻击，横向移动为源和目的都是内网的子集

### 4.1 内部攻击统计

{{internal_4_1}}

### 4.2 内部攻击趋势-按类型分布

{{internal_4_2}}

### 4.3 横向移动源IP Top10

{{internal_4_3}}

### 4.4 横向移动目标IP Top10

{{internal_4_4}}

### 4.5 横向移动攻击趋势-按时间分布

{{internal_4_5}}

---

## 5. 专项研判

### 5.1 XFF 代理攻击

{{xff_metrics}}

#### XFF-外部真实客户端IP

> 供研判人员溯源外部真实客户端IP：每行一个攻击 IP，受害 IP 以逗号分隔。

{{xff_real_client_investigate_table}}

#### XFF-受害IP

> 供资产责任人排查受害IP：每行一个受害 IP，外部真实客户端 IP 以逗号分隔。

{{xff_victim_investigate_table}}

#### XFF-IP封禁建议表

> 供处置人员封禁外部真实客户端IP。

{{xff_ban_ip_table}}

#### XFF-IP威胁情报

> 查询外部真实客户端IP威胁情报。

{{xff_threat_intel_table}}

### 5.2 弱口令,暴力猜解,非授权访问/权限绕过攻击

{{special_5_2}}

### 5.3 远控木马/C2 外联攻击

{{special_5_3}}

### 5.4 挖矿/勒索攻击

{{special_5_4}}

---

## 6. 详细数据附录

### 6.1 IP过滤结果

- 本次检出外部攻击IP：{{detected_external_ips}}
- {{filter_summary}}

### 6.2 外部攻击IP完整列表

{{external_full_ip_section}}

---

## 7. 安全建议

1. **跟踪处置**：对「封禁建议」 IP/域名 执行封禁或隔离。
2. **溯源排查**：对「攻击成功/失陷」 IP 进行溯源取证；重点排查内网横向移动与失陷的IDC主机/办公终端。
3. **规则优化**：根据攻击类型分布动向及时动态调整防守动作、调整IDS检测监控研判规则。
4. **应急联动**：持续监控、积极研判、跟踪处置，继续坚持`监控-研判-处置`联动机制。

---

**报告结束**

---

※ Powered by SecOps Agent Skill ※
内容由 AI 生成，请核实关键细节
