# XFF 代理攻击研判报告

> 外部源口径：`x_forwarded_for` 非空 且 `sip_addr != 局域网`；真实客户端 = XFF 链**最左端公网 IP**
> 报告时间：{{report_time}} ｜ 分析区间：{{date_range}}

## 概览

{{xff_metrics}}

## XFF-IP封禁建议表

> 供处置人员封禁攻击 IP：每行一个攻击 IP，受害 IP 以逗号分隔。

{{xff_ban_ip_table}}

## XFF-受害IP排查表

> 供资产责任人排查受害IP：每行一个受害 IP，外部真实客户端 IP 以逗号分隔。

{{xff_victim_investigate_table}}

## XFF-IP威胁情报

> 查询外部真实客户端IP威胁情报。

{{xff_threat_intel_table}}

## 研判与处置说明

{{enforcement_note}}

> 研判依据：XFF 为客户端可控请求头，存在伪造可能。本表假设前端 CDN 为我方可信前置；
> 若存在不可信直连端可伪造 XFF，应回退到 `sip`（直连公网 IP）交叉验证后再处置。
> 「攻击成功/失陷」以 `field_values.host_state` 为准；告警类型（如 webshell）仅代表攻击企图，不等于已失陷。

**报告结束**

---

※ Powered by SecOps Agent Skill ※
内容由 AI 生成，请核实关键细节
