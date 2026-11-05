##  安全运营告警分析研判 - 完成总结

### 执行流程

{step_status_table}

### 关键发现

- **告警总数**: {total_alerts} (全部) / {external_alerts} (外部攻击)
- **攻击成功/失陷**: {compromised_count}
- **Top攻击类型**: {top_attack_types}
- **攻击高峰**: {peak_hour}时 ({peak_count}次), 高危时段: {high_risk_hours}

### 重点输出文件

| 文件                                  | 说明                 |
| ------------------------------------- | -------------------- |
| `output/alert-report-{date}.md`     | Markdown格式分析报告 |
| `output/alert-report-{date}.html`   | HTML格式分析报告     |
| `output/ban-ip-table-{date}.md`     | IP封禁建议表         |
| `output/ban-domain-table-{date}.md` | Domain封禁建议表     |


---

※ Powered by SecOps Agent Skill ※
内容由 AI 生成，请核实关键细节
