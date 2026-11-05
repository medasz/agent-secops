# How-To

> 忽略A1 PF-ES-TCP FAIL（阻断项），所有脚本在WSL中执行，node调用统一经 scripts/wsl-node.sh。
>> 用 nvm 的 Linux node 二进制在 WSL 内运行js脚本（在 WSL 网络上栈运行，连通 VPN 可达内网 ES）。

## 告警分析
/secops-alert-analysis  分析今日告警
/secops-alert-analysis  分析告警，20260601
/secops-alert-analysis  分析告警，20260601 9:00-21:00
/secops-alert-analysis  分析告警，20260602-21:00--20260603-9:00

## 深度溯源
/secops-alert-analysis  溯源IP 5.5.5.5，最近7天
/secops-alert-analysis  使用 MCP ES 检索IP 5.5.5.5 最近7天访问记录，并按访问次数排序
/secops-alert-analysis  使用 MCP ES 查询XFF代理/真实客户端IP
/secops-alert-analysis  使用 MCP ES 查询XFF代理/真实客户端IP，限外部攻击


## 追问
对高危 IP 跑一遍微步威胁情报，确认恶意标签后生成「外部客户端 × 恶意标签 × 受害主机」的封禁建议表

