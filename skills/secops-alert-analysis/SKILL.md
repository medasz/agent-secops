---
name: secops-alert-analysis
description: |
  安全运营研判告警分析skill——当用户提到安全运营智能研判助手、告警分析、溯源分析、入侵检测告警、安全事件分析、攻击IP分析、威胁IP封禁建议、失陷主机分析、ESG日志分析、IP溯源、横向渗透检测、内网横移、查一下这个IP、查询IP、攻击路径时，必须使用此skill。
  特别适用于：安全分析师研判SOC告警、应急响应人员排查攻击源、安全团队生成威胁分析报告、单个IP的威胁溯源。

output:
  files:
    - pattern: "output/alert-report-{date}.md"
      description: "MD报告（Markdown格式，路径A 产出）"
      template: "templates/alert-report-template.md"
    - pattern: "output/alert-report-{date}.html"
      description: "HTML报告（深色模式+打印友好，路径A 产出）"
      template: "templates/alert-report-template-v1.html"
  terminal:
    summary: true
    template: "templates/terminal-summary-template.md"
    max_lines: 50

triggers:
  - "安全运营研判告警分析"
  - "入侵检测告警"
  - "安全事件分析"
  - "攻击IP分析"
  - "威胁IP封禁"
  - "ESG日志"
  - "告警日志"
  - "失陷主机"
  - "外部攻击"
  - "告警报告"
  - "IP溯源"
  - "溯源"
  - "查一下这个IP"
  - "查询IP"
  - "攻击路径"
  - "横向渗透"
  - "内网横移"
  - "XFF"
  - "X-Forwarded-For"
  - "代理攻击"
  - "代理链"
  - "代理IP"
---

# 安全运营研判告警分析 Skill（Router）

本 skill 为**路由薄壳**：负责意图识别，并按意图将工作流委派给对应子目录的 `SKILL.md` 执行。

- 路径A（告警研判分析）= `judgment/SKILL.md`，**纯脚本、零 MCP**。
- 路径A-IDS（IDS 导出 Excel 快速研判）= `ids-fastReport/SKILL.md`，**纯脚本 + LLM 研判、零 ES/零 MCP**（离线）。
- 路径A-XFF（XFF 代理攻击研判）= `judgment-xff/SKILL.md`。
- 路径B（深度溯源分析）= `trace/SKILL.md`，**保留 MCP 优先**，原样保留。

共享库（脚本 / 参考 / 模板）位于主目录 `scripts/`、`references/`、`templates/`，由各子目录经项目根相对路径调用。

---

## 路由规则

> **唯一入口**：本 router 持有全部 `triggers`，子目录 `judgment/`、`judgment-*/`、`ids-fastReport/`、`trace/` **不设 triggers**，仅由本 router 经 Read 工具显式加载。

**判定逻辑（按优先级从上到下，先命中先加载）**：

- 用户提供了 **IDS/流量传感器导出的告警 Excel（`*.xlsx`，含「受害IP/攻击IP/威胁名称/攻击结果」列）**，或意图含 `IDS导出` / `告警列表导出` / `Excel研判` / `快速研判` / `流量传感器导出` / `.xlsx告警` → 加载 **路径A-IDS（IDS 导出 Excel 快速研判）**：
  `ids-fastReport/SKILL.md`
- 用户意图含以下任一关键词 → 加载 **路径B（深度溯源分析）**：
  `溯源` / `查这个IP` / `查询IP` / `攻击路径` / `深度溯源`
- 用户意图含以下任一关键词 → 加载 **路径A-XFF（XFF 代理攻击研判）**：
  `XFF` / `X-Forwarded-For` / `代理攻击` / `代理链` / `代理IP`
- 其余（以下任一或泛化的告警研判意图）→ 加载 **路径A（告警研判分析）**：
  `告警分析` / `封禁建议` / `失陷主机` / `横向渗透` / `内网横移` / `ESG日志` / `入侵检测告警` / `安全事件分析` / `攻击IP分析` / `威胁IP封禁`

**执行指令（务必遵守）**：

1. 先按上方判定逻辑确定路径（IDS / A / A-XFF / B）。
2. **识别意图后，用 `Read` 工具读取对应子目录的 `SKILL.md` 内容并据此执行**：
   - 路径A-IDS → `skills/secops-alert-analysis/ids-fastReport/SKILL.md`
   - 路径A → `skills/secops-alert-analysis/judgment/SKILL.md`
   - 路径A-XFF → `skills/secops-alert-analysis/judgment-xff/SKILL.md`
   - 路径B → `skills/secops-alert-analysis/trace/SKILL.md`
3. **切勿在 router 内联工作流**：本文件不含任何分析步骤、MCP 调用、fallback 全局块或附录；所有执行细节与知识附录均定义在对应子目录 `SKILL.md` 内。
4. 调用命令时 **CWD 必须为项目根目录**（即 `agent-secops/`），命令 `scripts/...` 相对项目根的 `skills/secops-alert-analysis/` 前缀，输出 `output/...` 相对 CWD（宪法 VII）。

---

## 定时巡检（cron / 任务计划程序）

无人值守巡检由启动脚本承担，完整部署步骤见 **`ops/secops-cron-deploy/README.md`**：

- Linux：`skills/secops-alert-analysis/scripts/auto-patrol.sh`，cron 单行注册；脚本自带 TZ/PATH 归一化、互斥锁与日志轮转，无需在 crontab 里声明环境变量。
- Windows：不维护原生 wrapper（`.bat` 已于 2026-09-14 删除），由任务计划程序调用 `wsl.exe` 执行同一 `auto-patrol.sh`，见指南「附录 B」。
- 日志 `output/auto-patrol.log`；一键体检 `bash ops/secops-cron-deploy/install-cron.sh check`。

---

## 执行环境 / WSL 启动器

所有脚本的运行环境统一遵循「依赖探测 + 分级降级」原则执行。**只有依赖 ES 的脚本才做 ES 可达性（A1）两级探测**；零 ES 路径（如 `ids-fastReport`）不依赖 ES，**直接跳过 A1 探测**，不受 ES 不可达阻断。

```text
依赖矩阵（判断是否需要探测）：
  依赖 ES 的路径（judgment / judgment-xff / trace 中直连 ES 的环节）→ 做 A1 两级探测
  零 ES 的路径（ids-fastReport：仅解析 xlsx + 微步公网查询）    → 跳过 A1，仅做 C3 公网可达性判断
  微步威胁情报（任何路径的 threat-intel 环节）                  → 做 C3 公网可达性判断
```

【C3 · 微步/公网可达性判定（零 ES 路径与所有威胁情报环节必看）】
微步 API Key 绑定固定出口 IP（见 `.env` 的 `THREATBOOK_BOUND_IP`），必须经内网主机反向代理（`ENABLE_PROXY=true`，`PROXY_HOST/PORT`）以固定 IP 出网访问公网。

- 当前 shell 经 proxy 能取回真实数据（如 `node external.js --ip 8.8.8.8` 返回 `is_malicious`/`geo` 等实数据）→ **C3 = PASS，直接在当前 shell 用 `node` 继续**，无需 WSL。
- 当前 shell 连不上 proxy（DNS/连接失败）→ 再探测 WSL：`wsl bash skills/secops-alert-analysis/scripts/wsl-node.sh ...`；WSL 可达则后续加启动器前缀，两级都不可达才降级跳过微步（记录 `[FALLBACK] threatbook → unavailable`）。
- **区分「瞬时超时」与「网络不可达」**：单次 `NETWORK_TIMEOUT`（尤其域名接口 `/domain/report`）≠ 不可达，按各子技能约定**重试一次**；仍超时才降级。已能证明 C3=PASS（如 IP 批量查询成功）时，**不得**因单个域名超时而误判整体降级。

【A1 · ES 可达性两级探测（仅依赖 ES 的路径执行）】
0) 自检必须在【当前 shell】先跑一次（绝不经启动器！）：
     node skills/secops-alert-analysis/scripts/workflow/selfcheck.js --date YYYYMMDD

1) 当前 shell 自检 A1 PF-ES-TCP = PASS
     → 当前 shell 直连 ES 可达，**直接用 `node` 运行所有脚本，不调用启动器**。

2) 当前 shell 自检 A1 = FAIL（当前 shell 够不到 ES）
     → 再在 WSL 内跑一次自检（仅看 A1），探测 WSL 是否可达：
         wsl bash skills/secops-alert-analysis/scripts/wsl-node.sh \
             skills/secops-alert-analysis/scripts/workflow/selfcheck.js --date YYYYMMDD
     - WSL 自检 A1 = PASS
         → **使用 WSL node：后续每个脚本调用前加启动器前缀**
             wsl bash skills/secops-alert-analysis/scripts/wsl-node.sh <脚本> <参数...>
     - WSL 自检 A1 = FAIL（当前 shell 与 WSL 都够不到 ES，含 `wsl` 不可用 / 启动器报错）
         → **仅依赖 ES 的路径阻断流程**，提示检查 ES 服务 / VPN / 网络；零 ES 路径不受影响，可继续。

【wsl-node 启动器的实际触发条件】
- wsl-node 只在两种情况下启用：① 当前 shell 是 **Git Bash(MSYS)**（`~`/`$HOME` 会被路径转换吞空，`node` 起不来）；② 当前 shell（含 pwsh）连不上目标服务，但 **WSL shell 可达**。
- **PowerShell(pwsh)/当前 shell 下 `node` 直接可跑**（无 MSYS 路径坑），且当前 shell 经 proxy 可达公网时，**一律直接用 `node`**，不调用启动器。
- 不是每种执行都走 wsl-node：仅在上述 ①② 条件满足时启用，未触发探测子路径即不启用。

【为何需要】Git Bash(MSYS) 下 `~`/`$HOME` 会被路径转换吞空导致 node 起不来；WSL 自身无 node on PATH。把启动逻辑放进文件绕开此坑。

【子技能约定】各子目录 `SKILL.md` 与脚本头部**不再内嵌 WSL 调用细节**；脚本以 `node` 直接可跑为准（通用性），是否经启动器、两级探测逻辑统一见本专节。注：当前场景（pwsh + proxy 可达）零 ES 路径直接 `node` 运行即可，无需 wsl-node。

---

*本 skill 遵循：Router（元信息 + 路由判定） → 子目录 SKILL.md（执行手册 + 知识附录）*
