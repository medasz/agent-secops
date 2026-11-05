# secops-alert-analysis

SOC 告警研判 agent skill。输入 Elasticsearch 里 `logfmt_746_*` 索引的入侵检测告警，输出外部攻击源统计、失陷主机、横向渗透、封禁清单与研判报告。

按数据来源分四条路径，公网情报与内网资产分开处理：

| 路径 | 目录 | 数据来源 |
|---|---|---|
| A 告警研判 | `skills/secops-alert-analysis/judgment/` | 纯脚本查 ES |
| A-IDS 离线研判 | `skills/secops-alert-analysis/ids-fastReport/` | IDS 导出 Excel，无 ES 无 MCP |
| A-XFF 代理链研判 | `skills/secops-alert-analysis/judgment-xff/` | 经 X-Forwarded-For 还原真实源地址 |
| B 深度溯源 | `skills/secops-alert-analysis/trace/` | 脚本 + MCP 工具 |

`SKILL.md` 是路由层，持有全部触发词，按意图加载对应子目录的 `SKILL.md`。

## 关键机制

**白名单**（`references/ipWhite.md`）：判定源地址是否为外部。整段私网默认在册，命中的不算外部威胁。

**基础设施清单**（`references/ipInfra.md`）：判 `attack_sip` 是否自家转发设备。DNS 协议告警且源地址命中清单，剔除转发设备、底层数据保留；非 DNS 协议不盲目剔除，保留并附风险描述与研判意见。

两个文件都是示例内容，按自己的网段替换。**不要拿 `ipWhite.md` 充当 `ipInfra.md`**：白名单含整段私网，直接当基础设施清单用会把真实失陷的内网主机一并剔掉。

## 环境

要求 Node 22.5 以上，ES 7.16.3（ESQL 需要 8.11 以上，本 skill 走 `_search` 聚合，不用 `_query`）。

仓库自带 `skills/secops-alert-analysis/scripts/.env`，内容为示例值，改成自己的即可。`ES_HOST`、`ES_USERNAME`、`ES_PASSWORD` 必填；门户回写与威胁情报默认关闭，需要时置对应 `ENABLE_*` 为 `true` 并补凭据。系统环境变量优先于 `.env`。

## 用法

```bash
# 某一自然日的封禁 IP 表
node skills/secops-alert-analysis/scripts/reporting/ban-ip-table.js \
  --date 20260624 --format markdown -o output/ban-20260624.md

# 指定客户端 IP 的受害主机
node skills/secops-alert-analysis/scripts/judgment-xff/victim-hosts.js \
  --ips 192.0.2.31,192.0.2.32 --start-date 20260624 --end-date 20260624
```

各脚本 `--help` 有完整参数，多数支持 `--input` 消费上一步的 JSON 输出。文件默认写 `output/`。

## 测试

```bash
npm test
```

fixture 里是脱敏后的 ES 响应样本，不连真实环境。`env-credentials`、`env-feature-switch`、`local-selfcheck` 三组用例检查 `.env` 是否齐全、开关是否生效、本机是否就绪，只在配好环境时全绿。

## 许可

MIT，见 `LICENSE`。
