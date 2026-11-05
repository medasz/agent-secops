# secops-alert-analysis · Linux cron 定时巡检部署

前置：opencode CLI 已装好可用。

## 1. 前置检查

```bash
opencode --version                              # opencode 可用
node --version                                  # ≥ 22.5，skill 脚本依赖
unzip -v >/dev/null && command -v crontab       # 解压工具与 cron
nc -z <ES_HOST> 9200 && nc -z <PROXY_HOST> 443  # ES、微步出网
opencode debug config && opencode models | grep -F aiproxy/deepseek-v4-flash
```

## 2. 部署

### 2.1 投放工件到部署根

安装脚本和简版包放同一个目录，不建子目录。全程普通用户执行，不需要 sudo。

```bash
# 目标机，一次性（已有可跳过；部署根在用户目录下，天然可写）
mkdir -p ~/agent-secops
cd ~/agent-secops                            # 后面所有命令都在这里执行

# 本机（在仓库根）：两个工件一起送过去（简版包，别用 -full.zip）
scp ops/secops-cron-deploy/install-cron.sh releases/secops-alert-analysis-<版本>.zip <user>@<host>:agent-secops/
```

下面所有 `install-cron.sh` 命令都在部署根执行，所以只写脚本名。脚本本身与当前目录无关，选包、建软链、写 crontab 全按 `SECOPS_ROOT` 和自身位置来，换个目录跑结果一样，只是 shell 得先找得到这个文件。

别用 sudo 跑脚本。`sudo` 下 `HOME=/root`，crontab、skill 软链、`.env` 会全挂到 root 名下，以普通用户跑的巡检就找不到它们，事后用普通用户 `uninstall` 也摘不掉那条 crontab。

### 2.2 部署发布包

```bash
bash install-cron.sh deploy
```

脚本按 部署根、部署根/releases、`<install-cron.sh 所在仓库>/releases`、当前目录 的顺序找包，取版本号最大的 `secops-alert-analysis-<X.Y.Z>.zip`。`-full.zip` 和 `release-maker` 生成的 `.bak-<时间戳>.zip` 不会命中。

拿到包后先查包内必需件（`SKILL.md`、`scripts/.env`、`scripts/auto-patrol.sh`、`references/ipWhite.md`），再解密解压到 staging，然后整树替换（旧树留成 `.bak-<ts>`）、把 `.env` 设成 600、给入口脚本设执行位、写 `.deployed-release`（版本、sha256、时间）。缺件或中途失败都会自动回滚。

需要指定时：

```bash
bash install-cron.sh deploy --zip /path/xxx.zip             # 指定包
SECOPS_ZIP_DIR=/data/releases bash install-cron.sh deploy    # 指定选件目录
SECOPS_ZIP_PASSWORD=xxxx bash install-cron.sh deploy         # 包密码，默认与 release-maker.sh 一致
```

### 2.3 opencode provider 与 skill 可见性

```bash
chmod 600 ~/.config/opencode/opencode.json      # provider/MCP 配置，含 API Key
opencode models | grep -F aiproxy
mkdir -p ~/.agents/skills
ln -sfn ~/agent-secops/skills/secops-alert-analysis ~/.agents/skills/secops-alert-analysis
opencode debug skill | grep secops-alert-analysis
```

上面这些都用 cron 所属用户的 home。

### 2.4 安装（软链 + crontab）

```bash
bash install-cron.sh check                # 只读体检
bash install-cron.sh install --dry-run    # 演练，只打印动作
bash install-cron.sh install              # 正式安装，幂等
```

`install` 做这几件事：版本一致就跳过部署，把 `.env` 设成 600，建 skill 软链，校验入口脚本（随包已就位，缺了就拒绝写 crontab），写 crontab，最后自己跑一遍体检。

只想做其中一段：

```bash
bash install-cron.sh deploy                # 只部署，不动 crontab
bash install-cron.sh install --no-deploy   # 只做软链和 crontab，不动部署树
bash install-cron.sh uninstall             # 只摘掉 crontab 条目
```

以上命令都在部署根执行，换到别的目录跑结果一样。

常用变量：`SECOPS_ROOT`（默认 `$HOME/agent-secops`）、`CRON_SCHEDULE`（默认 `0 9 * * *`，每天 09:00）、`SECOPS_ZIP_DIR`。

### 2.5 凭据与发帖开关

```bash
chmod 600 ~/agent-secops/skills/secops-alert-analysis/scripts/.env
grep -E '^ENABLE_POST' ~/agent-secops/skills/secops-alert-analysis/scripts/.env
```

`.env` 跟着包走，`deploy` 已经把它设成 600。包里默认 `ENABLE_POST=true`，也就是每次执行都会向门户发帖。只想出报告不发帖，改成 `false` 即可，`install` 只提示不改。

## 3. 验证

### 3.1 手动跑一次（首次部署必做）

```bash
time bash ~/agent-secops/skills/secops-alert-analysis/scripts/auto-patrol.sh; echo "exit=$?"
tail -n 20 ~/agent-secops/output/auto-patrol.log
```

启动脚本会自己切到部署根，所以在哪个目录执行都一样。

退出码应该是 0，日志里有 `OK 退出码: 0 报告: output/alert-report-<日期>.md`。

### 3.2 最小 cron 环境复验

cron 不继承登录环境，所以要用最小环境再跑一次。不然就是「手动能跑、定时必挂」：

```bash
env -i HOME="$HOME" PATH=/usr/bin:/bin bash \
  ~/agent-secops/skills/secops-alert-analysis/scripts/auto-patrol.sh; echo "exit=$?"
```

退出码 `127` 说明 opencode 不在 PATH 里。在 crontab 条目前置 `PATH=`，或者把 opencode 软链到 `/usr/local/bin`。

### 3.3 等一个周期确认自动触发

```bash
tail -n 5 ~/agent-secops/output/auto-patrol.log   # 应该多出 START/OK
bash install-cron.sh check
```

## 4. 部署收尾

只摘定时任务，部署文件与软链保留：

```bash
bash install-cron.sh uninstall
```

整套回收，连部署根一起清掉：

```bash
bash install-cron.sh uninstall-all --dry-run   # 先看计划，不动手
bash install-cron.sh uninstall-all --yes       # 真删
```

这条会删除 `~/agent-secops` 整棵，包括投放进去的包和这个脚本本身，所以不带 `--yes` 只打印计划并退出 1。skill 软链只删指向本部署根的那种，指向开发仓的软链、以及被换成实体目录的位置都跳过并 WARN。

回滚到上一版：

```bash
mv ~/agent-secops/skills/secops-alert-analysis.bak-<ts> ~/agent-secops/skills/secops-alert-analysis
```
