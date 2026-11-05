# secops-alert-analysis · LibreChat 部署技能运维指南

> 适用：LibreChat 代码沙箱（code_interpreter 容器）中的各项安全运营研判技能。
> 本文档 + 一键脚本，把「部署/更新/回滚/体检」都固化成命令，日常维护只跑脚本即可。

## 1. 架构速览

```
本地开发机 Windows                                  serv 服务器
─────────────────────────────           ──────────────────────────────
C:\Users\Leion\T\agent-secops\           /root/LibreChat/
  skills\secops-alert-analysis\   --scp-->  secops-skill-local.tar.gz  (临时包)
  ops\secops-skill-deploy\                         skill\secops-alert-analysis\   ← 技能源(部署目标)
    deploy-to-librechat.sh  (唯一入口)                  │  ro 挂载
                      │  heredoc ─┐          ┌──────────▼──────────┐
    status.sh (体检)  │           └─────────▶│  LibreChat-CodeInterpreter │
    README.md                                  │  /app/skills/secops-alert-analysis   (ro 代码)
                                               │  /app/skills/secops-alert-analysis/output  (rw 输出)
                                               └─────────────────────┘
                                               hosted 输出: code-interpreter-outputs\secops-alert-analysis\
```

关键路径：

| 角色 | 宿主 serv 路径 | 沙箱容器内路径 | 权限 |
|------|---------------|---------------|------|
| 技能源 | `/root/LibreChat/skill/secops-alert-analysis/` | `/app/skills/secops-alert-analysis/` | ro（只读） |
| 输出目录 | `/root/LibreChat/code-interpreter-outputs/secops-alert-analysis/` | `/app/skills/secops-alert-analysis/output/` | rw（可写） |
| 备份 | `/root/LibreChat/backups/skills/` | — | — |
| 部署+体检入口 | **仅本地** `ops\secops-skill-deploy\{deploy-to-librechat.sh,status.sh}` | — | — |

**为什么这么设计**：
- 技能代码只读挂载（ro），防止沙箱内误改，安全。
- 输出目录单独可写挂载（rw），技能产出的 `alert-report-*.md/.html` 落盘到宿主机可见路径。
- output 子挂载必须在技能源里**预存在 `output/` 挂载点目录**，否则 ro 父挂载无法在运行时创建子挂载点（Docker 限制）。

---

## 2. 脚本清单

| 脚本 | 位置 | 作用 |
|------|------|------|
| `deploy-to-librechat.sh` | **本地** `ops\secops-skill-deploy\` | **唯一部署入口**：打包→上传→heredoc 远端部署+验证（幂等），支持 rollback |
| `status.sh` | **仅本地** `ops\secops-skill-deploy\` | 健康体检：容器、挂载、关键文件、output 可写 |

---

## 3. 首次部署

前提：serv 已配 ssh 免密（别名 `serv`），技能源码在本机。

```bash
# 在本地 git-bash 里执行一条命令即可
bash ./deploy-to-librechat.sh
```

脚本会自动完成：
1. 备份当前技能（若无则跳过）
2. 同步文件到 `/root/LibreChat/skill/secops-alert-analysis/`（rsync --delete，干净覆盖）
3. 确保输出源目录属主 1000:1000
4. 校验 docker-compose.override.yml 含两条挂载（缺失自动补齐）
5. 重建 CI 容器并等待 healthy
6. 逐项验证（挂载、文件、子技能、output 可写）

---

## 4. 日常更新技能

改了本地 `skills\secops-alert-analysis\` 里的脚本/SKILL.md 后：

```bash
bash ./deploy-to-librechat.sh
```

同样一条命令。脚本会自动备份旧版、覆盖新版、重建容器、验证。**旧的会被自动备份**到 `~/backups/skills/`（保留最近 10 份）。

---

## 5. 备份

回滚的前提是有备份。备份分**自动**与**手动**两层，日常基本靠自动即可。

### 5.1 自动备份（每次部署/回滚前触发）

`deploy-to-librechat.sh` 在**任何部署/回滚开始之前**，都会先把线上当前的技能目录打成 tar 包，存入
`/root/LibreChat/backups/skills/`，然后才覆盖新版本。这样"每次部署前的线上快照"天然成为下次回滚的源。

```bash
# 脚本 heredoc 段第 1 步的核心逻辑
STAMP="$(date +%Y%m%d-%H%M%S)"
tar czf "$BACKUP_DIR/${SKILL_NAME}-${STAMP}.tar.gz" -C "$LH/skill" "$SKILL_NAME"
# 只保留最近 10 份，更旧的自动清理
ls -1t "$BACKUP_DIR"/*.tar.gz | tail -n +11 | xargs -r rm -f
```

- 备份名形如 `secops-alert-analysis-20260818-183251.tar.gz`（含时间戳，可精确回滚到某个版本）。
- **保留 10 份滚动覆盖**，无需手动清理。

### 5.2 手动备份（兜底，可选）

| 方式 | 命令/做法 | 适用 |
|------|-----------|------|
| 留快照 | 跑一次部署脚本即可留档 | 想给当前线上状态留一份 |
| 黄金基线 | `tar czf /tmp/baseline-$(date +%Y%m%d).tar.gz -C skills secops-alert-analysis && scp /tmp/baseline-*.tar.gz serv:/root/LibreChat/backups/skills/` | 发布正式版时 |
| **git 基线（推荐）** | 本地 git 管理技能源，每次改动有历史，随时 `git checkout` 还原再部署 | 长期最可靠、可追溯每次改动 |

> 建议：**日常改动靠脚本自动备份（10 份滚动）**；**重要里程碑/正式发布前，把本地技能源提交一次 git** 作为长期基线。两层互补，回滚万无一失。

---

## 6. 回滚

若新版本有问题，从 serv 备份包一键回滚：

```bash
# 先看有哪些备份
ssh serv "ls -1t /root/LibreChat/backups/skills/"

# 从指定备份包回滚
bash ./deploy-to-librechat.sh serv rollback /root/LibreChat/backups/skills/secops-alert-analysis-<时间戳>.tar.gz
```

> 注意：备份包内也含 `output/` 目录条目，脚本会自动剔除由宿主机输出来接管，不影响。

---

## 7. 健康体检

```bash
bash ./status.sh
```

看输出是否全 `✓`：容器 healthy、技能挂载 ro、output 挂载 rw、关键文件在、output 可写、宿主机输出目录有产物。

---

## 8. 输出产物在哪

技能运行后生成的报告（`alert-report-<date>.md/.html`）会写到：
```
/root/LibreChat/code-interpreter-outputs/secops-alert-analysis/
```
宿主可直接读取，也可再挂到 1Panel/nginx 静态站点对外展示（可选扩展）。

---

## 9. 排障速查

| 现象 | 原因 | 处理 |
|------|------|------|
| 沙箱里技能目录是空的 / 脚本找不到 | 同步权限/嵌套出问题 | 重跑 `deploy-to-librechat.sh`（rsync --delete 会清干净） |
| output 不可写 (Permission denied) | 输出源属主不是 1000 | `chown -R 1000:1000 /root/LibreChat/code-interpreter-outputs/secops-alert-analysis` 后重跑 |
| 报错 Docker 无法创建 output 挂载点 | 技能源里没有预建 `output/` 目录 | 脚本已自动 `mkdir -p`，重跑即可 |
| 页面/模型说「技能只读、无法删」 | 这是 deployment skill，非页面用户技能 | 不用在页面删；改本机源→跑脚本即可更新 |
| CI 容器不重建 | 挂载没变化 | 脚本用 `--force-recreate`，必重建 |
| LibreChat 主程序没展示该技能 | 主容器需挂载 `./skill:/app/skill` | 检查 docker-compose.override.yml 的 api.volumes（一般已有） |

---

## 10. 重要提醒

- **.env 含密钥**（ES 连接、威胁情报 token 等）：随技能源一起部署进沙箱，务必不要提交到公开 git。
- 技能源以 `C:\Users\Leion\T\agent-secops\skills\secops-alert-analysis\` 为**事实源**，serv 只是部署副本。
- 不要通过 LibreChat **页面手动上传**这套技能（inline）——那只会传 SKILL.md 说明，不传脚本，跑不通。要用页面形式请走 deployment skill（本方案）。
- 修改 `docker-compose.override.yml` 前先备份；脚本会在 serv 上自动备份当前 override。

---

## 11. 快速参考命令

```bash
# 一键部署/更新（本地）
bash ./deploy-to-librechat.sh

# 健康体检
bash ./status.sh

# 回滚（从 serv 备份包恢复）
bash ./deploy-to-librechat.sh serv rollback /root/LibreChat/backups/skills/secops-alert-analysis-<备份>.tar.gz
```
