#!/usr/bin/env bash
#
# wsl-node.sh — 在 WSL 内运行 Node 脚本的启动器
#   （供 Git Bash 与 PowerShell(pwsh) 调用；跨 shell 通用）
#
# 它要解决的真问题：
#   在 Git Bash(MSYS) 下直接写 `NODE=~/.nvm/.../node` 或 `NODE=$HOME/...` 时，
#   MSYS 的路径自动转换会把 ~ / $HOME 改写/吞成空，导致变量永远为空、node 调不起来。
#   把启动逻辑放进"文件"而非"命令行"，路径就不经过命令行解析，绕开这个坑。
#   顺带：WSL 自身没有 node on PATH，裸 `wsl bash -c 'node ...'` 必然 command not found——
#   与 shell 无关，node 必须靠本启动器（或显式全路径）带进去。
#
# ── 用法（Git Bash）──────────────────────────────────────────────
#   wsl bash <本文件绝对路径> <传给 node 的参数...>
#   示例：
#     wsl bash skills/secops-alert-analysis/scripts/wsl-node.sh --version
#     wsl bash skills/secops-alert-analysis/scripts/wsl-node.sh \
#         skills/secops-alert-analysis/scripts/workflow/selfcheck.js --date 20260718 --format json
#     wsl bash skills/secops-alert-analysis/scripts/wsl-node.sh -e "console.log(process.version)"
#
# ── 用法（PowerShell / pwsh）─────────────────────────────────────
#   pwsh 没有 MSYS，所以 `~`/`$HOME` 被吞的坑不存在；但有自己的引号陷阱：
#     1) 调启动器请用 WSL 原生路径形式 `/mnt/c/...`（不要写 `C:\...` 让 shell 去猜）：
#          wsl bash /mnt/c/Users/Leion/T/agent-secops/skills/secops-alert-analysis/scripts/wsl-node.sh --version
#     2) 若一定要 inline `wsl bash -c '...'`，务必用【单引号】包住 -c 的参数——
#        pwsh 单引号是字面量，`$HOME` 等会原样送达 WSL、由 bash 自己展开。
#     3) 切勿用【双引号】包 -c 的参数：pwsh 会先把里面的 $HOME/$NODE/$@ 当成
#        PowerShell 变量先展开掉（实测变成坏路径 C:UsersLeion），再传给 bash。
#     4) JS 代码里本身含单引号时，在 pwsh 单引号串内【双写转义】：''。
#     5) 无论哪种 shell，裸 `wsl bash -c 'node ...'` 都失败（WSL 无 node）——用本启动器。
#

set -euo pipefail

# ---- 1. 在 WSL 内部用 $HOME 定位 Linux node ----
NODE="$(ls -d "$HOME/.nvm/versions/node/"*/bin/node 2>/dev/null | head -1)"
if [ -z "$NODE" ] || [ ! -x "$NODE" ]; then
  echo "ERROR: Linux node 未找到于 $HOME/.nvm/versions/node/" >&2
  echo "       请确认 WSL 内 nvm 已安装 node。" >&2
  exit 1
fi

# ---- 2. 向上查找项目根（含 skills/secops-alert-analysis 的目录），并切到该目录 ----
#       node 脚本以项目根为基准使用相对路径（skills/.../extract.js、output/...），
#       故 CWD 必须是项目根。脚本自身位置可能变动，这里动态探测，避免硬编码路径。
find_project_root() {
  local dir
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  while [ "$dir" != "/" ]; do
    if [ -d "$dir/skills/secops-alert-analysis" ]; then
      echo "$dir"
      return 0
    fi
    dir="$(dirname "$dir")"
  done
  return 1
}
PROJECT_ROOT="$(find_project_root)"
if [ -z "$PROJECT_ROOT" ]; then
  echo "ERROR: 无法向上定位项目根（未找到含 skills/secops-alert-analysis 的目录）。" >&2
  exit 1
fi
cd "$PROJECT_ROOT"

# ---- 3. 透传所有参数给 node ----
exec "$NODE" "$@"
