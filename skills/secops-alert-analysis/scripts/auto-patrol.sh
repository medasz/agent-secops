#!/usr/bin/env bash
# auto-patrol.sh - 告警分析定时巡检启动脚本 (Linux / cron)
#
# 用法:
#   cron 定时调用，或手动执行:
#     bash skills/secops-alert-analysis/scripts/auto-patrol.sh
# 日志:
#   output/auto-patrol.log（相对仓库根；超过 PATROL_LOG_MAX_BYTES 自动轮转）
#
# 可覆盖的环境变量:
#   PATROL_MODEL         LLM 模型（默认 aiproxy/deepseek-v4-flash）
#   PATROL_LLM_ARGS      opencode run 附加参数（默认 --auto；无人值守必需）
#   PATROL_TIMEOUT       单次执行超时秒数（默认 600）
#   PATROL_PROMPT        传给 opencode 的提示词（默认经斜杠命令路由至本 skill）
#   PATROL_LOG_MAX_BYTES 日志轮转阈值（默认 10485760 = 10 MiB）
#   PATROL_LOG_KEEP      轮转归档保留份数（默认 5）
#   TZ                   时区（默认 Asia/Shanghai；cron 环境默认常为 UTC）
#
# 退出码: 0 成功 / 124 超时 / 127 运行环境不满足(opencode 缺失) / 130 手动中断 / 其它=opencode 退出码
#
# 部署与定时任务设置见: ops/secops-cron-deploy/README.md

set -euo pipefail

# 设置工作目录为仓库根目录（skill 约定：CWD 必须为项目根，脚本与 output 路径均相对它解析）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

# ===== 运行环境归一化（cron 适配）=====
# cron 的 PATH 极简（通常 /usr/bin:/bin），nvm / 用户级安装的 node 与 opencode 不在其中。
# 故在 opencode 解析失败时补齐常见安装位置，避免整次执行以 127 静默失败。
# TZ 同理：cron 不继承登录 shell 的时区，默认 UTC 会使 "今日" 与报告日期错位。
export TZ="${TZ:-Asia/Shanghai}"
if ! command -v opencode >/dev/null 2>&1; then
    for _dir in "$HOME/.nvm/versions/node"/*/bin "$HOME/.local/bin" /usr/local/bin; do
        if [ -x "$_dir/opencode" ]; then
            PATH="$_dir:$PATH"
            break
        fi
    done
    export PATH
    unset _dir
fi

# ===== 参数（均可用环境变量覆盖，保持脚本与调度解耦）=====
PATROL_TIMEOUT="${PATROL_TIMEOUT:-600}"
PATROL_MODEL="${PATROL_MODEL:-aiproxy/deepseek-v4-flash}"
PATROL_LLM_ARGS="${PATROL_LLM_ARGS:---auto}"
PATROL_PROMPT="${PATROL_PROMPT:-/secops-alert-analysis 分析今日告警}"
PATROL_LOG_MAX_BYTES="${PATROL_LOG_MAX_BYTES:-10485760}"
PATROL_LOG_KEEP="${PATROL_LOG_KEEP:-5}"
PATROL_DATE="$(date '+%Y%m%d')"

LOG_DIR="output"
LOG_FILE="$LOG_DIR/auto-patrol.log"

# 确保日志目录存在
mkdir -p "$LOG_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

# ===== 前置检查：opencode 必须可用。缺则立即失败并记明原因，不得静默跳过 =====
if ! command -v opencode >/dev/null 2>&1; then
    log "FAILED 运行环境不满足: opencode 不在 PATH (PATH=$PATH)"
    exit 127
fi

# ===== 日志轮转：超阈值归档，仅保留最近 PATROL_LOG_KEEP 份 =====
if [ -f "$LOG_FILE" ]; then
    LOG_SIZE="$(wc -c < "$LOG_FILE" | tr -d ' ')"
    if [ "$LOG_SIZE" -ge "$PATROL_LOG_MAX_BYTES" ]; then
        mv "$LOG_FILE" "$LOG_FILE.$(date '+%Y%m%d%H%M%S')"
        { ls -1t "$LOG_FILE".* 2>/dev/null || true; } \
            | tail -n +"$((PATROL_LOG_KEEP + 1))" \
            | while read -r _archive; do rm -f "$_archive"; done
    fi
fi

# ===== 锁文件防止并发执行（cron 与手动执行、或上一次未跑完时重入）=====
LOCK_FILE="$LOG_DIR/auto-patrol.lock"
if [ -f "$LOCK_FILE" ]; then
    LOCK_PID=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [ -n "$LOCK_PID" ] && kill -0 "$LOCK_PID" 2>/dev/null; then
        log "SKIP 已有实例运行 (PID: $LOCK_PID)"
        exit 0
    fi
    # 清理过期锁文件
    rm -f "$LOCK_FILE"
fi
echo $$ > "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT

# 记录开始
TS_START=$(date '+%Y-%m-%d %H:%M:%S')
log "START 模型=$PATROL_MODEL 超时=${PATROL_TIMEOUT}s 工作目录=$REPO_ROOT"

# opencode（agent CLI）会自行捕获 SIGINT/SIGTERM：前台运行时 Ctrl+C 被 opencode 吞掉、无法中断。
# 故用 set -m 把 opencode 放进独立进程组后台运行，Ctrl+C 时以 SIGKILL 强杀整组（不可被 trap），使手动中断可靠生效；
# timeout 另加 --kill-after=30：先发 SIGTERM，若 opencode 仍存活再升格 SIGKILL，确保超时上限对 traps 信号的 opencode 也生效。
# 注：切勿用「setsid -f ... &」——setsid -f 父进程会瞬间 _exit(0)，导致 $! 拿到秒退的父 PID、wait 立即返回，
#     脚本"秒退"而 opencode 在后台游离（曾踩此坑）。set -m 下「cmd &」的后台任务自带独立进程组，$! 即该组 PGID，wait 真等、kill -PGID 只杀子组。
# --auto：无人值守必需——交互式 ask 权限（doom_loop / external_directory）在无 TTY 时会挂到超时。
set -m
INTERRUPTED=0
SPID=""
EXIT_CODE=0
cleanup_int() {
    INTERRUPTED=1
    if [ -n "$SPID" ]; then kill -KILL -"$SPID" 2>/dev/null || true; fi
}
# shellcheck disable=SC2086  # PATROL_LLM_ARGS 需按空格拆分为多个参数
timeout --kill-after=30 "$PATROL_TIMEOUT" \
    opencode run $PATROL_LLM_ARGS -m "$PATROL_MODEL" "$PATROL_PROMPT" >> "$LOG_FILE" 2>&1 &
SPID=$!
trap 'cleanup_int' INT TERM
wait "$SPID" || EXIT_CODE=$?
trap - INT TERM
set +m
if [ "$INTERRUPTED" -eq 1 ]; then
    TS_END=$(date '+%Y-%m-%d %H:%M:%S')
    log "INTERRUPTED 用户中断 (Ctrl+C)"
    exit 130
fi

# 记录结果（成功时一并记录产出报告路径，便于 FR-004 的可核验性）
TS_END=$(date '+%Y-%m-%d %H:%M:%S')
if [ "$EXIT_CODE" -eq 0 ]; then
    REPORT_MD="$LOG_DIR/alert-report-$PATROL_DATE.md"
    REPORT_HTML="$LOG_DIR/alert-report-$PATROL_DATE.html"
    if [ -f "$REPORT_MD" ]; then
        log "OK 退出码: 0 报告: $REPORT_MD $REPORT_HTML"
    else
        log "OK 退出码: 0 警告: 未发现当日报告 $REPORT_MD"
    fi
elif [ "$EXIT_CODE" -eq 124 ] || [ "$EXIT_CODE" -eq 137 ]; then
    log "TIMEOUT 超过 ${PATROL_TIMEOUT}s 未完成分析，已终止"
else
    log "FAILED 退出码: $EXIT_CODE"
fi

exit "$EXIT_CODE"
