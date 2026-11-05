#!/usr/bin/env bash
# install-cron.sh - secops-alert-analysis 定时巡检：部署 / 安装 / 卸载 / 体检（幂等）
#
# 部署模型：仅消费「简版包」（secops-alert-analysis-<版本>.zip，非 -full.zip），与安装脚本同放部署根。
#   选件 → 校验包内必需件 → 解密解压到 $SECOPS_ROOT/skills/ → 替换旧树（旧树留 .bak 备份）
#   → chmod 600 .env → 记录部署来源（zip 名 / 版本 / sha256）
#
# 包内必需件含 scripts/auto-patrol.sh（cron 定时入口）：简版包白名单保留该脚本，
#   故解压后即随包就位，install 一次即可完成部署 + 软链 + crontab，无手工前置件。
#
# 用法:
#   bash install-cron.sh check                 # 只读体检（不修改任何东西）
#   bash install-cron.sh deploy --dry-run      # 演练：只打印将执行的动作
#   bash install-cron.sh deploy                # 仅部署（选件→解压→校验），不动 crontab
#   bash install-cron.sh install               # 部署 + 软链 + 写 crontab
#   bash install-cron.sh uninstall             # 仅移除 crontab 条目（保留文件与软链）
#   bash install-cron.sh uninstall-all         # 全量回收：crontab + 软链 + 部署根（需 --yes）
#
# 选项:
#   --zip <路径>     指定简版 zip（等价 SECOPS_ZIP；默认自动选最新）
#   --zip-dir <目录> 选件目录（等价 SECOPS_ZIP_DIR）
#   --no-deploy      install 时跳过部署，仅写 crontab
#   --dry-run        只打印，不落盘
#   --yes, -y        确认执行破坏性动作（uninstall-all 必需）
#
# 环境变量（均有默认值，按需覆盖）:
#   SECOPS_ROOT          部署根目录                默认 $HOME/agent-secops（用户可写，全程不需要 sudo）
#   SECOPS_ZIP           简版 zip 路径             默认自动搜集
#   SECOPS_ZIP_DIR       选件目录                  默认 部署根、部署根/releases、仓库 releases、当前目录
#   SECOPS_ZIP_PASSWORD  包密码                    默认 152251（与 release-maker.sh 一致）
#   CRON_SCHEDULE        cron 时间表达式           默认 "0 9 * * *"（每天 09:00）
#   CRON_LOG             cron 层输出目标           默认 /dev/null（脚本自身已写 output/auto-patrol.log）
#   SKILL_LINK_DIR       用户级 skill 链接目录      默认 $HOME/.agents/skills
#
# 设计口径：调度与执行解耦——crontab 只留一行（含标记注释，便于幂等增删），
# 时区 / PATH / 模型 / 超时 / 日志轮转全部收进 auto-patrol.sh 的默认值。
set -euo pipefail

SECOPS_ROOT="${SECOPS_ROOT:-$HOME/agent-secops}"
CRON_SCHEDULE="${CRON_SCHEDULE:-0 9 * * *}"
CRON_LOG="${CRON_LOG:-/dev/null}"
SKILL_LINK_DIR="${SKILL_LINK_DIR:-$HOME/.agents/skills}"
SECOPS_ZIP_PASSWORD="${SECOPS_ZIP_PASSWORD:-152251}"
SECOPS_ZIP="${SECOPS_ZIP:-}"
SECOPS_ZIP_DIR="${SECOPS_ZIP_DIR:-}"

SKILL_NAME="secops-alert-analysis"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SKILL_SRC="$SECOPS_ROOT/skills/$SKILL_NAME"
SKILL_LINK="$SKILL_LINK_DIR/$SKILL_NAME"
SCRIPTS_DIR="$SKILL_SRC/scripts"
PATROL_SH="$SCRIPTS_DIR/auto-patrol.sh"
ENV_FILE="$SCRIPTS_DIR/.env"
OUTPUT_DIR="$SECOPS_ROOT/output"
RELEASE_RECORD="$SECOPS_ROOT/.deployed-release"
MARK="secops-auto-patrol"
CRON_LINE="$CRON_SCHEDULE $PATROL_SH >$CRON_LOG 2>&1 # $MARK"

# 包内必需件（相对包根，包根为 $SKILL_NAME/）
REQUIRED_MEMBERS=("SKILL.md" "scripts/.env" "scripts/auto-patrol.sh" "references/ipWhite.md")

# 输出助手（须先于参数解析定义：解析分支会用到 say）
FAIL=0
say()  { printf '%s\n' "$*"; }
ok()   { printf '  [OK]   %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; FAIL=1; }
run()  { if [ "$DRY_RUN" = "1" ]; then printf '  [DRY]  %s\n' "$*"; else eval "$*"; fi; }

ACTION="check"
DRY_RUN=0
NO_DEPLOY=0
CONFIRM=0

usage() {
    # 打印文件头注释里的用法块（第 4 行起，到 set -euo 之前），注释增删后不用改行号
    awk 'NR>=4 && /^set -euo pipefail/ {exit} NR>=4 {sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        check|deploy|install|uninstall|uninstall-all) ACTION="$1" ;;
        --dry-run)   DRY_RUN=1 ;;
        --no-deploy) NO_DEPLOY=1 ;;
        --yes|-y)    CONFIRM=1 ;;
        --zip)       shift; SECOPS_ZIP="${1:-}"; [ -n "$SECOPS_ZIP" ] || { say "错误: --zip 需要一个路径"; exit 2; } ;;
        --zip=*)     SECOPS_ZIP="${1#--zip=}" ;;
        --zip-dir)   shift; SECOPS_ZIP_DIR="${1:-}"; [ -n "$SECOPS_ZIP_DIR" ] || { say "错误: --zip-dir 需要一个目录"; exit 2; } ;;
        --zip-dir=*) SECOPS_ZIP_DIR="${1#--zip-dir=}" ;;
        -h|--help)   usage; exit 0 ;;
        *)           say "未知参数: $1"; say "用法: $0 [check|deploy|install|uninstall|uninstall-all] [--zip <路径>] [--zip-dir <目录>] [--no-deploy] [--dry-run] [--yes]"; exit 2 ;;
    esac
    shift
done

# ---------- 选件：定位最新简版包 ----------
# 匹配严格的三段版本号文件名，天然排除 -full.zip 与 release-maker 产生的 .bak-<时间戳>.zip
resolve_zip() {
    if [ -n "$SECOPS_ZIP" ]; then
        [ -f "$SECOPS_ZIP" ] || { say "错误: --zip 指定文件不存在: $SECOPS_ZIP" >&2; return 1; }
        printf '%s\n' "$SECOPS_ZIP"; return 0
    fi
    local d candidates best
    local dirs=()
    [ -n "$SECOPS_ZIP_DIR" ] && dirs+=("$SECOPS_ZIP_DIR")
    # 部署根本身排在最前：工件平铺投放即可，不必再建 releases/ 子目录
    dirs+=("$SECOPS_ROOT" "$SECOPS_ROOT/releases" "$REPO_ROOT/releases" "$PWD")
    for d in "${dirs[@]}"; do
        [ -d "$d" ] || continue
        candidates="$(find "$d" -maxdepth 1 -type f -name "${SKILL_NAME}-*.zip" -printf '%f\n' 2>/dev/null \
            | grep -E "^${SKILL_NAME}-[0-9]+\.[0-9]+\.[0-9]+\.zip$" || true)"
        [ -n "$candidates" ] || continue
        best="$(printf '%s\n' "$candidates" | sort -V | tail -1)"
        printf '%s\n' "$d/$best"; return 0
    done
    say "错误: 未找到简版包 ${SKILL_NAME}-<版本>.zip" >&2
    say "  已搜索: ${dirs[*]}" >&2
    say "  可用 --zip <路径> 明确指定；或在仓库执行 ./releases/release-maker.sh lite 生成" >&2
    return 1
}

zip_version() { basename "$1" .zip | sed -E "s/^${SKILL_NAME}-//"; }

# ---------- 部署：简版 zip -> $SKILL_SRC ----------
deploy() {
    say "== 部署（简版 zip → $SKILL_SRC）=="

    if ! command -v unzip >/dev/null 2>&1; then
        bad "缺少 unzip（无法解压发布包）"; return 1
    fi
    # 部署根：不存在则自动创建，省去目标机上手工 mkdir/chown 的往返
    if [ ! -d "$SECOPS_ROOT" ]; then
        if [ "$DRY_RUN" = "1" ]; then
            printf '  [DRY]  mkdir -p "%s"\n' "$SECOPS_ROOT"
        else
            say "  [INFO] 部署根不存在，自动创建: $SECOPS_ROOT"
            mkdir -p "$SECOPS_ROOT" 2>/dev/null \
                || { bad "无法创建部署根: $SECOPS_ROOT（父目录不可写；换成用户可写目录，或 sudo mkdir -p $SECOPS_ROOT && sudo chown \$USER $SECOPS_ROOT）"; return 1; }
        fi
    elif [ ! -w "$SECOPS_ROOT" ]; then
        bad "部署根不可写: $SECOPS_ROOT（试: sudo chown \$USER $SECOPS_ROOT，或换 SECOPS_ROOT=\$HOME/agent-secops）"; return 1
    fi

    local ZIP VERSION SHA
    if ! ZIP="$(resolve_zip)"; then bad "选件失败"; return 1; fi
    VERSION="$(zip_version "$ZIP")"
    SHA="$(sha256sum "$ZIP" | awk '{print $1}')"
    ok "选件: $ZIP（版本 $VERSION，sha256 ${SHA:0:16}…）"

    # 1) 解压前先在包清单上校验必需件（便宜的完整性闸门，避免解出半棵树）
    # 注意：必须先把清单读进变量再匹配。若写成 `unzip -Z1 | grep -q`，grep 命中即退出，
    # unzip 收 SIGPIPE，在 set -o pipefail 下整条管道返回 141 → 校验会被误判为「缺件」。
    local member missing=0 members
    members="$(unzip -Z1 "$ZIP" 2>/dev/null || true)"
    for member in "${REQUIRED_MEMBERS[@]}"; do
        if grep -Fqx "$SKILL_NAME/$member" <<< "$members"; then
            ok "包内含 $member"
        else
            bad "包内缺少必需件: $SKILL_NAME/$member（包不完整或版本不符）"; missing=1
        fi
    done
    [ "$missing" = "0" ] || return 1

    if [ "$DRY_RUN" = "1" ]; then
        printf '  [DRY]  unzip -q -P *** "%s" -d "%s/.staging-<ts>"\n' "$ZIP" "$SECOPS_ROOT"
        printf '  [DRY]  备份旧树: "%s" -> "%s.bak-<ts>"\n' "$SKILL_SRC" "$SKILL_SRC"
        printf '  [DRY]  切换新树: staging/%s -> "%s"\n' "$SKILL_NAME" "$SKILL_SRC"
        printf '  [DRY]  chmod 600 "%s"\n' "$ENV_FILE"
        printf '  [DRY]  mkdir -p "%s"；写入部署记录 "%s"\n' "$OUTPUT_DIR" "$RELEASE_RECORD"
        return 0
    fi

    # 2) 解压到独立 staging（同文件系统，切换用 mv，避免半棵树污染现网）
    local STAGING BAK
    STAGING="$SECOPS_ROOT/.staging-$(date '+%Y%m%d%H%M%S')"
    mkdir -p "$STAGING" "$SECOPS_ROOT/skills"
    if ! unzip -q -o -P "$SECOPS_ZIP_PASSWORD" "$ZIP" -d "$STAGING" 2>/dev/null; then
        bad "解压失败（密码错误或包损坏）: $ZIP"
        rm -rf "$STAGING"
        return 1
    fi
    if [ ! -f "$STAGING/$SKILL_NAME/SKILL.md" ]; then
        bad "解压结果异常：未见 $SKILL_NAME/SKILL.md"
        rm -rf "$STAGING"
        return 1
    fi
    ok "已解密解压到 staging（$(find "$STAGING/$SKILL_NAME" -type f | wc -l) 个文件）"

    # 3) 替换旧树（旧树留备份，便于回滚与比对）
    # 这些 mv 用显式错误检查而非 run/eval：中途失败必须能回滚，不能被 set -e 直接打断
    BAK=""
    if [ -d "$SKILL_SRC" ]; then
        BAK="$SKILL_SRC.bak-$(date '+%Y%m%d%H%M%S')"
        if ! mv "$SKILL_SRC" "$BAK"; then
            bad "备份旧树失败: $SKILL_SRC -> $BAK"
            rm -rf "$STAGING"
            return 1
        fi
        ok "旧树已备份: $BAK"
    fi
    if ! mv "$STAGING/$SKILL_NAME" "$SKILL_SRC"; then
        bad "新树切换失败: $STAGING/$SKILL_NAME -> $SKILL_SRC"
        if [ -n "$BAK" ]; then mv "$BAK" "$SKILL_SRC" 2>/dev/null || true; fi
        rm -rf "$STAGING"
        return 1
    fi
    rm -rf "$STAGING"

    # 4) 落地校验：必需件齐 + 权限；失败即回滚
    local landed=1
    for member in "${REQUIRED_MEMBERS[@]}"; do
        [ -f "$SKILL_SRC/$member" ] || { bad "落地校验失败，缺件: $SKILL_SRC/$member"; landed=0; }
    done
    if [ "$landed" = "0" ]; then
        say "  → 回滚：移除不完整新树，恢复备份"
        rm -rf "$SKILL_SRC"
        if [ -n "$BAK" ]; then mv "$BAK" "$SKILL_SRC" 2>/dev/null || true; fi
        return 1
    fi
    chmod 600 "$ENV_FILE"
    chmod 755 "$PATROL_SH" 2>/dev/null || true
    mkdir -p "$OUTPUT_DIR"
    printf 'zip=%s\nversion=%s\nsha256=%s\ndeployed_at=%s\nskill_dir=%s\n' \
        "$(basename "$ZIP")" "$VERSION" "$SHA" "$(date '+%F %T %z')" "$SKILL_SRC" > "$RELEASE_RECORD"
    ok "部署完成：版本 $VERSION，记录 $RELEASE_RECORD"

    # 5) 提示类（不阻断）
    local post
    post="$(grep -E '^ENABLE_POST=' "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2 | awk '{print $1}' || true)"
    if [ "$post" = "true" ]; then
        warn "包内 .env 为 ENABLE_POST=true：巡检会向门户发帖（保留包内原值，未代改）"
        say  "         如需仅出报告不发帖：编辑 $ENV_FILE"
    fi
}

# ---------- 体检（只读） ----------
check() {
    say "== 1. 运行时依赖 =="
    if command -v opencode >/dev/null 2>&1; then
        ok "opencode: $(command -v opencode) ($(opencode --version 2>/dev/null | head -1))"
    else
        bad "opencode 不在 PATH（cron 环境同样需要，可在脚本 PATROL 兜底路径或 crontab 中显式补 PATH）"
    fi
    if command -v node >/dev/null 2>&1; then
        ok "node: $(command -v node) ($(node --version 2>/dev/null))"
    else
        bad "node 不在 PATH（skill 脚本依赖 node）"
    fi
    if command -v timeout >/dev/null 2>&1; then ok "timeout: $(command -v timeout)"; else bad "缺少 timeout（coreutils）"; fi
    if command -v crontab >/dev/null 2>&1; then ok "crontab: $(command -v crontab)"; else bad "缺少 crontab（cron/cronie 未安装）"; fi
    if command -v unzip >/dev/null 2>&1; then ok "unzip: $(command -v unzip)"; else bad "缺少 unzip（deploy 需要）"; fi

    say "== 2. 部署来源 =="
    if [ -f "$RELEASE_RECORD" ]; then
        sed 's/^/         /' "$RELEASE_RECORD"
        local rec_ver cur_ver
        rec_ver="$(sed -n 's/^version=//p' "$RELEASE_RECORD" | head -1)"
        if cur_ver="$(resolve_zip 2>/dev/null)"; then
            cur_ver="$(zip_version "$cur_ver")"
            if [ "$rec_ver" = "$cur_ver" ]; then
                ok "已部署版本与选件一致（$rec_ver）"
            else
                warn "已部署 $rec_ver，但选件目录现最新为 $cur_ver（可重跑 deploy 升级）"
            fi
        fi
    else
        warn "无部署记录 $RELEASE_RECORD（可能由 git/rsync 方式投放，或尚未部署）"
    fi

    say "== 3. 部署文件 =="
    [ -d "$SKILL_SRC" ] && ok "skill 目录: $SKILL_SRC" || bad "skill 目录不存在: $SKILL_SRC（先执行 deploy）"
    if [ -x "$PATROL_SH" ]; then
        ok "启动脚本可执行: $PATROL_SH"
    elif [ -f "$PATROL_SH" ]; then
        bad "启动脚本无执行位: $PATROL_SH（chmod +x）"
    else
        warn "启动脚本未就位: $PATROL_SH（包白名单应含 scripts/auto-patrol.sh，重跑 deploy 即就位）"
    fi
    if [ -f "$ENV_FILE" ]; then
        local perm post
        perm="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || echo '?')"
        if [ "$perm" = "600" ]; then ok ".env 权限 600"; else warn ".env 权限为 $perm（含凭据，建议 chmod 600；WSL/drvfs 下权限恒为 777，属平台表现，请以宿主 ACL 为准）"; fi
        post="$(grep -E '^ENABLE_POST=' "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2 | awk '{print $1}' || true)"
        if [ "$post" = "true" ]; then
            warn "ENABLE_POST=true：巡检会向门户发帖（保留包内原值，install 未代改）"
        elif [ "$post" = "false" ]; then
            ok "ENABLE_POST=false：仅出报告，不发帖"
        fi
    else
        bad ".env 缺失: $ENV_FILE（ES / portal / 微步 凭据来源）"
    fi
    if [ -d "$OUTPUT_DIR" ]; then
        [ -w "$OUTPUT_DIR" ] && ok "输出目录可写: $OUTPUT_DIR" || bad "输出目录不可写: $OUTPUT_DIR"
    else
        warn "输出目录不存在: $OUTPUT_DIR（install 会创建）"
    fi

    say "== 4. opencode 可见性 =="
    if [ -L "$SKILL_LINK" ]; then
        target="$(readlink -f "$SKILL_LINK" 2>/dev/null || echo '?')"
        [ "$target" = "$(readlink -f "$SKILL_SRC" 2>/dev/null)" ] \
            && ok "skill 软链有效: $SKILL_LINK -> $target" \
            || warn "skill 软链指向异常: $SKILL_LINK -> $target（期望 $SKILL_SRC）"
    elif [ -d "$SKILL_LINK" ]; then
        warn "$SKILL_LINK 是实体目录（非软链）：改代码后需手工同步"
    else
        bad "skill 未对 opencode 暴露: $SKILL_LINK（install 会创建软链）"
    fi
    if command -v opencode >/dev/null 2>&1; then
        # 注：opencode debug skill 冷启约需 1–3 分钟，超时过短会误判为「未发现」
        set +e
        timeout 300 opencode debug skill 2>/dev/null | grep -q "$SKILL_NAME"
        sk_rc="${PIPESTATUS[0]}"
        set -e
        if [ "$sk_rc" = "124" ]; then
            warn "opencode debug skill 超过 300s 未返回，本项跳过（不影响其它检查）"
        elif [ "$sk_rc" = "0" ]; then
            ok "opencode 已能发现 skill（debug skill 命中 $SKILL_NAME）"
        else
            warn "opencode debug skill 未命中 $SKILL_NAME（核对用户级发现目录，或用 opencode debug skill 全量确认）"
        fi
    fi

    say "== 5. 定时任务 =="
    local cron_now
    cron_now="$(crontab -l 2>/dev/null || true)"
    # 不用 `crontab -l | grep -q`：grep 提前退出会让 crontab 收 SIGPIPE，pipefail 下误判为「无条目」
    if grep -q "$MARK" <<< "$cron_now"; then
        ok "crontab 条目已存在:"
        grep "$MARK" <<< "$cron_now" | sed 's/^/         /'
    else
        warn "crontab 中无 $MARK 条目（install 会写入）"
    fi
    if [ -f "$OUTPUT_DIR/auto-patrol.lock" ]; then
        lp="$(cat "$OUTPUT_DIR/auto-patrol.lock" 2>/dev/null || echo '')"
        if [ -n "$lp" ] && kill -0 "$lp" 2>/dev/null; then warn "有实例正在运行 (PID $lp)"; else warn "存在过期锁文件: $OUTPUT_DIR/auto-patrol.lock"; fi
    fi

    say "== 6. 最近执行记录 =="
    if [ -f "$OUTPUT_DIR/auto-patrol.log" ]; then
        local recent
        tail -n 5 "$OUTPUT_DIR/auto-patrol.log" | sed 's/^/         /'
        recent="$(tail -n 50 "$OUTPUT_DIR/auto-patrol.log" 2>/dev/null || true)"
        if grep -qE "FAILED|TIMEOUT" <<< "$recent"; then warn "最近 50 行含 FAILED/TIMEOUT，请查看日志"; fi
    else
        warn "尚无日志 $OUTPUT_DIR/auto-patrol.log（未执行过）"
    fi

    say ""
    if [ "$FAIL" = "0" ]; then say "体检结论: 通过"; else say "体检结论: 存在阻断项（见 [FAIL]）"; fi
    return "$FAIL"
}

# ---------- 安装（部署 + 软链 + crontab） ----------
install() {
    say "== 安装（SECOPS_ROOT=$SECOPS_ROOT, 计划=$CRON_SCHEDULE）=="

    if [ "$NO_DEPLOY" = "1" ]; then
        say "  [SKIP] --no-deploy：跳过部署，仅处理软链与 crontab"
    else
        # 幂等关键：选件版本与已部署版本一致时跳过部署，避免无谓地重建整棵树。
        local cur_ver want_ver want_zip
        cur_ver="$(sed -n 's/^version=//p' "$RELEASE_RECORD" 2>/dev/null | head -1 || true)"
        want_ver=""
        if want_zip="$(resolve_zip 2>/dev/null)"; then want_ver="$(zip_version "$want_zip")"; fi
        if [ -n "$cur_ver" ] && [ "$cur_ver" = "$want_ver" ] && [ -f "$SKILL_SRC/SKILL.md" ]; then
            say "  [SKIP] 已部署 $cur_ver 且与选件一致，跳过部署（保留现网树）"
            say "         如需强制重解压：先执行 $0 deploy"
        else
            deploy || return 1
        fi
    fi

    if [ "$DRY_RUN" != "1" ] && [ ! -d "$SKILL_SRC" ]; then
        bad "skill 目录不存在: $SKILL_SRC"; return 1
    fi

    run "mkdir -p \"$OUTPUT_DIR\""
    if [ -f "$ENV_FILE" ]; then
        perm="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || echo '?')"
        [ "$perm" = "600" ] || run "chmod 600 \"$ENV_FILE\""
    else
        if [ "$DRY_RUN" != "1" ]; then
            warn ".env 缺失：待解压的包应含 scripts/.env，请核查包版本"
        fi
    fi

    # 启动脚本随包投放（简版包白名单含 scripts/auto-patrol.sh）：缺失时阻断安装，避免装出每小时静默失败的定时任务
    if [ "$DRY_RUN" != "1" ]; then
        if [ ! -x "$PATROL_SH" ]; then
            bad "启动脚本未就位: $PATROL_SH"
            say  "         包白名单应含 scripts/auto-patrol.sh；重跑 $0 deploy 即随包就位"
            return 1
        fi
    else
        printf '  [DRY]  校验启动脚本存在且可执行: %s\n' "$PATROL_SH"
    fi

    run "mkdir -p \"$SKILL_LINK_DIR\""
    if [ -L "$SKILL_LINK" ] || [ -e "$SKILL_LINK" ]; then
        run "ln -sfn \"$SKILL_SRC\" \"$SKILL_LINK\""
    else
        run "ln -s \"$SKILL_SRC\" \"$SKILL_LINK\""
    fi

    local cron_now
    cron_now="$(crontab -l 2>/dev/null || true)"
    if grep -q "$MARK" <<< "$cron_now"; then
        say "  [SKIP] crontab 已有 $MARK 条目，先按目标值重写（幂等）"
    fi
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [DRY]  crontab 写入: %s\n' "$CRON_LINE"
    else
        { grep -v "$MARK" <<< "$cron_now" || true; printf '%s\n' "$CRON_LINE"; } | crontab -
        ok "crontab 已写入: $CRON_LINE"
    fi
    say ""
    if [ "$DRY_RUN" = "1" ]; then
        say "== 安装后体检 =="
        say "  [SKIP] 演练模式未做任何改动，跳过体检（正式安装会自动复跑）"
        return 0
    fi
    say "== 安装后体检 =="
    check
}

# ---------- 卸载 ----------
uninstall() {
    local cron_now
    cron_now="$(crontab -l 2>/dev/null || true)"
    if grep -q "$MARK" <<< "$cron_now"; then
        if [ "$DRY_RUN" = "1" ]; then
            printf '  [DRY]  从 crontab 移除 %s 条目\n' "$MARK"
        else
            { grep -v "$MARK" <<< "$cron_now" || true; } | crontab -
            ok "crontab 条目已移除（部署文件与软链保留）"
        fi
    else
        say "  [SKIP] crontab 无 $MARK 条目"
    fi
}

# ---------- 全量卸载（回收 crontab + 软链 + 部署根整棵） ----------
uninstall_all() {
    say "== 全量卸载（SECOPS_ROOT=$SECOPS_ROOT）=="

    # 防呆：只对绝对路径、且非 / 非 $HOME 的专用部署根动手
    case "$SECOPS_ROOT" in
        ""|"/"|"$HOME") bad "拒绝执行：SECOPS_ROOT=$SECOPS_ROOT 不是专用部署根"; return 1 ;;
    esac
    case "$SECOPS_ROOT" in
        /*) ;;
        *)  bad "拒绝执行：SECOPS_ROOT 必须是绝对路径（当前 $SECOPS_ROOT）"; return 1 ;;
    esac

    # 破坏性动作需显式确认；--dry-run 只打印，不必确认
    if [ "$CONFIRM" != "1" ] && [ "$DRY_RUN" != "1" ]; then
        warn "全量卸载会清除以下内容，确认后加 --yes 执行："
        printf '           crontab 条目  %s\n' "$MARK"
        printf '           skill 软链    %s\n' "$SKILL_LINK"
        printf '           部署根整棵    %s（含 skills/、.deployed-release、output/ 与投放的工件）\n' "$SECOPS_ROOT"
        say  "         确认命令: bash $0 uninstall-all --yes"
        FAIL=1
        return 1
    fi

    # 巡检正在跑时提示一句（读锁文件里的 PID，比 pgrep -f 可靠：不会误命中命令行里出现过脚本名的进程）
    local lock="$OUTPUT_DIR/auto-patrol.lock"
    if [ -f "$lock" ]; then
        local lock_pid
        lock_pid="$(cat "$lock" 2>/dev/null || true)"
        if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
            warn "巡检正在运行（锁 $lock，PID $lock_pid），删除会落在活动任务上"
        fi
    fi

    # 1) crontab 条目（先摘调度，避免边删边触发）
    local cron_now
    cron_now="$(crontab -l 2>/dev/null || true)"
    if grep -q "$MARK" <<< "$cron_now"; then
        if [ "$DRY_RUN" = "1" ]; then
            printf '  [DRY]  从 crontab 移除 %s 条目\n' "$MARK"
        else
            { grep -v "$MARK" <<< "$cron_now" || true; } | crontab -
            ok "crontab 条目已移除"
        fi
    else
        say "  [SKIP] crontab 无 $MARK 条目"
    fi

    # 2) skill 软链：只删指向本部署根的软链，实体目录与其他指向一律不动
    local link_ours=0
    if [ -L "$SKILL_LINK" ]; then
        local link_target
        link_target="$(readlink -f "$SKILL_LINK" 2>/dev/null || echo '?')"
        case "$link_target" in
            "$SECOPS_ROOT"|"$SECOPS_ROOT"/*)
                link_ours=1
                if [ "$DRY_RUN" = "1" ]; then
                    printf '  [DRY]  rm -f "%s"\n' "$SKILL_LINK"
                else
                    rm -f "$SKILL_LINK"
                    ok "skill 软链已移除: $SKILL_LINK"
                fi ;;
            *)
                warn "跳过 $SKILL_LINK：指向 $link_target（不在部署根内，可能是开发仓链接）" ;;
        esac
    elif [ -e "$SKILL_LINK" ]; then
        warn "跳过 $SKILL_LINK：是实体目录（非软链），按你的意图保留"
    else
        say "  [SKIP] skill 软链不存在: $SKILL_LINK"
    fi

    # 3) 部署根整棵（含投放的 zip 与 install-cron.sh）
    # 删目录看的是父目录写权限（/opt 归 root），删不掉时不能让 set -e 掐掉后面的收尾核对
    if [ -d "$SECOPS_ROOT" ]; then
        local root_parent
        root_parent="$(dirname "$SECOPS_ROOT")"
        if [ "$DRY_RUN" = "1" ]; then
            printf '  [DRY]  rm -rf "%s"\n' "$SECOPS_ROOT"
        else
            [ -w "$root_parent" ] || warn "父目录不可写（$root_parent）：非 root 删不掉部署根本身"
            rm -rf "$SECOPS_ROOT" 2>/dev/null || true
            if [ -e "$SECOPS_ROOT" ]; then
                warn "部署根未能删除: $SECOPS_ROOT（父目录 $root_parent 不可写，收尾: sudo rm -rf $SECOPS_ROOT）"
            else
                ok "部署根已删除: $SECOPS_ROOT"
            fi
        fi
    else
        say "  [SKIP] 部署根不存在: $SECOPS_ROOT"
    fi

    # 4) 回收核对
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [DRY]  回收核对（crontab / 软链 / 部署根）\n'
        return 0
    fi
    local left=0
    cron_now="$(crontab -l 2>/dev/null || true)"
    grep -q "$MARK" <<< "$cron_now" && { bad "残留：crontab 仍有 $MARK 条目"; left=1; }
    if [ "$link_ours" = "1" ] && { [ -e "$SKILL_LINK" ] || [ -L "$SKILL_LINK" ]; }; then
        bad "残留: $SKILL_LINK"; left=1
    fi
    [ -e "$SECOPS_ROOT" ] && { bad "残留: $SECOPS_ROOT（父目录不可写时收尾: sudo rm -rf $SECOPS_ROOT）"; left=1; }
    [ "$left" = "0" ] && ok "回收完成：crontab、软链、部署根均已清除"
    return "$left"
}

case "$ACTION" in
    check)         check ;;
    deploy)        deploy ;;
    install)       install ;;
    uninstall)     uninstall ;;
    uninstall-all) uninstall_all ;;
esac
