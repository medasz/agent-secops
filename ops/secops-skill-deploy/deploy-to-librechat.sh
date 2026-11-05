#!/usr/bin/env bash
# secops-alert-analysis · 本地一键部署/回滚
# 用法:
#   bash deploy-to-librechat.sh [serv用户名@serv]              # 默认部署本地技能源
#   bash deploy-to-librechat.sh [serv用户名@serv] rollback /root/LibreChat/backups/skills/<包>.tar.gz   # 从 serv 备份包回滚
# 前提: 已配置 ssh 免密登录 serv（别名 serv）；serv 有 rsync 3.2、docker compose
set -euo pipefail

HOST="${1:-serv}"
MODE="${2:-deploy}"
SKILL_SRC="/c/Users/Leion/T/agent-secops/skills/secops-alert-analysis"
REMOTE_TMP="/root/LibreChat/secops-skill-local.tar.gz"
ROLLBACK_SRC="${3:-}"
LOCAL_PKG="$(mktemp).tar.gz"

if [ "$MODE" = "deploy" ]; then
  echo "== 1/3 打包本地技能源 =="
  [ -d "$SKILL_SRC" ] || { echo "✗ 技能源不存在: $SKILL_SRC"; exit 1; }
  tar czf "$LOCAL_PKG" -C "$(dirname "$SKILL_SRC")" "$(basename "$SKILL_SRC")"
  echo "  ✓ 已打包 $LOCAL_PKG ($(du -h "$LOCAL_PKG" | cut -f1))"

  echo "== 2/3 上传到 serv =="
  scp -q "$LOCAL_PKG" "$HOST:$REMOTE_TMP"
  echo "  ✓ 已上传 $HOST:$REMOTE_TMP"
elif [ "$MODE" = "rollback" ]; then
  [ -n "$ROLLBACK_SRC" ] || { echo "✗ 回滚需传入备份包路径: rollback /root/LibreChat/backups/skills/<包>.tar.gz"; exit 1; }
  echo "== 1/2 校验备用源存在 =="
  ssh "$HOST" "[ -e '$ROLLBACK_SRC' ] && echo '  ✓ 存在: $ROLLBACK_SRC' || { echo '  ✗ 不存在: $ROLLBACK_SRC'; exit 1; }" || exit 1
  echo "== 2/2 远端从备份包恢复 =="
else
  echo "✗ 未知模式: $MODE（可用 deploy | rollback <包路径>）"; exit 1
fi

REAL_SRC="$ROLLBACK_SRC"; [ "$MODE" = "deploy" ] && REAL_SRC="$REMOTE_TMP"
echo "== 3/3 远端部署（heredoc 输送执行）=="
ssh "$HOST" "SRC='$REAL_SRC' bash -s" <<'REMOTE'
set -euo pipefail
LH="/root/LibreChat"
SKILL_NAME="secops-alert-analysis"
SKILL_DIR="$LH/skill/$SKILL_NAME"
OUTPUT_SRC="$LH/code-interpreter-outputs/$SKILL_NAME"
OVERRIDE="$LH/docker-compose.override.yml"
BACKUP_DIR="$LH/backups/skills"
STAMP="$(date +%Y%m%d-%H%M%S)"
CNT="LibreChat-CodeInterpreter"
SRC="${SRC:-$LH/secops-skill-local.tar.gz}"
log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "  \033[1;32m✓ $*\033[0m"; }
warn() { echo -e "  \033[1;33m⚠ $*\033[0m"; }
die()  { echo -e "\033[1;31m✗ $*\033[0m" >&2; exit 1; }
cd "$LH"
[ -e "$SRC" ] || die "源不存在: $SRC"
# 1. 备份
log "1/6 备份当前 skill"
mkdir -p "$BACKUP_DIR"
if [ -d "$SKILL_DIR" ] && [ -n "$(ls -A "$SKILL_DIR" 2>/dev/null)" ]; then
  tar czf "$BACKUP_DIR/${SKILL_NAME}-${STAMP}.tar.gz" -C "$LH/skill" "$SKILL_NAME" && ok "已备份 -> $BACKUP_DIR/${SKILL_NAME}-${STAMP}.tar.gz"
else warn "无现存 skill 内容，跳过备份"; fi
ls -1t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm -f
# 2. 干净同步
log "2/6 同步文件到 $SKILL_DIR"
STAGE="$(mktemp -d)"
tar xzf "$SRC" -C "$STAGE"
if [ -d "$STAGE/$SKILL_NAME" ]; then mv "$STAGE/$SKILL_NAME" "$STAGE/_pkg" && mv "$STAGE/_pkg"/* "$STAGE/" && rmdir "$STAGE/_pkg"; fi
rm -rf "$STAGE/output"   # 去掉包内自带 output 挂载点，由宿主机输出源接管
mkdir -p "$SKILL_DIR"
rsync -a --delete --exclude='/output/' "$STAGE/" "$SKILL_DIR/"
mkdir -p "$SKILL_DIR/output"
rm -rf "$STAGE"
find "$SKILL_DIR" -type d -exec chmod 755 {} +
find "$SKILL_DIR" -type f -exec chmod 644 {} +
ok "文件已就位 ($(find "$SKILL_DIR" -type f | wc -l) 个)"
# 3. 输出源
log "3/6 确保输出源目录可写"
mkdir -p "$OUTPUT_SRC"
chown -R 1000:1000 "$OUTPUT_SRC" 2>/dev/null || warn "chown 失败，请手动: chown -R 1000:1000 $OUTPUT_SRC"
isowner="$(stat -c %u "$OUTPUT_SRC" 2>/dev/null || echo x)"
[ "$isowner" = "1000" ] && ok "$OUTPUT_SRC (uid 1000)" || warn "$OUTPUT_SRC 属主为 $isowner（应 1000）"
# 4. override 挂载
log "4/6 校验 override 挂载"
[ -f "$OVERRIDE" ] || die "override 不存在: $OVERRIDE"
if ! grep -q "./skill/$SKILL_NAME:/app/skills/$SKILL_NAME:ro" "$OVERRIDE"; then
  sed -i "/.\/code-interpreter-notebooks:\/app\/notebooks/a\      - ./skill/$SKILL_NAME:/app/skills/$SKILL_NAME:ro" "$OVERRIDE"
fi
if ! grep -q "$OUTPUT_SRC:/app/skills/$SKILL_NAME/output" "$OVERRIDE"; then
  sed -i "/.\/skill\/$SKILL_NAME:\/app\/skills\/$SKILL_NAME:ro/a\      - $OUTPUT_SRC:/app/skills/$SKILL_NAME/output" "$OVERRIDE"
fi
python3 -c "import yaml; yaml.safe_load(open('$OVERRIDE'))" || die "override YAML 校验失败"
ok "override 含两条挂载且 YAML 有效"
# 5. 重建 CI
log "5/6 重建 CI 容器"
docker compose -f "$LH/docker-compose.yml" -f "$OVERRIDE" up -d --force-recreate code_interpreter 2>&1 | tail -2
for i in $(seq 1 30); do st="$(docker inspect -f '{{.State.Health.Status}}' "$CNT" 2>/dev/null || echo none)"; [ "$st" = "healthy" ] && break; sleep 2; done
echo "  容器状态: $(docker inspect -f '{{.State.Status}} (health: {{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}})' "$CNT")"
# 6. 验证
log "6/6 验证"
docker exec "$CNT" sh -c 'mount | grep -E "/app/skills/secops-alert-analysis" | sed "s/ on / -> /; s/ type xfs.*(/(/"' | sed 's/^/  /'
fail=0
docker exec "$CNT" sh -c 'for f in scripts/workflow/selfcheck.js scripts/es-tool/extract.js scripts/.env templates/alert-report-template.md scripts/threat-intel/external.js; do [ -f "/app/skills/'$SKILL_NAME'/$f" ] && echo "  ✓ $f" || { echo "  ✗ $f"; }; done; for d in judgment judgment-xff ids-fastReport trace; do [ -f "/app/skills/'$SKILL_NAME'/$d/SKILL.md" ] && echo "  ✓ 子技能 $d" || echo "  ✗ 子技能 $d"; done'
[ "$(docker exec "$CNT" sh -c '[ -f /app/skills/'$SKILL_NAME'/scripts/.env ] && echo Y')" = "Y" ] || fail=1
W=$(docker exec "$CNT" sh -c 'echo x > /app/skills/'$SKILL_NAME'/output/_rwtest 2>/dev/null && rm -f /app/skills/'$SKILL_NAME'/output/_rwtest && echo OK || echo FAIL')
if [ "$W" = "OK" ]; then ok "output 可写"; else die "output 不可写!"; fi
[ "$fail" = "0" ] || die "存在缺失文件，请检查"
echo
echo "============================================================"
echo " 部署完成 ✓  技能: $SKILL_NAME"
echo " 宿主机技能源:  $SKILL_DIR      (ro 挂载进沙箱)"
echo " 宿主机输出:    $OUTPUT_SRC     (rw, 沙箱 /app/skills/$SKILL_NAME/output)"
echo "============================================================"
REMOTE

rm -f "$LOCAL_PKG"
echo
echo "一键部署完成 ✓"
