#!/usr/bin/env bash
# secops-alert-analysis · 运行状态/健康检查脚本
# 用法: bash status.sh [serv用户名@serv]
# 前提: 已配置 ssh 免密登录 serv（别名 serv）
set -euo pipefail

HOST="${1:-serv}"
SKILL_NAME="secops-alert-analysis"
CNT="LibreChat-CodeInterpreter"
OUTPUT_SRC="/root/LibreChat/code-interpreter-outputs/$SKILL_NAME"

echo "== 健康体检: $HOST =="
ssh "$HOST" "SKILL_NAME='$SKILL_NAME' CNT='$CNT' OUTPUT_SRC='$OUTPUT_SRC' bash -s" <<'REMOTE'
set -euo pipefail
SKILL_NAME="${SKILL_NAME:-secops-alert-analysis}"
CNT="${CNT:-LibreChat-CodeInterpreter}"
OUTPUT_SRC="${OUTPUT_SRC:-/root/LibreChat/code-interpreter-outputs/$SKILL_NAME}"

echo
echo "== CI 容器状态 =="
docker ps --format '  {{.Names}}\t{{.Status}}' | grep -i code || echo "  ✗ CI 容器未运行"

echo
echo "== 挂载状态（技能=ro, output=rw）=="
docker exec "$CNT" sh -c 'mount | grep -E "/app/skills/secops-alert-analysis" | sed "s/ on / -> /; s/ type xfs.*(/(/"' 2>/dev/null

echo
echo "== 关键文件 =="
docker exec "$CNT" sh -c 'for f in scripts/workflow/selfcheck.js scripts/es-tool/extract.js scripts/.env scripts/threat-intel/external.js templates/alert-report-template.md; do [ -f "/app/skills/'$SKILL_NAME'/$f" ] && echo "  ✓ $f" || echo "  ✗ $f"; done' 2>/dev/null

echo
echo "== 子技能 =="
docker exec "$CNT" sh -c 'for d in judgment judgment-xff ids-fastReport trace; do [ -f "/app/skills/'$SKILL_NAME'/$d/SKILL.md" ] && echo "  ✓ $d" || echo "  ✗ $d"; done' 2>/dev/null

echo
echo "== output 可写 =="
W=$(docker exec "$CNT" sh -c 'echo x > /app/skills/'$SKILL_NAME'/output/_rwtest 2>/dev/null && rm -f /app/skills/'$SKILL_NAME'/output/_rwtest && echo OK || echo FAIL' 2>/dev/null)
echo "  $([ "$W" = "OK" ] && echo "✓ 可写" || echo "✗ 不可写")"

echo
echo "== 宿主机输出目录最近产物 =="
[ -d "$OUTPUT_SRC" ] && ls -1t "$OUTPUT_SRC" | head -5 || echo "  (空)"
REMOTE
