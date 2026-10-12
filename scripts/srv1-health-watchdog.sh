#!/usr/bin/env bash
# ============================================================
# srv1：健康看门狗（部署后"起来但不健康"的自动回滚）
# ------------------------------------------------------------
# 为什么需要它：
#   srv1-redeploy.sh 只保证"部署动作本身成功"（拉取/重建/硬校验/一次健康核对）。
#   但如果新版本【起来之后过一会儿才暴露问题】（内存泄漏、依赖失效、向量库损坏…），
#   发布流程已经结束，没人管了 —— 这条路径此前【从未被验证过】。
#   本看门狗每 2 分钟核一次健康，连续 3 次（≈6 分钟）不健康 → 回滚到 last-known-good。
#
# 保守设计（宁可少动，不可乱动）：
#   · 连续 3 次失败才动手（避免单次抖动触发回滚）
#   · 回滚有冷却（默认 30 分钟一次），避免回滚风暴
#   · 只回滚到 last-known-good.json 里的 digest；该文件不存在就只告警、不回滚
#   · 当前已在 last-known-good 上时不再回滚（回滚也没意义）
#   · --dry-run 只判断与记录，不执行回滚（用于验证判断逻辑）
#
# 用法（srv1，root）：
#   bash srv1-health-watchdog.sh            # 正常检查（可能触发回滚）
#   bash srv1-health-watchdog.sh --dry-run  # 只判断、只记录
#   bash srv1-health-watchdog.sh --status   # 打印当前状态与计数
# 退出码：0=健康或已处置；1=不健康但还在观察；2=已触发回滚
# ============================================================
set -uo pipefail

STATE_DIR=/opt/secagent/releases
STATE_FILE="$STATE_DIR/health-watchdog.state"
LKG=/opt/secagent/last-known-good.json
HEALTH_URL=${HEALTH_URL:-http://127.0.0.1:9900/api/health}
FAIL_THRESHOLD=3
COOLDOWN_SEC=1800
ROLLBACK_SCRIPT=/opt/secagent/scripts/srv1-rollback.sh
DRY_RUN=0
MODE=check

case "${1:-}" in
  --dry-run) DRY_RUN=1 ;;
  --status)  MODE=status ;;
  --help|-h) sed -n '2,30p' "$0"; exit 0 ;;
esac

mkdir -p "$STATE_DIR"
# 状态文件：FAILS=<连续失败次数> LAST_ROLLBACK=<epoch>  LAST_REASON=<文本>
FAILS=0; LAST_ROLLBACK=0; LAST_REASON=""
if [ -f "$STATE_FILE" ]; then
  # shellcheck disable=SC1090
  . "$STATE_FILE" || true
fi
save_state() {
  { echo "FAILS=$1"; echo "LAST_ROLLBACK=$2"; echo "LAST_REASON=\"$3\""; } > "$STATE_FILE"
}
now() { date +%s; }
log() { printf '%s %s\n' "$(date '+%F %T')" "$*"; }

# ---------- 健康判断 ----------
probe() {
  local body out
  body=$(curl -s -m 12 "$HEALTH_URL" 2>/dev/null) || { echo "无响应"; return 1; }
  [ -n "$body" ] || { echo "空响应"; return 1; }
  # 【踩坑】这里必须用 python3 -c（不能 python3 - <<'PY'）：heredoc 会抢占 stdin，
  # 管道传进来的响应体就读不到了，于是健康接口也会被判成"响应不是 JSON"。
  out=$(printf '%s' "$body" | python3 -c '
import json,sys
try:
    d=json.load(sys.stdin)
except Exception as e:
    print("响应不是 JSON: %s" % e); sys.exit(1)
st=str(d.get("status",""))
mm=str(d.get("fingerprintMismatch",""))
if st!="ok":
    print("status=%s（期望 ok）" % st); sys.exit(1)
if mm not in ("False","false","None"):
    print("fingerprintMismatch=%s（指纹不一致）" % mm); sys.exit(1)
print("OK commit=%s vectors=%s" % (str(d.get("embeddedGitCommit",""))[:7], d.get("documentVectors","?")))
' 2>&1)
  local rc=$?
  echo "$out"
  return $rc
}

if [ "$MODE" = "status" ]; then
  echo "看门狗状态：连续失败=$FAILS  上次回滚=$( [ "$LAST_ROLLBACK" = "0" ] && echo 从未 || date -d "@$LAST_ROLLBACK" '+%F %T' ) 原因=[$LAST_REASON]"
  R=$(probe) && echo "当前探测：健康（$R）" || echo "当前探测：不健康（$R）"
  exit 0
fi

REASON=$(probe) && RC=0 || RC=1

if [ "$RC" = "0" ]; then
  if [ "$FAILS" != "0" ]; then log "恢复健康（$REASON），重置失败计数"; fi
  save_state 0 "$LAST_ROLLBACK" ""
  log "健康：$REASON"
  exit 0
fi

# 不健康
FAILS=$((FAILS + 1))
log "不健康（第 $FAILS/$FAIL_THRESHOLD 次）：$REASON"

if [ "$FAILS" -lt "$FAIL_THRESHOLD" ]; then
  save_state "$FAILS" "$LAST_ROLLBACK" "$REASON"
  exit 1
fi

# 达阈值 → 决定是否回滚
if [ ! -f "$LKG" ]; then
  log "[!] 连续 $FAILS 次不健康，但没有 $LKG —— 无法自动回滚，只记录（请人工介入）"
  save_state "$FAILS" "$LAST_ROLLBACK" "$REASON"
  exit 1
fi

LKG_DIGEST=$(python3 -c 'import json;print(json.load(open("'"$LKG"'")).get("digest",""))' 2>/dev/null || echo "")
LKG_COMMIT=$(python3 -c 'import json;print(json.load(open("'"$LKG"'")).get("commit",""))' 2>/dev/null || echo "")
CUR_DIGEST=$(docker inspect --format '{{index .Config.Image}}' secagent 2>/dev/null | sed 's/.*@//')
CUR_COMMIT=$(curl -s -m 12 "$HEALTH_URL" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("embeddedGitCommit",""))' 2>/dev/null || echo "")

if [ -n "$CUR_COMMIT" ] && [ "${CUR_COMMIT:0:7}" = "${LKG_COMMIT:0:7}" ]; then
  log "[!] 连续 $FAILS 次不健康，但当前运行的提交 == last-known-good（${LKG_COMMIT:0:7}）—— 回滚无意义，改人工介入"
  save_state "$FAILS" "$LAST_ROLLBACK" "$REASON"
  exit 1
fi

ELAPSED=$(( $(now) - LAST_ROLLBACK ))
if [ "$LAST_ROLLBACK" != "0" ] && [ "$ELAPSED" -lt "$COOLDOWN_SEC" ]; then
  log "[!] 需要回滚，但处于冷却期（$(( COOLDOWN_SEC - ELAPSED )) 秒后可再动手）—— 跳过本次"
  save_state "$FAILS" "$LAST_ROLLBACK" "$REASON"
  exit 1
fi

log "决定回滚：现状 commit=${CUR_COMMIT:0:7} → last-known-good commit=${LKG_COMMIT:0:7} digest=${LKG_DIGEST:0:19}…"
if [ "$DRY_RUN" = "1" ]; then
  log "[dry-run] 不真正执行回滚（若真跑会执行：bash $ROLLBACK_SCRIPT）"
  save_state "$FAILS" "$LAST_ROLLBACK" "$REASON"
  exit 2
fi

if [ ! -x "$ROLLBACK_SCRIPT" ] && [ ! -f "$ROLLBACK_SCRIPT" ]; then
  log "[X] 找不到回滚脚本 $ROLLBACK_SCRIPT —— 只告警，请人工介入"
  save_state "$FAILS" "$LAST_ROLLBACK" "$REASON"
  exit 1
fi

log "执行回滚……"
# 与 srv1-redeploy.sh 用同一把锁：避免"发布"与"回滚"同时操作容器
if command -v flock >/dev/null 2>&1; then
  ROLLBACK_CMD=(flock -w 300 /var/lock/secagent-deploy.lock bash "$ROLLBACK_SCRIPT")
else
  ROLLBACK_CMD=(bash "$ROLLBACK_SCRIPT")
fi
if "${ROLLBACK_CMD[@]}" 2>&1 | sed 's/^/    /'; then
  log "回滚脚本返回成功，稍后复查健康"
  save_state 0 "$(now)" "连续 $FAILS 次不健康（$REASON）→ 已回滚到 ${LKG_COMMIT:0:7}"
  sleep 25
  R2=$(probe) && log "回滚后健康：$R2" || log "[!] 回滚后仍不健康：$R2 —— 需要人工介入"
  exit 2
else
  log "[X] 回滚脚本失败 —— 需要人工介入"
  save_state "$FAILS" "$LAST_ROLLBACK" "$REASON"
  exit 1
fi
