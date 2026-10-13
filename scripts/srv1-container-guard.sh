#!/usr/bin/env bash
# ============================================================
# srv1-container-guard.sh —— 容器"消失/停止"的秒级检测（补 25~30 秒盲区）
# ------------------------------------------------------------
# 为什么需要它（这不是假想问题）：
#   2026-10-14 21:58 有人误删了 srv1 的生产容器 → 停机约 25–30 秒，
#   【期间没有任何告警】。因为既有的巡检是 2 分钟级的：
#     · secagent-healthwatch.timer  每 2 分钟一次，且要连续 3 次才动作（≈6 分钟）
#     · secagent-srv1deadman.timer（在 srv2）每 3 分钟一次，连续 3 次（≈9 分钟）
#   25–30 秒的窗口从它们的采样缝里漏过去了，notify.log 里一个字都没有。
#   本脚本就是专门盯这个窗口的：每 25 秒断言一次"容器存在且在跑"，
#   连续 2 次（≈≤60 秒）失败即告警。
#
# 判定条件（故意只有一条，且只用【容器名】精确操作）：
#   docker inspect -f '{{.State.Running}}' secagent  ==  true
#   容器不存在（docker inspect 非 0）或 Running != true → 记一次失败。
#   ⚠️ 只用容器名，绝不用 --filter ancestor= / --filter name= 这类选择器：
#      上一个实施方就是用 ancestor 选择器误伤了别的生产容器。
#   .State.Health 只在日志/告警正文里【如实展示】，不参与判定 ——
#      "容器在跑但应用不健康"是看门狗（2 分钟级）的职责，两者不重叠。
#
# 去抖与防刷屏（与 RUNBOOK §20 的既有设计一致）：
#   · 连续 FAIL_THRESHOLD（默认 2）次失败才算故障 —— 单次抖动不报
#   · 达到阈值后告警一次；仍不恢复则每 COOLDOWN_SEC（默认 600s）重提醒一次
#   · 恢复时发一条 INFO「已恢复」，且冷却键带上"本次故障起点"，
#     避免紧邻的第二次故障的恢复通知被上一次的冷却吞掉（§20 踩过的坑）
#   · 部署窗口抑制：/var/lock/secagent-deploy.lock 被持有时（发布链正在重建容器）
#     只记录不告警 —— 否则每次正常发布都会误报一次。手工 docker stop 不持锁，
#     照样会报（这正是我们要抓的场景）。可用 GUARD_SUPPRESS_DURING_DEPLOY=0 关掉。
#
# 状态落盘：/opt/secagent/state/container-guard.state（KEY=value，可 source）
# 日志：    /opt/secagent/logs/container-guard.log
#
# 退出码：0=健康；1=失败但未达阈值；2=已发告警；3=已发恢复；4=用法/配置错误
#
# 用法（srv1，root）：
#   bash srv1-container-guard.sh              # 正常一轮（timer 调的就是这个）
#   bash srv1-container-guard.sh --status     # 只看当前探测结果与状态
#   bash srv1-container-guard.sh --dry-run    # 只判断、只记录，不发通知
#   bash srv1-container-guard.sh --reset-state
# 临时关闭：systemctl disable --now secagent-containerguard.timer
# ============================================================
set -uo pipefail

CONTAINER=${GUARD_CONTAINER:-secagent}
FAIL_THRESHOLD=${FAIL_THRESHOLD:-2}
COOLDOWN_SEC=${COOLDOWN_SEC:-600}
DEPLOY_LOCK=${DEPLOY_LOCK:-/var/lock/secagent-deploy.lock}
SUPPRESS_IN_DEPLOY=${GUARD_SUPPRESS_DURING_DEPLOY:-1}
STATE_DIR=${GUARD_STATE_DIR:-/opt/secagent/state}
STATE_FILE=${GUARD_STATE_FILE:-$STATE_DIR/container-guard.state}
LOG_FILE=${GUARD_LOG_FILE:-/opt/secagent/logs/container-guard.log}
NOTIFY_SCRIPT=${NOTIFY_SCRIPT:-/opt/secagent/scripts/notify.sh}

DRY=0
MODE=check
case "${1:-}" in
  --status)      MODE=status ;;
  --dry-run)     DRY=1 ;;
  --reset-state) MODE=reset ;;
  --help|-h)     sed -n '2,44p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  --*)           echo "未知参数：$1（--status / --dry-run / --reset-state / --help）" >&2; exit 4 ;;
esac

mkdir -p "$STATE_DIR" "$(dirname "$LOG_FILE")" 2>/dev/null || true

log() {
  local line; line="$(date '+%F %T') [container-guard] $*"
  if [ -w "$(dirname "$LOG_FILE")" ] 2>/dev/null || [ -w "$LOG_FILE" ]; then
    printf '%s\n' "$line" >> "$LOG_FILE" 2>/dev/null || printf '%s\n' "$line" >&2
  else
    printf '%s\n' "$line" >&2
  fi
}

# ---------- 状态文件（§20 同款：可 source 的 KEY=value） ----------
FAILS=0; DOWN_SINCE=0; LAST_ALERT=0; LAST_REASON=""; ALERTED=0
if [ -f "$STATE_FILE" ]; then
  # shellcheck disable=SC1090
  . "$STATE_FILE" || true
fi
save_state() {
  local tmp="$STATE_FILE.tmp.$$"
  {
    echo "FAILS=$1"
    echo "DOWN_SINCE=$2"
    echo "LAST_ALERT=$3"
    echo "ALERTED=$4"
    echo "LAST_REASON=\"${5//\"/\\\"}\""
  } > "$tmp" 2>/dev/null && mv "$tmp" "$STATE_FILE" 2>/dev/null || rm -f "$tmp"
}
now() { date +%s; }

# ---------- 唯一的判定：容器存在且在跑 ----------
# 输出一行： ok<TAB>detail<TAB>digest    或    fail<TAB>detail<TAB>digest
probe() {
  local out rc running status health started digest
  out=$(docker inspect -f '{{.State.Running}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.StartedAt}}' "$CONTAINER" 2>/dev/null)
  rc=$?
  digest=$(docker inspect -f '{{index .Config.Image}}' "$CONTAINER" 2>/dev/null || echo "")
  if [ $rc -ne 0 ] || [ -z "$out" ]; then
    printf 'fail\t容器 %s 不存在（docker inspect 退出码 %s）\t%s\n' "$CONTAINER" "$rc" "$digest"
    return 1
  fi
  running=${out%%|*};  local rest=${out#*|}
  status=${rest%%|*};  rest=${rest#*|}
  health=${rest%%|*};  started=${rest#*|}
  if [ "$running" != "true" ]; then
    printf 'fail\t容器 %s 存在但未运行（Running=%s status=%s health=%s started=%s）\t%s\n' \
      "$CONTAINER" "$running" "$status" "$health" "$started" "$digest"
    return 1
  fi
  printf 'ok\t容器 %s 在跑（status=%s health=%s started=%s）\t%s\n' \
    "$CONTAINER" "$status" "$health" "$started" "$digest"
  return 0
}

# ---------- 部署窗口抑制 ----------
deploy_in_progress() {
  [ "$SUPPRESS_IN_DEPLOY" = "1" ] || return 1
  command -v flock >/dev/null 2>&1 || return 1
  [ -e "$DEPLOY_LOCK" ] || return 1
  # 能拿到锁 = 没有发布在跑；拿不到 = 发布链正持有它
  flock -n "$DEPLOY_LOCK" true 2>/dev/null && return 1
  return 0
}

RES=$(probe); RC=$?
DETAIL=$(printf '%s' "$RES" | cut -f2)
DIGEST=$(printf '%s' "$RES" | cut -f3)
NOW=$(now)

# ---------- 只读模式 ----------
if [ "$MODE" = "status" ]; then
  echo "== 容器守卫（每 25s 一轮，连续 $FAIL_THRESHOLD 次失败告警）=="
  printf '  探测    ：%s\n' "$([ "$RC" = "0" ] && echo OK || echo FAIL)  $DETAIL"
  printf '  镜像    ：%s\n' "${DIGEST:-（未知）}"
  printf '  状态文件：FAILS=%s DOWN_SINCE=%s LAST_ALERT=%s ALERTED=%s\n' "$FAILS" "$DOWN_SINCE" "$LAST_ALERT" "$ALERTED"
  [ "$DOWN_SINCE" -gt 0 ] 2>/dev/null && \
    printf '  故障起点：%s（已持续 %s 秒）\n' "$(date -d "@$DOWN_SINCE" '+%F %T')" "$((NOW - DOWN_SINCE))"
  [ -n "$LAST_REASON" ] && printf '  最近原因：%s\n' "$LAST_REASON"
  exit $([ "$RC" = "0" ] && echo 0 || echo 1)
fi

if [ "$MODE" = "reset" ]; then
  save_state 0 0 0 0 ""
  echo "状态已重置：$STATE_FILE"
  exit 0
fi

# ---------- 正常一轮 ----------
if [ "$RC" = "0" ]; then
  # ---- 健康 ----
  if [ "$ALERTED" = "1" ] || [ "$FAILS" -gt 0 ] 2>/dev/null; then
    SINCE=$DOWN_SINCE; [ "$SINCE" -gt 0 ] 2>/dev/null || SINCE=$NOW
    DUR=$((NOW - SINCE))
    DUR_TXT="$((DUR / 60)) 分 $((DUR % 60)) 秒"
    log "恢复：$DETAIL（故障持续 $DUR_TXT）"
    if [ "$ALERTED" = "1" ]; then
      if [ "$DRY" = "1" ]; then
        log "（dry-run）本应通知：[INFO] srv1 容器已恢复"
      else
        # 冷却键带"本次故障起点"：紧邻的第二次故障的恢复通知才不会被吞（§20 的坑）
        if NOTIFY_ENV_FILE=${NOTIFY_ENV_FILE:-} bash "$NOTIFY_SCRIPT" INFO "srv1 容器已恢复（$CONTAINER）" \
          "容器 $CONTAINER 已恢复 Running。
不可用时长：$DUR_TXT（自 $(date -d "@$SINCE" '+%F %T')）。
当前状态：$DETAIL
镜像：${DIGEST:-（未知）}
本通知由 srv1 容器守卫发出（每 25 秒一轮，连续 ${FAIL_THRESHOLD} 次失败告警）。" \
          --key "container-recovered-$CONTAINER-since-$SINCE" --cooldown 0; then
          log "恢复通知已发出"
        else
          log "[!] 恢复通知未发出（notify.sh 退出码 $?）"
        fi
      fi
      save_state 0 0 0 0 ""
      exit 3
    fi
    save_state 0 0 "$LAST_ALERT" 0 ""
    exit 3
  fi
  save_state 0 0 "$LAST_ALERT" 0 ""
  log "健康：$DETAIL"
  exit 0
fi

# ---- 失败 ----
FAILS=$((FAILS + 1))
[ "$DOWN_SINCE" -gt 0 ] 2>/dev/null || DOWN_SINCE=$NOW

if deploy_in_progress; then
  log "失败（第 $FAILS/$FAIL_THRESHOLD 次）：$DETAIL —— 但发布链正持有 $DEPLOY_LOCK，判定为[部署中]，本轮不告警（仅记录）"
  save_state "$FAILS" "$DOWN_SINCE" "$LAST_ALERT" "$ALERTED" "$DETAIL"
  exit 1
fi

if [ "$FAILS" -lt "$FAIL_THRESHOLD" ]; then
  log "失败（第 $FAILS/$FAIL_THRESHOLD 次）：$DETAIL"
  save_state "$FAILS" "$DOWN_SINCE" "$LAST_ALERT" "$ALERTED" "$DETAIL"
  exit 1
fi

log "失败（第 $FAILS 次，已达阈值 $FAIL_THRESHOLD）：$DETAIL"

# 达阈值 → 是否需要发（首次 or 冷却到期）
NEED=0
if [ "$ALERTED" != "1" ]; then
  NEED=1
elif [ "$LAST_ALERT" -gt 0 ] 2>/dev/null && [ $((NOW - LAST_ALERT)) -ge "$COOLDOWN_SEC" ]; then
  NEED=2
fi

if [ "$NEED" = "0" ]; then
  LEFT=$(( COOLDOWN_SEC - (NOW - LAST_ALERT) ))
  log "已达阈值但处于冷却期（还剩 ${LEFT}s / 共 ${COOLDOWN_SEC}s），本轮不重复告警"
  save_state "$FAILS" "$DOWN_SINCE" "$LAST_ALERT" "$ALERTED" "$DETAIL"
  exit 2
fi

TITLE="srv1 生产容器未运行"
[ "$NEED" = "2" ] && TITLE="$TITLE（仍未恢复）"
BODY="容器 ${CONTAINER} 不存在或未在运行 —— 已连续 ${FAILS} 次探测失败（≥阈值 ${FAIL_THRESHOLD}，约 $((FAILS * 25)) 秒）。
判定：$DETAIL
镜像：${DIGEST:-（未知）}
故障起点：$(date -d "@$DOWN_SINCE" '+%F %T')（已持续 $(( (NOW - DOWN_SINCE) / 60 )) 分 $(( (NOW - DOWN_SINCE) % 60 )) 秒）
检测时间：$(date '+%F %T')
本通知由 srv1 容器守卫发出（secagent-containerguard.timer，每 25 秒一轮）。
排查：docker ps -a --filter name=^/${CONTAINER}$ ; journalctl -u secagent-containerguard.service -n 30 --no-pager
恢复：走发布链（CI→ACR→digest 重建）或 systemctl start secagent-redeploy.service，不要手工 docker run。"

if [ "$DRY" = "1" ]; then
  log "（dry-run）本应通知：[$TITLE] $BODY"
  save_state "$FAILS" "$DOWN_SINCE" "$NOW" 1 "$DETAIL"
  exit 2
fi

# 冷却键带"本次故障起点"：同一次故障内不重复告警由本脚本的 LAST_ALERT 负责，
# 不依赖 notify.sh 的冷却（否则 10 分钟内第二次故障的告警会被上一次的冷却吞掉）。
if NOTIFY_ENV_FILE=${NOTIFY_ENV_FILE:-} bash "$NOTIFY_SCRIPT" HIGH "$TITLE" "$BODY" \
     --key "container-down-$CONTAINER-since-$DOWN_SINCE" --cooldown 0; then
  log "已达阈值 → 已发 HIGH「$TITLE」"
  save_state "$FAILS" "$DOWN_SINCE" "$NOW" 1 "$DETAIL"
  exit 2
else
  rc=$?
  # 【刻意行为】没发出去就【不】记 LAST_ALERT："没发出去"不等于"报过了"。
  # 下一轮（25 秒后）会重试；代价是未配置期间每轮写一行日志 —— 可见的代价，
  # 好过"以为报过了"（§20 同款取舍）。
  log "[!] 告警【没发出去】（notify.sh 退出码 $rc）。退出码 3=NOTIFY_WEBHOOK_URL 未配置 —— 此时容器没了也无人知晓；25 秒后重试。"
  save_state "$FAILS" "$DOWN_SINCE" "$LAST_ALERT" "$ALERTED" "$DETAIL"
  exit 2
fi
