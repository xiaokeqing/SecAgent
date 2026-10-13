#!/usr/bin/env bash
# ============================================================
# srv2-watch-srv1.sh —— srv2 反向盯 srv1（dead man switch / 外部心跳）
# ------------------------------------------------------------
# 为什么必须由 srv2 来盯：
#   srv1 上的看门狗（srv1-health-watchdog.sh）和应用内的通知中枢，都跑在 srv1 上。
#   srv1 整机断电/云主机故障/内核 panic 时，它们【一起死】，没人会报警。
#   所以"报警的人"必须在另一台机器上 —— 这里是 srv2，不引第三方服务。
#
# 每 3 分钟（deploy/secagent-srv1deadman.timer）探三个面：
#   ① 应用 /api/health（走公网 https://demo.xiaokeqing.cn，等价于"外部可达性"）
#   ② SSH 连通性（到 srv1:22，用一把【只能读心跳】的强制命令钥匙）
#   ③ srv1 上关键 systemd 单元是否 active（由 ② 拿回的心跳 JSON 提供）
#
# 判定：
#   任一探测面失败 = 本轮失败；连续 3 次（≈9 分钟）→ 发 HIGH
#   标题按失败面区分（不要把"单元挂了"说成"整机不可用"）：
#     ②③ 或 ①② 同时失败 → 「srv1 疑似整机不可用」
#     只有 ① 失败        → 「srv1 应用健康异常（公网不可达）」
#     只有 ② 失败        → 「srv1 SSH 不可达」
#     只有 ③ 失败        → 「srv1 关键 systemd 单元异常」
#   恢复时发一条 INFO「已恢复（不可用时长达 …）」。
#   状态落 /opt/secagent/heartbeat-state.json：一次故障只报一次，
#   仍不恢复则每 REALERT_SECONDS（默认 6h）提醒一次，避免刷屏也避免被遗忘。
#
# 退出码：0=健康；1=失败但未达阈值；2=已发告警；3=已发恢复；4=用法/配置错误
#
# 用法（srv2，root）：
#   bash srv2-watch-srv1.sh                # 正常一轮（timer 调的就是这个）
#   bash srv2-watch-srv1.sh --status       # 只看当前三个面的结果与状态文件
#   bash srv2-watch-srv1.sh --self-test    # 只检查配置/依赖是否齐（不发通知、不改状态）
# 演练（不改文件就能制造失败）：
#   SRV1_HEALTH_URL=http://127.0.0.1:9/api/health SRV1_SSH_PORT=9 bash srv2-watch-srv1.sh
# ============================================================
set -uo pipefail

PROG=$(basename "$0")

# ---------- 配置（环境变量优先，其次 /opt/secagent/heartbeat.env） ----------
CONF_FILE=${HEARTBEAT_CONF_FILE:-/opt/secagent/heartbeat.env}
if [ -f "$CONF_FILE" ]; then
  # 解析而不是 source：配置文件里的值不该被当成命令执行
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    k=${line%%=*}; v=${line#*=}
    k=$(printf '%s' "$k" | tr -d '[:space:]')
    case "$k" in
      SRV1_HEALTH_URL|SRV1_HEALTH_EXPECT|SRV1_SSH_HOST|SRV1_SSH_PORT|SRV1_SSH_USER|SRV1_SSH_KEY|SRV1_KNOWN_HOSTS|\
      SRV1_REQUIRED_UNITS|FAIL_THRESHOLD|STATE_FILE|REALERT_SECONDS|NOTIFY_SCRIPT|WATCH_LOG_FILE|NOTIFY_ENV_FILE)
        v=$(printf '%s' "$v" | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")
        # 只在环境里没有该变量时填入（printf -v 而不是 eval：值里带空格/通配符也不会被再解释一次）
        eval "[ -n \"\${$k:-}\" ]" || printf -v "$k" '%s' "$v"
        ;;
    esac
  done < "$CONF_FILE"
fi

SRV1_HEALTH_URL=${SRV1_HEALTH_URL:-https://demo.xiaokeqing.cn/api/health}
SRV1_HEALTH_EXPECT=${SRV1_HEALTH_EXPECT:-ok}
SRV1_HEALTH_TIMEOUT=${SRV1_HEALTH_TIMEOUT:-15}
SRV1_SSH_HOST=${SRV1_SSH_HOST:-47.96.106.187}
SRV1_SSH_PORT=${SRV1_SSH_PORT:-22}
SRV1_SSH_USER=${SRV1_SSH_USER:-root}
SRV1_SSH_KEY=${SRV1_SSH_KEY:-/etc/secagent/heartbeat/srv1_ed25519}
SRV1_KNOWN_HOSTS=${SRV1_KNOWN_HOSTS:-/var/lib/secagent/heartbeat/known_hosts}
SRV1_SSH_TIMEOUT=${SRV1_SSH_TIMEOUT:-10}
SRV1_REQUIRED_UNITS=${SRV1_REQUIRED_UNITS:-"secagent-redeploy.timer secagent-healthwatch.timer"}
FAIL_THRESHOLD=${FAIL_THRESHOLD:-3}
STATE_FILE=${STATE_FILE:-/opt/secagent/heartbeat-state.json}
REALERT_SECONDS=${REALERT_SECONDS:-21600}
NOTIFY_SCRIPT=${NOTIFY_SCRIPT:-/opt/secagent/scripts/notify.sh}
WATCH_LOG_FILE=${WATCH_LOG_FILE:-/opt/secagent/logs/srv1-watch.log}

MODE=check
case "${1:-}" in
  --status)    MODE=status ;;
  --self-test) MODE=selftest ;;
  --reset-state) MODE=reset ;;
  --help|-h)   sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac

mkdir -p "$(dirname "$WATCH_LOG_FILE")" 2>/dev/null || WATCH_LOG_FILE=""
log() {
  local line; line="$(date '+%F %T') [$PROG] $*"
  if [ -n "$WATCH_LOG_FILE" ]; then printf '%s\n' "$line" >> "$WATCH_LOG_FILE" 2>/dev/null || printf '%s\n' "$line" >&2
  else printf '%s\n' "$line" >&2; fi
}

je() { # JSON 字符串转义
  # 【实测踩坑】只删控制字符是不够的：ssh 的 stderr 里带 CR（"\r\n"），
  #   原样写进 JSON 字符串就是【非法 JSON】（RFC 8259 要求 <0x20 必须转义）。
  #   所以先把 \ \r \n \t 转成转义序列，再清掉剩下的控制字符。
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\r'/\\r}
  s=${s//$'\n'/\\n}
  s=${s//$'\t'/\\t}
  printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037'
}

# ---------- 状态文件读写（不引 jq） ----------
state_num() { # $1=键
  [ -f "$STATE_FILE" ] || { echo 0; return; }
  local v; v=$(sed -n 's/.*"'"$1"'":[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' "$STATE_FILE" | head -1)
  echo "${v:-0}"
}
state_str() { # $1=键
  [ -f "$STATE_FILE" ] || { echo ""; return; }
  sed -n 's/.*"'"$1"'":[[:space:]]*"\([^"]*\)".*/\1/p' "$STATE_FILE" | head -1
}
write_state() { # 参数见下（全部已转义过的字符串/数字）
  local tmp="$STATE_FILE.tmp.$$"
  {
    printf '{\n'
    printf '  "schema": "secagent-heartbeat-state/1",\n'
    printf '  "updated": "%s",\n' "$(je "$UPDATED")"
    printf '  "updated_epoch": %s,\n' "$NOW"
    printf '  "state": "%s",\n' "$(je "$ST_STATE")"
    printf '  "consecutive_failures": %s,\n' "$ST_FAILS"
    printf '  "threshold": %s,\n' "$FAIL_THRESHOLD"
    printf '  "last_ok": "%s",\n' "$(je "$ST_LAST_OK_H")"
    printf '  "last_ok_epoch": %s,\n' "$ST_LAST_OK"
    printf '  "down_since": "%s",\n' "$(je "$ST_DOWN_SINCE_H")"
    printf '  "down_since_epoch": %s,\n' "$ST_DOWN_SINCE"
    printf '  "outage_seconds": %s,\n' "$ST_OUTAGE"
    printf '  "last_alert": "%s",\n' "$(je "$ST_LAST_ALERT_H")"
    printf '  "last_alert_epoch": %s,\n' "$ST_LAST_ALERT"
    printf '  "failed_faces": "%s",\n' "$(je "$FAILED_FACES")"
    printf '  "probes": {\n'
    printf '    "health": {"ok": %s, "detail": "%s"},\n' "$P_HEALTH_OK" "$(je "$P_HEALTH_D")"
    printf '    "ssh": {"ok": %s, "detail": "%s"},\n' "$P_SSH_OK" "$(je "$P_SSH_D")"
    printf '    "units": {"ok": %s, "detail": "%s"},\n' "$P_UNITS_OK" "$(je "$P_UNITS_D")"
    printf '    "heartbeat_raw": "%s"\n' "$(je "$HEARTBEAT_RAW")"
    printf '  }\n'
    printf '}\n'
  } > "$tmp" 2>/dev/null && mv "$tmp" "$STATE_FILE" 2>/dev/null || { rm -f "$tmp"; log "[!] 状态文件写不进去：$STATE_FILE"; }
}

# ---------- 三个探测面 ----------
probe_health() {
  local body code
  body=$(mktemp 2>/dev/null || echo /tmp/hb.$$)
  code=$(curl -sS -m "$SRV1_HEALTH_TIMEOUT" -o "$body" -w '%{http_code}' "$SRV1_HEALTH_URL" 2>/dev/null)
  local rc=$?
  if [ "$rc" != "0" ]; then
    P_HEALTH_OK=false; P_HEALTH_D="curl 失败(rc=$rc)：$SRV1_HEALTH_URL"; rm -f "$body"; return 1
  fi
  case "$code" in
    2*) : ;;
    *) P_HEALTH_OK=false; P_HEALTH_D="HTTP $code：$SRV1_HEALTH_URL"; rm -f "$body"; return 1 ;;
  esac
  if grep -qE "\"status\"[[:space:]]*:[[:space:]]*\"$SRV1_HEALTH_EXPECT\"" "$body" 2>/dev/null; then
    local commit
    commit=$(sed -n 's/.*"embeddedGitCommit":"\([^"]*\)".*/\1/p' "$body" | head -1)
    P_HEALTH_OK=true; P_HEALTH_D="HTTP $code status=$SRV1_HEALTH_EXPECT commit=${commit:-?}"
    rm -f "$body"; return 0
  fi
  local got
  got=$(sed -n 's/.*"status":"\([^"]*\)".*/\1/p' "$body" | head -1)
  P_HEALTH_OK=false; P_HEALTH_D="HTTP $code 但 status=${got:-无法解析}（期望 $SRV1_HEALTH_EXPECT）"
  rm -f "$body"; return 1
}

probe_ssh() {
  local out rc
  if [ ! -f "$SRV1_SSH_KEY" ]; then
    P_SSH_OK=false; P_SSH_D="找不到私钥 $SRV1_SSH_KEY"; HEARTBEAT_RAW=""; return 1
  fi
  # known_hosts 放 /var/lib（systemd 的 ProtectSystem=full 下 /etc 只读，写不进去）
  mkdir -p "$(dirname "$SRV1_KNOWN_HOSTS")" 2>/dev/null || true
  touch "$SRV1_KNOWN_HOSTS" 2>/dev/null || true
  out=$(ssh -i "$SRV1_SSH_KEY" -p "$SRV1_SSH_PORT" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o UserKnownHostsFile="$SRV1_KNOWN_HOSTS" -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout="$SRV1_SSH_TIMEOUT" \
        "$SRV1_SSH_USER@$SRV1_SSH_HOST" secagent-heartbeat 2>/tmp/hb-ssh-err.$$)
  rc=$?
  local err; err=$(head -c 200 /tmp/hb-ssh-err.$$ 2>/dev/null | tr -d '\n'); rm -f /tmp/hb-ssh-err.$$
  HEARTBEAT_RAW="$out"
  if [ "$rc" != "0" ]; then
    P_SSH_OK=false; P_SSH_D="ssh rc=$rc $SRV1_SSH_USER@$SRV1_SSH_HOST:$SRV1_SSH_PORT ${err:+| $err}"; return 1
  fi
  if ! printf '%s' "$out" | grep -q '"marker":"secagent-heartbeat/1"'; then
    P_SSH_OK=false; P_SSH_D="SSH 通了但没拿到心跳（强制命令没生效/被改？）"; return 1
  fi
  P_SSH_OK=true; P_SSH_D="ssh ok：$(printf '%s' "$out" | head -c 60)…"; return 0
}

hb_get() { # $1=键名 → 心跳 JSON 里的值（找不到给空）
  printf '%s' "$HEARTBEAT_RAW" | grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"[a-z]+\"" \
    | sed -n 's/.*"\([a-z]*\)"$/\1/p' | head -1
}

probe_units() {
  if [ "$P_SSH_OK" != "true" ]; then
    P_UNITS_OK=false; P_UNITS_D="SSH 不可达，无法核对单元（顺带失败）"; return 1
  fi
  local bad="" u st comp cst note good=""
  for u in $SRV1_REQUIRED_UNITS; do
    st=$(hb_get "$u")
    [ -n "$st" ] || st=missing
    note=""
    # 【2026-10-13 实测】部署期间 secagent-redeploy.timer 会被重启，is-active 的
    # 瞬间读到 inactive —— 那时它的 companion service 正在跑。这种情况是"系统在正常工作"，
    # 不是"关键单元挂了"：若不区分，每次发布都会误报一次整机故障。
    # 但降级为 OK 的同时把原因写进 detail，绝不悄悄放过（可见，而不是隐藏）。
    if [ "$st" != "active" ]; then
      case "$u" in
        *.timer)
          comp="${u%.timer}.service"
          cst=$(hb_get "$comp")
          case "$cst" in
            active|activating|deactivating)
              st=active
              note="（部署进行中：$comp=$cst，timer 暂时停止，不算故障）" ;;
          esac ;;
      esac
    fi
    if [ "$st" != "active" ]; then
      bad="$bad $u=$st"
    else
      good="$good $u${note:+ $note}"
    fi
  done
  if [ -n "$bad" ]; then
    P_UNITS_OK=false; P_UNITS_D="关键单元非 active：$bad"; return 1
  fi
  P_UNITS_OK=true; P_UNITS_D="关键单元 OK：$good"
  return 0
}

run_probes() {
  P_HEALTH_OK=false; P_HEALTH_D=""; P_SSH_OK=false; P_SSH_D=""; P_UNITS_OK=false; P_UNITS_D=""
  HEARTBEAT_RAW=""
  probe_health || true
  probe_ssh    || true
  probe_units  || true
  FAILED_FACES=""
  [ "$P_HEALTH_OK" = "true" ] || FAILED_FACES="${FAILED_FACES}health "
  [ "$P_SSH_OK"    = "true" ] || FAILED_FACES="${FAILED_FACES}ssh "
  [ "$P_UNITS_OK"  = "true" ] || FAILED_FACES="${FAILED_FACES}units "
  FAILED_FACES=$(printf '%s' "$FAILED_FACES" | sed 's/[[:space:]]*$//')
}

if [ "$MODE" = "selftest" ]; then
  echo "== 依赖与配置自检 =="
  printf '  notify.sh      : '; [ -f "$NOTIFY_SCRIPT" ] && echo "$NOTIFY_SCRIPT" || echo "[X] 缺失"
  printf '  ssh 私钥       : '; [ -f "$SRV1_SSH_KEY" ] && echo "$SRV1_SSH_KEY" || echo "[X] 缺失（先跑 scripts/srv2-gen-heartbeat-key.sh）"
  printf '  curl/python3   : '; command -v curl >/dev/null && printf 'curl ' ; command -v python3 >/dev/null && printf 'python3' ; echo
  printf '  心跳地址       : %s（期望 status=%s）\n' "$SRV1_HEALTH_URL" "$SRV1_HEALTH_EXPECT"
  printf '  SSH 目标       : %s@%s:%s\n' "$SRV1_SSH_USER" "$SRV1_SSH_HOST" "$SRV1_SSH_PORT"
  printf '  必须 active 的 : %s\n' "$SRV1_REQUIRED_UNITS"
  printf '  阈值/状态文件  : %s 次 → %s\n' "$FAIL_THRESHOLD" "$STATE_FILE"
  printf '  通知配置       : '; NOTIFY_ENV_FILE=${NOTIFY_ENV_FILE:-} bash "$NOTIFY_SCRIPT" INFO selftest "自检" --dry-run >/dev/null 2>&1 && echo "可渲染（dry-run 通过）" || echo "[!] notify.sh dry-run 失败或未配置 URL（未配置 URL 时告警只能写日志，见 RUNBOOK §20）"
  exit 0
fi

if [ "$MODE" = "reset" ]; then
  run_probes
  ST_STATE=unknown; ST_FAILS=0; ST_LAST_OK=0; ST_LAST_OK_H=""; ST_DOWN_SINCE=0; ST_DOWN_SINCE_H=""
  ST_OUTAGE=0; ST_LAST_ALERT=0; ST_LAST_ALERT_H=""; NOW=$(date +%s); UPDATED=$(date '+%F %T')
  write_state
  echo "状态已重置：$STATE_FILE"
  exit 0
fi

if [ "$MODE" = "status" ]; then
  run_probes
  echo "== srv2 看 srv1：三个探测面 =="
  printf '  ① 应用健康 : %s  %s\n' "$([ "$P_HEALTH_OK" = true ] && echo OK || echo FAIL)" "$P_HEALTH_D"
  printf '  ② SSH 连通 : %s  %s\n' "$([ "$P_SSH_OK" = true ] && echo OK || echo FAIL)" "$P_SSH_D"
  printf '  ③ 关键单元 : %s  %s\n' "$([ "$P_UNITS_OK" = true ] && echo OK || echo FAIL)" "$P_UNITS_D"
  printf '  失败面     : %s\n' "${FAILED_FACES:-无}"
  echo
  echo "== 状态文件 $STATE_FILE =="
  if [ -f "$STATE_FILE" ]; then cat "$STATE_FILE"; else echo "（还没有状态文件）"; fi
  exit 0
fi

# ---------- 正常一轮 ----------
NOW=$(date +%s); UPDATED=$(date '+%F %T')
PREV_FAILS=$(state_num consecutive_failures)
PREV_STATE=$(state_str state)
ST_LAST_OK=$(state_num last_ok_epoch)
ST_LAST_ALERT=$(state_num last_alert_epoch)
ST_DOWN_SINCE=$(state_num down_since_epoch)
ST_LAST_OK_H="$(state_str last_ok)"
ST_LAST_ALERT_H="$(state_str last_alert)"
ST_DOWN_SINCE_H="$(state_str down_since)"

run_probes

if [ -z "$FAILED_FACES" ]; then
  # ---- 健康 ----
  ST_LAST_OK=$NOW; ST_LAST_OK_H="$UPDATED"
  if [ "$PREV_FAILS" -gt 0 ] && [ "$PREV_STATE" != "up" ]; then
    local_since=$ST_DOWN_SINCE; [ "$local_since" -gt 0 ] || local_since=$NOW
    DUR=$((NOW - local_since))
    DUR_TXT="$((DUR / 60)) 分 $((DUR % 60)) 秒"
    log "恢复：三面皆通（故障持续 $DUR_TXT）→ 发 INFO 恢复通知"
    # 冷却键带上"本次故障的起点"：否则相隔不到 10 分钟的第二次故障，
    # 它的恢复通知会被【上一次恢复】的冷却吞掉（演练时实测到）。
    NOTIFY_ENV_FILE=${NOTIFY_ENV_FILE:-} bash "$NOTIFY_SCRIPT" INFO "srv1 已恢复" \
      "srv1 三个探测面已全部恢复。不可用/降级时长：$DUR_TXT（自 $ST_DOWN_SINCE_H）。健康详情：$P_HEALTH_D" \
      --key "srv1-recovered-since-$local_since" || log "[!] 恢复通知未发出（notify.sh 退出码 $?）"
    ST_STATE=up; ST_FAILS=0; ST_DOWN_SINCE=0; ST_DOWN_SINCE_H=""; ST_OUTAGE=0; ST_LAST_ALERT=0; ST_LAST_ALERT_H=""
    write_state
    exit 3
  fi
  ST_STATE=up; ST_FAILS=0; ST_DOWN_SINCE=0; ST_DOWN_SINCE_H=""; ST_OUTAGE=0
  write_state
  log "健康：$P_HEALTH_D | $P_SSH_D | $P_UNITS_D"
  exit 0
fi

# ---- 失败 ----
ST_FAILS=$((PREV_FAILS + 1))
[ "$ST_DOWN_SINCE" -gt 0 ] || { ST_DOWN_SINCE=$NOW; ST_DOWN_SINCE_H="$UPDATED"; }
ST_OUTAGE=$((NOW - ST_DOWN_SINCE))
# 计数显示：超过阈值后别再写"第 4/3 次"（4/3 会让人以为计数坏了）
if [ "$ST_FAILS" -lt "$FAIL_THRESHOLD" ]; then
  FAIL_TXT="第 $ST_FAILS/$FAIL_THRESHOLD 次"
else
  FAIL_TXT="第 $ST_FAILS 次（已达阈值 $FAIL_THRESHOLD）"
fi
log "失败（$FAIL_TXT，失败面=[$FAILED_FACES]）：$P_HEALTH_D | $P_SSH_D | $P_UNITS_D"

if [ "$ST_FAILS" -lt "$FAIL_THRESHOLD" ]; then
  ST_STATE=$([ "$PREV_STATE" = "down" ] && echo down || echo degraded)
  write_state
  exit 1
fi

# 达阈值：决定标题（不要把"单元挂了"说成"整机不可用"）
if printf '%s' "$FAILED_FACES" | grep -q health && printf '%s' "$FAILED_FACES" | grep -q ssh; then
  TITLE="srv1 疑似整机不可用"; KIND="整机不可用"
elif printf '%s' "$FAILED_FACES" | grep -q ssh; then
  TITLE="srv1 SSH 不可达"; KIND="SSH 不可达"
elif printf '%s' "$FAILED_FACES" | grep -q health; then
  TITLE="srv1 应用健康异常（公网不可达）"; KIND="应用健康异常"
else
  TITLE="srv1 关键 systemd 单元异常"; KIND="关键单元异常"
fi

ST_STATE=down
NEED_NOTIFY=0
if [ "$ST_LAST_ALERT" -eq 0 ]; then
  NEED_NOTIFY=1
elif [ $((NOW - ST_LAST_ALERT)) -ge "$REALERT_SECONDS" ]; then
  NEED_NOTIFY=2   # 仍未恢复的定期提醒
fi

BODY="连续 ${ST_FAILS} 次探测失败（≥阈值 ${FAIL_THRESHOLD}，约 $((ST_FAILS * 3)) 分钟），判定：${KIND}。
失败面：${FAILED_FACES}
① 应用健康：${P_HEALTH_D}
② SSH 连通：${P_SSH_D}
③ 关键单元：${P_UNITS_D}
不可用起点：${ST_DOWN_SINCE_H}（已持续 $((ST_OUTAGE / 60)) 分 $((ST_OUTAGE % 60)) 秒）
srv2 侧探测时间：${UPDATED}
排查入口：ssh secagent-srv1 'systemctl status secagent-redeploy.timer secagent-healthwatch.timer'
（本通知由 srv2 的 dead man switch 发出：srv1 整机失联时，它自己的看门狗发不出任何东西。）"

if [ "$NEED_NOTIFY" -eq 1 ]; then
  log "达阈值 → 发 HIGH「$TITLE」"
  # 冷却键带上"本次故障起点"：否则【10 分钟内第二次故障】的告警会被上一次的冷却吞掉
  # （复验时实测到：第二次故障的 HIGH 只写进日志，sink 里什么都没收到）。
  # 同一次故障内不重复告警由本脚本的 last_alert_epoch 负责，不依赖 notify.sh 的冷却。
  if NOTIFY_ENV_FILE=${NOTIFY_ENV_FILE:-} bash "$NOTIFY_SCRIPT" HIGH "$TITLE" "$BODY" --key "srv1-down-$TITLE-since-$ST_DOWN_SINCE"; then
    ST_LAST_ALERT=$NOW; ST_LAST_ALERT_H="$UPDATED"
    write_state
    exit 2
  else
    rc=$?
    # 【刻意行为】通知没发出去时【不】记 last_alert：
    #   "没发出去"不等于"报过了"。下一轮 timer（3 分钟后）会重试，
    #   这样即使当时的 NOTIFY_WEBHOOK_URL 是空的，配好之后仍会立刻补发出去。
    #   代价是未配置期间每 3 分钟写一行日志 —— 这是可见的代价，比"以为报过了"好。
    log "[!] 告警【没发出去】（notify.sh 退出码 $rc）。注意：退出码 3=未配置 NOTIFY_WEBHOOK_URL —— 此时整机失联无人知晓；下一轮会重试。"
    write_state
    exit 2
  fi
elif [ "$NEED_NOTIFY" -eq 2 ]; then
  log "仍未恢复，超过 $((REALERT_SECONDS / 3600))h → 再提醒一次"
  NOTIFY_ENV_FILE=${NOTIFY_ENV_FILE:-} bash "$NOTIFY_SCRIPT" HIGH "$TITLE（仍未恢复）" "$BODY" --key "srv1-down-$TITLE-since-$ST_DOWN_SINCE" --cooldown 0 || log "[!] 提醒未发出（退出码 $?）"
  ST_LAST_ALERT=$NOW; ST_LAST_ALERT_H="$UPDATED"
  write_state
  exit 2
else
  log "已达阈值但本轮不重复告警（上次告警 $ST_LAST_ALERT_H，重提醒间隔 $((REALERT_SECONDS / 3600))h）"
  write_state
  exit 2
fi
