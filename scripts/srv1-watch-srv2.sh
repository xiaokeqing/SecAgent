#!/usr/bin/env bash
# ============================================================
# srv1-watch-srv2.sh —— srv1 反向盯 srv2（对称的 dead man switch）
# ------------------------------------------------------------
# 为什么需要它（改之前的缺口）：
#   原来只有 srv2 盯 srv1（deploy/secagent-srv1deadman.timer + scripts/srv2-watch-srv1.sh）。
#   可 srv2 是检测/索引器 + 异地备份的接收端：它挂了，Wazuh 告警、备份落盘、
#   备份抽测全部【静默停止】，而 srv1 看上去一切正常 —— 没有任何人会知道。
#   这就是"单向探活"的盲区，本脚本补上反方向。
#
# 每 3 分钟（deploy/secagent-srv2deadman.timer）探三个面：
#   ① SSH + 心跳：用一把【只能读心跳】的强制命令钥匙连 srv2，取回心跳 JSON
#       （等价于"sshd 活着 + 强制命令没被改 + 应答脚本能跑"）
#   ② 关键容器（含 Suricata）：心跳 JSON 里 wazuh.indexer / wazuh.manager /
#       wazuh.dashboard / cowrie / suricata 是否都是 running
#   ③ 备份与密钥：心跳 JSON 里"最新备份有多旧"（超过 SRV2_BACKUP_MAX_AGE 算失败）
#      与"解密密钥是否还在"—— 备份链断掉是 srv2 最容易被忽略的失效方式
#
# 判定（与 srv2-watch-srv1.sh 同一套口径）：
#   任一面失败 = 本轮失败；连续 FAIL_THRESHOLD（默认 3）次（≈9 分钟）→ 发 HIGH
#   标题按失败面区分，绝不把"一个容器挂了"说成"整机不可用"：
#     ① 也失败（多半是整机/网络没了）→ 「srv2 疑似整机不可用」
#     只有 ① 失败                    → 「srv2 SSH 不可达」
#     只有 ② 失败                    → 「srv2 关键容器异常」
#     只有 ③ 失败                    → 「srv2 备份/密钥状态异常」
#   恢复时发一条 INFO「已恢复（不可用时长达 …）」，冷却键带"本次故障起点"。
#   状态落 /opt/secagent/state/srv2-watch-state.json：一次故障只报一次，
#   仍不恢复则每 REALERT_SECONDS（默认 6h）提醒一次。
#
# 退出码：0=健康；1=失败但未达阈值；2=已发告警；3=已发恢复；4=用法/配置错误
#
# 用法（srv1，root）：
#   bash srv1-watch-srv2.sh                # 正常一轮（timer 调的就是这个）
#   bash srv1-watch-srv2.sh --status       # 只看当前三个面的结果与状态文件
#   bash srv1-watch-srv2.sh --self-test    # 只检查配置/依赖是否齐（不发通知、不改状态）
#   bash srv1-watch-srv2.sh --reset-state
# 演练（不改文件就能制造失败）：
#   SRV2_SSH_PORT=9 bash srv1-watch-srv2.sh          # 模拟 SSH 面失败
#   SRV2_REQUIRED_CONTAINERS="no-such-container" bash srv1-watch-srv2.sh
# 临时关闭：systemctl disable --now secagent-srv2deadman.timer
# ============================================================
set -uo pipefail

PROG=$(basename "$0")

# ---------- 配置（环境变量优先，其次 /opt/secagent/srv2watch.env） ----------
CONF_FILE=${SRV2WATCH_CONF_FILE:-/opt/secagent/srv2watch.env}
if [ -f "$CONF_FILE" ]; then
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    k=${line%%=*}; v=${line#*=}
    k=$(printf '%s' "$k" | tr -d '[:space:]')
    case "$k" in
      SRV2_SSH_HOST|SRV2_SSH_PORT|SRV2_SSH_USER|SRV2_SSH_KEY|SRV2_KNOWN_HOSTS|SRV2_SSH_TIMEOUT|\
      SRV2_REQUIRED_CONTAINERS|SRV2_BACKUP_MAX_AGE|FAIL_THRESHOLD|STATE_FILE|REALERT_SECONDS|\
      NOTIFY_SCRIPT|WATCH_LOG_FILE|NOTIFY_ENV_FILE)
        v=$(printf '%s' "$v" | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")
        eval "[ -n \"\${$k:-}\" ]" || printf -v "$k" '%s' "$v"
        ;;
    esac
  done < "$CONF_FILE"
fi

SRV2_SSH_HOST=${SRV2_SSH_HOST:-43.143.114.79}
SRV2_SSH_PORT=${SRV2_SSH_PORT:-22}
SRV2_SSH_USER=${SRV2_SSH_USER:-root}
SRV2_SSH_KEY=${SRV2_SSH_KEY:-/etc/secagent/heartbeat/srv2_ed25519}
SRV2_KNOWN_HOSTS=${SRV2_KNOWN_HOSTS:-/var/lib/secagent/heartbeat/known_hosts-srv2}
SRV2_SSH_TIMEOUT=${SRV2_SSH_TIMEOUT:-10}
SRV2_REQUIRED_CONTAINERS=${SRV2_REQUIRED_CONTAINERS:-"wazuh.indexer wazuh.manager cowrie suricata"}
SRV2_BACKUP_MAX_AGE=${SRV2_BACKUP_MAX_AGE:-129600}   # 36h：备份每天 03:30 一次，留足余量
FAIL_THRESHOLD=${FAIL_THRESHOLD:-3}
STATE_FILE=${STATE_FILE:-/opt/secagent/state/srv2-watch-state.json}
REALERT_SECONDS=${REALERT_SECONDS:-21600}
NOTIFY_SCRIPT=${NOTIFY_SCRIPT:-/opt/secagent/scripts/notify.sh}
WATCH_LOG_FILE=${WATCH_LOG_FILE:-/opt/secagent/logs/srv2-watch.log}

MODE=check
case "${1:-}" in
  --status)      MODE=status ;;
  --self-test)   MODE=selftest ;;
  --reset-state) MODE=reset ;;
  --help|-h)     sed -n '2,48p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac

mkdir -p "$(dirname "$WATCH_LOG_FILE")" "$(dirname "$STATE_FILE")" 2>/dev/null || WATCH_LOG_FILE=""
log() {
  local line; line="$(date '+%F %T') [$PROG] $*"
  if [ -n "$WATCH_LOG_FILE" ]; then printf '%s\n' "$line" >> "$WATCH_LOG_FILE" 2>/dev/null || printf '%s\n' "$line" >&2
  else printf '%s\n' "$line" >&2; fi
}

je() { # JSON 字符串转义（ssh stderr 里的 CR 不转义会产出非法 JSON）
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\r'/\\r}
  s=${s//$'\n'/\\n}
  s=${s//$'\t'/\\t}
  printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037'
}

# ---------- 状态文件读写（不引 jq；与 srv2-watch-srv1.sh 同一套） ----------
state_num() {
  [ -f "$STATE_FILE" ] || { echo 0; return; }
  local v; v=$(sed -n 's/.*"'"$1"'":[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' "$STATE_FILE" | head -1)
  echo "${v:-0}"
}
state_str() {
  [ -f "$STATE_FILE" ] || { echo ""; return; }
  sed -n 's/.*"'"$1"'":[[:space:]]*"\([^"]*\)".*/\1/p' "$STATE_FILE" | head -1
}
write_state() {
  local tmp="$STATE_FILE.tmp.$$"
  {
    printf '{\n'
    printf '  "schema": "secagent-srv2watch-state/1",\n'
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
    printf '    "ssh": {"ok": %s, "detail": "%s"},\n' "$P_SSH_OK" "$(je "$P_SSH_D")"
    printf '    "containers": {"ok": %s, "detail": "%s"},\n' "$P_CONT_OK" "$(je "$P_CONT_D")"
    printf '    "backups": {"ok": %s, "detail": "%s"},\n' "$P_BAK_OK" "$(je "$P_BAK_D")"
    printf '    "heartbeat_raw": "%s"\n' "$(je "$HEARTBEAT_RAW")"
    printf '  }\n'
    printf '}\n'
  } > "$tmp" 2>/dev/null && mv "$tmp" "$STATE_FILE" 2>/dev/null || { rm -f "$tmp"; log "[!] 状态文件写不进去：$STATE_FILE"; }
}

# ---------- 心跳 JSON 取值 ----------
hb_str()  { printf '%s' "$HEARTBEAT_RAW" | sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p' | head -1; }
hb_num()  { printf '%s' "$HEARTBEAT_RAW" | sed -n 's/.*"'"$1"'":[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -1; }
hb_bool() { printf '%s' "$HEARTBEAT_RAW" | sed -n 's/.*"'"$1"'":\(true\|false\).*/\1/p' | head -1; }
cont_state() { # 1=容器名
  printf '%s' "$HEARTBEAT_RAW" | sed -n 's/.*"containers":{\([^}]*\)}.*/\1/p' \
    | tr ',' '\n' | sed -n 's/^"'"$1"'":"\([a-z]*\)"$/\1/p' | head -1
}

# ---------- 探测面 ①：SSH + 心跳 ----------
probe_ssh() {
  local out rc
  if [ ! -f "$SRV2_SSH_KEY" ]; then
    P_SSH_OK=false; P_SSH_D="找不到私钥 $SRV2_SSH_KEY（先跑 scripts/srv1-gen-srv2-heartbeat-key.sh 并在 srv2 授权）"
    HEARTBEAT_RAW=""; return 1
  fi
  mkdir -p "$(dirname "$SRV2_KNOWN_HOSTS")" 2>/dev/null || true
  touch "$SRV2_KNOWN_HOSTS" 2>/dev/null || true
  # 【踩坑】必须加 -n：ssh 默认会去读 stdin 转发给对端。本脚本经常被
  #   `bash srv1-watch-srv2.sh` 以「脚本从 stdin 读入」的方式跑
  #   （例如 ssh srv1 'sudo bash -s' < script），此时 ssh 会把【剩下的脚本内容】
  #   当 stdin 吞掉，脚本就此截断、静默只跑一半。心跳命令不需要 stdin。
  out=$(ssh -n -i "$SRV2_SSH_KEY" -p "$SRV2_SSH_PORT" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o UserKnownHostsFile="$SRV2_KNOWN_HOSTS" -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout="$SRV2_SSH_TIMEOUT" \
        "$SRV2_SSH_USER@$SRV2_SSH_HOST" secagent-srv2-heartbeat 2>/tmp/srv2hb-err.$$)
  rc=$?
  local err; err=$(head -c 200 /tmp/srv2hb-err.$$ 2>/dev/null | tr -d '\n'); rm -f /tmp/srv2hb-err.$$
  HEARTBEAT_RAW="$out"
  if [ "$rc" != "0" ]; then
    P_SSH_OK=false; P_SSH_D="ssh rc=$rc $SRV2_SSH_USER@$SRV2_SSH_HOST:$SRV2_SSH_PORT ${err:+| $err}"; return 1
  fi
  if ! printf '%s' "$out" | grep -q '"marker":"secagent-srv2-heartbeat/1"'; then
    P_SSH_OK=false; P_SSH_D="SSH 通了但没拿到 srv2 心跳（强制命令没生效/被改？）"; return 1
  fi
  P_SSH_OK=true; P_SSH_D="ssh ok：$(printf '%s' "$out" | head -c 60)…"; return 0
}

# ---------- 探测面 ②：关键容器（含 Suricata） ----------
probe_containers() {
  if [ "$P_SSH_OK" != "true" ]; then
    P_CONT_OK=false; P_CONT_D="SSH 不可达，无法核对容器（顺带失败）"; return 1
  fi
  local bad="" good="" c st
  for c in $SRV2_REQUIRED_CONTAINERS; do
    st=$(cont_state "$c")
    [ -n "$st" ] || st=missing
    if [ "$st" != "running" ]; then bad="$bad $c=$st"; else good="$good $c=running"; fi
  done
  local idx; idx=$(hb_str indexer_health)
  if [ -n "$bad" ]; then
    P_CONT_OK=false; P_CONT_D="关键容器非 running：$bad（索引器 health=${idx:-?}）"; return 1
  fi
  P_CONT_OK=true; P_CONT_D="关键容器 OK：$good（索引器 health=${idx:-?}）"
  return 0
}

# ---------- 探测面 ③：备份新鲜度 + 密钥 ----------
probe_backups() {
  if [ "$P_SSH_OK" != "true" ]; then
    P_BAK_OK=false; P_BAK_D="SSH 不可达，无法核对备份状态（顺带失败）"; return 1
  fi
  local age cnt latest keyp enc msg=""
  age=$(hb_num age_s);  [ -n "$age" ] || age=-1
  cnt=$(hb_num count);  [ -n "$cnt" ] || cnt=0
  keyp=$(hb_bool key_present); enc=$(hb_bool enc)
  latest=$(hb_str latest)
  if [ "$keyp" != "true" ]; then
    P_BAK_OK=false; P_BAK_D="srv2 上解密密钥不在了（key_present=$keyp）—— 加密备份当前解不开"; return 1
  fi
  if [ "$cnt" -eq 0 ] 2>/dev/null; then
    P_BAK_OK=false; P_BAK_D="srv2 上没有任何备份（count=0）"; return 1
  fi
  if [ "$age" -lt 0 ] 2>/dev/null; then
    P_BAK_OK=false; P_BAK_D="拿不到最新备份的时间（latest=${latest:-空}）"; return 1
  fi
  if [ "$age" -gt "$SRV2_BACKUP_MAX_AGE" ]; then
    P_BAK_OK=false
    P_BAK_D="最新备份 ${latest} 已有 $((age / 3600)) 小时（阈值 $((SRV2_BACKUP_MAX_AGE / 3600))h）—— 备份链可能断了"
    return 1
  fi
  P_BAK_OK=true
  P_BAK_D="备份 OK：最新 ${latest}（$((age / 3600))h 前，共 ${cnt} 份，enc=${enc}, key=存在）"
  return 0
}

run_probes() {
  P_SSH_OK=false; P_SSH_D=""; P_CONT_OK=false; P_CONT_D=""; P_BAK_OK=false; P_BAK_D=""
  HEARTBEAT_RAW=""
  probe_ssh        || true
  probe_containers || true
  probe_backups    || true
  FAILED_FACES=""
  [ "$P_SSH_OK"  = "true" ] || FAILED_FACES="${FAILED_FACES}ssh "
  [ "$P_CONT_OK" = "true" ] || FAILED_FACES="${FAILED_FACES}containers "
  [ "$P_BAK_OK"  = "true" ] || FAILED_FACES="${FAILED_FACES}backups "
  FAILED_FACES=$(printf '%s' "$FAILED_FACES" | sed 's/[[:space:]]*$//')
}

if [ "$MODE" = "selftest" ]; then
  echo "== 依赖与配置自检 =="
  printf '  notify.sh      : '; [ -f "$NOTIFY_SCRIPT" ] && echo "$NOTIFY_SCRIPT" || echo "[X] 缺失"
  printf '  ssh 私钥       : '; [ -f "$SRV2_SSH_KEY" ] && echo "$SRV2_SSH_KEY" || echo "[X] 缺失（先跑 scripts/srv1-gen-srv2-heartbeat-key.sh）"
  printf '  ssh / python3  : '; command -v ssh >/dev/null && printf 'ssh ' ; command -v python3 >/dev/null && printf 'python3' ; echo
  printf '  SSH 目标       : %s@%s:%s\n' "$SRV2_SSH_USER" "$SRV2_SSH_HOST" "$SRV2_SSH_PORT"
  printf '  必须 running 的: %s\n' "$SRV2_REQUIRED_CONTAINERS"
  printf '  备份最大年龄   : %ss（%sh）\n' "$SRV2_BACKUP_MAX_AGE" "$((SRV2_BACKUP_MAX_AGE / 3600))"
  printf '  阈值/状态文件  : %s 次 → %s\n' "$FAIL_THRESHOLD" "$STATE_FILE"
  printf '  通知配置       : '; NOTIFY_ENV_FILE=${NOTIFY_ENV_FILE:-} bash "$NOTIFY_SCRIPT" INFO selftest "自检" --dry-run >/dev/null 2>&1 && echo "可渲染（dry-run 通过）" || echo "[!] notify.sh dry-run 失败或未配置 URL（未配置 URL 时告警只能写日志）"
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
  echo "== srv1 看 srv2：三个探测面 =="
  printf '  ① SSH+心跳   : %s  %s\n' "$([ "$P_SSH_OK" = true ] && echo OK || echo FAIL)" "$P_SSH_D"
  printf '  ② 关键容器   : %s  %s\n' "$([ "$P_CONT_OK" = true ] && echo OK || echo FAIL)" "$P_CONT_D"
  printf '  ③ 备份/密钥  : %s  %s\n' "$([ "$P_BAK_OK" = true ] && echo OK || echo FAIL)" "$P_BAK_D"
  printf '  失败面       : %s\n' "${FAILED_FACES:-无}"
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
    # 冷却键带"本次故障起点"：否则相隔不到 10 分钟的第二次故障，
    # 它的恢复通知会被【上一次恢复】的冷却吞掉（§20 演练时实测到）。
    if NOTIFY_ENV_FILE=${NOTIFY_ENV_FILE:-} bash "$NOTIFY_SCRIPT" INFO "srv2 已恢复" \
      "srv2 三个探测面已全部恢复。不可用/降级时长：$DUR_TXT（自 $ST_DOWN_SINCE_H）。
当前状态：$P_CONT_D；$P_BAK_D
本通知由 srv1 的反向 dead man switch 发出（secagent-srv2deadman.timer，每 3 分钟一轮）。" \
      --key "srv2-recovered-since-$local_since" --cooldown 0; then
      log "恢复通知已发出"
    else
      log "[!] 恢复通知未发出（notify.sh 退出码 $?）"
    fi
    ST_STATE=up; ST_FAILS=0; ST_DOWN_SINCE=0; ST_DOWN_SINCE_H=""; ST_OUTAGE=0; ST_LAST_ALERT=0; ST_LAST_ALERT_H=""
    write_state
    exit 3
  fi
  ST_STATE=up; ST_FAILS=0; ST_DOWN_SINCE=0; ST_DOWN_SINCE_H=""; ST_OUTAGE=0
  write_state
  log "健康：$P_SSH_D | $P_CONT_D | $P_BAK_D"
  exit 0
fi

# ---- 失败 ----
ST_FAILS=$((PREV_FAILS + 1))
[ "$ST_DOWN_SINCE" -gt 0 ] || { ST_DOWN_SINCE=$NOW; ST_DOWN_SINCE_H="$UPDATED"; }
ST_OUTAGE=$((NOW - ST_DOWN_SINCE))
if [ "$ST_FAILS" -lt "$FAIL_THRESHOLD" ]; then
  FAIL_TXT="第 $ST_FAILS/$FAIL_THRESHOLD 次"
else
  FAIL_TXT="第 $ST_FAILS 次（已达阈值 $FAIL_THRESHOLD）"
fi
log "失败（$FAIL_TXT，失败面=[$FAILED_FACES]）：$P_SSH_D | $P_CONT_D | $P_BAK_D"

if [ "$ST_FAILS" -lt "$FAIL_THRESHOLD" ]; then
  ST_STATE=$([ "$PREV_STATE" = "down" ] && echo down || echo degraded)
  write_state
  exit 1
fi

# 达阈值：按失败面给标题（不要把"一个容器挂了"说成"整机不可用"）
if printf '%s' "$FAILED_FACES" | grep -q ssh; then
  TITLE="srv2 疑似整机不可用"; KIND="整机不可用（SSH/心跳拿不到）"
elif printf '%s' "$FAILED_FACES" | grep -q containers; then
  TITLE="srv2 关键容器异常"; KIND="关键容器异常"
else
  TITLE="srv2 备份/密钥状态异常"; KIND="备份链异常"
fi

ST_STATE=down
NEED_NOTIFY=0
if [ "$ST_LAST_ALERT" -eq 0 ]; then
  NEED_NOTIFY=1
elif [ $((NOW - ST_LAST_ALERT)) -ge "$REALERT_SECONDS" ]; then
  NEED_NOTIFY=2
fi

BODY="连续 ${ST_FAILS} 次探测失败（≥阈值 ${FAIL_THRESHOLD}，约 $((ST_FAILS * 3)) 分钟），判定：${KIND}。
失败面：${FAILED_FACES}
① SSH+心跳 ：${P_SSH_D}
② 关键容器 ：${P_CONT_D}
③ 备份/密钥：${P_BAK_D}
不可用起点：${ST_DOWN_SINCE_H}（已持续 $((ST_OUTAGE / 60)) 分 $((ST_OUTAGE % 60)) 秒）
srv1 侧探测时间：${UPDATED}
排查入口：ssh secagent-srv2 'sudo docker ps; sudo ls -la /opt/secagent-backup | tail'
（本通知由 srv1 的反向 dead man switch 发出：srv2 自己不会为"我挂了"发出任何东西 ——
  原来只有 srv2 盯 srv1，方向是单向的，这就是本次补上的缺口。）"

if [ "$NEED_NOTIFY" -eq 1 ]; then
  log "达阈值 → 发 HIGH「$TITLE」"
  # 冷却键带"本次故障起点"，避免 10 分钟内第二次故障的告警被上一次冷却吞掉；
  # 同一次故障内不重复告警由本脚本的 last_alert_epoch 负责。
  if NOTIFY_ENV_FILE=${NOTIFY_ENV_FILE:-} bash "$NOTIFY_SCRIPT" HIGH "$TITLE" "$BODY" \
       --key "srv2-down-$TITLE-since-$ST_DOWN_SINCE" --cooldown 0; then
    ST_LAST_ALERT=$NOW; ST_LAST_ALERT_H="$UPDATED"
    write_state
    exit 2
  else
    rc=$?
    # 【刻意行为】没发出去就【不】记 last_alert："没发出去"不等于"报过了"。
    log "[!] 告警【没发出去】（notify.sh 退出码 $rc）。退出码 3=未配置 NOTIFY_WEBHOOK_URL —— 此时 srv2 挂了无人知晓；下一轮会重试。"
    write_state
    exit 2
  fi
elif [ "$NEED_NOTIFY" -eq 2 ]; then
  log "仍未恢复，超过 $((REALERT_SECONDS / 3600))h → 再提醒一次"
  NOTIFY_ENV_FILE=${NOTIFY_ENV_FILE:-} bash "$NOTIFY_SCRIPT" HIGH "$TITLE（仍未恢复）" "$BODY" \
    --key "srv2-down-$TITLE-since-$ST_DOWN_SINCE" --cooldown 0 || log "[!] 提醒未发出（退出码 $?）"
  ST_LAST_ALERT=$NOW; ST_LAST_ALERT_H="$UPDATED"
  write_state
  exit 2
else
  log "已达阈值但本轮不重复告警（上次告警 $ST_LAST_ALERT_H，重提醒间隔 $((REALERT_SECONDS / 3600))h）"
  write_state
  exit 2
fi
