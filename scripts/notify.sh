#!/usr/bin/env bash
# ============================================================
# notify.sh —— 服务器侧「通知出口」（不依赖 Java 应用，可独立使用）
# ------------------------------------------------------------
# 为什么要有这个文件（P0 缺口的真正含义）：
#   应用内的 NotificationService 只在【应用活着】时有用。而"整机死了/磁盘满了"
#   恰恰是应用【不能】替你报警的场景 —— 报警必须由应用之外的东西发出。
#   所以这里是纯 bash + curl 的出口，任何脚本（心跳、容量、看门狗）都能调它。
#
# 用法：
#   notify.sh <级别> <标题> <正文> [选项]
#     <级别>：CRITICAL | HIGH | MEDIUM | LOW | INFO（大小写不敏感）
#   选项：
#     --key K        冷却键（默认 = 级别+标题 的 md5）。同键在冷却窗口内不重复发。
#     --cooldown N   本次调用的冷却秒数（覆盖配置里的 NOTIFY_SERVER_COOLDOWN_SECONDS）
#     --config F     指定配置文件（默认按 NOTIFY_ENV_FILE → /opt/secagent/.env
#                    → /etc/secagent/notify.env → /opt/secagent/notify.env 顺序找）
#     --force        越过冷却、夜间静默、最低级别（演练/手工推送用）
#     --dry-run      只打印将发送的载荷，不发送
#     --help
#
# 退出码（区分"发出去了"与"没发出去"是本脚本的核心设计）：
#   0  已发送（或 --dry-run 成功）
#   2  用法/配置错误（未知模板变量、渲染后不是合法 JSON 等）
#   3  NOTIFY_WEBHOOK_URL 未配置 —— 【没发出去】
#   4  冷却中跳过 —— 没发出去
#   5  发送失败（curl 非 2xx / 超时 / 连不上）—— 没发出去
#   6  级别低于最低通知级别（或被夜间静默压到阈值以下）—— 没发出去
#   调用方必须检查退出码：把 3/4/5/6 当成"发出去了"就是"看得见的成功"。
#
# 配置（从配置文件读；环境变量优先于文件，便于演练时临时覆盖）：
#   NOTIFY_WEBHOOK_URL                 为空 = 通知功能关闭（退出码 3）
#   NOTIFY_WEBHOOK_TEMPLATE            默认 {"text":"{{title}}\n{{body}}"}
#                                      —— 与应用内 NotificationService 同一份模板语义，
#                                      同一份配置可以同时喂给应用和本脚本（见 RUNBOOK §19/§20）
#   NOTIFY_SERVER_MIN_SEVERITY         默认 INFO。刻意【不】复用 NOTIFY_MIN_SEVERITY：
#                                      应用侧默认 HIGH，若这里也跟着 HIGH，
#                                      "已恢复"(INFO) 这类好消息会被静默吞掉。
#   NOTIFY_SERVER_COOLDOWN_SECONDS     默认 600（同键 600s 内不重复）
#   NOTIFY_NIGHT_QUIET                 夜间静默窗口，如 22:00-07:00；空 = 不静默
#   NOTIFY_NIGHT_QUIET_MODE            downgrade（默认，只压级别）/ high-only / off
#   NOTIFY_TIMEOUT_SECONDS             默认 15
#   NOTIFY_STATE_DIR                   冷却状态目录，默认 /opt/secagent/state/notify
#   NOTIFY_LOG_FILE                    日志文件，默认 /opt/secagent/logs/notify.log
#
# 模板变量：title body severity severityLabel type typeLabel ip actor time count
#           host source key level levelLabel
#   未知变量 → 直接报错退出 2（不替换成空串）：写错 {{titel}} 的通知会
#   "看起来发出去了"，只是正文少一截，在手机上只会被当成"对端渲染怪怪的"。
#
# 安全：配置文件用【解析】而不是 source。source 一个 .env 等于执行它，
#   而 .env 里可能有从别处粘来的值（含 $(...) 或反引号）—— 那是把"改配置"变成"执行命令"。
# ============================================================
set -uo pipefail

PROG=$(basename "$0")

# ---------- 配置键：先记下"哪些是环境变量给的" ----------
# 【实测踩坑】必须在套用默认值【之前】记录，否则默认值会冒充"用户设置"，
#   把配置文件的值挡在外面（或反过来被文件覆盖）。本脚本第一次自测就栽在这里：
#   NOTIFY_SERVER_MIN_SEVERITY=HIGH 从环境变量传入，却被 /tmp/*.env 里的 INFO 覆盖，
#   于是"该被压制的 INFO 告警"真的发出去了 —— 而测试 6 正是为抓这类问题写的。
CFG_KEYS="NOTIFY_WEBHOOK_URL NOTIFY_WEBHOOK_TEMPLATE NOTIFY_SERVER_MIN_SEVERITY \
NOTIFY_SERVER_COOLDOWN_SECONDS NOTIFY_NIGHT_QUIET NOTIFY_NIGHT_QUIET_MODE \
NOTIFY_TIMEOUT_SECONDS NOTIFY_STATE_DIR NOTIFY_LOG_FILE"
declare -A ENV_SET=()
for _k in $CFG_KEYS; do
  if eval "[ -n \"\${$_k:-}\" ]"; then ENV_SET[$_k]=1; fi
done
NOTIFY_ENV_FILE=${NOTIFY_ENV_FILE:-}

# ---------- 参数 ----------
LEVEL=""; TITLE=""; BODY=""
OPT_KEY=""; OPT_COOLDOWN=""; FORCE=0; DRY_RUN=0
usage() { sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --key)      OPT_KEY=${2:-}; shift 2 ;;
    --cooldown) OPT_COOLDOWN=${2:-}; shift 2 ;;
    --config)   NOTIFY_ENV_FILE=${2:-}; shift 2 ;;
    --force)    FORCE=1; shift ;;
    --dry-run)  DRY_RUN=1; shift ;;
    --help|-h)  usage; exit 0 ;;
    --*)        echo "未知选项：$1（用 --help 看用法）" >&2; exit 2 ;;
    *)
      if   [ -z "$LEVEL" ]; then LEVEL=$1
      elif [ -z "$TITLE" ]; then TITLE=$1
      elif [ -z "$BODY"  ]; then BODY=$1
      else echo "多余参数：$1（正文请合并成第三个参数）" >&2; exit 2
      fi
      shift ;;
  esac
done

if [ -z "$LEVEL" ] || [ -z "$TITLE" ]; then
  echo "用法：$PROG <级别> <标题> <正文> [--key K] [--cooldown N] [--force] [--dry-run]" >&2
  exit 2
fi
[ -n "$BODY" ] || BODY="（无正文）"

# ---------- 读配置（解析，不 source） ----------
# 只认 NOTIFY_ 前缀，避免把 .env 里的应用密钥读进环境造成意外扩散。
read_kv() { # $1=文件 $2=键
  [ -f "$1" ] || return 0
  grep -E "^[[:space:]]*$2=" "$1" 2>/dev/null | tail -1 \
    | sed -e "s/^[[:space:]]*$2=//" \
          -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/" \
          -e 's/[[:space:]]*$//'
}

apply_kv() { # $1=键 $2=值：环境变量优先；已被先出现的文件填过就不再覆盖
  [ -n "${2:-}" ] || return 0
  [ -n "${ENV_SET[$1]:-}" ] && return 0
  eval "[ -n \"\${$1:-}\" ]" && return 0
  printf -v "$1" '%s' "$2"
}

CONFIG_FILES=()
[ -n "$NOTIFY_ENV_FILE" ] && CONFIG_FILES+=("$NOTIFY_ENV_FILE")
CONFIG_FILES+=(/opt/secagent/.env /etc/secagent/notify.env /opt/secagent/notify.env)

CONFIG_USED=""
for f in "${CONFIG_FILES[@]}"; do
  [ -f "$f" ] || continue
  for _k in $CFG_KEYS; do apply_kv "$_k" "$(read_kv "$f" "$_k")"; done
  # URL 已有着落就不用再往后找，但继续扫完以补齐其它键（多文件互为补充）
  [ -z "$CONFIG_USED" ] && [ -n "$(read_kv "$f" NOTIFY_WEBHOOK_URL)" ] && CONFIG_USED=$f
done

# ---------- 默认值：只有环境变量与所有配置文件都没给才生效 ----------
NOTIFY_WEBHOOK_URL=${NOTIFY_WEBHOOK_URL:-}
NOTIFY_WEBHOOK_TEMPLATE=${NOTIFY_WEBHOOK_TEMPLATE:-}
NOTIFY_SERVER_MIN_SEVERITY=${NOTIFY_SERVER_MIN_SEVERITY:-INFO}
NOTIFY_SERVER_COOLDOWN_SECONDS=${NOTIFY_SERVER_COOLDOWN_SECONDS:-600}
NOTIFY_NIGHT_QUIET=${NOTIFY_NIGHT_QUIET:-}
NOTIFY_NIGHT_QUIET_MODE=${NOTIFY_NIGHT_QUIET_MODE:-downgrade}
NOTIFY_TIMEOUT_SECONDS=${NOTIFY_TIMEOUT_SECONDS:-15}
NOTIFY_STATE_DIR=${NOTIFY_STATE_DIR:-/opt/secagent/state/notify}
NOTIFY_LOG_FILE=${NOTIFY_LOG_FILE:-/opt/secagent/logs/notify.log}

# 日志：目标目录不可写时退到 /var/log，再退到 stderr —— 绝不因为日志写不了就丢告警
LOG_TARGET="$NOTIFY_LOG_FILE"
log_init() {
  mkdir -p "$(dirname "$LOG_TARGET")" 2>/dev/null || true
  if ! { touch "$LOG_TARGET" 2>/dev/null && [ -w "$LOG_TARGET" ]; }; then
    LOG_TARGET=/var/log/secagent-notify.log
    mkdir -p /var/log 2>/dev/null || true
    touch "$LOG_TARGET" 2>/dev/null || LOG_TARGET=""
  fi
}
LOG_TARGET_READY=0
log() {
  local line
  line="$(date '+%F %T') [$PROG] $*"
  if [ "$LOG_TARGET_READY" = "0" ]; then log_init; LOG_TARGET_READY=1; fi
  if [ -n "$LOG_TARGET" ]; then printf '%s\n' "$line" >> "$LOG_TARGET" 2>/dev/null || printf '%s\n' "$line" >&2
  else printf '%s\n' "$line" >&2; fi
}

# 状态目录：不可写时退到 /tmp（告警比冷却更重要）
if ! mkdir -p "$NOTIFY_STATE_DIR" 2>/dev/null || [ ! -w "$NOTIFY_STATE_DIR" ]; then
  NOTIFY_STATE_DIR=${TMPDIR:-/tmp}/secagent-notify-state
  mkdir -p "$NOTIFY_STATE_DIR" 2>/dev/null || true
fi

# ---------- 级别 ----------
sev_rank() {
  case "$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')" in
    CRITICAL) echo 4 ;; HIGH) echo 3 ;; MEDIUM) echo 2 ;; LOW) echo 1 ;; INFO) echo 0 ;;
    *) echo "" ;;
  esac
}
sev_name() { # $1=rank
  case "$1" in 4) echo CRITICAL ;; 3) echo HIGH ;; 2) echo MEDIUM ;; 1) echo LOW ;; *) echo INFO ;; esac
}
sev_label() {
  case "$1" in CRITICAL) echo 严重 ;; HIGH) echo 高危 ;; MEDIUM) echo 中危 ;; LOW) echo 低危 ;; *) echo 提示 ;; esac
}

LEVEL=$(printf '%s' "$LEVEL" | tr '[:lower:]' '[:upper:]')
RANK=$(sev_rank "$LEVEL")
if [ -z "$RANK" ]; then
  echo "级别不认识：$LEVEL（只认 CRITICAL/HIGH/MEDIUM/LOW/INFO）" >&2
  exit 2
fi
MIN_RANK=$(sev_rank "$NOTIFY_SERVER_MIN_SEVERITY")
[ -z "$MIN_RANK" ] && { log "配置 NOTIFY_SERVER_MIN_SEVERITY=$NOTIFY_SERVER_MIN_SEVERITY 不认识，按 INFO 处理"; MIN_RANK=0; }

# ---------- 夜间静默：只压级别，不静悄悄丢 ----------
QUIET_NOTE=""
in_quiet_window() {
  local win=$1 now_h now_m h1 m1 h2 m2
  [ -z "$win" ] && return 1
  case "$win" in off|OFF|none) return 1 ;; esac
  now_h=$(date +%H); now_m=$(date +%M)
  local now_min=$((10#$now_h * 60 + 10#$now_m))
  # 支持 "22:00-07:00"；跨零点自动处理
  local start=${win%%-*} end=${win##*-}
  case "$start" in *:*) h1=${start%%:*}; m1=${start##*:} ;; *) h1=$start; m1=00 ;; esac
  case "$end"   in *:*) h2=${end%%:*};   m2=${end##*:}   ;; *) h2=$end;   m2=00 ;; esac
  local s=$((10#$h1 * 60 + 10#$m1)) e=$((10#$h2 * 60 + 10#$m2))
  if [ "$s" -le "$e" ]; then [ "$now_min" -ge "$s" ] && [ "$now_min" -lt "$e" ]
  else [ "$now_min" -ge "$s" ] || [ "$now_min" -lt "$e" ]; fi
}

if [ "$FORCE" != "1" ] && in_quiet_window "$NOTIFY_NIGHT_QUIET"; then
  case "$NOTIFY_NIGHT_QUIET_MODE" in
    off|OFF)
      :
      ;;
    high-only|HIGH-ONLY)
      # 与应用内 NotificationService 同一口径：只有 HIGH/CRITICAL 能穿过夜间
      if [ "$RANK" -lt 3 ]; then
        log "夜间静默（$NOTIFY_NIGHT_QUIET，mode=high-only）：$LEVEL「$TITLE」按阈值压制 —— 没发出去"
        exit 6
      fi
      ;;
    *)
      # 默认：只把级别压低一档，正文里如实标注；够不到最低级别才不发
      if [ "$RANK" -gt 0 ]; then
        NEW_RANK=$((RANK - 1))
        QUIET_NOTE="［夜间静默 $NOTIFY_NIGHT_QUIET：级别 $LEVEL → $(sev_name "$NEW_RANK")］"
        log "夜间静默：级别 $LEVEL → $(sev_name "$NEW_RANK")（消息仍会发出，只是降级）"
        RANK=$NEW_RANK; LEVEL=$(sev_name "$NEW_RANK")
      fi
      ;;
  esac
fi

if [ "$FORCE" != "1" ] && [ "$RANK" -lt "$MIN_RANK" ]; then
  log "级别 $LEVEL 低于最低通知级别 $NOTIFY_SERVER_MIN_SEVERITY —— 没发出去"
  exit 6
fi

# ---------- 载荷渲染 ----------
# JSON 字符串转义（值里带引号/换行是最容易把载荷拼坏的地方）
json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037'
}

HOSTNAME_V=$(hostname 2>/dev/null || echo unknown)
NOW_ISO=$(date '+%F %T%z')
[ -n "$QUIET_NOTE" ] && BODY="$BODY
$QUIET_NOTE"

TPL="$NOTIFY_WEBHOOK_TEMPLATE"
[ -n "$TPL" ] || TPL='{"text":"{{title}}\n{{body}}"}'

PAYLOAD="$TPL"
# 逐个占位符替换：未知变量视为配置错误（fail-closed）
PLACEHOLDERS=$(printf '%s' "$TPL" | grep -oE '\{\{[[:space:]]*[A-Za-z0-9_.]+[[:space:]]*\}\}' | sort -u)
while IFS= read -r ph; do
  [ -n "$ph" ] || continue
  name=$(printf '%s' "$ph" | sed -e 's/^{{[[:space:]]*//' -e 's/[[:space:]]*}}$//')
  lname=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')
  case "$lname" in
    title)         val="$TITLE" ;;
    body)          val="$BODY" ;;
    severity|level)      val="$LEVEL" ;;
    severitylabel|levellabel) val="$(sev_label "$LEVEL")" ;;
    type|source)   val="SERVER" ;;
    typelabel)     val="服务器" ;;
    ip)            val="" ;;
    actor)         val="SERVER" ;;
    time)          val="$NOW_ISO" ;;
    count)         val="1" ;;
    host)          val="$HOSTNAME_V" ;;
    key)           val="${OPT_KEY:-}" ;;
    *)
      log "通知模板里的变量 {{$name}} 不存在（可用：title body severity severityLabel type typeLabel ip actor time count host source key level levelLabel）—— 拒绝发送"
      echo "模板变量 {{$name}} 未知；拒绝发送（不替换成空串）" >&2
      exit 2 ;;
  esac
  PAYLOAD=${PAYLOAD//"$ph"/$(json_escape "$val")}
done <<< "$PLACEHOLDERS"

# 渲染结果必须是合法 JSON 才发（有 python3 就校验；没有就如实说明未校验）
if command -v python3 >/dev/null 2>&1; then
  if ! printf '%s' "$PAYLOAD" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
    log "模板渲染结果不是合法 JSON，拒绝发送（fail-closed）：$PAYLOAD"
    echo "模板渲染结果不是合法 JSON，拒绝发送" >&2
    exit 2
  fi
fi

# ---------- 冷却（同键 N 秒内不重复） ----------
KEY=${OPT_KEY:-}
[ -n "$KEY" ] || KEY="$LEVEL|$TITLE"
if command -v md5sum >/dev/null 2>&1; then
  KEY_HASH=$(printf '%s' "$KEY" | md5sum | cut -c1-16)
else
  KEY_HASH=$(printf '%s' "$KEY" | cksum | tr -d ' ' )
fi
COOLDOWN=${OPT_COOLDOWN:-$NOTIFY_SERVER_COOLDOWN_SECONDS}
COOLDOWN_FILE="$NOTIFY_STATE_DIR/cooldown_${KEY_HASH}.ts"
NOW_EPOCH=$(date +%s)

if [ "$FORCE" != "1" ] && [ "$COOLDOWN" -gt 0 ] 2>/dev/null && [ -f "$COOLDOWN_FILE" ]; then
  LAST=$(cat "$COOLDOWN_FILE" 2>/dev/null | tr -dc '0-9')
  if [ -n "$LAST" ] && [ "$LAST" -gt 0 ] 2>/dev/null; then
    AGE=$((NOW_EPOCH - LAST))
    if [ "$AGE" -ge 0 ] && [ "$AGE" -lt "$COOLDOWN" ]; then
      LEFT=$((COOLDOWN - AGE))
      log "冷却中（键=$KEY，还剩 ${LEFT}s / 共 ${COOLDOWN}s）—— 没发出去"
      echo "冷却中：${LEFT}s 后再发（键=$KEY）"
      exit 4
    fi
  fi
fi

# ---------- 未配置 URL：写日志 + 退出码 3 ----------
if [ -z "$NOTIFY_WEBHOOK_URL" ]; then
  log "[!] NOTIFY_WEBHOOK_URL 未配置 —— 【没发出去】：[$LEVEL] $TITLE | $BODY"
  log "    配置位置：${CONFIG_FILES[*]}（键 NOTIFY_WEBHOOK_URL）"
  echo "notify.sh: NOTIFY_WEBHOOK_URL 未配置，未发送（exit 3）" >&2
  exit 3
fi

if [ "$DRY_RUN" = "1" ]; then
  log "[dry-run] 将 POST 到 $NOTIFY_WEBHOOK_URL：$PAYLOAD"
  printf '%s\n' "$PAYLOAD"
  exit 0
fi

# ---------- 发送 ----------
RESP_FILE=$(mktemp 2>/dev/null || echo /tmp/notify-resp.$$)
HTTP_CODE=$(curl -sS -m "$NOTIFY_TIMEOUT_SECONDS" -o "$RESP_FILE" -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json; charset=utf-8' \
  --data-binary "$PAYLOAD" "$NOTIFY_WEBHOOK_URL" 2>/dev/null)
CURL_RC=$?
RESP_SNIPPET=$(head -c 200 "$RESP_FILE" 2>/dev/null | tr -d '\n')
rm -f "$RESP_FILE" 2>/dev/null

if [ "$CURL_RC" != "0" ]; then
  log "[X] 发送失败（curl 退出码 $CURL_RC，超时 ${NOTIFY_TIMEOUT_SECONDS}s）：[$LEVEL] $TITLE → $NOTIFY_WEBHOOK_URL"
  echo "notify.sh: 发送失败 curl_rc=$CURL_RC" >&2
  exit 5
fi
case "$HTTP_CODE" in
  2*) : ;;
  *)
    log "[X] 发送失败：HTTP $HTTP_CODE（对端响应片段：$RESP_SNIPPET）：[$LEVEL] $TITLE → $NOTIFY_WEBHOOK_URL"
    echo "notify.sh: 发送失败 HTTP $HTTP_CODE" >&2
    exit 5 ;;
esac

# 只有真的发出去了才更新冷却时间戳（否则一次失败会把自己锁住，重试全被吞）
printf '%s\n' "$NOW_EPOCH" > "$COOLDOWN_FILE" 2>/dev/null || true
log "已发送 HTTP $HTTP_CODE：[$LEVEL] $TITLE → $NOTIFY_WEBHOOK_URL（键=$KEY 冷却=${COOLDOWN}s）"
echo "已发送（HTTP $HTTP_CODE）"
exit 0
