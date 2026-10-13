#!/usr/bin/env bash
# ============================================================
# capacity-watch.sh —— 宿主磁盘 / OpenSearch 水位告警（srv1 与 srv2 共用）
# ------------------------------------------------------------
# 为什么需要它：
#   "磁盘写满"是少数【必然发生且完全可预防】的故障：Opensearch 写满会变只读、
#   Wazuh 会丢告警、蜜罐日志会丢证据 —— 而这之前一定有几天的高水位窗口。
#   此前没有任何东西在这个窗口里说过话（外部评审指出的 P0 缺口之一）。
#
# 检查项：
#   A. 宿主磁盘：>/80% 告警（MEDIUM），>/90% 用 HIGH。同一文件系统只报一次（避免刷屏），
#      但会把挂在同一设备上的路径都列出来（例如 srv1 的 / 与 /opt/secagent）。
#   B. OpenSearch（只有本机真有端点时才查；查不到就如实说"本机不是索引器"）：
#      · /_cluster/health 状态（red → HIGH）
#      · 磁盘分配水位现值（cluster.routing.allocation.disk.watermark.low/high/flood_stage
#        与 enable_for_single_data_node）
#      · /_cat/allocation 的实际 disk.percent 与水位对照（到 flood_stage → HIGH）
#      · ISM/保留策略是否【真的在删】旧索引：策略的 index_patterns + min_index_age
#        与实际索引的创建时间对照，超龄还在 = 保留策略没生效 → HIGH
#      · 现有索引与大小（Top N）
#   C. 通知全部走 notify.sh，带冷却（默认 6 小时），同一问题不会每轮刷屏。
#
# 用法（root）：
#   bash capacity-watch.sh                # 体检 + 必要时告警（timer 调的就是这个）
#   bash capacity-watch.sh --no-notify    # 只看数值，不发通知
#   bash capacity-watch.sh --json         # 只输出一份机器可读摘要
# 环境变量：
#   CAPACITY_PATHS     要看的路径（默认 "/ /opt/secagent /var/lib/docker"）
#   DISK_WARN_PCT/ DISK_HIGH_PCT（默认 80 / 90）
#   OPENSEARCH_URL     默认 https://127.0.0.1:9200（本机没有就跳过）
#   OPENSEARCH_USER    默认 admin
#   OPENSEARCH_PASSWORD / OPENSEARCH_PASSWORD_FILE（默认先读 /root/.wazuh-new-creds.txt）
#   CAPACITY_COOLDOWN_SECONDS 默认 21600（6h）
#   INDEX_TOP_N        默认 5
# ============================================================
set -uo pipefail

PROG=$(basename "$0")

CONF_FILE=${CAPACITY_CONF_FILE:-/opt/secagent/capacity.env}
if [ -f "$CONF_FILE" ]; then
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    k=${line%%=*}; v=${line#*=}
    k=$(printf '%s' "$k" | tr -d '[:space:]')
    case "$k" in
      CAPACITY_PATHS|DISK_WARN_PCT|DISK_HIGH_PCT|OPENSEARCH_URL|OPENSEARCH_USER|\
      OPENSEARCH_PASSWORD|OPENSEARCH_PASSWORD_FILE|CAPACITY_COOLDOWN_SECONDS|INDEX_TOP_N|NOTIFY_SCRIPT)
        v=$(printf '%s' "$v" | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")
        eval "[ -n \"\${$k:-}\" ]" || printf -v "$k" '%s' "$v"
        ;;
    esac
  done < "$CONF_FILE"
fi

CAPACITY_PATHS=${CAPACITY_PATHS:-"/ /opt/secagent /var/lib/docker"}
DISK_WARN_PCT=${DISK_WARN_PCT:-80}
DISK_HIGH_PCT=${DISK_HIGH_PCT:-90}
OPENSEARCH_URL=${OPENSEARCH_URL:-https://127.0.0.1:9200}
OPENSEARCH_USER=${OPENSEARCH_USER:-admin}
OPENSEARCH_PASSWORD=${OPENSEARCH_PASSWORD:-}
OPENSEARCH_PASSWORD_FILE=${OPENSEARCH_PASSWORD_FILE:-/root/.wazuh-new-creds.txt}
CAPACITY_COOLDOWN_SECONDS=${CAPACITY_COOLDOWN_SECONDS:-21600}
INDEX_TOP_N=${INDEX_TOP_N:-5}
NOTIFY_SCRIPT=${NOTIFY_SCRIPT:-/opt/secagent/scripts/notify.sh}

MODE=check
case "${1:-}" in
  --no-notify|--report-only) MODE=report ;;
  --json)                    MODE=json ;;
  --help|-h) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac

HOST=$(hostname -s 2>/dev/null || hostname || echo unknown)
NOW_H=$(date '+%F %T')
log() { printf '%s %s\n' "$(date '+%F %T')" "$*"; }

# 通知：把 exit code 如实带回来（3=没配置 URL，4=冷却中，5=发送失败，6=级别被抑制）
NOTIFY_RESULTS=""
notify() { # $1=级别 $2=标题 $3=正文 $4=key
  if [ "$MODE" != "check" ]; then
    NOTIFY_RESULTS="${NOTIFY_RESULTS}  [跳过通知（$MODE）] $1 $2"$'\n'
    return 0
  fi
  local rc
  NOTIFY_ENV_FILE=${NOTIFY_ENV_FILE:-} bash "$NOTIFY_SCRIPT" "$1" "$2" "$3" \
      --key "$4" --cooldown "$CAPACITY_COOLDOWN_SECONDS" >/dev/null 2>&1
  rc=$?
  case "$rc" in
    0) NOTIFY_RESULTS="${NOTIFY_RESULTS}  [已发送] $1 $2"$'\n' ;;
    4) NOTIFY_RESULTS="${NOTIFY_RESULTS}  [冷却中，未重复发送] $1 $2"$'\n' ;;
    6) NOTIFY_RESULTS="${NOTIFY_RESULTS}  [低于通知级别被抑制] $1 $2"$'\n' ;;
    *) NOTIFY_RESULTS="${NOTIFY_RESULTS}  [!] 通知【没发出去】（notify.sh 退出码 $rc）$1 $2"$'\n' ;;
  esac
  return 0
}

ISSUES=""
add_issue() { ISSUES="${ISSUES}$1"$'\n'; }

# ============================================================
# A. 宿主磁盘
# ============================================================
printf '== A. 宿主磁盘（%s，%s）==\n' "$HOST" "$NOW_H"
# 同一设备只告警一次：device → 最高使用率 + 挂在它上面的路径
declare -A DEV_PCT DEV_MOUNTS DEV_SIZE DEV_AVAIL
for p in $CAPACITY_PATHS; do
  if [ ! -e "$p" ]; then
    printf '  %-18s : 路径不存在（跳过）\n' "$p"
    continue
  fi
  read -r dev size used avail pct mnt < <(df -P "$p" 2>/dev/null | awk 'NR==2{print $1, $2, $3, $4, $5, $6}')
  if [ -z "${dev:-}" ]; then
    printf '  %-18s : df 读不到（跳过）\n' "$p"
    continue
  fi
  pct_n=${pct%\%}
  printf '  %-18s : %s%%  已用 %s / 共 %s（剩余 %s，设备 %s，挂载点 %s）\n' \
    "$p" "$pct_n" "$used" "$size" "$avail" "$dev" "$mnt"
  cur=${DEV_PCT[$dev]:-}
  if [ -z "$cur" ] || [ "$pct_n" -gt "$cur" ]; then DEV_PCT[$dev]=$pct_n; fi
  DEV_MOUNTS[$dev]="${DEV_MOUNTS[$dev]:-} $p"
  DEV_SIZE[$dev]=$size; DEV_AVAIL[$dev]=$avail
done

for dev in "${!DEV_PCT[@]}"; do
  pct=${DEV_PCT[$dev]}
  paths=${DEV_MOUNTS[$dev]}
  if [ "$pct" -ge "$DISK_HIGH_PCT" ]; then
    SEV=HIGH
  elif [ "$pct" -ge "$DISK_WARN_PCT" ]; then
    SEV=MEDIUM
  else
    continue
  fi
  msg="宿主磁盘使用率 ${pct}%（设备 $dev，共 ${DEV_SIZE[$dev]}，剩余 ${DEV_AVAIL[$dev]}）
涉及路径：$paths
阈值：告警 ${DISK_WARN_PCT}% ／ HIGH ${DISK_HIGH_PCT}%
位置：$HOST
建议：docker system df；du -xh --max-depth=1 / | sort -rh | head；
      索引侧：curl -sk -u admin:<pw> https://127.0.0.1:9200/_cat/indices?v&s=store.size:desc
（本告警同键 ${CAPACITY_COOLDOWN_SECONDS}s 内只发一次）"
  add_issue "磁盘 ${pct}%（$dev）→ $SEV"
  notify "$SEV" "磁盘告警：$HOST 使用率 ${pct}%" "$msg" "disk-$HOST-$dev"
done
echo

# ============================================================
# B. OpenSearch 水位
# ============================================================
printf '== B. OpenSearch 水位 ==\n'
OS_PW="$OPENSEARCH_PASSWORD"
if [ -z "$OS_PW" ] && [ -f "$OPENSEARCH_PASSWORD_FILE" ]; then
  OS_PW=$(grep -E '^INDEXER_ADMIN_PASSWORD=' "$OPENSEARCH_PASSWORD_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)
fi
OS_AUTH_OK=0
if [ -n "$OS_PW" ]; then
  code=$(curl -sk -o /dev/null -w '%{http_code}' -m 10 -u "$OPENSEARCH_USER:$OS_PW" "$OPENSEARCH_URL/_cluster/health" 2>/dev/null)
  [ "$code" = "200" ] && OS_AUTH_OK=1
fi
if [ "$OS_AUTH_OK" != "1" ]; then
  # 密码文件没读到/口令变了：再用历史默认口令试一次（迁移期常见），失败就如实跳过
  for cand in SecretPassword; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' -m 10 -u "$OPENSEARCH_USER:$cand" "$OPENSEARCH_URL/_cluster/health" 2>/dev/null)
    if [ "$code" = "200" ]; then OS_PW=$cand; OS_AUTH_OK=1; break; fi
  done
fi

if [ "$OS_AUTH_OK" != "1" ]; then
  printf '  未发现可用 OpenSearch 端点（%s）—— 本机不是索引器，跳过水位检查\n' "$OPENSEARCH_URL"
  printf '  （提示：本项目索引器在 srv2 的 wazuh.indexer 容器上，仅监听 127.0.0.1:9200）\n'
  echo
else
  OSC() { curl -sk -m 15 -u "$OPENSEARCH_USER:$OS_PW" "$OPENSEARCH_URL$1" 2>/dev/null; }

  HEALTH=$(OSC /_cluster/health)
  HS=$(printf '%s' "$HEALTH" | grep -oE '"status"[[:space:]]*:[[:space:]]*"[a-z]+"' | sed -n 's/.*"\([a-z]*\)"$/\1/p' | head -1)
  UNASSIGNED=$(printf '%s' "$HEALTH" | grep -oE '"unassigned_shards"[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+$' | head -1)
  SHARDS=$(printf '%s' "$HEALTH" | grep -oE '"active_shards"[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+$' | head -1)
  printf '  集群状态：%s（active_shards=%s，unassigned=%s）\n' "${HS:-读不到}" "${SHARDS:-?}" "${UNASSIGNED:-?}"
  if [ "${HS:-}" = "red" ]; then
    add_issue "OpenSearch 集群 red"
    notify HIGH "OpenSearch 集群 red：$HOST" "集群状态 red（active_shards=${SHARDS:-?}，unassigned=${UNASSIGNED:-?}）。
至少一个主分片未分配，写入/检索可能已经失败。立即看：
  curl -sk -u admin:<pw> $OPENSEARCH_URL/_cat/shards?v | grep -i unassign
  journalctl -u docker -n 100；docker logs wazuh.indexer --tail 200" "os-red-$HOST"
  elif [ "${HS:-}" = "yellow" ]; then
    printf '  （yellow 在本项目通常是 ISM 每日历史索引的副本分不出去，见 RUNBOOK §14）\n'
  fi

  # --- 水位配置现值 ---
  SETTINGS=$(curl -sk -m 15 -u "$OPENSEARCH_USER:$OS_PW" "$OPENSEARCH_URL/_cluster/settings?include_defaults=true&flat_settings=true" 2>/dev/null)
  get_set() { printf '%s' "$SETTINGS" | grep -oE "\"cluster.routing.allocation.disk.watermark.$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | sed -n 's/.*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1; }
  WM_LOW=$(get_set low); WM_HIGH=$(get_set high); WM_FLOOD=$(get_set flood_stage)
  SINGLE=$(printf '%s' "$SETTINGS" | grep -oE '"cluster.routing.allocation.disk.watermark.enable_for_single_data_node"[[:space:]]*:[[:space:]]*"?[a-z]+"?' | sed -n 's/.*:[[:space:]]*"\?\([a-z]*\)"\?$/\1/p' | head -1)
  printf '  水位配置：low=%s high=%s flood_stage=%s ｜ enable_for_single_data_node=%s\n' \
    "${WM_LOW:-读不到}" "${WM_HIGH:-读不到}" "${WM_FLOOD:-读不到}" "${SINGLE:-读不到}"
  if [ "${SINGLE:-}" = "false" ]; then
    printf '  [!] 注意：单数据节点上的磁盘水位【未启用】（enable_for_single_data_node=false）——\n'
    printf '      也就是说磁盘写满时 OpenSearch 不会自动把索引置只读/停止分配，\n'
    printf '      唯一的防线就是本告警。这条必须知道。\n'
  fi

  # --- 实际使用率 ---
  ALLOC=$(OSC "/_cat/allocation?v&h=shards,disk.indices,disk.used,disk.avail,disk.total,disk.percent,node")
  printf '  _cat/allocation：\n'
  printf '%s\n' "$ALLOC" | sed 's/^/    /'
  OS_PCT=$(printf '%s' "$ALLOC" | awk 'NR>=2{print $6; exit}')
  OS_NODE=$(printf '%s' "$ALLOC" | awk 'NR>=2{print $7; exit}')
  OS_AVAIL=$(printf '%s' "$ALLOC" | awk 'NR>=2{print $4; exit}')
  # 阈值默认取【集群里真实配置的水位】—— 这才是"接近水位就告警"的正确口径：
  # 集群改了水位，告警跟着改，不需要有人记得同步两边。
  # WATERMARK_*_OVERRIDE 只为演练存在：把判断阈值临时压低，用来验证告警链路是否真的通
  # （只影响本脚本的比较，绝不改集群设置）。
  HIGH_EFF=${WATERMARK_HIGH_OVERRIDE:-${WM_HIGH%\%}}
  FLOOD_EFF=${WATERMARK_FLOOD_OVERRIDE:-${WM_FLOOD%\%}}
  if [ -n "${WATERMARK_HIGH_OVERRIDE:-}" ] || [ -n "${WATERMARK_FLOOD_OVERRIDE:-}" ]; then
    printf '  [演练] 水位阈值被覆盖：high=%s%% flood=%s%%（集群现值仍是 high=%s flood=%s）\n' \
      "$HIGH_EFF" "$FLOOD_EFF" "$WM_HIGH" "$WM_FLOOD"
  fi
  if [ -n "${OS_PCT:-}" ]; then
    printf '  索引器节点 %s 磁盘：%s%%（剩余 %s）\n' "${OS_NODE:-?}" "$OS_PCT" "${OS_AVAIL:-?}"
    OVR_NOTE=""
    if [ -n "${WATERMARK_HIGH_OVERRIDE:-}" ] || [ -n "${WATERMARK_FLOOD_OVERRIDE:-}" ]; then
      OVR_NOTE="（注意：本次判断用的是演练覆盖阈值，不是集群现值）"
    fi
    if [ -n "${FLOOD_EFF:-}" ] && [ "$OS_PCT" -ge "$FLOOD_EFF" ] 2>/dev/null; then
      add_issue "OpenSearch 磁盘 ${OS_PCT}% ≥ flood_stage ${FLOOD_EFF}%"
      notify HIGH "OpenSearch 已达 flood_stage：$HOST 磁盘 ${OS_PCT}%" \
"索引器节点 ${OS_NODE:-?} 磁盘使用率 ${OS_PCT}%，已达到 flood_stage（判断阈值 ${FLOOD_EFF}%，集群现值 ${WM_FLOOD}）$OVR_NOTE。
语义：新索引创建/写入会被拒绝（除非单节点豁免生效 —— 本机 enable_for_single_data_node=${SINGLE:-?}）。
剩余空间：${OS_AVAIL:-?}
立即处理：清旧索引（ISM 或手工 DELETE /wazuh-alerts-4.x-YYYY.MM.DD）或扩容磁盘。@$HOST" "os-flood-$HOST"
    elif [ -n "${HIGH_EFF:-}" ] && [ "$OS_PCT" -ge "$HIGH_EFF" ] 2>/dev/null; then
      add_issue "OpenSearch 磁盘 ${OS_PCT}% ≥ high ${HIGH_EFF}%"
      notify MEDIUM "OpenSearch 接近水位：$HOST 磁盘 ${OS_PCT}%" \
"索引器节点 ${OS_NODE:-?} 磁盘使用率 ${OS_PCT}%，已过 high 水位（判断阈值 ${HIGH_EFF}%，集群现值 ${WM_HIGH}；flood_stage=${WM_FLOOD}）$OVR_NOTE。
再过一步就是写入被拒。剩余空间 ${OS_AVAIL:-?}。
处理方向：ISM 保留期是否合适（当前见下方 ISM 检查）；必要时手工删旧索引或扩容。@$HOST" "os-high-$HOST"
    fi
  fi

  # --- 索引占用 TopN ---
  TOPN=$(OSC "/_cat/indices?v&s=store.size:desc&h=health,status,index,pri,rep,docs.count,store.size,creation.date.string")
  printf '  索引占用 Top%s：\n' "$INDEX_TOP_N"
  printf '%s\n' "$TOPN" | head -n $((INDEX_TOP_N + 1)) | sed 's/^/    /'
  TOTAL=$(printf '%s\n' "$TOPN" | awk 'NR>=2' | wc -l)
  printf '  索引总数：%s\n' "$TOTAL"

  # --- ISM / 保留策略是否真的在删 ---
  ISM=$(OSC "/_plugins/_ism/policies")
  IDXJSON=$(curl -sk -m 20 -u "$OPENSEARCH_USER:$OS_PW" "$OPENSEARCH_URL/_cat/indices?format=json&h=index,creation.date,store.size" 2>/dev/null)
  ISM_FILE=$(mktemp 2>/dev/null || echo /tmp/ism.$$)
  IDX_FILE=$(mktemp 2>/dev/null || echo /tmp/idx.$$)
  printf '%s' "$ISM" > "$ISM_FILE"
  printf '%s' "$IDXJSON" > "$IDX_FILE"
  ISM_OUT=""
  if command -v python3 >/dev/null 2>&1; then
    ISM_OUT=$(python3 -c '
import json, sys, re, datetime
def load(p, d):
    try:
        return json.load(open(p))
    except Exception:
        return d
pol = load(sys.argv[1], {})
idx = load(sys.argv[2], [])
now = datetime.datetime.now(datetime.timezone.utc)
print("  保留策略（ISM）现值：")
if not pol.get("policies"):
    print("    [!] 读不到 ISM 策略 —— 无法确认旧索引是否会被删（这条要人工看一眼）")
stale = []
for p in pol.get("policies", []):
    pid = p.get("_id")
    body = p.get("policy", {}) or {}
    pats = []
    for t in (body.get("ism_template") or []):
        pats += list(t.get("index_patterns") or [])
    days = None
    for st in (body.get("states") or []):
        for tr in (st.get("transitions") or []):
            a = ((tr.get("conditions") or {}).get("min_index_age"))
            if a:
                days = a
    pats_s = ",".join(pats) if pats else "(没有 ism_template —— 不会被自动套用!)"
    print("    %-24s 保留=%-6s 适用=%s" % (pid, days or "?", pats_s))
    if not days or not pats:
        continue
    m = re.match(r"^(\d+)d$", str(days))
    if not m:
        continue
    lim = int(m.group(1))
    for it in idx:
        name = it.get("index", "")
        for pat in pats:
            rx = "^" + re.escape(pat).replace("\\*", ".*") + "$"
            if re.match(rx, name):
                cd = it.get("creation.date")
                try:
                    created = datetime.datetime.fromtimestamp(int(cd) / 1000.0, datetime.timezone.utc)
                except Exception:
                    continue
                age = (now - created).days
                if age > lim:
                    stale.append((name, age, lim, pid, it.get("store.size", "?")))
for s in stale:
    print("    [!] 超龄未删：%s 已 %d 天 > 保留 %dd（策略 %s，占用 %s）" % s)
if not stale:
    print("    （当前没有超过保留期的索引 —— 保留策略与现状一致）")
' "$ISM_FILE" "$IDX_FILE" 2>&1)
    printf '%s\n' "$ISM_OUT"
  else
    printf '  （没有 python3，跳过 ISM 保留期对照；请人工核对）\n'
  fi
  rm -f "$ISM_FILE" "$IDX_FILE" 2>/dev/null

  if printf '%s' "$ISM_OUT" | grep -q "超龄未删"; then
    add_issue "ISM 有超龄未删索引"
    notify HIGH "ISM 保留策略没在删旧索引：$HOST" \
"以下索引已超过其 ISM 策略的保留期却仍然存在（说明保留策略没有真正生效）：
$ISM_OUT

含义：磁盘会被无限占用，直到写满（水位告警随后才响，那时代价更大）。
排查：GET /_plugins/_ism/explain/<索引名>?pretty 看 ISM 对该索引的判定；
      确认索引是否真的被 ism_template 覆盖（模式不一致是常见原因）。@$HOST" "os-ism-stale-$HOST"
  fi
  echo
fi

# ============================================================
# 汇总
# ============================================================
if [ -n "$ISSUES" ]; then
  printf '== 结论：发现问题 ==\n'
  printf '%s' "$ISSUES" | sed 's/^/  · /'
else
  printf '== 结论：未触发阈值 ==\n'
fi
if [ -n "$NOTIFY_RESULTS" ]; then
  printf '== 通知 ==\n%s' "$NOTIFY_RESULTS"
fi

if [ "$MODE" = "json" ]; then
  # 机器可读摘要（给下游/巡检用，不用 jq）
  printf '{"host":"%s","time":"%s","disk":{' "$HOST" "$NOW_H"
  first=1
  for dev in "${!DEV_PCT[@]}"; do
    [ "$first" = "1" ] || printf ','
    printf '"%s":{"percent":%s,"paths":"%s"}' "$dev" "${DEV_PCT[$dev]}" "$(printf '%s' "${DEV_MOUNTS[$dev]}" | sed 's/^ //')"
    first=0
  done
  printf '},"opensearch":{"auth_ok":%s,"cluster_status":"%s","disk_percent":"%s","watermark_low":"%s","watermark_high":"%s","watermark_flood":"%s","single_node_watermark":"%s"},"issues":%s}\n' \
    "$OS_AUTH_OK" "${HS:-unknown}" "${OS_PCT:-}" "${WM_LOW:-}" "${WM_HIGH:-}" "${WM_FLOOD:-}" "${SINGLE:-}" \
    "$(printf '%s' "$ISSUES" | sed -e 's/"/\\"/g' | tr '\n' '|' | sed 's/^/"/;s/$/"/')"
fi

[ -n "$ISSUES" ] && exit 1
exit 0
