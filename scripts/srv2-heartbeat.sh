#!/usr/bin/env bash
# ============================================================
# srv2-heartbeat.sh —— srv2 侧「心跳应答器」（只读，供 srv1 反向探测用）
# ------------------------------------------------------------
# 它是什么：srv1 的 dead man switch（scripts/srv1-watch-srv2.sh）通过 SSH 连到
#   srv2 时，sshd 会执行【这个脚本】（authorized_keys 里用 `command=` 强制指定，
#   见 scripts/srv2-authorize-srv1-heartbeat-key.sh）。
#   也就是说：这把钥匙在网络层只能"要一份心跳"，拿不到 shell、不能执行别的命令。
#   —— 与 srv2→srv1 的方向完全对称（那边是 scripts/srv1-heartbeat.sh）。
#
# 为什么需要它（补的缺口）：
#   改之前只有 srv2 盯 srv1（srv2-watch-srv1.sh）。srv2 是检测/索引器 + 备份的
#   接收端，它挂了没人知道：告警（Wazuh 告警、备份落盘、备份抽测）全部静默停止，
#   而 srv1 这边看起来一切正常。
#
# 输出：单行 JSON（srv1 用 grep/sed 取值，不需要额外依赖）
#   {"marker":"secagent-srv2-heartbeat/1", ...,
#    "containers":{"wazuh.indexer":"running",...},   ← 关键容器（含 suricata）
#    "indexer_health":"healthy",                      ← 索引器自身 health
#    "backups":{"latest":"...","age_s":123,"count":4,"key_present":true,"enc":true}}
#
# 手动看（在 srv2 上）：
#   bash /opt/secagent/scripts/srv2-heartbeat.sh
# ============================================================
set -uo pipefail

BASE=/opt/secagent-backup
BACKUP_KEY=${BACKUP_KEY:-/opt/secagent-backup.key}
# 关键容器（按【容器名】精确 inspect，绝不用 --filter ancestor= 这类选择器：
# 上一个实施方就是用 ancestor 选择器误伤了别的生产容器）
CONTAINERS=${SRV2_HEARTBEAT_CONTAINERS:-"wazuh.indexer wazuh.manager wazuh.dashboard cowrie suricata"}

je() { # JSON 字符串转义（控制字符必须转义，否则产出的是非法 JSON）
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\r'/\\r}
  s=${s//$'\n'/\\n}
  s=${s//$'\t'/\\t}
  printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037'
}

disk_pct() { # 挂载点使用率（整数百分比）；路径不存在给 -1
  local p
  p=$(df -P "$1" 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')
  [ -n "$p" ] || p=-1
  printf '%s' "$p"
}

unit_state() {
  local s
  s=$(systemctl is-active "$1" 2>/dev/null | head -1)
  [ -n "$s" ] || s=unknown
  printf '%s' "$s"
}

# 容器状态：running / exited / created / paused / missing
container_state() {
  local c=$1 st
  if ! docker inspect "$c" >/dev/null 2>&1; then printf 'missing'; return; fi
  st=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null)
  [ -n "$st" ] || st=unknown
  printf '%s' "$st"
}
# 索引器 health（容器自带 HEALTHCHECK；没有就 none）
container_health() {
  docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$1" 2>/dev/null || printf 'missing'
}

HOST=$(hostname 2>/dev/null || echo unknown)
NOW=$(date +%s)
NOW_H=$(date '+%F %T')
UP=$(awk '{printf "%d", $1}' /proc/uptime 2>/dev/null || echo 0)
LOAD1=$(awk '{print $1}' /proc/loadavg 2>/dev/null | tr -dc '0-9.')
[ -n "$LOAD1" ] || LOAD1=0
MEM_AVAIL=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null | tr -dc '0-9')
[ -n "$MEM_AVAIL" ] || MEM_AVAIL=0

# ---- 关键容器 ----
CONT_JSON=""
for c in $CONTAINERS; do
  CONT_JSON="$CONT_JSON\"$(je "$c")\":\"$(container_state "$c")\","
done
CONT_JSON="{${CONT_JSON%,}}"
IDX_HEALTH=$(container_health wazuh.indexer)

# ---- 备份状态（"备份通道还在工作吗"）----
LATEST=""; AGE=-1; CNT=0; ENC=false
if [ -d "$BASE" ]; then
  LATEST=$(ls -1 "$BASE" 2>/dev/null | grep -E '^[0-9]{8}-[0-9]{6}$' | sort -r | head -1)
  CNT=$(ls -1 "$BASE" 2>/dev/null | grep -cE '^[0-9]{8}-[0-9]{6}$')
  if [ -n "$LATEST" ]; then
    D="$BASE/$LATEST"
    # 用最新目录里【文件的 mtime】算新鲜度（目录本身可能被 prune 触碰过）
    NEWEST_F=$(find "$D" -maxdepth 1 -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | awk '{print $2}')
    if [ -n "$NEWEST_F" ]; then
      MT=$(stat -c %Y "$NEWEST_F" 2>/dev/null || echo 0)
      [ "$MT" -gt 0 ] && AGE=$((NOW - MT))
    fi
    [ -f "$D/data-$LATEST.tar.gz.enc" ] && ENC=true
  fi
fi
KEYP=false; [ -f "$BACKUP_KEY" ] && KEYP=true
DRILL_LAST=""
if [ -n "$LATEST" ] && [ -f "$BASE/$LATEST/DRILL.log" ]; then
  DRILL_LAST=$(tail -1 "$BASE/$LATEST/DRILL.log" 2>/dev/null | tr -d '\r\n' | cut -c1-120)
fi

printf '{"marker":"secagent-srv2-heartbeat/1","host":"%s","ts":%s,"time":"%s","uptime_s":%s,"load1":"%s","mem_avail_mb":%s,"disk":{"root_pct":%s,"backup_pct":%s},"units":{"docker":"%s","sshd":"%s"},"containers":%s,"indexer_health":"%s","backups":{"latest":"%s","age_s":%s,"count":%s,"key_present":%s,"enc":%s,"drill_last":"%s"}}\n' \
  "$(je "$HOST")" "$NOW" "$(je "$NOW_H")" "$UP" "$(je "$LOAD1")" "$MEM_AVAIL" \
  "$(disk_pct /)" "$(disk_pct "$BASE")" \
  "$(unit_state docker)" "$(unit_state sshd)" \
  "$CONT_JSON" "$(je "$IDX_HEALTH")" \
  "$(je "$LATEST")" "$AGE" "$CNT" "$KEYP" "$ENC" "$(je "$DRILL_LAST")"
