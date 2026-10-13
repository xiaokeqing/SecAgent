#!/usr/bin/env bash
# ============================================================
# srv1-heartbeat.sh —— srv1 侧「心跳应答器」（只读，供 srv2 反向探测用）
# ------------------------------------------------------------
# 它是什么：srv2 的 dead man switch 通过 SSH 连到 srv1 时，sshd 会执行【这个脚本】
#   （authorized_keys 里用 `command=` 强制指定，见 scripts/srv1-authorize-heartbeat-key.sh）。
#   也就是说：这把钥匙在网络层只能"要一份心跳"，拿不到 shell、不能执行别的命令。
#
# 为什么用强制命令而不是给 srv2 一把普通 root 钥匙：
#   srv2 是蜜罐机、暴露面更大。它一旦被拿下，一把普通 root 钥匙等于 srv1 也没了。
#   强制命令把"被拿下之后的破坏力"限制在"读一份状态 JSON"。
#
# 输出：单行 JSON（srv2 用 grep 取值，不需要额外依赖）
#   {"marker":"secagent-heartbeat/1", ... "units":{...}, "disk":{...}}
#
# 手动看（在 srv1 上）：
#   bash /opt/secagent/scripts/srv1-heartbeat.sh
# ============================================================
set -uo pipefail

je() { # JSON 字符串转义（控制字符必须转义，否则产出的是非法 JSON）
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\r'/\\r}
  s=${s//$'\n'/\\n}
  s=${s//$'\t'/\\t}
  printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037'
}

unit_state() { # systemd 单元状态；读不到时给 unknown（不假装 active）
  local s
  s=$(systemctl is-active "$1" 2>/dev/null | head -1)
  [ -n "$s" ] || s=unknown
  printf '%s' "$s"
}

# 【踩坑】这台 Aliyun 镜像上 SSH 的单元叫 sshd.service，不叫 ssh.service；
#   `systemctl is-active ssh` 会老老实实返回 "inactive"（rc=3）——
#   也就是"名字写错"会被读成"服务挂了"。所以这里两个名字都试。
unit_state_any() {
  local u s
  for u in "$@"; do
    s=$(systemctl is-active "$u" 2>/dev/null | head -1)
    case "$s" in active|activating|deactivating|failed) printf '%s' "$s"; return 0 ;; esac
  done
  printf 'unknown'
}

disk_pct() { # 挂载点使用率（整数百分比）；路径不存在给 -1
  local p
  p=$(df -P "$1" 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')
  [ -n "$p" ] || p=-1
  printf '%s' "$p"
}

HOST=$(hostname 2>/dev/null || echo unknown)
NOW=$(date +%s)
NOW_H=$(date '+%F %T')
UP=$(awk '{printf "%d", $1}' /proc/uptime 2>/dev/null || echo 0)
LOAD1=$(awk '{print $1}' /proc/loadavg 2>/dev/null | tr -dc '0-9.')
[ -n "$LOAD1" ] || LOAD1=0
MEM_AVAIL=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null | tr -dc '0-9')
[ -n "$MEM_AVAIL" ] || MEM_AVAIL=0

# 只报"读了能说明问题"的单元；哪些是【必须 active】由 srv2 侧决定（SRV1_REQUIRED_UNITS），
# 免得这边新增一个单元就把对面的判定改了。
U_REDEPLOY=$(unit_state secagent-redeploy.timer)
U_HEALTHWATCH=$(unit_state secagent-healthwatch.timer)
U_CAPACITY=$(unit_state secagent-capacity-srv1.timer)
U_DOCKER=$(unit_state docker)
U_SSHD=$(unit_state_any sshd ssh)
# 【2026-10-13 实测】secagent-redeploy.timer 会被外部重启（journal 里成对出现
#   "Stopped ... Started ..."），重启的瞬间 is-active 读到 inactive。
#   若只看 timer，这种"正在部署"的瞬间会被对面判成故障 —— 所以把 companion service
#   的状态一起报出去，让 srv2 侧能区分"部署进行中"与"单元真的挂了"。
S_REDEPLOY=$(unit_state secagent-redeploy.service)
S_HEALTHWATCH=$(unit_state secagent-healthwatch.service)

printf '{"marker":"secagent-heartbeat/1","host":"%s","ts":%s,"time":"%s","uptime_s":%s,"load1":"%s","mem_avail_mb":%s,"disk":{"root_pct":%s,"opt_pct":%s},"units":{"secagent-redeploy.timer":"%s","secagent-healthwatch.timer":"%s","secagent-capacity-srv1.timer":"%s","docker":"%s","sshd":"%s"},"services":{"secagent-redeploy.service":"%s","secagent-healthwatch.service":"%s"}}\n' \
  "$(je "$HOST")" "$NOW" "$(je "$NOW_H")" "$UP" "$(je "$LOAD1")" "$MEM_AVAIL" \
  "$(disk_pct /)" "$(disk_pct /opt/secagent)" \
  "$U_REDEPLOY" "$U_HEALTHWATCH" "$U_CAPACITY" "$U_DOCKER" "$U_SSHD" \
  "$S_REDEPLOY" "$S_HEALTHWATCH"
