#!/usr/bin/env bash
# ============================================================
# srv2 侧：为 srv1 主机侧 Wazuh agent 生成注册凭证（client.keys 行）
# ------------------------------------------------------------
# 用法（在 srv2 上）：
#   sudo bash -s -- --name srv1-host --out /tmp/srv1-client.keys
#
# 为什么要独立成一步：
#   注册返回的 key 是 agent 的身份凭证，等于密码。
#   本脚本【只把 key 写进 --out 指定的文件】，绝不打印到终端，
#   避免它进 shell 历史 / CI 日志 / 会话记录。
#
# 为什么用 "any" 作为注册 IP：
#   srv1 是通过 SSH 隧道连过来的，manager 看到的源地址是 127.0.0.1，
#   注册成真实公网 IP 反而会错。authd 的 use_source_ip=no，
#   实际是按 key 认证，不是按 IP。
# ============================================================
set -uo pipefail

NAME="srv1-host"; OUT="/tmp/srv1-client.keys"; FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2 ;;
    --out)  OUT="$2";  shift 2 ;;
    --force) FORCE=1; shift ;;
    *) echo "[X] 未知参数：$1"; exit 2 ;;
  esac
done

C_CY='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_0='\033[0m'
log()  { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }
ok()   { printf "  ${C_OK}[OK]${C_0} %s\n" "$*"; }
warn() { printf "  ${C_WARN}[!]${C_0} %s\n" "$*"; }
die()  { printf "  ${C_ERR}[X]${C_0} %s\n" "$*"; exit 1; }

[ "$(id -u)" = "0" ] || die "需要 root"
docker ps --format '{{.Names}}' | grep -qx wazuh.manager || die "wazuh.manager 容器没在跑"
M="docker exec wazuh.manager"

log "1/4 看 manager 里现有 agent"
$M /var/ossec/bin/manage_agents -l | sed 's/^/  /'

log "2/4 注册（已存在就复用）"
EXIST_ID="$($M /var/ossec/bin/manage_agents -l 2>/dev/null | awk -v n="$NAME" -F'[, ]+' '$0 ~ n {for(i=1;i<=NF;i++) if($i=="ID:") print $(i+1)}' | head -1)"
if [ -n "$EXIST_ID" ] && [ "$FORCE" = 0 ]; then
  ok "agent '$NAME' 已存在，ID=$EXIST_ID（不改动；要重建用 --force）"
  ID="$EXIST_ID"
else
  if [ -n "$EXIST_ID" ] && [ "$FORCE" = 1 ]; then
    warn "移除旧 agent ID=$EXIST_ID"
    $M /var/ossec/bin/manage_agents -r "$EXIST_ID" | sed 's/^/  /'
  fi
  OUTADD="$($M /var/ossec/bin/manage_agents -a any -n "$NAME" 2>&1)"
  echo "$OUTADD" | sed 's/^/  /'
  ID="$(echo "$OUTADD" | grep -oE 'ID:?[[:space:]]+[0-9]+' | grep -oE '[0-9]+' | head -1)"
  [ -n "$ID" ] || ID="$(echo "$OUTADD" | sed -n 's/.*added with ID \([0-9]\+\).*/\1/p' | head -1)"
  [ -n "$ID" ] || die "注册失败，拿不到 agent ID（原始输出见上）"
  ok "已注册 agent ID=$ID name=$NAME ip=any"
fi

log "3/4 取出 key 并写入 $OUT（内容不打印）"
rm -f "$OUT"
umask 077
$M /var/ossec/bin/manage_agents -e "$ID" 2>/dev/null \
  | grep -oE '[A-Za-z0-9+/]{40,}={0,2}' | head -1 > /tmp/.k
KEY="$(cat /tmp/.k)"; rm -f /tmp/.k
[ -n "$KEY" ] || die "取 key 失败"
printf '%s %s any %s\n' "$ID" "$NAME" "$KEY" > "$OUT"
chmod 600 "$OUT"
ok "已写 $OUT（$(wc -c < "$OUT") 字节，含 ID/name/IP/key 四段）"

log "4/4 复核"
printf '  client.keys 的 ID/name/IP 段: %s\n' "$(awk '{print $1, $2, $3}' "$OUT")"
echo "  manager 侧 agent 列表:"
$M /var/ossec/bin/manage_agents -l | sed 's/^/    /'
echo
ok "下一步：把 $OUT 送到 srv1，用 scripts/srv1-wazuh-agent-install.sh 安装"
