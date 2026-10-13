#!/usr/bin/env bash
# ============================================================
# srv2 侧：授权 srv1 的 Wazuh agent 隧道公钥（只允许转发 1514/1515）
# ------------------------------------------------------------
# 用法（在 srv2 上）：
#   sudo bash -s -- --apply      # 从 srv1 读公钥（或读本地缓存）并授权
#   sudo bash -s -- --check
#   sudo bash -s -- --rollback
#
# 授权行的限制（关键）：
#   command="/bin/false"   不允许执行任何命令（-N 隧道不受影响）
#   restrict               关掉 pty/agent/x11/端口转发以外的所有能力
#   port-forwarding        只开转发
#   permitopen 1514/1515   只允许转发这两个回环端口，别的端口转不出去
#
# 这是"最小授权"：即使 srv1 被拿下、这把私钥被拿走，
# 也只能把 srv2 的 1514/1515 映射出去，拿不到 shell、读不到别的端口。
# ============================================================
set -uo pipefail

MODE="--apply"
for a in "$@"; do
  case "$a" in
    --check|--apply|--rollback) MODE="$a" ;;
    *) echo "[X] 未知参数：$a"; exit 2 ;;
  esac
done

AK=/root/.ssh/authorized_keys
KEY_COMMENT="secagent-srv1-wazuh-agent"
TAG="secagent-wazuh-agent-from-srv1"
BACKUP_ROOT=/var/backups/secagent/wazuh-agent-auth
# srv1 上的公钥缓存路径（由 srv1 侧脚本生成；本脚本可读取它做幂等）
SRC_PUB=${SRC_PUB:-/root/.ssh/wazuh_agent_srv1.pub}

C_CY='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_0='\033[0m'
log()  { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }
ok()   { printf "  ${C_OK}[OK]${C_0} %s\n" "$*"; }
warn() { printf "  ${C_WARN}[!]${C_0} %s\n" "$*"; }
die()  { printf "  ${C_ERR}[X]${C_0} %s\n" "$*"; exit 1; }

[ "$(id -u)" = "0" ] || die "需要 root（sudo bash -s -- $MODE）"

restrict_prefix='command="/bin/false",restrict,port-forwarding,permitopen="127.0.0.1:1514",permitopen="127.0.0.1:1515"'

get_pubkey() {
  if [ -s "$SRC_PUB" ]; then cat "$SRC_PUB"; return 0; fi
  # 兜底：从 stdin 读（sudo bash -s -- --apply < srv1 公钥文件 这种用法）
  if [ ! -t 0 ]; then cat -; return 0; fi
  return 1
}

case "$MODE" in
  --check)
    log "体检"
    echo "  authorized_keys: $AK"
    echo "  已授权的本项目隧道 key 行数: $(grep -c "$TAG" "$AK" 2>/dev/null || echo 0)"
    grep -n "$TAG" "$AK" 2>/dev/null | sed 's/^/    /' || true
    echo "  srv2 上 1514/1515 监听:"
    ss -tlnp 2>/dev/null | grep -E '1514|1515' | sed 's/^/    /'
    echo "  srv2 fail2ban 是否把 srv1 加入白名单（否则隧道迟早被自己的 fail2ban 封）:"
    fail2ban-client get sshd ignoreip 2>/dev/null | sed 's/^/    /' || echo "    （拿不到）"
    ;;
  --apply)
    log "1/4 取公钥"
    PUB="$(get_pubkey)" || die "拿不到公钥（把 srv1 的 wazuh_agent_srv2_ed25519.pub 放到 $SRC_PUB，或用 stdin 传入）"
    echo "$PUB" | head -1 | awk '{print "  待授权: "$1" ... "$NF}'
    case "$PUB" in ssh-ed25519*|ssh-rsa*|ecdsa-*) ;; *) die "公钥格式不对" ;; esac
    log "2/4 备份 authorized_keys"
    ts="$(date +%Y%m%d-%H%M%S)"; d="$BACKUP_ROOT/$ts"; mkdir -p "$d"
    cp -a "$AK" "$d/authorized_keys"
    printf 'yes\t%s\t%s\n' "$AK" "authorized_keys" > "$d/manifest"
    ln -sfn "$d" "$BACKUP_ROOT/last"
    cat > "$d/restore.sh" <<'RESTORE'
#!/usr/bin/env bash
set -u
D="$(cd "$(dirname "$0")" && pwd)"
install -m 600 -o root -g root "$D/authorized_keys" /root/.ssh/authorized_keys && echo "  restored authorized_keys"
RESTORE
    chmod +x "$d/restore.sh"
    ok "备份在 $d"
    log "3/4 授权（幂等，按 tag 去重）"
    if grep -q "$TAG" "$AK" 2>/dev/null; then
      # 已有同 tag 的行：替换掉（保证限制项与当前脚本一致）
      cp -a "$AK" "$d/authorized_keys.before-update"
      grep -v "$TAG" "$AK" > "$AK.new" && cat "$AK.new" > "$AK" && rm -f "$AK.new"
      ok "已移除旧的同 tag 授权行（准备重写）"
    fi
    printf '%s %s %s\n' "$restrict_prefix" "$(echo "$PUB" | awk '{print $1" "$2}')" "$TAG" >> "$AK"
    chmod 600 "$AK"; chown root:root "$AK"
    ok "已写入授权行（限制：命令禁用 + 只允许转发 127.0.0.1:1514/1515）"
    log "4/4 复核"
    echo "  authorized_keys 行数: $(wc -l < "$AK")"
    grep -n "$TAG" "$AK" | sed 's/^/    /'
    echo "  现有全部授权（只看限制前缀）:"
    awk '{print "    "$1" "$2" ... "$NF}' "$AK"
    ;;
  --rollback)
    d="$(readlink -f "$BACKUP_ROOT/last" 2>/dev/null || true)"
    [ -n "$d" ] && [ -d "$d" ] || die "没有备份"
    log "回滚到 $d"; ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
    ;;
esac
