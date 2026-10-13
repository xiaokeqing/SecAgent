#!/usr/bin/env bash
# ============================================================
# srv1 主机侧：建立到 srv2 Wazuh manager 的 1514/1515 隧道（systemd 固化）
# ------------------------------------------------------------
# 用法：
#   sudo bash -s -- --check     # 只体检
#   sudo bash -s -- --apply     # 生成密钥（如缺）+ 安装/启用隧道单元
#   sudo bash -s -- --pubkey    # 打印待授权的公钥（给 srv2 侧用）
#   sudo bash -s -- --status
#   sudo bash -s -- --rollback
#
# apply 之后必须把公钥授权到 srv2（scripts/srv2-authorize-wazuh-agent.sh），
# 否则隧道会起不来（ssh 报 Permission denied）。
# ============================================================
set -uo pipefail

MODE="--apply"
for a in "$@"; do
  case "$a" in
    --check|--apply|--pubkey|--status|--rollback) MODE="$a" ;;
    *) echo "[X] 未知参数：$a"; exit 2 ;;
  esac
done

REPO="${SECAGENT_REPO:-/opt/secagent}"
KEY=/root/.ssh/wazuh_agent_srv2_ed25519
SRV2=43.143.114.79
UNIT=/etc/systemd/system/secagent-wazuh-agent-tunnel.service
SRC_UNIT="$REPO/deploy/secagent-wazuh-agent-tunnel.service"
BACKUP_ROOT=/var/backups/secagent/wazuh-tunnel

C_CY='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_0='\033[0m'
log()  { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }
ok()   { printf "  ${C_OK}[OK]${C_0} %s\n" "$*"; }
warn() { printf "  ${C_WARN}[!]${C_0} %s\n" "$*"; }
die()  { printf "  ${C_ERR}[X]${C_0} %s\n" "$*"; exit 1; }

need_root() { [ "$(id -u)" = "0" ] || die "需要 root"; }

ensure_key() {
  log "1/4 密钥"
  if [ -f "$KEY" ]; then ok "已有密钥 $KEY"
  else
    ssh-keygen -t ed25519 -N '' -C "secagent-srv1-wazuh-agent" -f "$KEY" >/dev/null
    chmod 600 "$KEY"; chmod 644 "$KEY.pub"
    ok "已生成 $KEY（专用密钥，只在 srv2 上授权转发 1514/1515）"
  fi
  echo "  公钥指纹: $(ssh-keygen -lf "$KEY.pub" | awk '{print $2}')"
}

show_pubkey() { [ -f "$KEY.pub" ] && cat "$KEY.pub" || die "还没有公钥，先 --apply"; }

backup_state() {
  local ts d; ts="$(date +%Y%m%d-%H%M%S)"; d="$BACKUP_ROOT/$ts"; mkdir -p "$d"
  : > "$d/manifest"
  if [ -e "$UNIT" ]; then cp -a "$UNIT" "$d/"; printf 'yes\t%s\t%s\n' "$UNIT" "$(basename "$UNIT")" >> "$d/manifest"
  else printf 'no\t%s\t%s\n' "$UNIT" "$(basename "$UNIT")" >> "$d/manifest"; fi
  ln -sfn "$d" "$BACKUP_ROOT/last"
  cat > "$d/restore.sh" <<'RESTORE'
#!/usr/bin/env bash
set -u
D="$(cd "$(dirname "$0")" && pwd)"
while IFS=$'\t' read -r existed target name; do
  if [ "$existed" = "yes" ]; then install -m 0644 "$D/$name" "$target" && echo "  restored $target"
  else [ -e "$target" ] && rm -f "$target" && echo "  removed  $target"; fi
done < "$D/manifest"
systemctl daemon-reload
systemctl restart secagent-wazuh-agent-tunnel 2>/dev/null || true
RESTORE
  chmod +x "$d/restore.sh"; echo "$d"
}

check_state() {
  log "1/3 体检"
  [ -f "$KEY" ] && ok "密钥在" || warn "密钥不存在（--apply 会生成）"
  [ -f "$SRC_UNIT" ] && ok "单元模板在 $SRC_UNIT" || die "缺 $SRC_UNIT"
  echo "  当前单元状态: $(systemctl is-active secagent-wazuh-agent-tunnel 2>/dev/null || echo '未安装')"
  echo "  当前 1514/1515 监听:"; ss -tlnp 2>/dev/null | grep -E '1514|1515' | sed 's/^/    /' || echo "    （无）"
}

verify_tunnel() {
  log "4/4 验证"
  echo "  服务状态: $(systemctl is-active secagent-wazuh-agent-tunnel)"
  ss -tlnp 2>/dev/null | grep -E '1514|1515' | sed 's/^/    /'
  local okc=0
  for p in 1514 1515; do
    if ss -tln | grep -q "127.0.0.1:$p"; then ok "127.0.0.1:$p 已监听（仅回环，未对公网/内网暴露）"; else warn "127.0.0.1:$p 没有监听"; okc=1; fi
  done
  if ss -tln | grep -E '1514|1515' | grep -qv '127.0.0.1'; then
    warn "有非回环地址在监听 1514/1515 —— 这不符合「只给本机 agent 用」的设计，请检查"
    okc=1
  fi
  # 真连一次（1514 是 manager 的事件端口；连上后不发送任何东西，立刻断开）
  if timeout 8 bash -c 'exec 3<>/dev/tcp/127.0.0.1/1514' 2>/dev/null; then
    ok "到 manager 的 1514 通道可用（TCP 握手成功）"
  else
    warn "连不上 127.0.0.1:1514 —— 隧道/key 授权/manager 监听 三者有一个不对"
    journalctl -u secagent-wazuh-agent-tunnel --no-pager -n 15 | sed 's/^/    /'
    okc=1
  fi
  return "$okc"
}

need_root
case "$MODE" in
  --pubkey) show_pubkey ;;
  --check)  check_state ;;
  --status)
    check_state; verify_tunnel || true ;;
  --rollback)
    d="$(readlink -f "$BACKUP_ROOT/last" 2>/dev/null || true)"
    [ -n "$d" ] && [ -d "$d" ] || die "没有备份"
    log "回滚到 $d"; ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
    ;;
  --apply)
    ensure_key
    log "2/4 备份 + 安装单元"
    BAK="$(backup_state)"; ok "备份在 $BAK"
    install -m 0644 -o root -g root "$SRC_UNIT" "$UNIT" && ok "$UNIT"
    systemctl daemon-reload
    systemctl enable secagent-wazuh-agent-tunnel >/dev/null 2>&1
    log "3/4 启动隧道"
    systemctl restart secagent-wazuh-agent-tunnel
    sleep 6
    if ! verify_tunnel; then
      echo
      warn "隧道没通。最常见原因：公钥还没授权到 srv2（或缺 permitopen）。请执行："
      echo "    在 srv2 上跑：sudo bash scripts/srv2-authorize-wazuh-agent.sh"
      echo "    公钥内容（本机 --pubkey 可再打印）："
      show_pubkey | sed 's/^/      /'
      exit 1
    fi
    echo
    ok "隧道已固化（systemd，开机自启 + 断线自动重连）"
    echo "  记下：这条隧道只绑 127.0.0.1，srv1 上只有 wazuh-agent 会用它。"
    ;;
esac
