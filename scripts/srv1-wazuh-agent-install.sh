#!/usr/bin/env bash
# ============================================================
# srv1 主机侧检测（二）：Wazuh agent
# ------------------------------------------------------------
# 装什么：
#   · wazuh-agent 4.9.2（RPM，与 manager 同版本）
#   · /var/ossec/etc/ossec.conf <- deploy/wazuh/srv1-ossec.conf
#   · /var/ossec/etc/client.keys <- 由 manager 侧生成后送过来
#     （scripts/srv2-wazuh-agent-key.sh --out ...）
#
# 用法（srv1 上）：
#   sudo bash -s -- --check
#   sudo bash -s -- --apply --keys /path/to/srv1-client.keys
#   sudo bash -s -- --status
#   sudo bash -s -- --rollback
#
# 前置条件（脚本会自己检查，不满足就拒绝改）：
#   ① 隧道 secagent-wazuh-agent-tunnel 在跑，且 127.0.0.1:1514 可连
#   ② vendor 目录里有同版本 RPM（本机可直连 packages.wazuh.com，已实测可下）
#   ③ 已有 client.keys 文件（--keys）
#
# 备份 -> 改 -> 校验 -> 失败回滚：
#   · 备份 /var/ossec/etc/ossec.conf 与 client.keys 到
#     /var/backups/secagent/wazuh-agent/<ts>/（附 restore.sh）
#   · 改完用 /var/ossec/bin/wazuh-agentd -t 校验配置（不是靠"服务起来了"猜）
#   · 失败就把文件换回去
# ============================================================
set -uo pipefail

MODE="--apply"; KEYS=""; RPM=""; FORCE_KEYS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --check|--apply|--status|--rollback) MODE="$1"; shift ;;
    --keys) KEYS="$2"; shift 2 ;;
    --rpm)  RPM="$2";  shift 2 ;;
    --force-keys) FORCE_KEYS=1; shift ;;
    --enroll)
      # 正式注册：走隧道到 srv2 的 1515，用 agent-auth 拿一把正确的 key。
      # （这就是本次实测唯一可靠的方式；见 RUNBOOK §21）
      echo "==> 用 agent-auth 注册（名称 $ENROLL_NAME，经 127.0.0.1:1515 隧道）"
      [ "$(id -u)" = 0 ] || { echo "需要 root"; exit 1; }
      /var/ossec/bin/agent-auth -m 127.0.0.1 -p 1515 -A "$ENROLL_NAME" 2>&1 | tail -6
      awk '{print "  client.keys: id="$1" name="$2" ip="$3}' /var/ossec/etc/client.keys
      systemctl restart wazuh-agent
      sleep 8
      echo "  服务: $(systemctl is-active wazuh-agent)"
      grep -a 'Connected to the server' /var/ossec/logs/ossec.log | tail -1
      exit 0 ;;
    *) echo "[X] 未知参数：$1"; exit 2 ;;
  esac
done

REPO="${SECAGENT_REPO:-/opt/secagent}"
ENROLL_NAME="${ENROLL_NAME:-srv1-host}"
OSCONF="/var/ossec/etc/ossec.conf"
CLIENTKEYS="/var/ossec/etc/client.keys"
SRC_CONF="$REPO/deploy/wazuh/srv1-ossec.conf"
VENDOR_RPM_DEFAULT="$REPO/vendor/wazuh-agent-4.9.2-1.x86_64.rpm"
BACKUP_ROOT=/var/backups/secagent/wazuh-agent
[ -n "$RPM" ] || RPM="$VENDOR_RPM_DEFAULT"
[ -n "$KEYS" ] || KEYS="$REPO/vendor/srv1-client.keys"

C_CY='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_0='\033[0m'
log()  { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }
ok()   { printf "  ${C_OK}[OK]${C_0} %s\n" "$*"; }
warn() { printf "  ${C_WARN}[!]${C_0} %s\n" "$*"; }
die()  { printf "  ${C_ERR}[X]${C_0} %s\n" "$*"; exit 1; }

need_root() { [ "$(id -u)" = "0" ] || die "需要 root"; }

preflight() {
  log "1/6 前置检查"
  local bad=0
  if systemctl is-active --quiet secagent-wazuh-agent-tunnel; then
    ok "隧道服务在跑"
  else warn "隧道 secagent-wazuh-agent-tunnel 没在跑（先跑 srv1-wazuh-tunnel-setup.sh --apply）"; bad=1; fi
  if timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/1514' 2>/dev/null; then
    ok "127.0.0.1:1514 可连（到 manager 的通道通）"
  else warn "连不上 127.0.0.1:1514"; bad=1; fi
  [ -f "$SRC_CONF" ] && ok "配置模板 $SRC_CONF" || { warn "缺 $SRC_CONF"; bad=1; }
  if [ -f "$RPM" ]; then ok "RPM $RPM ($(stat -c %s "$RPM") 字节)"
  elif rpm -q wazuh-agent >/dev/null 2>&1; then ok "wazuh-agent 已安装（不需要 RPM）"
  else warn "既没装 wazuh-agent，也找不到 RPM：$RPM"; bad=1; fi
  if [ -f "$KEYS" ]; then
    ok "client.keys 来源 $KEYS（ID/name/IP: $(awk '{print $1, $2, $3}' "$KEYS")）"
  elif [ -s "$CLIENTKEYS" ]; then ok "已装机器上已有 client.keys（$(awk '{print $1, $2, $3}' "$CLIENTKEYS")）"
  else warn "没有 client.keys 来源（--keys 指定，或用 srv2-wazuh-agent-key.sh 生成）"; bad=1; fi
  echo "  磁盘: $(df -h / | awk 'NR==2{print $4" 可用"}')   内存: $(free -m | awk 'NR==2{print $7" MB 可用"}')"
  return "$bad"
}

backup_state() {
  local ts d; ts="$(date +%Y%m%d-%H%M%S)"; d="$BACKUP_ROOT/$ts"; mkdir -p "$d"; : > "$d/manifest"
  local t n
  for t in "$OSCONF" "$CLIENTKEYS"; do
    n="$(basename "$t")"
    if [ -e "$t" ]; then cp -a "$t" "$d/$n"; printf 'yes\t%s\t%s\n' "$t" "$n" >> "$d/manifest"
    else printf 'no\t%s\t%s\n' "$t" "$n" >> "$d/manifest"; fi
  done
  ln -sfn "$d" "$BACKUP_ROOT/last"
  cat > "$d/restore.sh" <<'RESTORE'
#!/usr/bin/env bash
set -u
D="$(cd "$(dirname "$0")" && pwd)"
while IFS=$'\t' read -r existed target name; do
  if [ "$existed" = "yes" ]; then install -m 640 -o root -g wazuh "$D/$name" "$target" && echo "  restored $target"
  else [ -e "$target" ] && rm -f "$target" && echo "  removed  $target"; fi
done < "$D/manifest"
systemctl restart wazuh-agent 2>/dev/null || true
RESTORE
  chmod +x "$d/restore.sh"; echo "$d"
}

install_rpm() {
  if rpm -q wazuh-agent >/dev/null 2>&1; then
    ok "wazuh-agent 已安装：$(rpm -q wazuh-agent)"
    return 0
  fi
  log "3/6 安装 RPM"
  rpm -ivh "$RPM" 2>&1 | tail -5 | sed 's/^/  /'
  rpm -q wazuh-agent >/dev/null 2>&1 || return 1
  ok "已安装 $(rpm -q wazuh-agent)"
}

write_config() {
  log "4/6 写配置"
  install -m 0640 -o root -g wazuh "$SRC_CONF" "$OSCONF" && ok "$OSCONF"
  # client.keys 的处理（实测踩过坑，这里是有意为之）：
  #   只要机器上已经有一份能用的 client.keys，就【不要】拿 --keys 再覆盖它。
  #   原因：离线那套 key 是 manager 侧 manage_agents -e 导出的 base64 串，
  #   直接塞进 client.keys 会 "Wrong key or corrupt payload"；
  #   而 agent 发现 key 不对时会【自己重新注册】，于是 agent ID 一路往上飘
  #   （本次实测：003 -> 004 -> 005 -> 006），manager 上留一堆 Disconnected 的僵尸 agent。
  #   正确姿势：用 agent-auth（见 RUNBOOK §21），或者用 --force-keys 明确表示"我知道我在覆盖"。
  if [ -s "$CLIENTKEYS" ] && [ "$FORCE_KEYS" != 1 ]; then
    ok "$CLIENTKEYS 已存在（ID $(awk '{print $1}' "$CLIENTKEYS")），保留不动"
  elif [ -f "$KEYS" ]; then
    install -m 0640 -o root -g wazuh "$KEYS" "$CLIENTKEYS" && ok "$CLIENTKEYS（来自 $KEYS，ID $(awk '{print $1}' "$CLIENTKEYS")）"
  else
    chmod 640 "$CLIENTKEYS"; chown root:wazuh "$CLIENTKEYS"
    ok "$CLIENTKEYS 沿用机器上已有的"
  fi
  systemctl daemon-reload
}

validate_config() {
  log "5/6 校验 agent 配置"
  if [ -x /var/ossec/bin/wazuh-agentd ]; then
    if /var/ossec/bin/wazuh-agentd -t 2>&1 | sed 's/^/    /'; then ok "wazuh-agentd -t 通过"; else return 1; fi
  else
    warn "没有 /var/ossec/bin/wazuh-agentd，跳过 -t（改回滚判据：服务起不来就回滚）"
  fi
  return 0
}

start_and_verify() {
  log "6/6 启动并验证"
  systemctl enable wazuh-agent >/dev/null 2>&1
  systemctl restart wazuh-agent
  sleep 10
  echo "  服务状态: $(systemctl is-active wazuh-agent)"
  [ "$(systemctl is-active wazuh-agent)" = "active" ] || {
    journalctl -u wazuh-agent --no-pager -n 20 | sed 's/^/    /'; return 1; }
  echo "  --- agent 自己的日志（最后 12 行）---"
  tail -12 /var/ossec/logs/ossec.log 2>/dev/null | sed 's/^/    /'
  if grep -aq 'Connected to the server' /var/ossec/logs/ossec.log 2>/dev/null; then
    ok "已连上 manager（ossec.log 出现 Connected to the server）"
  else
    warn "还没看到 'Connected to the server'（可能刚起步，稍后用 --status 复查）"
  fi
  # 配置里被关掉的项要能自证：不能让"关了"这件事只存在于文件里
  echo "  --- 生效的采集项 ---"
  grep -aE 'Analyzing file|Monitoring' /var/ossec/logs/ossec.log 2>/dev/null | tail -8 | sed 's/^/    /'
  return 0
}

show_status() {
  log "运行态"
  echo "  包版本: $(rpm -q wazuh-agent 2>/dev/null || echo 未安装)"
  echo "  服务: $(systemctl is-active wazuh-agent 2>/dev/null) / enabled=$(systemctl is-enabled wazuh-agent 2>/dev/null)"
  echo "  client.keys: $(awk '{print "ID="$1" name="$2" ip="$3}' "$CLIENTKEYS" 2>/dev/null || echo 无)"
  echo "  隧道: $(systemctl is-active secagent-wazuh-agent-tunnel 2>/dev/null)  1514/1515 监听:"
  ss -tln 2>/dev/null | grep -E '1514|1515' | sed 's/^/    /'
  echo "  ossec.log 尾部:"
  tail -8 /var/ossec/logs/ossec.log 2>/dev/null | sed 's/^/    /'
  echo "  各进程 RSS:"
  ps -eo rss,comm --sort=-rss 2>/dev/null | grep -E 'wazuh|ossec' | sed 's/^/    /'
  echo "  总计 RSS: $(ps -eo rss,comm 2>/dev/null | grep -E 'wazuh|ossec' | awk '{s+=$1} END{printf "%.1f MB\n", s/1024}')"
}

need_root
case "$MODE" in
  --check) preflight || true ;;
  --status) show_status ;;
  --rollback)
    d="$(readlink -f "$BACKUP_ROOT/last" 2>/dev/null || true)"
    [ -n "$d" ] && [ -d "$d" ] || die "没有备份"
    log "回滚到 $d"; ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
    ;;
  --apply)
    preflight || die "前置条件不满足，不动任何配置"
    log "2/6 备份"
    BAK="$(backup_state)"; ok "备份在 $BAK（回滚：sudo bash -s -- --rollback）"
    install_rpm || die "RPM 安装失败（引擎依赖缺失？看上面输出）"
    write_config
    if ! validate_config; then
      warn "配置校验失败 —— 回滚"
      ( cd "$BAK" && ./restore.sh ) | sed 's/^/  /'
      die "已回滚；请修 $SRC_CONF 后重试"
    fi
    if ! start_and_verify; then
      warn "服务没起来 —— 回滚"
      ( cd "$BAK" && ./restore.sh ) | sed 's/^/  /'
      die "已回滚；看 journalctl -u wazuh-agent"
    fi
    echo
    ok "srv1 Wazuh agent 已就位"
    echo "  下一步（在 srv2 上）："
    echo "    docker exec wazuh.manager /var/ossec/bin/agent_control -l   # 应看到该 agent 为 Active"
    ;;
esac
