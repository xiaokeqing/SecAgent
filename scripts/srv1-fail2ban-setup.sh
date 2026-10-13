#!/usr/bin/env bash
# ============================================================
# srv1 主机侧检测（一）：fail2ban
# ------------------------------------------------------------
# 装什么：
#   1) sshd jail —— maxretry=4 / findtime=10m / bantime=1h（沿用已有口径）
#   2) secagent-public-api jail —— 盯应用日志里的"公开端点注入尝试"
#   3) secagent-applog-mirror.service —— 把应用容器 stdout 落到
#      /var/log/secagent/app.log（jail 的日志来源，路径稳定）
#
# 用法（服务器上）：
#   sudo bash -s -- --check      # 只体检，不改任何东西
#   sudo bash -s -- --apply      # 备份 -> 改 -> 校验 -> 失败自动回滚（默认）
#   sudo bash -s -- --selftest   # 用样例日志验证过滤器正则（不改配置）
#   sudo bash -s -- --status     # 看当前运行态
#   sudo bash -s -- --rollback   # 回滚到最近一次 --apply 之前的配置
#
# 仓库路径：默认 /opt/secagent，可用 SECAGENT_REPO=... 覆盖。
# 本脚本只从仓库里的 deploy/fail2ban/** 安装配置 ——
# 配置片段在仓库里只有一份，避免"脚本里一份、deploy 里一份"迟早漂移。
# ============================================================
set -uo pipefail

MODE="--apply"
for a in "$@"; do
  case "$a" in
    --check|--apply|--rollback|--status|--selftest) MODE="$a" ;;
    -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]:-$0}" 2>/dev/null || true; exit 0 ;;
    *) echo "[X] 未知参数：$a"; exit 2 ;;
  esac
done

REPO="${SECAGENT_REPO:-/opt/secagent}"
JAIL_D="/etc/fail2ban/jail.d"
FILTER_D="/etc/fail2ban/filter.d"
LOG_DIR="/var/log/secagent"
APP_LOG="$LOG_DIR/app.log"
BACKUP_ROOT="/var/backups/secagent/fail2ban"
UNIT_DST="/etc/systemd/system/secagent-applog-mirror.service"
LOGROTATE_DST="/etc/logrotate.d/secagent-applog"

SRC_SSHD="$REPO/deploy/fail2ban/jail.d/sshd.local"
SRC_JAIL="$REPO/deploy/fail2ban/jail.d/secagent-public-api.local"
SRC_FILTER="$REPO/deploy/fail2ban/filter.d/secagent-public-api.conf"
SRC_UNIT="$REPO/deploy/secagent-applog-mirror.service"
SRC_LOGROTATE="$REPO/deploy/logrotate/secagent-applog"
SRC_MIRROR="$REPO/scripts/srv1-applog-mirror.sh"

C_CY='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_0='\033[0m'
log()  { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }
ok()   { printf "  ${C_OK}[OK]${C_0} %s\n" "$*"; }
warn() { printf "  ${C_WARN}[!]${C_0} %s\n" "$*"; }
die()  { printf "  ${C_ERR}[X]${C_0} %s\n" "$*"; exit 1; }

# ------------------------------------------------------------
need_root() { [ "$(id -u)" = "0" ] || die "需要 root（用 sudo bash -s -- $MODE）"; }

check_sources() {
  log "1/6 前置检查"
  echo "  仓库路径: $REPO"
  local miss=0
  for f in "$SRC_SSHD" "$SRC_JAIL" "$SRC_FILTER" "$SRC_UNIT" "$SRC_LOGROTATE" "$SRC_MIRROR"; do
    if [ -f "$f" ]; then ok "找到 $f"; else warn "缺失 $f"; miss=1; fi
  done
  command -v fail2ban-client >/dev/null 2>&1 || die "没装 fail2ban（dnf install -y fail2ban）"
  ok "fail2ban-client: $(fail2ban-client --version 2>/dev/null | head -1)"
  systemctl is-active --quiet fail2ban && ok "fail2ban 服务在跑" || warn "fail2ban 服务未运行"
  command -v firewall-cmd >/dev/null 2>&1 && ok "firewalld 工具在位" || warn "没有 firewall-cmd（封禁动作会退化）"
  [ "$miss" = 0 ] || die "仓库里配置片段不全，先同步仓库（缺文件见上）"
}

# ------------------------------------------------------------
# 备份：把每一个"将被写"的目标路径记进 manifest，回滚时按 manifest 还原
backup_state() {
  local ts dir
  ts="$(date +%Y%m%d-%H%M%S)"; dir="$BACKUP_ROOT/$ts"
  mkdir -p "$dir"
  : > "$dir/manifest"
  local t n
  for t in "$JAIL_D/sshd.local" "$JAIL_D/secagent-public-api.local" \
           "$FILTER_D/secagent-public-api.conf" "$UNIT_DST" "$LOGROTATE_DST"; do
    n="$(basename "$t")"
    if [ -e "$t" ]; then
      cp -a "$t" "$dir/$n"
      printf 'yes\t%s\t%s\n' "$t" "$n" >> "$dir/manifest"
    else
      printf 'no\t%s\t%s\n' "$t" "$n" >> "$dir/manifest"
    fi
  done
  ln -sfn "$dir" "$BACKUP_ROOT/last"
  cat > "$dir/restore.sh" <<'RESTORE'
#!/usr/bin/env bash
# 由 scripts/srv1-fail2ban-setup.sh 生成：把本目录列的文件还原到备份前状态
set -u
D="$(cd "$(dirname "$0")" && pwd)"
while IFS=$'\t' read -r existed target name; do
  if [ "$existed" = "yes" ]; then
    install -m 0644 -o root -g root "$D/$name" "$target" && echo "  restored $target"
  else
    [ -e "$target" ] && rm -f "$target" && echo "  removed  $target (原本不存在)"
  fi
done < "$D/manifest"
systemctl daemon-reload 2>/dev/null || true
echo "  提示：接下来执行 fail2ban-client reload 或 systemctl restart fail2ban 生效"
RESTORE
  chmod +x "$dir/restore.sh"
  echo "$dir"
}

# ------------------------------------------------------------
install_fragments() {
  log "3/6 安装配置片段"
  install -m 0644 -o root -g root "$SRC_SSHD"   "$JAIL_D/sshd.local"                  && ok "$JAIL_D/sshd.local"
  install -m 0644 -o root -g root "$SRC_JAIL"   "$JAIL_D/secagent-public-api.local"    && ok "$JAIL_D/secagent-public-api.local"
  install -m 0644 -o root -g root "$SRC_FILTER" "$FILTER_D/secagent-public-api.conf"   && ok "$FILTER_D/secagent-public-api.conf"
  install -m 0644 -o root -g root "$SRC_UNIT"   "$UNIT_DST"                            && ok "$UNIT_DST"
  install -m 0644 -o root -g root "$SRC_LOGROTATE" "$LOGROTATE_DST"                    && ok "$LOGROTATE_DST"
  # 镜像循环脚本被 unit 直接引用（ExecStart=/bin/bash $SRC_MIRROR），
  # 所以只需要保证它在仓库里且可执行 —— 不额外复制一份，避免两份实现漂移。
  chmod 0755 "$SRC_MIRROR" && ok "$SRC_MIRROR（可执行）"
}

validate_config() {
  log "4/6 校验配置（失败就回滚）"
  # 先保证 logpath 存在再校验 —— fail2ban-client -t 对"logpath 文件不存在"
  # 是【硬失败】：'Have not found any log file for <jail> jail'。
  # 这一步踩过：顺序反了会把整个 jail 判成配置错误，然后触发回滚。
  mkdir -p "$LOG_DIR"
  [ -e "$APP_LOG" ] || : > "$APP_LOG"
  chmod 0640 "$APP_LOG"
  if fail2ban-client -t 2>&1 | sed 's/^/    /'; then
    ok "fail2ban-client -t 通过（logpath $APP_LOG 存在）"
  else
    return 1
  fi
  systemd-analyze verify "$UNIT_DST" >/dev/null 2>&1 && ok "systemd 单元语法通过" \
    || warn "systemd-analyze verify 没通过（继续，稍后用 systemctl 实测）"
  return 0
}

start_mirror() {
  log "5/6 启动日志镜像"
  mkdir -p "$LOG_DIR"
  [ -e "$APP_LOG" ] || : > "$APP_LOG"
  chmod 0640 "$APP_LOG"
  systemctl daemon-reload
  systemctl enable secagent-applog-mirror >/dev/null 2>&1
  systemctl restart secagent-applog-mirror
  # 别只看一眼就判决：systemd 的 activating -> active 有过渡态，
  # 而 `docker logs -f` 在容器重启中会正常退出一次再由循环重连。
  local i=0 state=""
  while [ "$i" -lt 20 ]; do
    state="$(systemctl is-active secagent-applog-mirror)"
    [ "$state" = "active" ] && break
    sleep 2; i=$((i+2))
  done
  echo "  单元状态: $state（等待 ${i}s）"
  if [ "$state" != "active" ]; then
    journalctl -u secagent-applog-mirror --no-pager -n 15 | sed 's/^/    /'
    return 1
  fi
  # 真实流量验证：等容器下一次输出，看文件有没有长
  local before after
  before=$(stat -c %s "$APP_LOG")
  sleep 12
  after=$(stat -c %s "$APP_LOG")
  echo "  $APP_LOG 大小: $before -> $after"
  if [ "$after" -gt "$before" ]; then ok "镜像文件正在增长（应用日志已落到宿主）"
  else warn "12 秒内文件没长（应用这段时间可能本来就没输出，稍后 --status 复核）"; fi
  return 0
}

# 为什么一律 restart 而不是 fail2ban-client reload：
#   实测（fail2ban 1.0.2 / EPEL）：reload 会重建 jail，但【不会重跑 actionstart】。
#   如果这次改的是封禁动作（banaction/action），新动作需要的内核链就不会被创建，
#   于是之后每次封禁只在日志里留一条 "Ban x.x.x.x"：
#   没有 ERROR、status 显示已封，但 iptables 里没有任何规则 —— 假成功。
#   restart 才能保证 actionstart 执行。
bounce_fail2ban() { systemctl restart fail2ban; sleep 5; }

# 断言：封禁动作真的能落到内核（防"假封禁"的最后一道门）
# 为什么不是"检查链是否存在"：
#   fail2ban 的动作是【惰性启动】的 —— restart 之后、第一次真正封禁之前，
#   f2b-<jail> 链根本还不存在（实测确认）。所以只能真的封一个测试地址看结果。
#   这里用 198.51.100.0/24（RFC5737 文档用地址，公网不存在，误伤不了人）。
selftest_action_landing() {
  local jail ip ok_all=0
  for jail_ip in "sshd:198.51.100.9" "secagent-public-api:198.51.100.10"; do
    jail="${jail_ip%%:*}"; ip="${jail_ip##*:}"
    printf '  --- %s：试封 %s ---\n' "$jail" "$ip"
    fail2ban-client set "$jail" banip "$ip" >/dev/null 2>&1
    sleep 2
    if iptables -S 2>/dev/null | grep -qF -- "$ip"; then
      printf '    \033[1;32m[OK]\033[0m 内核规则已落地：%s\n' "$(iptables -S 2>/dev/null | grep -F -- "$ip" | head -1)"
    else
      printf '    \033[1;31m[X]\033[0m 内核里没有 %s 的规则 —— 这个 jail 是【假封禁】\n' "$ip"
      grep -a 'ERROR' /var/log/fail2ban.log | tail -3 | sed 's/^/      /'
      ok_all=1
    fi
    fail2ban-client set "$jail" unbanip "$ip" >/dev/null 2>&1
    sleep 1
    if iptables -S 2>/dev/null | grep -qF -- "$ip"; then
      printf '    \033[1;33m[!]\033[0m 解封后内核里仍残留 %s 的规则\n' "$ip"; ok_all=1
    else
      printf '    \033[1;32m[OK]\033[0m 解封后内核规则已清除\n'
    fi
  done
  return "$ok_all"
}

reload_and_verify() {
  log "6/6 生效并验证（含「真的封得动」自检）"
  bounce_fail2ban
  echo "  fail2ban 服务: $(systemctl is-active fail2ban)"
  echo "  jail 列表:"; fail2ban-client status 2>&1 | sed 's/^/    /'
  local jails; jails="$(fail2ban-client status 2>/dev/null)"
  echo "$jails" | grep -q 'secagent-public-api' || { warn "secagent-public-api jail 没起来"; return 1; }
  echo "$jails" | grep -q 'sshd' || { warn "sshd jail 没起来"; return 1; }
  selftest_action_landing || return 1
  show_status
  return 0
}

show_status() {
  log "运行态"
  for j in sshd secagent-public-api; do
    echo "  --- $j ---"
    fail2ban-client status "$j" 2>&1 | sed 's/^/    /'
  done
  echo "  --- 关键参数 ---"
  printf '    sshd.maxretry=%s sshd.findtime=%s sshd.bantime=%s\n' \
    "$(fail2ban-client get sshd maxretry 2>/dev/null)" \
    "$(fail2ban-client get sshd findtime 2>/dev/null)" \
    "$(fail2ban-client get sshd bantime 2>/dev/null)"
  printf '    secagent-public-api.maxretry=%s findtime=%s bantime=%s\n' \
    "$(fail2ban-client get secagent-public-api maxretry 2>/dev/null)" \
    "$(fail2ban-client get secagent-public-api findtime 2>/dev/null)" \
    "$(fail2ban-client get secagent-public-api bantime 2>/dev/null)"
  printf '    sshd.ignoreip=%s\n' "$(fail2ban-client get sshd ignoreip 2>/dev/null | tr '\n' ' ')"
  echo "  --- 镜像服务 ---"
  printf '    secagent-applog-mirror=%s  %s: %s bytes\n' \
    "$(systemctl is-active secagent-applog-mirror 2>/dev/null)" \
    "$APP_LOG" "$(stat -c %s "$APP_LOG" 2>/dev/null || echo NA)"
  echo "  --- 封禁落地形式：iptables（table ip filter，INPUT 链）---"
  iptables -S 2>/dev/null | grep -E 'f2b-' | head -10 | sed 's/^/    /'
  [ -n "$(iptables -S 2>/dev/null | grep -E 'f2b-')" ] || echo "    （当前没有活跃封禁；链在第一次封禁时创建）"
  echo "  --- 对照 firewalld rich rules（注意：对 docker 网桥进来的流量不生效）---"
  firewall-cmd --list-rich-rules 2>/dev/null | sed 's/^/    /' | head -10
  echo "  --- 资源占用 ---"
  ps -o pid,rss,comm,args -C fail2ban-server 2>/dev/null | sed 's/^/    /'
}

selftest() {
  log "过滤器自测（fail2ban-regex，不动线上配置）"
  local sample="$REPO/deploy/fail2ban/sample/secagent-public-api.sample.txt"
  if [ ! -f "$sample" ]; then
    warn "没有样例文件 $sample，用内联样例"
    sample="$(mktemp)"; chmod 600 "$sample"
    cat > "$sample" <<'EOS'
2026-10-13T11:28:36.677+08:00  WARN 1 --- [nio-9900-exec-1] o.example.publicapi.PublicAlertSource    : 公网只读端点：从上游结果中剔除 6 条内置样本告警
2026-10-13T11:34:02.526+08:00  INFO 1 --- [nio-9900-exec-2] o.example.publicapi.PublicAskService     : 公开提问命中注入特征 2 条，按设计拒绝生成（来源=203.0.113.77）
2026-10-13T11:34:03.100+08:00  INFO 1 --- [nio-9900-exec-3] o.example.publicapi.PublicAskService     : 公开提问命中注入特征 1 条，按设计拒绝生成（来源=198.51.100.9）
2026-10-13T11:34:04.100+08:00  INFO 1 --- [nio-9900-exec-4] o.example.publicapi.PublicAskService     : 公开提问命中注入特征 3 条，按设计拒绝生成（来源=127.0.0.1）
2026-10-13T11:35:00.000+08:00 ERROR 1 --- [nio-9900-exec-1] o.e.security.GlobalExceptionHandler      : 未处理异常
EOS
  fi
  fail2ban-regex "$sample" "$SRC_FILTER" 2>&1 | sed -n '1,40p' | sed 's/^/  /'
  echo
  echo "  期望：匹配 3 行（203.0.113.77 / 198.51.100.9 / 127.0.0.1），WARN 与 ERROR 行不匹配。"
  echo "  注意最后一条：来源=127.0.0.1 —— 靠 jail 的 ignoreip 才不会被封（别删 ignoreip）。"
}

# ============================================================
need_root
case "$MODE" in
  --check)
    check_sources
    log "体检结论"
    echo "  fail2ban 当前 jail:"; fail2ban-client status 2>&1 | sed 's/^/    /'
    echo "  现有 $JAIL_D:"; ls -la "$JAIL_D" 2>/dev/null | sed 's/^/    /'
    echo "  应用日志是否已落盘: $([ -e "$APP_LOG" ] && stat -c '%s bytes' "$APP_LOG" || echo '不存在（需要 --apply）')"
    echo "  样例过滤器自测:"; [ -f "$SRC_FILTER" ] && fail2ban-regex /dev/null "$SRC_FILTER" >/dev/null 2>&1 && ok "过滤器语法可加载"
    echo
    echo "  下一步：sudo bash -s -- --apply"
    ;;
  --selftest)
    check_sources; selftest ;;
  --status)
    show_status ;;
  --rollback)
    d="$(readlink -f "$BACKUP_ROOT/last" 2>/dev/null || true)"
    [ -n "$d" ] && [ -d "$d" ] || die "没有找到备份（$BACKUP_ROOT/last）"
    log "回滚到 $d"
    ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
    bounce_fail2ban
    ok "已重启；当前状态："
    fail2ban-client status 2>&1 | sed 's/^/    /'
    ;;
  --apply)
    check_sources
    log "2/6 备份当前状态"
    BAK="$(backup_state)"
    ok "备份在 $BAK（回滚：sudo bash -s -- --rollback）"
    install_fragments
    if ! validate_config; then
      warn "配置校验失败 —— 自动回滚"
      ( cd "$BAK" && ./restore.sh ) | sed 's/^/  /'
      systemctl daemon-reload
      bounce_fail2ban
      die "已回滚到改动前状态，请修好 $REPO/deploy/fail2ban/ 下的片段后重试"
    fi
    if ! start_mirror; then
      warn "日志镜像没起来 —— 回滚"
      ( cd "$BAK" && ./restore.sh ) | sed 's/^/  /'
      systemctl daemon-reload; bounce_fail2ban
      die "已回滚（app jail 依赖这个镜像，没有它 jail 会 'Have not found any log file'）"
    fi
    if ! reload_and_verify; then
      warn "jail 没按预期起来 —— 回滚"
      ( cd "$BAK" && ./restore.sh ) | sed 's/^/  /'
      systemctl daemon-reload; bounce_fail2ban
      die "已回滚；请检查 fail2ban-client -t 与 journalctl -u fail2ban"
    fi
    echo
    ok "fail2ban 主机侧检测已就位（sshd + secagent-public-api）"
    echo "  下一步：bash scripts/srv1-fail2ban-verify.sh  # 封禁-解封全过程实测"
    ;;
esac
