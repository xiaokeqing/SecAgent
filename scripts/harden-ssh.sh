#!/usr/bin/env bash
# ============================================================
# SecAgent 服务器 SSH 与防火墙加固
# ------------------------------------------------------------
# 用法（在服务器上）：sudo bash harden-ssh.sh
#
# 在改 SSH 配置之前，本脚本会先验证「密钥登录确实可用」，
# 验证不过就中止 —— 避免把自己锁在门外。
#
# 保留 22 端口不变。改端口需要同步改阿里云安全组，
# 顺序搞错会直接失联，收益也不大（fail2ban 已经能挡住爆破）。
#
# ------------------------------------------------------------
# 踩过的两个坑（都已在脚本里处理）：
#
# 坑1：Alibaba Cloud Linux 3 的 /etc/ssh/sshd_config 里
#      【没有 Include 指令】，所以 /etc/ssh/sshd_config.d/
#      整个目录根本不会被读取。drop-in 文件写了等于没写，
#      而且 sshd -t 语法检查会"通过"、脚本会"报告成功"，
#      但 sshd -T 一看还是老配置。本脚本会先补上 Include。
#
# 坑2：firewalld 必须先写永久规则再启动，否则启动那一瞬间
#      SSH 会被拦掉。用 firewall-offline-cmd 可以在服务未运行时配置。
# ============================================================
set -euo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请用 root 运行"

DROPIN=/etc/ssh/sshd_config.d/99-secagent-hardening.conf

# ------------------------------------------------------------
log "0/6 前置检查：确认密钥登录可用"
# ------------------------------------------------------------
if [[ ! -s /root/.ssh/authorized_keys ]]; then
  die "/root/.ssh/authorized_keys 为空，先配置公钥再跑本脚本"
fi
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
ok "authorized_keys 存在，包含 $(wc -l < /root/.ssh/authorized_keys) 个公钥"

# ------------------------------------------------------------
log "1/6 备份 sshd 配置"
# ------------------------------------------------------------
BACKUP=/root/sshd_config.bak.$(date +%Y%m%d%H%M%S)
cp /etc/ssh/sshd_config "$BACKUP"
ok "已备份到 $BACKUP"
echo "     回滚：cp $BACKUP /etc/ssh/sshd_config && systemctl reload sshd"

# ------------------------------------------------------------
log "2/6 确保 sshd 会读取 drop-in 目录（坑1）"
# ------------------------------------------------------------
if grep -qiE '^\s*Include\s+/etc/ssh/sshd_config\.d' /etc/ssh/sshd_config; then
  ok "Include 指令已存在"
else
  # 必须插到文件最前面：sshd 对同一参数是「首次出现的值生效」，
  # 放末尾的话文件里原有的 PasswordAuthentication yes 会赢。
  {
    echo '# 读取 drop-in 配置目录（加固项放在 /etc/ssh/sshd_config.d/ 下）'
    echo 'Include /etc/ssh/sshd_config.d/*.conf'
    echo
    cat /etc/ssh/sshd_config
  } > /tmp/sshd_config.new
  mv /tmp/sshd_config.new /etc/ssh/sshd_config
  chmod 600 /etc/ssh/sshd_config
  ok "已在 sshd_config 开头插入 Include"
fi

# ------------------------------------------------------------
log "3/6 写入加固配置"
# ------------------------------------------------------------
mkdir -p /etc/ssh/sshd_config.d
cat > "$DROPIN" <<'EOF'
# --- SecAgent 加固 ---
# 只允许密钥登录。密码登录是公网 SSH 上最高频的攻击入口，
# fail2ban 只能缓解爆破速度，关掉才是根治。
PasswordAuthentication no
ChallengeResponseAuthentication no
# root 仍可登录但必须用密钥（阿里云控制台的 VNC 是最后的兜底通道）
PermitRootLogin prohibit-password
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

if ! sshd -t; then
  rm -f "$DROPIN"
  cp "$BACKUP" /etc/ssh/sshd_config
  die "sshd 配置语法错误，已回滚"
fi
ok "配置语法检查通过"

systemctl reload sshd
sleep 2

# 复核：不能只看 reload 成功，必须看 sshd 实际生效的值
echo
echo "  --- sshd 实际生效的加固项 ---"
sshd -T | grep -iE '^(passwordauthentication|permitrootlogin|maxauthtries|permitemptypasswords|x11forwarding)' | sed 's/^/    /'
if ! sshd -T | grep -qi '^passwordauthentication no'; then
  die "passwordauthentication 仍为 yes —— 加固未生效，检查上面第 2 步"
fi
ok "已确认密码登录关闭"

# ------------------------------------------------------------
log "4/6 安装 fail2ban"
# ------------------------------------------------------------
if command -v fail2ban-client >/dev/null 2>&1; then
  ok "fail2ban 已安装"
else
  dnf install -y fail2ban >/dev/null
  ok "fail2ban 安装完成"
fi

cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled  = true
port     = ssh
# aggressive：连"用户名不存在"的尝试也计入，能更早发现扫描
mode     = aggressive
maxretry = 4
findtime = 10m
bantime  = 1h
EOF
systemctl enable --now fail2ban >/dev/null
ok "fail2ban 已启用（10 分钟内失败 4 次封禁 1 小时）"

# ------------------------------------------------------------
log "5/6 配置防火墙（坑2）"
# ------------------------------------------------------------
# 服务只监听 127.0.0.1，隧道是服务器主动向外的连接，
# 所以 inbound 只需要放行 SSH。
if rpm -q firewalld >/dev/null 2>&1; then
  # 先写永久规则再启动，避免启动瞬间被拦
  firewall-offline-cmd --add-service=ssh >/dev/null 2>&1 || true
  firewall-offline-cmd --set-default-zone=public >/dev/null 2>&1 || true
  # cockpit 是 9090 端口的管理面板，这里用不到，去掉
  firewall-offline-cmd --remove-service=cockpit >/dev/null 2>&1 || true
  systemctl enable --now firewalld >/dev/null
  sleep 3
  ok "firewalld 已启用"
  firewall-cmd --list-all | sed 's/^/    /'
else
  warn "未安装 firewalld，跳过（阿里云安全组本身也是一层防护）"
fi

# ------------------------------------------------------------
log "6/6 复核"
# ------------------------------------------------------------
echo
for s in sshd firewalld fail2ban; do
  printf "  %-12s %s\n" "$s" "$(systemctl is-active "$s" 2>/dev/null || echo unknown)"
done
echo
echo "  --- fail2ban ---"
fail2ban-client status sshd 2>/dev/null | sed 's/^/    /' || echo "    （暂无拦截记录）"
echo
warn "密码登录已关闭。如果密钥丢失，只能用阿里云控制台的「远程连接」进来，执行："
warn "  rm -f $DROPIN && systemctl reload sshd"
