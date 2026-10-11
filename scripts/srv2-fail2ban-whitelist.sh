#!/usr/bin/env bash
# ============================================================
# B3 步骤 4：解封服务器 1，并把内网地址加入 fail2ban 白名单
# ------------------------------------------------------------
# 发生了什么：
#   服务器 1 的 IP（47.96.106.187）被服务器 2 的 fail2ban 封了。
#   表现是 22/443/55000 全部 "Connection refused" ——
#   因为 fail2ban 的封禁是【整 IP 拒绝】，不是只封触发规则的那个端口。
#   我一开始以为是安全组或 ufw 的问题，查了半天才发现。
#
# 为什么会封：
#   早先测试隧道时那几次 SSH 认证失败触发了它。
#
# 为什么必须加白名单（这个点比"解封"重要得多）：
#   隧道会持续从服务器 1 发起 SSH 连接。这是【合法的内部连接】，
#   但它在 fail2ban 眼里和"暴力破解"长得一模一样。
#   如果不定白名单，迟早会再被封一次 —— 而后果很隐蔽：
#   隧道断了 -> SecAgent 连不上 Wazuh -> 自动降级回 MOCK
#   -> 页面上还显示得挺正常，只是数据变成假的了，没人会发现。
#
#   也就是说：这条白名单防的不是"现在能不能连"，
#   而是"某天数据悄悄变假"。
# ============================================================
set -uo pipefail

SRV1_IP=47.96.106.187
JAIL_LOCAL=/etc/fail2ban/jail.local

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\n\033[1;33m  [!] $*\033[0m"; }

log "1/5 先解封服务器 1"
if fail2ban-client status sshd 2>/dev/null | grep -q "$SRV1_IP"; then
  fail2ban-client set sshd unbanip "$SRV1_IP" 2>&1 | sed 's/^/  /'
  ok "已解封 $SRV1_IP"
else
  echo "  $SRV1_IP 不在封禁列表里"
fi
echo "  当前封禁列表:"
fail2ban-client status sshd 2>/dev/null | grep -i 'banned ip' | sed 's/^/    /'

log "2/5 配置 fail2ban 白名单"
# 幂等：已经有 ignoreip 就跳过
if [ -f "$JAIL_LOCAL" ] && grep -q '^ignoreip' "$JAIL_LOCAL"; then
  warn "$JAIL_LOCAL 里已有 ignoreip，先看现有内容"
  grep '^ignoreip' "$JAIL_LOCAL" | sed 's/^/    /'
  # 确保服务器1 在里面
  if grep -q "$SRV1_IP" "$JAIL_LOCAL"; then
    ok "服务器 1 已在白名单里"
  else
    sed -i "s|^ignoreip *=.*|& $SRV1_IP|" "$JAIL_LOCAL"
    ok "已把服务器 1 追加到现有 ignoreip"
  fi
else
  cp "$JAIL_LOCAL" "$JAIL_LOCAL.bak-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  cat >> "$JAIL_LOCAL" <<EOF

# ===== 本项目追加：内网互信地址白名单 =====
# 服务器 1 的 IP 是 SecAgent 所在机器，它会通过 SSH 隧道读 Wazuh API。
# 那条隧道的连接看起来和暴力破解一模一样，不白名单迟早会被封。
# 被封的后果很隐蔽：隧道断 -> SecAgent 连不上 Wazuh -> 自动降级 MOCK
# -> 页面显示正常，只是数据变假了。
ignoreip = 127.0.0.1/8 ::1 $SRV1_IP
EOF
  ok "已写入 $JAIL_LOCAL"
fi

log "3/5 确认配置内容"
grep -n 'ignoreip' "$JAIL_LOCAL" | sed 's/^/  /'

log "4/5 重启 fail2ban 并验证"
fail2ban-client reload 2>&1 | sed 's/^/  /' || systemctl restart fail2ban
sleep 6
echo "  服务状态: $(systemctl is-active fail2ban)"
echo "  jail 的 ignoreip:"
fail2ban-client get sshd ignoreip 2>/dev/null | sed 's/^/    /'

log "5/5 最终确认"
echo "  sshd jail 状态:"
fail2ban-client status sshd 2>/dev/null | sed 's/^/    /'

echo
echo "  从服务器 1 再测一次连通性（这一步由调用方执行更合适，"
echo "  因为要看到真实网络路径的结果）"
