#!/usr/bin/env bash
# 启用 firewalld 并放行 SSH。
# 单独的脚本，避免经 ssh 传递内联命令时的引号问题。
set -euo pipefail

echo "1) 写入永久规则（firewalld 未运行时也能改）"
firewall-offline-cmd --add-service=ssh || true
firewall-offline-cmd --set-default-zone=public || true

echo
echo "2) 启动 firewalld"
systemctl enable --now firewalld
sleep 3
echo "  状态: $(systemctl is-active firewalld)"

echo
echo "3) 当前规则"
firewall-cmd --list-all

echo
echo "4) 服务总览"
for s in sshd firewalld fail2ban secagent-tunnel docker; do
  printf "  %-18s %s\n" "$s" "$(systemctl is-active "$s" 2>/dev/null || echo unknown)"
done
