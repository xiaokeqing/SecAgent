#!/usr/bin/env bash
# ============================================================
# B3 步骤 1：在服务器 1 上生成专用隧道密钥
# ------------------------------------------------------------
# 设计取舍：
#
# 为什么需要隧道，而不是把 Wazuh API 暴露出来？
#   Wazuh 的 55000 端口是管理 API，一旦公网可达就是高危面。
#   而 SecAgent 在另一台机器上，需要读它的告警数据。
#   两种做法：
#     a) 把 55000 暴露到公网 —— 简单，但等于把管理面交出去
#     b) SSH 隧道 —— SecAgent 连本机 127.0.0.1:55000，
#        数据走加密通道，服务器 2 上【一个端口都不用开】
#   选 b。这个项目的原则是"不暴露就不需要防护"。
#
# 为什么用专用密钥而不是复用现有密钥？
#   最小权限：这把密钥【只】用于这条隧道，不用于登录 shell。
#   而且下面会配合服务器 2 的 authorized_keys 限制，
#   让它连 shell 都开不了、只能转发一个端口。
#
# 为什么在这个脚本里做密钥生成，而不是手工敲命令？
#   因为密钥生成、取公钥、装到对端、写 systemd 单元、验证
#   是一串必须一次做对的动作。中间断了会留下半成品状态
#   （比如密钥生成了但没装对端），排查起来很费劲。
# ============================================================
set -uo pipefail

KEY=/root/.ssh/tunnel_srv2_ed25519

echo "==> 生成专用隧道密钥（已存在则复用）"
if [ -f "$KEY" ]; then
  echo "  密钥已存在，复用"
else
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  ssh-keygen -t ed25519 -f "$KEY" -N "" -C "secagent-tunnel-to-srv2" -q
  echo "  已生成 $KEY"
fi
chmod 600 "$KEY"
chmod 644 "$KEY.pub"

echo
echo "==> 公钥内容（需要装到服务器 2）"
echo "---BEGIN-PUBKEY---"
cat "$KEY.pub"
echo "---END-PUBKEY---"

echo
echo "==> 密钥信息"
ssh-keygen -lf "$KEY.pub" | sed 's/^/  /'

echo
echo "==> 把服务器 2 加进 known_hosts（避免首次连接交互）"
ssh-keyscan -H 43.143.114.79 >> /root/.ssh/known_hosts 2>/dev/null
echo "  known_hosts 行数: $(wc -l < /root/.ssh/known_hosts)"
