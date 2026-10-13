#!/usr/bin/env bash
# ============================================================
# srv1：生成「状态备份」专用密钥（与隧道密钥分开的另一把）
# ------------------------------------------------------------
# 为什么另开一把，不复用 /root/.ssh/tunnel_srv2_ed25519：
#   那把钥匙在 srv2 侧被限制成 restrict,port-forwarding,permitopen=127.0.0.1:55000
#   （只做 Wazuh API 的端口转发，连 shell 都开不了）。
#   要传文件就得放宽它 —— 那会让"隧道钥匙泄露"的后果从
#   "只能转发一个内网端口"升级成"能往 srv2 写文件"。
#   所以新开一把：权限边界各自独立，谁也不因为谁而变宽。
#
# 这把钥匙在 srv2 侧会被写成【强制命令】：
#   command="/usr/local/sbin/secagent-backup-receive",restrict <pub>
#   —— 拿不到 shell/tty/端口转发，只能 push/drill/list 三个动作。
# 公钥的安装见 scripts/srv2-authorize-backup-key.sh。
# ============================================================
set -uo pipefail

KEY=/root/.ssh/backup_srv2_ed25519
SRV2=43.143.114.79

echo "==> 1/4 生成备份专用密钥（已存在则复用）"
if [ -f "$KEY" ]; then
  echo "  密钥已存在，复用：$KEY"
else
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  ssh-keygen -t ed25519 -f "$KEY" -N "" -C "secagent-backup-from-srv1" -q
  echo "  已生成 $KEY"
fi
chmod 600 "$KEY"
chmod 644 "$KEY.pub"

echo
echo "==> 2/4 公钥内容（需要装到 srv2）"
echo "---BEGIN-PUBKEY---"
cat "$KEY.pub"
echo "---END-PUBKEY---"

echo
echo "==> 3/4 密钥指纹"
ssh-keygen -lf "$KEY.pub" | sed 's/^/  /'

echo
echo "==> 4/4 把 srv2 加进 known_hosts（避免首次连接交互）"
if ssh-keygen -F "$SRV2" -f /root/.ssh/known_hosts >/dev/null 2>&1; then
  echo "  known_hosts 里已有 $SRV2"
else
  ssh-keyscan -H "$SRV2" >> /root/.ssh/known_hosts 2>/dev/null
  echo "  已追加 $SRV2"
fi
echo "  known_hosts 行数: $(wc -l < /root/.ssh/known_hosts)"
