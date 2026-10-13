#!/usr/bin/env bash
# ============================================================
# 步骤 1（在 srv1 上跑）：生成"反向探活 srv2"专用密钥
# ------------------------------------------------------------
# 与 srv2-gen-heartbeat-key.sh 完全对称，只是方向相反：
#   srv2-gen-heartbeat-key.sh  ：在 srv2 生成 srv2→srv1 的钥匙
#   本脚本                     ：在 srv1 生成 srv1→srv2 的钥匙
#
# 设计取舍（与对面一致）：
#   · 为什么需要 SSH 而不是只 curl：只有 SSH 才能拿到 srv2 的
#     关键容器状态、备份新鲜度这些"机器内部"的事实
#   · 为什么不是普通 root 钥匙：srv2 是蜜罐机、暴露面最大。这把钥匙在 srv2 侧被
#     authorized_keys 的 command= 钉死成"只能读一份心跳 JSON"，
#     拿到私钥也执行不了别的命令（见 scripts/srv2-authorize-srv1-heartbeat-key.sh）
#   · 为什么密钥放 /etc 而不是 /root/.ssh：systemd 服务用 ProtectHome=yes 跑，
#     私钥必须在 /etc 才读得到
#
# 用法（srv1，root）：
#   bash srv1-gen-srv2-heartbeat-key.sh
# 然后把打印出来的公钥交给 srv2 上的 srv2-authorize-srv1-heartbeat-key.sh。
# ============================================================
set -uo pipefail

KEY_DIR=/etc/secagent/heartbeat
KEY="$KEY_DIR/srv2_ed25519"
MARK="secagent-heartbeat-to-srv2"

echo "==> 1/4 准备目录（$KEY_DIR，仅 root 可读）"
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"
chown root:root "$KEY_DIR" 2>/dev/null || true

echo
echo "==> 2/4 生成专用密钥（已存在则复用）"
if [ -f "$KEY" ]; then
  echo "  已存在，复用：$KEY"
else
  ssh-keygen -t ed25519 -f "$KEY" -N "" -C "$MARK" -q
  echo "  已生成：$KEY"
fi
chmod 600 "$KEY"
chmod 644 "$KEY.pub"

echo
echo "==> 3/4 密钥指纹与公钥"
ssh-keygen -lf "$KEY.pub" | sed 's/^/  /'
echo "---BEGIN-PUBKEY---"
cat "$KEY.pub"
echo "---END-PUBKEY---"

echo
echo "==> 4/4 交给 srv2 的方式（二选一）"
echo "  方式 A（推荐，本机执行）："
echo "    scp $KEY.pub secagent-srv2:/tmp/srv1-heartbeat.pub"
echo "    ssh secagent-srv2 'sudo bash -s' < /opt/secagent/scripts/srv2-authorize-srv1-heartbeat-key.sh"
echo "    # 或：ssh secagent-srv2 \"sudo bash /tmp/srv2-authorize-srv1-heartbeat-key.sh /tmp/srv1-heartbeat.pub\""
echo "  方式 B：把 BEGIN/END 之间的内容粘到 srv2 的 /tmp/srv1-heartbeat.pub，再跑那个脚本。"
echo
echo "  注意：srv2 侧写入的是【带强制命令】的条目，"
echo "  也就是说这把钥匙在 srv2 上只能读心跳 —— 这是刻意的最小权限。"
