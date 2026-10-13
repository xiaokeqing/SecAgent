#!/usr/bin/env bash
# ============================================================
# 步骤 1（在 srv2 上跑）：生成"反向探活"专用密钥
# ------------------------------------------------------------
# 设计取舍：
#
# 为什么 srv2 需要一把到 srv1 的 SSH 钥匙？
#   因为要判"整机是否活着"，只看公网 HTTP 不够：
#   · 应用挂了但机器活着 → 与"整机没了"是两种故障，处置完全不同
#   · 关键 systemd 单元（发布/看门狗定时器）不 active 也要能发现
#   这两件事只能通过 SSH 拿到，而 srv1 的 22 端口本来就是唯一对外开着的管理口。
#
# 为什么不能给它一把普通 root 钥匙？
#   srv2 是蜜罐机、暴露面最大。它一旦被拿下，一把普通 root 钥匙等于 srv1 也没了。
#   所以这把钥匙在 srv1 侧被 authorized_keys 的 `command=` 限制成
#   "只能读一份心跳 JSON"（见 scripts/srv1-authorize-heartbeat-key.sh）——
#   拿到这把私钥也没法执行别的命令。
#
# 为什么密钥放 /etc 而不是 /root/.ssh？
#   systemd 服务用 ProtectHome=yes 跑（不让它碰 /root），私钥必须在 /etc。
#
# 用法（srv2，root）：
#   bash srv2-gen-heartbeat-key.sh
# 然后在【本机】把公钥内容交给 srv1（脚本会打印可直接粘贴的那一行）。
# ============================================================
set -uo pipefail

KEY_DIR=/etc/secagent/heartbeat
KEY="$KEY_DIR/srv1_ed25519"
MARK="secagent-heartbeat-to-srv1"

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
echo "==> 4/4 交给 srv1 的方式（二选一）"
echo "  方式 A（推荐，本机执行）："
echo "    ssh secagent-srv2 'cat $KEY.pub' > /tmp/heartbeat.pub"
echo "    scp /tmp/heartbeat.pub secagent-srv1:/tmp/heartbeat.pub"
echo "    # 再在 srv1 上：bash /opt/secagent/scripts/srv1-authorize-heartbeat-key.sh /tmp/heartbeat.pub"
echo "  方式 B：把上面 BEGIN/END 之间的公钥内容粘到 srv1 的 /tmp/heartbeat.pub，再跑同一个脚本。"
echo
echo "  注意：authorized_keys 里写入的是【带强制命令】的条目，"
echo "  也就是说这把钥匙在 srv1 上只能读心跳 —— 这是刻意的最小权限。"
