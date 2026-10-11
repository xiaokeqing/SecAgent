#!/usr/bin/env bash
# ============================================================
# B3 步骤 2：在服务器 2 上授权隧道密钥（带最小权限限制）
# ------------------------------------------------------------
# 关键在 authorized_keys 的选项那一串，逐条解释：
#
#   restrict          关掉所有权限（包括 tty、agent 转发、X11、端口转发）
#                     —— 这是一个"白名单式"的起点，比逐条禁用好：
#                     以后 SSH 新增功能时，默认是关的
#   port-forwarding   再把【端口转发】单独打开（restrict 会把它关掉）
#   permitopen=...    只允许转发到 127.0.0.1:55000 这一个目标
#
# 效果：这把密钥即使泄露，攻击者也只能：
#   · 转发到 Wazuh API 的 55000 端口
#   · 拿不到 shell、拿不到 tty、转发不到别的任何端口
#
# 为什么不干脆给它完整 SSH 权限：
#   隧道只需要"转发"这一个能力。给它更多权限只是因为省事，
#   而省事换来的是一把万能钥匙。这个项目的原则是：
#   【每一处权限都应该是"刚好够用"，而不是"顺便都能"】。
# ============================================================
set -uo pipefail

PUBKEY_FILE=/tmp/tunnel_pub.key
AK=/root/.ssh/authorized_keys
MARK="secagent-tunnel-to-srv2"

echo "==> 1/4 准备 authorized_keys"
mkdir -p /root/.ssh && chmod 700 /root/.ssh
touch "$AK" && chmod 600 "$AK"

if [ ! -f "$PUBKEY_FILE" ]; then
  echo "  [X] 找不到 $PUBKEY_FILE"
  exit 1
fi
PUB=$(tr -d '\n' < "$PUBKEY_FILE")
echo "  待授权公钥: ${PUB:0:60}..."

echo
echo "==> 2/4 幂等处理（先移除同名的旧条目）"
if grep -q "$MARK" "$AK" 2>/dev/null; then
  cp "$AK" "$AK.bak-$(date +%Y%m%d-%H%M%S)"
  grep -v "$MARK" "$AK" > "$AK.tmp" && mv "$AK.tmp" "$AK"
  chmod 600 "$AK"
  echo "  已移除旧条目"
else
  echo "  没有旧条目"
fi

echo
echo "==> 3/4 写入带限制的新条目"
RESTRICTED="restrict,port-forwarding,permitopen=\"127.0.0.1:55000\" $PUB"
echo "$RESTRICTED" >> "$AK"
chmod 600 "$AK"

echo "  写入后的内容（只显示选项部分，不打印完整公钥）："
tail -1 "$AK" | cut -c1-110 | sed 's/^/    /'

echo
echo "==> 4/4 自检：读回并确认限制选项都在"
LAST=$(tail -1 "$AK")
for opt in restrict port-forwarding permitopen; do
  if echo "$LAST" | grep -q "$opt"; then
    echo "  ✅ 含 $opt"
  else
    echo "  ❌ 缺 $opt —— 限制没生效，需要检查"
  fi
done

echo
echo "  当前 authorized_keys 的条目数: $(wc -l < "$AK")"
echo "  各条目的用途（按注释区分）:"
awk '{print "    - " $NF}' "$AK" | sed 's/^/  /'
