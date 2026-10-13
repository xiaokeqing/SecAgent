#!/usr/bin/env bash
# 测试 Cloudflare 隧道出口机房是否可切换。
# 当前落在 lax13（洛杉矶），对杭州服务器来说绕了地球半圈。
set -uo pipefail

check_poc() {
  local url="$1"
  curl -s -o /dev/null -D - --max-time 20 "$url" 2>/dev/null \
    | grep -i 'cf-ray' | head -1 | sed 's/^/    /'
}

TUNNEL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /var/log/cloudflared.log 2>/dev/null | tail -1)
echo "current tunnel: $TUNNEL"
echo "current PoP:"
check_poc "$TUNNEL"

echo
echo "=== 到 Cloudflare 各个 Anycast 地址的 TCP 握手延迟 ==="
echo "    （哪个近，就说明应该连哪个）"
for target in 198.41.192.57 198.41.200.13 162.159.192.1 104.16.0.1; do
  t=$(curl -o /dev/null -s -w '%{time_connect}' --max-time 6 --connect-to "::${target}:443" https://cf-test.invalid/ 2>/dev/null)
  printf "    %-18s connect=%ss\n" "$target" "${t:-fail}"
done

echo
echo "=== 本机到公网的出口路径（看默认路由偏向哪边）==="
timeout 25 traceroute -n -m 12 -q 1 1.1.1.1 2>/dev/null | sed 's/^/    /' || echo "    traceroute 不可用"

echo
echo "=== 到香港/日本/新加坡的延迟对比 ==="
for h in 1.1.1.1 8.8.8.8 223.5.5.5; do
  t=$(curl -o /dev/null -s -w '%{time_connect}' --max-time 6 "https://$h/" 2>/dev/null)
  printf "    %-14s connect=%ss\n" "$h" "${t:-fail}"
done

echo
echo "=== 重启隧道，看是否会换机房 ==="
systemctl restart secagent-tunnel
sleep 25
NEWTUNNEL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /var/log/cloudflared.log 2>/dev/null | tail -1)
echo "    new tunnel: $NEWTUNNEL"
echo "    new PoP:"
check_poc "$NEWTUNNEL"
echo "    outbound endpoints:"
grep -oE 'location=[a-z0-9]+' /var/log/cloudflared.log 2>/dev/null | tail -4 | sed 's/^/      /'
