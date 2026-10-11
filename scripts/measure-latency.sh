#!/usr/bin/env bash
# 从杭州这台服务器（真实国内网络、无代理）实测各访问路径的延迟。
# 它的视角就代表国内访客的视角。
set -uo pipefail

TUNNEL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /var/log/cloudflared.log 2>/dev/null | tail -1)
echo "tunnel url: $TUNNEL"
echo

sample() {
  local label="$1" url="$2" n="$3"
  local sum=0 min=99 max=0 t
  for i in $(seq 1 "$n"); do
    t=$(curl -o /dev/null -s -w '%{time_total}' --max-time 25 "$url" 2>/dev/null || echo 99)
    echo "    $label  #$i  ${t}s"
    awk -v a="$sum" -v b="$t" 'BEGIN{exit !(b<99)}' && sum=$(awk -v a="$sum" -v b="$t" 'BEGIN{print a+b}')
    min=$(awk -v a="$min" -v b="$t" 'BEGIN{print (b<a)?b:a}')
    max=$(awk -v a="$max" -v b="$t" 'BEGIN{print (b>a)?b:a}')
  done
  echo "    --> $label  min=${min}s  max=${max}s"
  echo
}

echo "=== path 1: via Cloudflare tunnel ==="
sample "cf-tunnel" "$TUNNEL/api/health" 5

echo "=== path 2: direct localhost (baseline) ==="
sample "localhost" "http://127.0.0.1:9900/api/health" 5

echo "=== path 3: via public IP (no domain, plain http) ==="
# 服务器自己的公网出口访问自己的公网 IP，绕一圈回来，能反映国内直连的量级
PUBIP=$(curl -s --max-time 8 https://ipinfo.io/ip 2>/dev/null || echo "")
echo "    public ip seen as: ${PUBIP:-unknown}"
if [ -n "$PUBIP" ]; then
  sample "public-ip" "http://$PUBIP:9900/api/health" 3
fi

echo "=== cloudflare PoP handling the request ==="
curl -s -o /dev/null -D - --max-time 20 "$TUNNEL/api/health" 2>/dev/null \
  | grep -iE 'cf-ray|cf-cache-status|server:' | sed 's/^/    /'

echo
echo "=== tunnel outbound connection endpoint ==="
grep -oE 'location=[a-z0-9]+' /var/log/cloudflared.log 2>/dev/null | tail -3 | sed 's/^/    /'

echo
echo "=== traceroute to cloudflare edge (first 10 hops) ==="
CFIP=$(getent hosts region1.v2.argotunnel.com 2>/dev/null | awk '{print $1}' | head -1)
echo "    argotunnel resolved: ${CFIP:-none}"
if [ -n "$CFIP" ]; then
  timeout 30 traceroute -n -m 10 "$CFIP" 2>/dev/null | sed 's/^/    /' || echo "    traceroute unavailable"
fi
