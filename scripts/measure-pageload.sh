#!/usr/bin/env bash
# 测量完整页面加载耗时，模拟面试官首次打开 Demo 的体验。
set -uo pipefail

TUNNEL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /var/log/cloudflared.log 2>/dev/null | tail -1)
echo "tunnel: $TUNNEL"
echo

echo "=== A. full page load via Cloudflare tunnel ==="
for i in 1 2 3; do
  r=$(curl -o /dev/null -s -w 'dns=%{time_namelookup} connect=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total} size=%{size_download}' \
      --max-time 40 "$TUNNEL/" 2>/dev/null)
  echo "    #$i  $r"
done

echo
echo "=== B. static assets via tunnel (CSS/JS) ==="
for asset in /styles.css /app.js; do
  r=$(curl -o /dev/null -s -w 'total=%{time_total} size=%{size_download} speed=%{speed_download}B/s' \
      --max-time 40 "$TUNNEL$asset" 2>/dev/null)
  printf "    %-14s %s\n" "$asset" "$r"
done

echo
echo "=== C. localhost baseline ==="
curl -o /dev/null -s -w '    total=%{time_total} size=%{size_download}\n' --max-time 10 http://127.0.0.1:9900/

echo
echo "=== D. tunnel to Cloudflare edge RTT (repeated) ==="
for i in 1 2 3 4 5; do
  t=$(curl -o /dev/null -s -w '%{time_connect}' --max-time 20 "$TUNNEL/api/health" 2>/dev/null)
  echo "    connect=$t"
done

echo
echo "=== E. which anycast IP cloudflared actually uses ==="
grep -oE 'ip=[0-9.]+' /var/log/cloudflared.log 2>/dev/null | sort | uniq -c | sed 's/^/    /'
