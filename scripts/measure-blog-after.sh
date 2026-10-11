#!/usr/bin/env bash
# 从杭州（国内视角）复测博客加载速度，验证图片优化效果。
set -uo pipefail

probe() {
  local label="$1" url="$2"
  local r
  r=$(curl -o /dev/null -s -w 'ttfb=%{time_starttransfer}s total=%{time_total}s size=%{size_download}B speed=%{speed_download}B/s' \
      --max-time 30 "$url" 2>/dev/null)
  printf "  %-30s %s\n" "$label" "${r:-FAILED}"
}

echo "=== blog pages ==="
probe "home"          "https://xiaokeqing.github.io/"
probe "posts list"    "https://xiaokeqing.github.io/posts/"

echo
echo "=== images (the thing we optimized) ==="
probe "hero.webp  81KB" "https://xiaokeqing.github.io/images/hero.webp"
probe "bg.webp    28KB" "https://xiaokeqing.github.io/images/bg.webp"
probe "og-cover.jpg 91KB" "https://xiaokeqing.github.io/images/og-cover.jpg"

echo
echo "=== fetch the real CSS referenced by the page, then measure it ==="
CSSPATH=$(curl -s --max-time 25 "https://xiaokeqing.github.io/" 2>/dev/null \
  | grep -oE '/assets/css/stylesheet\.[a-f0-9]+\.css' | head -1)
echo "  css: ${CSSPATH:-not found}"
if [ -n "${CSSPATH:-}" ]; then
  probe "stylesheet" "https://xiaokeqing.github.io$CSSPATH"
fi

echo
echo "=== simulate first-visit total (html + css + hero) ==="
T0=$(date +%s%N)
curl -s -o /dev/null --max-time 30 "https://xiaokeqing.github.io/" 2>/dev/null
[ -n "${CSSPATH:-}" ] && curl -s -o /dev/null --max-time 30 "https://xiaokeqing.github.io$CSSPATH" 2>/dev/null
curl -s -o /dev/null --max-time 30 "https://xiaokeqing.github.io/images/hero.webp" 2>/dev/null
T1=$(date +%s%N)
echo "  首屏关键资源合计: $(( (T1-T0)/1000000 )) ms"

echo
echo "=== demo tunnel (for comparison) ==="
TUNNEL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /var/log/cloudflared.log 2>/dev/null | tail -1)
probe "demo home" "$TUNNEL/"
