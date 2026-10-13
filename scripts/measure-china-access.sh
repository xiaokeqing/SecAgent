#!/usr/bin/env bash
# 从杭州服务器（国内视角）测量各个候选托管方案的真实速度。
# 目的：搞清楚「面试官在国内打开你的链接」到底要等多久。
set -uo pipefail

probe() {
  local label="$1" url="$2"
  local r
  r=$(curl -o /dev/null -s -w 'dns=%{time_namelookup} conn=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total} size=%{size_download}' \
      --max-time 30 "$url" 2>/dev/null)
  printf "  %-34s %s\n" "$label" "${r:-FAILED}"
}

echo "=============================================="
echo " 国内（杭州）视角的实测速度"
echo "=============================================="
echo

echo "--- 1. 你的博客 GitHub Pages ---"
probe "blog home" "https://xiaokeqing.github.io/"
probe "blog css"  "https://xiaokeqing.github.io/assets/css/stylesheet.e1c79dffc8cf00f0ffad8470879b05af83111b41140c69ca41cf4862d02520d7.css"
probe "blog hero img" "https://xiaokeqing.github.io/images/hero.jpg"

echo
echo "--- 2. GitHub 本体 ---"
probe "github.com" "https://github.com/"

echo
echo "--- 3. 当前 Demo 隧道 ---"
TUNNEL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /var/log/cloudflared.log 2>/dev/null | tail -1)
probe "demo tunnel home" "$TUNNEL/"

echo
echo "--- 4. 国内基线（对照）---"
probe "aliyun mirrors" "https://mirrors.aliyun.com/"
probe "baidu" "https://www.baidu.com/"
probe "taobao" "https://www.taobao.com/"

echo
echo "--- 5. 海外基线（对照）---"
probe "cloudflare.com" "https://www.cloudflare.com/"

echo
echo "=============================================="
echo " 解读："
echo "  ttfb  = 首字节时间，真实体感的主要部分"
echo "  total = 完整下载耗时"
echo "=============================================="
