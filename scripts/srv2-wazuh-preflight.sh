#!/usr/bin/env bash
# ============================================================
# Wazuh 安装前预检
# ------------------------------------------------------------
# 为什么先做这一步：
#   Wazuh 全家桶要下几个 G。如果 packages.wazuh.com 从上海访问很慢或不通，
#   装到一半失败会留下半成品状态（apt 半装、服务没起、配置写了一半），
#   清理比重新开始还麻烦。
#   所以先花一分钟测连通性，再决定用官方源、镜像源，还是换方案。
# ============================================================
echo "=============================================="
echo " Wazuh 安装前预检"
echo "=============================================="

echo
echo "--- 1. DNS 解析 ---"
for h in packages.wazuh.com documentation.wazuh.com; do
  printf "  %-28s " "$h"
  ip=$(getent hosts "$h" 2>/dev/null | awk '{print $1}' | head -1)
  if [ -n "$ip" ]; then echo "$ip"; else echo "解析失败"; fi
done

echo
echo "--- 2. HTTPS 连通性 ---"
for u in https://packages.wazuh.com/ https://documentation.wazuh.com/; do
  printf "  %-36s " "$u"
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$u" 2>/dev/null)
  echo "HTTP $code"
done

echo
echo "--- 3. 关键文件能不能取到（4.x 仓库结构）---"
for f in \
  "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-manager/wazuh-manager_4.9.2-1_amd64.deb" \
  "https://packages.wazuh.com/4.x/apt/dists/stable/InRelease" \
  "https://packages.wazuh.com/4.x/wazuh-install.sh" \
  "https://packages.wazuh.com/key/GPG-KEY-WAZUH" ; do
  printf "  %-72s " "$(basename "$f")"
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 25 -I "$f" 2>/dev/null)
  echo "HTTP $code"
done

echo
echo "--- 4. 下载测速（取 1MB 样本）---"
printf "  packages.wazuh.com  "
speed=$(curl -s -o /dev/null -w '%{speed_download}' --max-time 25 \
  -r 0-1048576 "https://packages.wazuh.com/4.x/apt/dists/stable/InRelease" 2>/dev/null)
if [ -n "$speed" ] && [ "${speed%.*}" -gt 0 ] 2>/dev/null; then
  echo "$(awk -v s="$speed" 'BEGIN{printf "%.0f KB/s", s/1024}')"
else
  echo "测不出来（可能太慢或不通）"
fi

echo
echo "--- 5. 出站访问是否被限（整体判断）---"
printf "  github.com        "
curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://github.com 2>/dev/null || echo "不通"
echo
printf "  raw.githubusercontent.com  "
curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://raw.githubusercontent.com 2>/dev/null || echo "不通"
echo
printf "  pypi.org          "
curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://pypi.org 2>/dev/null || echo "不通"
echo

echo
echo "--- 6. 资源余量（Wazuh 全家桶要几个 G）---"
df -h / | tail -1 | sed 's/^/    /'
free -m | sed 's/^/    /'

echo
echo "--- 7. 安装方式判断 ---"
SPEED_KB=$(awk -v s="${speed:-0}" 'BEGIN{printf "%d", s/1024}')
if [ "$SPEED_KB" -gt 500 ]; then
  echo "  ✅ 速度 ${SPEED_KB} KB/s，官方 install.sh 可行"
elif [ "$SPEED_KB" -gt 100 ]; then
  echo "  ⚠️  速度 ${SPEED_KB} KB/s，偏慢但可用；考虑只装必要组件"
elif [ "$SPEED_KB" -gt 0 ]; then
  echo "  ❌ 速度仅 ${SPEED_KB} KB/s，官方源基本不可用，需要换方案"
else
  echo "  ❌ 测不到速度，先确认网络"
fi

echo
echo "--- 8. 有没有国内镜像可作为替代 ---"
printf "  mirrors.aliyun.com/wazuh   "
curl -s -o /dev/null -w '%{http_code}' --max-time 15 "https://mirrors.aliyun.com/wazuh/" 2>/dev/null || echo "无"
echo
printf "  mirrors.tuna.tsinghua.edu.cn  "
curl -s -o /dev/null -w '%{http_code}' --max-time 15 "https://mirrors.tuna.tsinghua.edu.cn/wazuh/" 2>/dev/null || echo "无"
echo
