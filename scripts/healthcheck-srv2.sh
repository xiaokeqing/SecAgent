#!/usr/bin/env bash
# 服务器 2 健康检查：输出 KEY=VALUE 行
#
# ⚠️ 必须以 root 运行！
# docker / sshd -T 在普通用户下会静默失败（返回空），
# 而检查脚本会把"命令没输出"误解成"状态不对"，产生误报。
# 第一次跑这个检查时就是用 ubuntu 用户跑的，结果报出
# 「Wazuh 容器都不在」「SSH 密码登录还开着」两个假警报 ——
# 差点让我去修两个根本不存在的问题。
# 所以这里显式自检，宁可直接失败也不要给错结论。
if [ "$(id -u)" != "0" ]; then
  echo "IS_ROOT=no"
  echo "FATAL=必须以 root 运行（docker/sshd -T 需要），否则结果全是误报"
  exit 1
fi
echo "IS_ROOT=yes"
echo "OS=$(grep -oP '(?<=PRETTY_NAME=")[^"]+' /etc/os-release 2>/dev/null)"
echo "UPTIME=$(uptime -p 2>/dev/null)"

# --- Wazuh 容器 ---
echo "WAZUH_N=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -c wazuh)"
echo "WAZUH_LIST=$(docker ps --format '{{.Names}}' 2>/dev/null | grep wazuh | tr '\n' ',')"

# 三个容器的健康状态
for c in wazuh.indexer wazuh.manager wazuh.dashboard; do
  key=$(echo "$c" | tr '.' '_' | tr 'a-z' 'A-Z')
  echo "${key}_STATUS=$(docker inspect --format '{{.State.Status}}' $c 2>/dev/null)"
done

# --- Wazuh 健康 ---
echo "IDX_HEALTH=$(curl -sk -u admin:SecretPassword --max-time 8 https://127.0.0.1:9200/_cluster/health 2>/dev/null | grep -o '"status":"[a-z]*"' | head -1)"
echo "MGR_API=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1:55000/ 2>/dev/null)"
echo "DASH=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1:443/app/login 2>/dev/null)"

# --- 安全加固 ---
echo "SSHPW=$(sshd -T 2>/dev/null | grep -c '^passwordauthentication no')"
echo "MAXAUTH=$(sshd -T 2>/dev/null | grep '^maxauthtries' | awk '{print $2}')"
echo "F2B=$(systemctl is-active fail2ban 2>/dev/null)"
echo "UFW=$(systemctl is-active ufw 2>/dev/null)"
echo "SWAPPINESS=$(cat /proc/sys/vm/swappiness)"
echo "MAXMAP=$(cat /proc/sys/vm/max_map_count)"
echo "SSHINC=$(grep -c '^Include' /etc/ssh/sshd_config 2>/dev/null)"

# --- 资源 ---
echo "MEM=$(free -m | awk '/Mem:/{print $3"/"$2}')"
echo "MEMAVAIL=$(free -m | awk '/Mem:/{print $7}')"
echo "SWAP=$(free -m | awk '/Swap:/{print $2}')"
echo "SWAPUSED=$(free -m | awk '/Swap:/{print $3}')"
echo "DISK=$(df -h / | tail -1 | awk '{print $5}')"
echo "DISKFREE=$(df -h / | tail -1 | awk '{print $4}')"

# --- 端口（应全部在 127.0.0.1） ---
echo "EXPOSED=$(ss -tlnp 2>/dev/null | grep -cE '0\.0\.0\.0:(9200|55000|443|5601|1514)')"

# --- 凭据状态（判断 indexer 默认口令改了没） ---
echo "IDX_DEFAULT_ALIVE=$(curl -sk -o /dev/null -w '%{http_code}' -u admin:SecretPassword --max-time 8 https://127.0.0.1:9200/_cluster/health 2>/dev/null)"
echo "API_NEWPW_OK=$([ -n "$(grep -o '^WAZUH_API_WUI_PASSWORD=' /root/.wazuh-new-creds.txt 2>/dev/null)" ] && echo yes || echo no)"

# --- 磁盘增长关注点 ---
echo "DOCKER_SIZE=$(docker system df --format '{{.Size}}' 2>/dev/null | head -1)"
echo "IMG_N=$(docker images -q 2>/dev/null | wc -l)"
echo "WAZUH_IDX_DATA=$(du -sh /var/lib/docker/volumes/wazuh_wazuh-indexer-data 2>/dev/null | cut -f1)"
