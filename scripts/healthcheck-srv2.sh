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
# ⚠️ 不能硬编码 indexer 口令！
# 第一版写死了 admin:SecretPassword，结果口令一改，检查立刻开始说谎 ——
# 401（认证失败）被报成"集群异常"。凭据轮换后必须所有引用处一起改，
# 这个坑我在 Wazuh 配置里刚踩过，又在自己脚本里踩了第二次。
# 正确做法：从服务器上的口令文件读。读不到再退化为默认值（并标注）。
IDX_PW=$(grep '^INDEXER_ADMIN_PASSWORD=' /root/.wazuh-new-creds.txt 2>/dev/null | cut -d= -f2)
if [ -z "$IDX_PW" ]; then
  IDX_PW="SecretPassword"
  echo "IDX_PW_SOURCE=default(未找到口令文件，可能还是默认口令)"
else
  echo "IDX_PW_SOURCE=file"
fi
# 注意引号：不能写成 echo "IDX_CODE=$(curl ... -u "admin:${IDX_PW}" ...)"
# 内层双引号会提前闭合外层字符串。必须先算到变量再输出 —— 这个坑
# 在这个项目里已经出现好几次了（PowerShell + bash 双层的引号地狱）。
IDX_URL="https://127.0.0.1:9200/_cluster/health"
IDX_RAW=$(curl -sk -u "admin:${IDX_PW}" --max-time 8 "$IDX_URL" 2>/dev/null)
IDX_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -u "admin:${IDX_PW}" --max-time 8 "$IDX_URL" 2>/dev/null)
IDX_STATUS=$(echo "$IDX_RAW" | grep -o '"status":"[a-z]*"' | head -1)
echo "IDX_CODE=${IDX_CODE}"
echo "IDX_HEALTH=${IDX_STATUS}"
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
# 反过来测【默认口令】是否还有效（有效=还没改，需要改）
echo "IDX_DEFAULT_ALIVE=$(curl -sk -o /dev/null -w '%{http_code}' -u admin:SecretPassword --max-time 8 https://127.0.0.1:9200/_cluster/health 2>/dev/null)"
echo "API_NEWPW_OK=$([ -n "$(grep -o '^WAZUH_API_WUI_PASSWORD=' /root/.wazuh-new-creds.txt 2>/dev/null)" ] && echo yes || echo no)"

# --- 磁盘增长关注点 ---
echo "DOCKER_SIZE=$(docker system df --format '{{.Size}}' 2>/dev/null | head -1)"
echo "IMG_N=$(docker images -q 2>/dev/null | wc -l)"
echo "WAZUH_IDX_DATA=$(du -sh /var/lib/docker/volumes/wazuh_wazuh-indexer-data 2>/dev/null | cut -f1)"
