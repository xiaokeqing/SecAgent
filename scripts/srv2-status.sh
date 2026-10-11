#!/usr/bin/env bash
# 服务器 2 当前状态总览（步骤 ② 收尾）
echo "=============================================="
echo " 服务器 2 状态总览"
echo "=============================================="
echo
echo "--- 主机 ---"
echo "  主机名:   $(hostname)"
echo "  系统:     $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
echo "  运行时长: $(uptime -p)"
echo "  时间:     $(date '+%F %T %Z')"
echo
echo "--- 资源 ---"
free -m | sed 's/^/  /'
echo
df -h / | tail -1 | sed 's/^/  /'
echo
echo "--- 容器 ---"
docker ps --format '  {{.Names}}    {{.Status}}'
echo
echo "--- 容器内存 ---"
docker stats --no-stream --format '  {{.Name}}    {{.MemUsage}}    {{.MemPerc}}' 2>/dev/null
echo
echo "--- 监听端口（应全部在 127.0.0.1）---"
ss -tlnp 2>/dev/null | grep -E '127.0.0.1:(9200|55000|443|1514|1515)' | awk '{print "  "$4}'
echo
echo "--- 安全加固状态 ---"
echo "  sshd 密码登录:    $(sshd -T 2>/dev/null | grep -c '^passwordauthentication no') (1=已关)"
echo "  sshd MaxAuthTries: $(sshd -T 2>/dev/null | grep '^maxauthtries' | awk '{print $2}')"
echo "  fail2ban:         $(systemctl is-active fail2ban)"
echo "  ufw:              $(systemctl is-active ufw)"
echo "  swappiness:       $(cat /proc/sys/vm/swappiness)"
echo "  Swap:             $(free -m | awk '/Swap:/ {print $2" MB"}')"
echo
echo "--- Wazuh 服务健康 ---"
printf "  indexer 集群:  "
curl -sk -u admin:SecretPassword https://127.0.0.1:9200/_cluster/health 2>/dev/null \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["status"], "nodes:", d["number_of_nodes"])' 2>/dev/null || echo "查询失败"
printf "  manager API:   "
API_PW=$(grep '^WAZUH_API_WUI_PASSWORD=' /root/.wazuh-new-creds.txt | cut -d= -f2)
T=$(curl -sk -u "wazuh-wui:${API_PW}" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null | sed 's/^Bearer //')
if [ "${#T}" -gt 20 ]; then echo "认证成功（新口令）"; else echo "认证失败"; fi
printf "  dashboard:     "
echo "HTTP $(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:443/app/login 2>/dev/null)"
echo
echo "--- 凭据状态（重要）---"
echo "  Wazuh API wazuh-wui   : 已改为随机口令 ✅"
echo "  indexer admin         : 仍是默认 SecretPassword ⚠️ 待改"
echo "  indexer kibanaserver  : 仍是默认 kibanaserver  ⚠️ 待改"
echo
echo "--- 未完成项 ---"
echo "  · indexer 的 admin/kibanaserver 口令（要用 securityadmin.sh，见下）"
echo "  · Cowrie 蜜罐（步骤 ③）"
echo "  · Suricata（步骤 ④）"
echo "  · 隧道暴露（步骤 ⑤）"
echo
echo "=============================================="
