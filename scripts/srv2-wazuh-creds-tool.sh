#!/usr/bin/env bash
# 摸清 wazuh-passwords-tool.sh 的用法与依赖
echo "===== 1. 工具的用法说明 ====="
docker exec wazuh.indexer bash -c 'cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools && ./wazuh-passwords-tool.sh -h 2>&1 | head -40' | sed 's/^/  /'

echo
echo "===== 2. 容器里的 JAVA_HOME 情况 ====="
docker exec wazuh.indexer bash -c 'echo "OPENSEARCH_JAVA_HOME=$OPENSEARCH_JAVA_HOME"; echo "JAVA_HOME=$JAVA_HOME"; ls -d /usr/share/wazuh-indexer/jdk 2>/dev/null && echo "自带 JDK 存在"' | sed 's/^/  /'

echo
echo "===== 3. 带上 JAVA_HOME 再试 hash.sh ====="
docker exec wazuh.indexer bash -c 'export JAVA_HOME=/usr/share/wazuh-indexer/jdk; cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools && ./hash.sh -p TestPass123 2>&1 | tail -3' | sed 's/^/  /'

echo
echo "===== 4. Wazuh API 的用户表在哪 ====="
docker exec wazuh.manager bash -c 'ls -la /var/ossec/api/configuration/security/ 2>/dev/null; echo ---; ls -la /var/ossec/etc/ 2>/dev/null | head' | sed 's/^/  /'

echo
echo "===== 5. dashboard 的登录走哪条路（看 wazuh.yml 全文）====="
cat /opt/wazuh/config/wazuh_dashboard/wazuh.yml | sed 's/^/  /'

echo
echo "===== 6. 目前 dashboard 能登录吗（用默认 admin/SecretPassword）====="
printf "  dashboard 首页: HTTP "
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:443/app/login
printf "  indexer 用 admin:SecretPassword 查集群: "
curl -sk -u admin:SecretPassword https://127.0.0.1:9200/_cluster/health 2>/dev/null | head -c 80
echo
printf "  Wazuh API 认证（wazuh-wui）: "
TOKEN=$(curl -sk -u wazuh-wui:'MyS3cr37P450r.*-' -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null)
if [ -n "$TOKEN" ] && [ "${#TOKEN}" -gt 20 ]; then
  echo "成功，token 长度 ${#TOKEN}"
else
  echo "失败: $(echo "$TOKEN" | head -c 120)"
fi
