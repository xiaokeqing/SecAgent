#!/usr/bin/env bash
# 摸清 Wazuh 各处的凭据分布，为改密做准备
echo "===== 1. internal_users.yml 里的账号与哈希 ====="
grep -nE '^[a-zA-Z_-]+:|^  hash:|^  reserved:|^  backend_roles:' \
  /opt/wazuh/config/wazuh_indexer/internal_users.yml | head -50 | sed 's/^/  /'

echo
echo "===== 2. 各账号的哈希行（只看格式，不看内容）====="
awk '/^[a-zA-Z_-]+:/{name=$1} /hash:/{print "  "name"  hash 长度 "length($2)}' \
  /opt/wazuh/config/wazuh_indexer/internal_users.yml

echo
echo "===== 3. dashboard 的 wazuh.yml（Wazuh API 连接信息）====="
grep -nE 'url|port|username|password|api' /opt/wazuh/config/wazuh_dashboard/wazuh.yml | head -20 | sed 's/^/  /'

echo
echo "===== 4. compose 里写死的凭据 ====="
grep -nE 'PASSWORD|USERNAME' /opt/wazuh/docker-compose.yml | sed 's/^/  /'

echo
echo "===== 5. 官方改密工具 ====="
docker exec wazuh.indexer ls -1 /usr/share/wazuh-indexer/plugins/opensearch-security/tools/ 2>/dev/null | sed 's/^/  /'

echo
echo "===== 6. hash.sh 试跑（生成一个测试哈希）====="
docker exec wazuh.indexer bash -c 'cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools && ./hash.sh -p TestPass123 2>&1 | tail -5' | sed 's/^/  /'

echo
echo "===== 7. 当前用的默认口令（三个已知值）====="
echo "  indexer admin     : SecretPassword"
echo "  indexer kibanaserver: kibanaserver"
echo "  Wazuh API wazuh-wui: MyS3cr37P450r.*-"
