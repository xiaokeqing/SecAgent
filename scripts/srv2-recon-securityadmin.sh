#!/usr/bin/env bash
# 摸清 securityadmin.sh 的正确调用方式
# 照抄镜像自己的初始化脚本，比自己拼参数可靠
echo "===== 1. 镜像的初始化脚本内容 ====="
docker exec wazuh.indexer bash -c 'cat /usr/share/wazuh-indexer/bin/indexer-security-init.sh 2>/dev/null' | sed 's/^/  /'

echo
echo "===== 2. securityadmin.sh 的用法 ====="
docker exec wazuh.indexer bash -c 'cat /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh 2>/dev/null | head -60' | sed 's/^/  /'

echo
echo "===== 3. config.yml（securityadmin 的默认参数）====="
docker exec wazuh.indexer bash -c 'cat /usr/share/wazuh-indexer/plugins/opensearch-security/tools/config.yml 2>/dev/null' | sed 's/^/  /'

echo
echo "===== 4. 容器里有没有 sudo（确认之前失败的原因）====="
docker exec wazuh.indexer bash -c 'command -v sudo || echo "  没有 sudo"'

echo
echo "===== 5. 容器是不是 root 跑的 ====="
docker exec wazuh.indexer bash -c 'id'

echo
echo "===== 6. internal_users.yml 的完整头尾结构（为改哈希做准备）====="
head -20 /opt/wazuh/config/wazuh_indexer/internal_users.yml | sed 's/^/  /'
echo "  ..."
echo "  总行数: $(wc -l < /opt/wazuh/config/wazuh_indexer/internal_users.yml)"
