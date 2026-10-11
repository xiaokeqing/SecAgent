#!/usr/bin/env bash
# 确认 securityadmin 到底从哪里读 internal_users.yml
# 这是个容易搞错的地方：compose 挂载点和初始化脚本的 -cd 参数可能不是同一个目录
echo "===== 1. /etc/wazuh-indexer 是什么（符号链接？）====="
docker exec wazuh.indexer bash -c 'ls -la /etc/ | grep wazuh; echo ---; ls -la /etc/wazuh-indexer/ 2>/dev/null | head -20'

echo
echo "===== 2. 两个候选路径的实际内容 ====="
echo "  --- /etc/wazuh-indexer/opensearch-security/ ---"
docker exec wazuh.indexer bash -c 'ls -la /etc/wazuh-indexer/opensearch-security/ 2>/dev/null' | sed 's/^/    /'
echo "  --- /usr/share/wazuh-indexer/opensearch-security/ ---"
docker exec wazuh.indexer bash -c 'ls -la /usr/share/wazuh-indexer/opensearch-security/ 2>/dev/null' | sed 's/^/    /'

echo
echo "===== 3. 两边是不是同一份（inode 对比）====="
docker exec wazuh.indexer bash -c '
A=/etc/wazuh-indexer/opensearch-security/internal_users.yml
B=/usr/share/wazuh-indexer/opensearch-security/internal_users.yml
if [ -f "$A" ]; then echo "  $A -> inode $(stat -c %i "$A")"; else echo "  $A 不存在"; fi
if [ -f "$B" ]; then echo "  $B -> inode $(stat -c %i "$B")"; else echo "  $B 不存在"; fi
'

echo
echo "===== 4. 宿主机改一下文件，容器里能不能看到（验证挂载方向）====="
HOST_F=/opt/wazuh/config/wazuh_indexer/internal_users.yml
echo "  宿主文件 inode: $(stat -c %i $HOST_F)  修改时间: $(stat -c %y $HOST_F | cut -d. -f1)"
docker exec wazuh.indexer bash -c 'stat -c "  容器内 /usr/share/.../internal_users.yml inode %i 修改时间 %y" /usr/share/wazuh-indexer/opensearch-security/internal_users.yml 2>/dev/null'
docker exec wazuh.indexer bash -c 'stat -c "  容器内 /etc/.../internal_users.yml      inode %i 修改时间 %y" /etc/wazuh-indexer/opensearch-security/internal_users.yml 2>/dev/null'

echo
echo "===== 5. opensearch.yml 里 http.pemtrustedcas 指向哪（初始化脚本靠它找证书）====="
docker exec wazuh.indexer bash -c 'grep -E "http.pemtrustedcas|network.host|transport.tcp.port" /etc/wazuh-indexer/opensearch.yml 2>/dev/null' | sed 's/^/  /'

echo
echo "===== 6. 证书在容器里的位置 ====="
docker exec wazuh.indexer bash -c 'ls -la /etc/wazuh-indexer/*.pem /usr/share/wazuh-indexer/certs/*.pem 2>/dev/null | head -12' | sed 's/^/  /'

echo
echo "===== 7. runuser 存在吗 ====="
docker exec wazuh.indexer bash -c 'command -v runuser || echo "  没有 runuser"'
