#!/usr/bin/env bash
# 恢复一致性：让配置如实反映 indexer 的实际口令状态
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }

WORK=/opt/wazuh
cd "$WORK" || exit 1

log "1/4 看 securityadmin 到底报什么错（上次只看了尾部）"
docker exec wazuh.indexer bash -c '
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools
./securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security \
  -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  -cert  /usr/share/wazuh-indexer/certs/admin.pem \
  -key   /usr/share/wazuh-indexer/certs/admin-key.pem \
  -h 127.0.0.1 -p 9200 -icl -nhnv -f 2>&1 | head -12' | sed 's/^/    /'

log "2/4 把 compose 改回 indexer 的实际口令"
sed -i "s|INDEXER_PASSWORD=.*|INDEXER_PASSWORD=SecretPassword|g" docker-compose.yml
sed -i "s|DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=kibanaserver|g" docker-compose.yml
ok "compose 已对齐实际状态"

log "3/4 把 internal_users.yml 也回滚（避免成为隐患）"
# 现在磁盘上的 yml 是新哈希，但索引里是旧哈希 —— 不一致。
# 如果哪天索引重建、或者有人手动跑了 securityadmin，口令会突然变，
# 而没人记得为什么。这种「潜伏的不一致」比明面上的错误更麻烦。
BK=$(ls -1t "$WORK"/config/wazuh_indexer/internal_users.yml.bak-* 2>/dev/null | head -1)
if [ -n "$BK" ]; then
  cp "$BK" "$WORK/config/wazuh_indexer/internal_users.yml"
  ok "已从 $BK 回滚"
  # 校验当前 admin 哈希就是默认那个
  if grep -q 'K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO' "$WORK/config/wazuh_indexer/internal_users.yml"; then
    ok "确认 admin 哈希 = 默认值（与索引一致）"
  else
    warn "哈希和预期不符，手工检查"
  fi
else
  warn "找不到备份"
fi

log "4/4 重启并验证"
docker compose up -d wazuh.manager wazuh.dashboard 2>&1 | tail -3 | sed 's/^/    /'
echo "    等待..."
for i in $(seq 1 24); do
  sleep 5
  C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1:443/app/login 2>/dev/null)
  if [ "$C" = "200" ]; then echo "    第 $((i*5)) 秒: dashboard HTTP 200"; break; fi
done

echo
echo "    --- 最终验证 ---"
printf "    indexer admin:SecretPassword -> HTTP "
curl -sk -o /dev/null -w '%{http_code}\n' -u admin:SecretPassword https://127.0.0.1:9200/_cluster/health
printf "    dashboard                    -> HTTP "
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:443/app/login
printf "    Wazuh API（新口令）           -> "
API_PW=$(grep '^WAZUH_API_WUI_PASSWORD=' /root/.wazuh-new-creds.txt | cut -d= -f2)
T=$(curl -sk -u "wazuh-wui:${API_PW}" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null | sed 's/^Bearer //')
[ "${#T}" -gt 20 ] && echo "认证成功 ✅" || echo "失败"

echo
docker ps --format '    {{.Names}}  {{.Status}}'
echo
ok "状态已恢复一致"
echo
echo "  当前事实："
echo "    indexer admin/kibanaserver/demo 账号 : 仍是 Wazuh 默认口令"
echo "    Wazuh API wazuh-wui                  : 已是随机口令 ✅"
echo "    securityadmin.sh 参数问题待查（见上面第 1 步的输出）"
