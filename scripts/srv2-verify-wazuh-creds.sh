#!/usr/bin/env bash
# 等 manager API 真正就绪后再验证（上次就是测早了）
API_PW=$(grep '^WAZUH_API_WUI_PASSWORD=' /root/.wazuh-new-creds.txt | cut -d= -f2)

echo "=== 等 manager API 就绪 ==="
READY=0
for i in $(seq 1 36); do
  C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 https://127.0.0.1:55000/ 2>/dev/null)
  if [ "$C" = "401" ] || [ "$C" = "200" ]; then
    echo "  第 $((i*5)) 秒: API 响应 HTTP $C"
    READY=1; break
  fi
  sleep 5
done
[ "$READY" -eq 1 ] || { echo "  API 一直没起来"; docker logs --tail 20 wazuh.manager | sed 's/^/    /'; exit 1; }

# 再等 10 秒让 RBAC 初始化完（API 端口通了不等于用户库可用）
sleep 10

echo
echo "=== 验证：Wazuh API 三个口令的实际情况 ==="
printf "  旧默认口令 MyS3cr37P450r.*-  -> "
OLD=$(curl -sk -u 'wazuh-wui:MyS3cr37P450r.*-' -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null)
if echo "$OLD" | grep -q 'Bearer\|^ey'; then
  echo "成功（旧口令【仍然有效】）"
else
  echo "失败（旧口令已失效）"
fi

printf "  新口令                       -> "
NEW=$(curl -sk -u "wazuh-wui:${API_PW}" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null)
if echo "$NEW" | grep -q 'Bearer\|^ey'; then
  echo "成功（新口令有效 ✅）"
  # 拿它去查一下告警，证明不只是能认证
  echo
  echo "=== 用新口令实际调一个业务接口 ==="
  TOKEN=$(echo "$NEW" | sed 's/^Bearer //')
  curl -sk -H "Authorization: Bearer $TOKEN" "https://127.0.0.1:55000/manager/info" 2>/dev/null | head -c 300 | sed 's/^/  /'
else
  echo "失败"
  echo "  返回: $(echo "$NEW" | head -c 200)"
fi

echo
echo
echo "=== indexer 口令现状 ==="
printf "  admin:SecretPassword  -> HTTP "
curl -sk -o /dev/null -w '%{http_code}\n' -u admin:SecretPassword https://127.0.0.1:9200/_cluster/health

echo
echo "=== dashboard ==="
printf "  HTTP "
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:443/app/login

echo
echo "=== 内存 ==="
free -m | sed 's/^/  /'
docker stats --no-stream --format '  {{.Name}}  {{.MemUsage}}' 2>/dev/null
