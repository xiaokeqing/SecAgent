#!/usr/bin/env bash
# ============================================================
# 修复改密搞出的不一致状态
# ------------------------------------------------------------
# 现状（事实）：
#   indexer  admin       = SecretPassword   （改密工具失败，没变）
#   indexer  kibanaserver= kibanaserver     （同上）
#   API      wazuh-wui   = <新口令>          （改成功了）
#   compose  里却已经被改成新口令            （对不上 -> dashboard 503）
#   wazuh.yml 还是旧 API 口令               （对不上）
#
# 目标：让所有配置【如实反映现状】，先把服务恢复，再谈改密。
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

WORK=/opt/wazuh
cd "$WORK" || die "找不到 $WORK"

# 取出实际生效的 API 新口令
API_PW=$(grep '^WAZUH_API_WUI_PASSWORD=' /root/.wazuh-new-creds.txt | cut -d= -f2)
[ -n "$API_PW" ] || die "读不到 API 新口令"

log "1/5 把 compose 的 indexer 口令改回【实际值】"
# indexer 侧没改成功，所以配置必须回退到实际值，否则 dashboard 连不上
sed -i "s|INDEXER_PASSWORD=.*|INDEXER_PASSWORD=SecretPassword|g" docker-compose.yml
sed -i "s|DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=kibanaserver|g" docker-compose.yml
# API 口令改成实际生效的新值
sed -i "s|API_PASSWORD=.*|API_PASSWORD=${API_PW}|g" docker-compose.yml
ok "compose 已对齐实际状态"
grep -nE 'INDEXER_PASSWORD|DASHBOARD_PASSWORD|API_PASSWORD' docker-compose.yml | sed 's/=.*/= <已对齐>/' | sed 's/^/      /'

log "2/5 把 wazuh.yml 的 API 口令改成新值"
sed -i "s|password: \".*\"|password: \"${API_PW}\"|" config/wazuh_dashboard/wazuh.yml
ok "wazuh.yml 已对齐"
grep -nE 'username|password' config/wazuh_dashboard/wazuh.yml | sed 's/password: .*/password: <已对齐>/' | sed 's/^/      /'

log "3/5 重启"
docker compose up -d 2>&1 | tail -4 | sed 's/^/      /'
echo "      等待就绪..."
for i in $(seq 1 24); do
  sleep 5
  C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1:443/app/login 2>/dev/null)
  if [ "$C" = "200" ]; then echo "      第 $((i*5)) 秒: dashboard HTTP 200"; break; fi
done

log "4/5 验证一致性"
echo "      --- indexer（应该还是老口令，因为没改成）---"
printf "        admin:SecretPassword      -> HTTP "
curl -sk -o /dev/null -w '%{http_code}\n' -u admin:SecretPassword https://127.0.0.1:9200/_cluster/health
printf "        admin:<新口令>             -> HTTP "
ADMIN_NEW=$(grep '^INDEXER_ADMIN_PASSWORD=' /root/.wazuh-new-creds.txt | cut -d= -f2)
curl -sk -o /dev/null -w '%{http_code}\n' -u "admin:${ADMIN_NEW}" https://127.0.0.1:9200/_cluster/health

echo "      --- Wazuh API（应该是新口令）---"
printf "        wazuh-wui:<新口令>         -> "
NT=$(curl -sk -u "wazuh-wui:${API_PW}" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null)
if [ "${#NT}" -gt 20 ]; then echo "成功（token ${#NT} 字符）"; else echo "失败"; fi

echo "      --- dashboard ---"
printf "        HTTP "; curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:443/app/login

echo "      --- dashboard 能不能连上 API（看它日志有没有认证失败）---"
docker logs --tail 15 wazuh.dashboard 2>&1 | grep -iE 'error|401|unauthor|refused' | head -5 | sed 's/^/        /' || echo "        没有错误"

log "5/5 容器状态"
docker ps --format '      {{.Names}}  {{.Status}}'
echo
docker stats --no-stream --format '      {{.Name}}  {{.MemUsage}}' 2>/dev/null

echo
ok "一致性修复完成"
echo
echo "  当前【事实】："
echo "    indexer admin/kibanaserver : 仍是 Wazuh 默认口令（未改成功）"
echo "    Wazuh API wazuh-wui        : 已改为随机口令 ✅"
echo
warn "indexer 口令还没改 —— 原因是官方工具依赖容器内的 sudo，而这个镜像没装。"
warn "下一步改用 securityadmin.sh 直接应用（不走那个包装脚本）。"
