#!/usr/bin/env bash
# ============================================================
# 改掉 Wazuh 的默认口令
# ------------------------------------------------------------
# 为什么要改：
#   官方 docker-compose 里写死了 Wazuh 文档中公开的三个口令：
#     SecretPassword / kibanaserver / MyS3cr37P450r.*-
#   现在机器没暴露还好，但步骤⑤要通过隧道把 dashboard 挂出去 ——
#   带着公开口令暴露等于没设防。
#
# 为什么必须用官方工具而不是手改配置文件：
#   indexer 的口令不是存在 internal_users.yml 里就生效的。
#   那份 yml 只是【源】，真正生效的是安全索引里的哈希（由 securityadmin 应用）。
#   所以：改 yml 不重启不生效；改了 yml 又重启，则要看镜像的初始化逻辑是否重放。
#   官方工具 wazuh-passwords-tool.sh 会同时改索引和 yml，是唯一可靠的路。
#   这也解释了为什么"看着改了但登录还是老口令"这种问题会出现。
#
# 安全措施：
#   1) 先备份全部配置
#   2) 停掉 dashboard，避免改密期间它用老口令反复认证失败刷日志
#   3) 改完逐项验证（不是只看命令退出码）
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

WORK=/opt/wazuh
CRED_FILE=/root/.wazuh-new-creds.txt
cd "$WORK" || die "找不到 $WORK"

log "1/7 备份现有配置"
BK="/root/wazuh-config-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BK"
cp -r config "$BK/" 2>/dev/null
cp docker-compose.yml "$BK/" 2>/dev/null
echo "$BK" > /root/.wazuh-last-backup
ok "已备份到 $BK"

log "2/7 生成新口令"
# 用 openssl 生成随机口令。刻意避开 shell 特殊字符（$ ` " \ !），
# 因为这些值要写进 YAML 和 JSON，转义问题会让排查变得很烦。
gen() { openssl rand -base64 24 | tr -d '/+=' | cut -c1-20; }
ADMIN_PW=$(gen)
KIBANA_PW=$(gen)
API_PW=$(gen)

cat > "$CRED_FILE" <<EOF
# Wazuh 新口令（本文件含明文，权限 600，不要提交进 git）
# 生成时间: $(date -Is)
INDEXER_ADMIN_PASSWORD=$ADMIN_PW
INDEXER_KIBANASERVER_PASSWORD=$KIBANA_PW
WAZUH_API_WUI_PASSWORD=$API_PW
EOF
chmod 600 "$CRED_FILE"
ok "已写入 $CRED_FILE（权限 600）"

log "3/7 停掉 dashboard（避免改密期间认证风暴）"
docker compose stop wazuh.dashboard >/dev/null 2>&1
ok "dashboard 已停"

log "4/7 用官方工具改 indexer 口令"
TOOLS=/usr/share/wazuh-indexer/plugins/opensearch-security/tools
change_indexer_pw() {
  local user="$1" pw="$2"
  echo "      改 $user ..."
  # 必须以 root 运行（工具的硬要求），且要设 JAVA_HOME
  docker exec -u root wazuh.indexer bash -c \
    "export JAVA_HOME=/usr/share/wazuh-indexer/jdk; cd $TOOLS && ./wazuh-passwords-tool.sh -u '$user' -p '$pw' 2>&1 | tail -6" \
    | sed 's/^/        /'
}

change_indexer_pw admin "$ADMIN_PW"
change_indexer_pw kibanaserver "$KIBANA_PW"

log "5/7 更新引用这些口令的配置文件"
# compose 里的 INDEXER_PASSWORD / DASHBOARD_PASSWORD
sed -i "s|INDEXER_PASSWORD=SecretPassword|INDEXER_PASSWORD=${ADMIN_PW}|g" docker-compose.yml
sed -i "s|DASHBOARD_PASSWORD=kibanaserver|DASHBOARD_PASSWORD=${KIBANA_PW}|g" docker-compose.yml
ok "docker-compose.yml 已更新"
grep -nE 'INDEXER_PASSWORD|DASHBOARD_PASSWORD' docker-compose.yml | sed 's/=.*/=<新口令>/' | sed 's/^/      /'

# wazuh.yml 里的 API 凭据（下一步改 API 用户后再改这里）
log "6/7 改 Wazuh API 的 wazuh-wui 口令"
# 先用老口令换 token，再改自己
OLD_TOKEN=$(curl -sk -u "wazuh-wui:MyS3cr37P450r.*-" -X POST \
  "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null)
if [ -z "$OLD_TOKEN" ] || [ "${#OLD_TOKEN}" -lt 20 ]; then
  warn "用旧口令拿不到 token，跳过 API 改密（可稍后手工处理）"
else
  ok "已用旧口令拿到 token"
  # 先查 wazuh-wui 的用户 id
  UID_JSON=$(curl -sk -H "Authorization: Bearer $OLD_TOKEN" \
    "https://127.0.0.1:55000/security/users?search=wazuh-wui" 2>/dev/null)
  WUI_ID=$(echo "$UID_JSON" | grep -oE '"id":[0-9]+' | head -1 | cut -d: -f2)
  if [ -n "$WUI_ID" ]; then
    echo "      wazuh-wui 的用户 id = $WUI_ID"
    RESP=$(curl -sk -X PUT -H "Authorization: Bearer $OLD_TOKEN" \
      -H 'Content-Type: application/json' \
      -d "{\"password\":\"${API_PW}\"}" \
      "https://127.0.0.1:55000/security/users/${WUI_ID}" 2>/dev/null)
    if echo "$RESP" | grep -q '"error":0'; then
      ok "Wazuh API 口令已改"
      sed -i "s|password: \"MyS3cr37P450r.\*-\"|password: \"${API_PW}\"|" config/wazuh_dashboard/wazuh.yml
      sed -i "s|API_PASSWORD=MyS3cr37P450r.\*\-|API_PASSWORD=${API_PW}|g" docker-compose.yml
      ok "wazuh.yml 与 docker-compose.yml 已同步"
    else
      warn "改 API 口令失败: $(echo "$RESP" | head -c 200)"
    fi
  else
    warn "没找到 wazuh-wui 用户: $(echo "$UID_JSON" | head -c 200)"
  fi
fi

log "7/7 重启并验证"
docker compose up -d 2>&1 | tail -4 | sed 's/^/      /'
echo "      等待服务就绪..."
sleep 45

echo
echo "      --- 验证 1: 旧口令应该失效 ---"
printf "        admin:SecretPassword -> "
C=$(curl -sk -o /dev/null -w '%{http_code}' -u admin:SecretPassword https://127.0.0.1:9200/_cluster/health 2>/dev/null)
if [ "$C" = "401" ]; then echo "HTTP 401 ✅ 旧口令已失效"; else echo "HTTP $C ⚠️ 旧口令还能用？"; fi

echo "      --- 验证 2: 新口令应该可用 ---"
printf "        admin:<新口令> -> "
R=$(curl -sk -u "admin:${ADMIN_PW}" https://127.0.0.1:9200/_cluster/health 2>/dev/null | head -c 60)
echo "$R"

echo "      --- 验证 3: Wazuh API 旧口令应失效 ---"
printf "        wazuh-wui:MyS3cr37P450r.*- -> "
T=$(curl -sk -o /dev/null -w '%{http_code}' -u 'wazuh-wui:MyS3cr37P450r.*-' -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null)
echo "HTTP $T"

echo "      --- 验证 4: Wazuh API 新口令 ---"
printf "        wazuh-wui:<新口令> -> "
NT=$(curl -sk -u "wazuh-wui:${API_PW}" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null)
if [ "${#NT}" -gt 20 ]; then echo "成功，token 长度 ${#NT} ✅"; else echo "失败: $(echo "$NT" | head -c 150)"; fi

echo "      --- 验证 5: dashboard ---"
printf "        HTTP "; curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:443/app/login

echo
echo "      --- 容器状态 ---"
docker ps --format '        {{.Names}}  {{.Status}}'

echo
ok "改密流程结束"
echo
echo "  新口令保存在: $CRED_FILE"
echo "  配置备份在:   $(cat /root/.wazuh-last-backup)"
echo
warn "如果上面的【验证 2】或【验证 4】失败，用备份回滚："
warn "  cp -r \$(cat /root/.wazuh-last-backup)/config /opt/wazuh/ && cd /opt/wazuh && docker compose up -d"
