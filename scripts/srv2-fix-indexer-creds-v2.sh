#!/usr/bin/env bash
# ============================================================
# A1：改掉 Wazuh indexer 的默认口令（第二次尝试，修正了 -f 的用法）
# ------------------------------------------------------------
# 上一次失败的原因（已经查清）：
#   ERR: Parsing failed. Reason: Missing argument for option: f
#   `-f` 不是 "force"，而是「指定单个配置文件」，需要跟一个文件名。
#   正确做法是只用 `-cd <目录>`（应用目录下全部配置文件），
#   需要强制时用 `-ff`。
#
# 【这次加了硬性验证门槛】
# 前两次失败都是同一个流程缺陷：改密失败后，脚本仍然无条件地去改配置文件，
# 结果 compose 说口令是新的、indexer 里还是老的 -> dashboard 挂了 503。
#
# 正确顺序必须是：
#     执行改密 -> 【验证改密确实生效】-> 只有通过了才改配置
# 所以下面用 verify_or_die 把这一步做成不可跳过的门槛，
# 而不是靠"我记得要看一眼"。
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

WORK=/opt/wazuh
IU="$WORK/config/wazuh_indexer/internal_users.yml"
CRED=/root/.wazuh-new-creds.txt
cd "$WORK" || die "找不到 $WORK"

log "1/8 备份"
BK="$WORK/config/wazuh_indexer/internal_users.yml.bak-$(date +%Y%m%d-%H%M%S)"
cp "$IU" "$BK"
echo "    $BK" | tee /root/.wazuh-last-iu-backup

log "2/8 生成符合策略的口令（6 个账号）"
# 固定前缀 Aa1* 保证满足 Wazuh/OpenSearch 的复杂度要求（大小写+数字+特殊字符），
# 后面 16 位随机提供熵。特殊字符选 * —— shell/YAML/JSON 三处都安全。
gen() { echo "Aa1*$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-16)"; }
PW_ADMIN=$(gen); PW_KIBANA=$(gen); PW_KIBANARO=$(gen)
PW_LOGSTASH=$(gen); PW_READALL=$(gen); PW_SNAPSHOT=$(gen)
for pw in "$PW_ADMIN" "$PW_KIBANA" "$PW_KIBANARO" "$PW_LOGSTASH" "$PW_READALL" "$PW_SNAPSHOT"; do
  [ "${#pw}" -ge 12 ] && echo "$pw" | grep -q '[A-Z]' && echo "$pw" | grep -q '[a-z]' \
    && echo "$pw" | grep -q '[0-9]' && echo "$pw" | grep -q '[^a-zA-Z0-9]' \
    || die "生成的口令不符合策略"
done
ok "6 个口令已生成并自检通过"

log "3/8 计算 bcrypt 哈希"
hash_of() {
  docker exec wazuh.indexer bash -c \
    "export JAVA_HOME=/usr/share/wazuh-indexer/jdk; cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools && ./hash.sh -p '$1' 2>/dev/null | tail -1" | tr -d '\r'
}
H_ADMIN=$(hash_of "$PW_ADMIN");       H_KIBANA=$(hash_of "$PW_KIBANA")
H_KIBANARO=$(hash_of "$PW_KIBANARO"); H_LOGSTASH=$(hash_of "$PW_LOGSTASH")
H_READALL=$(hash_of "$PW_READALL");   H_SNAPSHOT=$(hash_of "$PW_SNAPSHOT")
for h in "$H_ADMIN" "$H_KIBANA" "$H_KIBANARO" "$H_LOGSTASH" "$H_READALL" "$H_SNAPSHOT"; do
  case "$h" in \$2*) ;; *) die "哈希格式不对: $(echo "$h" | head -c 40)";; esac
done
ok "6 个哈希已生成"

log "4/8 写进 internal_users.yml"
python3 - "$IU" "$H_ADMIN" "$H_KIBANA" "$H_KIBANARO" "$H_LOGSTASH" "$H_READALL" "$H_SNAPSHOT" <<'PYEOF'
import re, sys
path = sys.argv[1]
mapping = {"admin": sys.argv[2], "kibanaserver": sys.argv[3], "kibanaro": sys.argv[4],
           "logstash": sys.argv[5], "readall": sys.argv[6], "snapshotrestore": sys.argv[7]}
lines = open(path, encoding="utf-8").readlines()
current, changed = None, set()
for i, line in enumerate(lines):
    m = re.match(r'^([A-Za-z0-9_-]+):\s*$', line)
    if m:
        current = m.group(1); continue
    if current in mapping and re.match(r'^\s+hash:\s*"', line):
        lines[i] = '  hash: "%s"\n' % mapping[current]; changed.add(current); current = None
missing = set(mapping) - changed
if missing:
    print("  未替换:", ", ".join(sorted(missing))); sys.exit(1)
open(path, "w", encoding="utf-8").writelines(lines)
print("  已替换 %d 个账号" % len(changed))
PYEOF
[ $? -eq 0 ] || die "yml 改写失败"
python3 -c "import yaml;yaml.safe_load(open('$IU'))" || die "YAML 语法坏了"
ok "yml 已更新且语法正确"

log "5/8 用 securityadmin.sh 应用（这次【不用 -f】）"
docker exec wazuh.indexer bash -c '
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools
./securityadmin.sh \
  -cd /usr/share/wazuh-indexer/opensearch-security \
  -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  -cert  /usr/share/wazuh-indexer/certs/admin.pem \
  -key   /usr/share/wazuh-indexer/certs/admin-key.pem \
  -h 127.0.0.1 -p 9200 -icl -nhnv 2>&1
' | grep -viE '^\s*$' | tail -20 | sed 's/^/    /'

log "6/8 【硬性门槛】验证改密真的生效 —— 不通过就到此为止，不改任何配置"
sleep 3
OLD_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -u admin:SecretPassword --max-time 8 https://127.0.0.1:9200/_cluster/health 2>/dev/null)
NEW_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -u "admin:${PW_ADMIN}" --max-time 8 https://127.0.0.1:9200/_cluster/health 2>/dev/null)
echo "    旧口令 admin:SecretPassword -> HTTP $OLD_CODE  （期望 401）"
echo "    新口令 admin:<新>            -> HTTP $NEW_CODE  （期望 200）"

verify_or_die() {
  if [ "$OLD_CODE" = "401" ] && [ "$NEW_CODE" = "200" ]; then
    ok "改密已生效，旧口令失效、新口令可用 —— 可以继续改配置"
    return 0
  fi
  warn "改密【没有生效】，中止流程，不改任何配置文件"
  echo "      回滚 internal_users.yml："
  cp "$(cat /root/.wazuh-last-iu-backup)" "$IU"
  echo "      已回滚 $IU"
  die "改密失败 —— 这正是前两次犯的错：命令失败后还去改配置，把 dashboard 弄挂了"
}
verify_or_die

log "7/8 改配置（只有上一步通过了才会走到这里）"
sed -i "s|INDEXER_PASSWORD=.*|INDEXER_PASSWORD=${PW_ADMIN}|g" docker-compose.yml
sed -i "s|DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=${PW_KIBANA}|g" docker-compose.yml
ok "compose 已更新（密码值不打印）"

{
  echo "# Wazuh 口令（明文，权限 600，不要提交进 git）"
  echo "# 更新时间: $(date -Is)"
  echo "INDEXER_ADMIN_PASSWORD=${PW_ADMIN}"
  echo "INDEXER_KIBANASERVER_PASSWORD=${PW_KIBANA}"
  echo "INDEXER_KIBANARO_PASSWORD=${PW_KIBANARO}"
  echo "INDEXER_LOGSTASH_PASSWORD=${PW_LOGSTASH}"
  echo "INDEXER_READALL_PASSWORD=${PW_READALL}"
  echo "INDEXER_SNAPSHOTRESTORE_PASSWORD=${PW_SNAPSHOT}"
  grep '^WAZUH_API_WUI_PASSWORD=' "$CRED" 2>/dev/null || true
} > "${CRED}.tmp"
mv "${CRED}.tmp" "$CRED"
chmod 600 "$CRED"
ok "口令文件已更新"

log "8/8 重启并全面验证"
docker compose up -d wazuh.manager wazuh.dashboard 2>&1 | tail -3 | sed 's/^/    /'
echo "    等待服务..."
for i in $(seq 1 30); do
  sleep 5
  C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1:443/app/login 2>/dev/null)
  [ "$C" = "200" ] && { echo "    第 $((i*5)) 秒: dashboard HTTP 200"; break; }
done
# manager 要单独等（它启动慢，之前"测太早"踩过三次）
for i in $(seq 1 24); do
  sleep 5
  M=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1:55000/ 2>/dev/null)
  [ "$M" = "401" ] || [ "$M" = "200" ] && { echo "    第 $((i*5)) 秒: manager API HTTP $M"; break; }
done
sleep 5

echo
echo "    ===== 最终验证 ====="
printf "    indexer 旧口令 admin:SecretPassword -> HTTP "
C=$(curl -sk -o /dev/null -w '%{http_code}' -u admin:SecretPassword https://127.0.0.1:9200/_cluster/health); echo "$C"
printf "    indexer 新口令                     -> HTTP "
C=$(curl -sk -o /dev/null -w '%{http_code}' -u "admin:${PW_ADMIN}" https://127.0.0.1:9200/_cluster/health); echo "$C"
printf "    demo 账号 kibanaro:kibanaro        -> HTTP "
C=$(curl -sk -o /dev/null -w '%{http_code}' -u kibanaro:kibanaro https://127.0.0.1:9200/_cluster/health); echo "$C"
printf "    dashboard                          -> HTTP "
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:443/app/login
printf "    Wazuh API（新口令）                 -> "
API_PW=$(grep '^WAZUH_API_WUI_PASSWORD=' "$CRED" | cut -d= -f2)
T=$(curl -sk -u "wazuh-wui:${API_PW}" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null | sed 's/^Bearer //')
[ "${#T}" -gt 20 ] && echo "认证成功 ✅" || echo "失败 ⚠️"

echo
docker ps --format '    {{.Names}}  {{.Status}}'
echo
echo "    新口令在: $CRED"
echo "    indexer 配置文件备份: $(cat /root/.wazuh-last-iu-backup)"
