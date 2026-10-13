#!/usr/bin/env bash
# ============================================================
# 改掉 indexer 的默认口令（走 securityadmin.sh，不走官方包装脚本）
# ------------------------------------------------------------
# 为什么不能用官方的 wazuh-passwords-tool.sh：
#   它硬依赖容器内的 sudo，而这个镜像没装 sudo。
# 为什么也不能用镜像自带的 indexer-security-init.sh：
#   它假设 CONFIG_PATH=/etc/wazuh-indexer（这个镜像里根本没这个目录），
#   而且用 runuser 切用户（这个镜像也没有 runuser）。
#   【教训】"官方脚本"不等于"在你的镜像版本上能跑"。
#
# 可靠的路子：直接调 securityadmin.sh。
#   · 容器默认用户就是 wazuh-indexer，而 opensearch-security 目录属主也是它
#     -> 不需要切用户，直接跑
#   · 用 admin 客户端证书认证（不是口令），所以不受改密影响
#   · -f 强制覆盖安全索引里的配置
#
# 改 6 个账号：admin / kibanaserver / kibanaro / logstash / readall / snapshotrestore
# 后 4 个是 demo 账号，口令也是 Wazuh 文档里公开的，一并换掉。
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

WORK=/opt/wazuh
IU="$WORK/config/wazuh_indexer/internal_users.yml"
CRED=/root/.wazuh-new-creds.txt
cd "$WORK" || die "找不到 $WORK"

log "1/6 备份"
BK="$WORK/config/wazuh_indexer/internal_users.yml.bak-$(date +%Y%m%d-%H%M%S)"
cp "$IU" "$BK"
ok "已备份到 $BK"

log "2/6 生成 6 个符合策略的口令"
# 固定前缀保证「大写+小写+数字+特殊字符」四类齐备（Wazuh/OpenSearch 都要求），
# 后面 16 位随机字母数字提供熵。
# 特殊字符选 * —— 在 shell 双引号 / YAML 双引号 / JSON 里都安全。
gen() { echo "Aa1*$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-16)"; }

PW_ADMIN=$(gen); PW_KIBANA=$(gen); PW_KIBANARO=$(gen)
PW_LOGSTASH=$(gen); PW_READALL=$(gen); PW_SNAPSHOT=$(gen)

# 本地先自检，不要等应用时才失败
for pw in "$PW_ADMIN" "$PW_KIBANA" "$PW_KIBANARO" "$PW_LOGSTASH" "$PW_READALL" "$PW_SNAPSHOT"; do
  [ "${#pw}" -ge 12 ] && echo "$pw" | grep -q '[A-Z]' && echo "$pw" | grep -q '[a-z]' \
    && echo "$pw" | grep -q '[0-9]' && echo "$pw" | grep -q '[^a-zA-Z0-9]' \
    || die "生成的口令不符合策略: 长度或字符类不足"
done
ok "6 个口令已生成并通过策略自检"

log "3/6 用 hash.sh 计算 bcrypt 哈希"
hash_of() {
  docker exec wazuh.indexer bash -c \
    "export JAVA_HOME=/usr/share/wazuh-indexer/jdk; cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools && ./hash.sh -p '$1' 2>/dev/null | tail -1" \
    | tr -d '\r'
}
H_ADMIN=$(hash_of "$PW_ADMIN");       H_KIBANA=$(hash_of "$PW_KIBANA")
H_KIBANARO=$(hash_of "$PW_KIBANARO"); H_LOGSTASH=$(hash_of "$PW_LOGSTASH")
H_READALL=$(hash_of "$PW_READALL");   H_SNAPSHOT=$(hash_of "$PW_SNAPSHOT")

for h in "$H_ADMIN" "$H_KIBANA" "$H_KIBANARO" "$H_LOGSTASH" "$H_READALL" "$H_SNAPSHOT"; do
  case "$h" in
    \$2*) ;;
    *) die "哈希格式不对: $(echo "$h" | head -c 60)" ;;
  esac
done
ok "6 个哈希已生成（都是 \$2y\$ / \$2a\$ bcrypt 格式）"

log "4/6 把哈希写进 internal_users.yml"
# 用 Python 做定位替换：找到 "账号:" 行，替换它后面第一行 "  hash: ..."，保留其它格式和注释
python3 - "$IU" "$H_ADMIN" "$H_KIBANA" "$H_KIBANARO" "$H_LOGSTASH" "$H_READALL" "$H_SNAPSHOT" <<'PYEOF'
import re, sys
path = sys.argv[1]
mapping = {
    "admin": sys.argv[2], "kibanaserver": sys.argv[3], "kibanaro": sys.argv[4],
    "logstash": sys.argv[5], "readall": sys.argv[6], "snapshotrestore": sys.argv[7],
}
with open(path, encoding="utf-8") as f:
    lines = f.readlines()

current = None
changed = set()
for i, line in enumerate(lines):
    m = re.match(r'^([A-Za-z0-9_-]+):\s*$', line)
    if m:
        current = m.group(1)
        continue
    if current in mapping and re.match(r'^\s+hash:\s*"', line):
        lines[i] = '  hash: "%s"\n' % mapping[current]
        changed.add(current)
        current = None

missing = set(mapping) - changed
if missing:
    print("  未替换到这些账号:", ", ".join(sorted(missing)))
    sys.exit(1)
with open(path, "w", encoding="utf-8") as f:
    f.writelines(lines)
print("  已替换 %d 个账号的哈希: %s" % (len(changed), ", ".join(sorted(changed))))
PYEOF
[ $? -eq 0 ] || die "internal_users.yml 改写失败"
ok "yml 已更新"

# 校验 YAML 语法（改坏了后面全白干）
python3 -c "import yaml,sys; yaml.safe_load(open('$IU')); print('  YAML 语法 OK')" || die "YAML 语法错误"
ok "YAML 可解析"

log "5/6 用 securityadmin.sh 应用（-f 强制覆盖安全索引）"
docker exec wazuh.indexer bash -c '
set -e
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools
./securityadmin.sh \
  -cd /usr/share/wazuh-indexer/opensearch-security \
  -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  -cert  /usr/share/wazuh-indexer/certs/admin.pem \
  -key   /usr/share/wazuh-indexer/certs/admin-key.pem \
  -h 127.0.0.1 -p 9200 -icl -nhnv -f
' 2>&1 | grep -viE '^$' | tail -25 | sed 's/^/      /'

log "6/6 更新 compose 与口令文件，重启并验证"
sed -i "s|INDEXER_PASSWORD=.*|INDEXER_PASSWORD=${PW_ADMIN}|g" docker-compose.yml
sed -i "s|DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=${PW_KIBANA}|g" docker-compose.yml

{
  echo "# Wazuh 口令（明文，权限 600，不要提交进 git）"
  echo "# 更新时间: $(date -Is)"
  echo "INDEXER_ADMIN_PASSWORD=${PW_ADMIN}"
  echo "INDEXER_KIBANASERVER_PASSWORD=${PW_KIBANA}"
  echo "INDEXER_KIBANARO_PASSWORD=${PW_KIBANARO}"
  echo "INDEXER_LOGSTASH_PASSWORD=${PW_LOGSTASH}"
  echo "INDEXER_READALL_PASSWORD=${PW_READALL}"
  echo "INDEXER_SNAPSHOTRESTORE_PASSWORD=${PW_SNAPSHOT}"
  # 保留已有的 API 口令行
  grep '^WAZUH_API_WUI_PASSWORD=' "$CRED" 2>/dev/null || true
} > "${CRED}.tmp"
mv "${CRED}.tmp" "$CRED"
chmod 600 "$CRED"
ok "口令文件与 compose 已更新"

docker compose up -d wazuh.manager wazuh.dashboard 2>&1 | tail -3 | sed 's/^/      /'
echo "      等待服务..."
sleep 50

echo
echo "      ===== 验证 ====="
printf "      旧 indexer 口令 admin:SecretPassword -> HTTP "
C1=$(curl -sk -o /dev/null -w '%{http_code}' -u admin:SecretPassword https://127.0.0.1:9200/_cluster/health)
if [ "$C1" = "401" ]; then echo "401 ✅ 已失效"; else echo "$C1 ⚠️ 还能用？"; fi

printf "      新 indexer 口令 admin:<新>          -> "
R=$(curl -sk -u "admin:${PW_ADMIN}" https://127.0.0.1:9200/_cluster/health 2>/dev/null | head -c 70)
echo "$R"

printf "      旧 kibanaserver:kibanaserver        -> HTTP "
C2=$(curl -sk -o /dev/null -w '%{http_code}' -u kibanaserver:kibanaserver https://127.0.0.1:9200/_cluster/health)
if [ "$C2" = "401" ]; then echo "401 ✅ 已失效"; else echo "$C2 ⚠️"; fi

printf "      旧 demo 账号 kibanaro:kibanaro      -> HTTP "
C3=$(curl -sk -o /dev/null -w '%{http_code}' -u kibanaro:kibanaro https://127.0.0.1:9200/_cluster/health)
if [ "$C3" = "401" ]; then echo "401 ✅ 已失效"; else echo "$C3 ⚠️"; fi

printf "      dashboard                            -> HTTP "
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:443/app/login

printf "      Wazuh API（应仍可用）                 -> "
API_PW=$(grep '^WAZUH_API_WUI_PASSWORD=' "$CRED" | cut -d= -f2)
T=$(curl -sk -u "wazuh-wui:${API_PW}" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null | sed 's/^Bearer //')
if [ "${#T}" -gt 20 ]; then echo "认证成功 ✅"; else echo "失败 ⚠️"; fi

echo
docker ps --format '      {{.Names}}  {{.Status}}'
echo
echo "      新口令在: $CRED"
echo "      回滚用:   cp $BK $IU && cd $WORK && docker compose restart wazuh.indexer"
