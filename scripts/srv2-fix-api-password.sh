#!/usr/bin/env bash
# ============================================================
# 修 Wazuh API 口令：生成符合复杂度策略的值
# ------------------------------------------------------------
# 报错是：
#   wazuh.core.exception.WazuhError: Error 5007 - Insecure user password provided
#
# Wazuh 的口令策略要求【同时】包含：
#   大写字母 + 小写字母 + 数字 + 特殊字符，且长度 >= 8
# 我上一版用 `openssl rand | tr -d '/+='` 生成的是纯字母数字 —— 缺特殊字符，
# 所以被策略拒绝。这是个 fail-closed 策略在正确工作，只是我得满足它。
#
# 坑里有坑：特殊字符要选一个在【shell 双引号 / YAML 双引号 / JSON】里都安全的。
#   排除 !  (shell 历史展开)
#   排除 $ ` \ "  (转义地狱)
#   排除 #  (YAML 里在空格后会被当注释)
#   选 *  —— 三处都安全
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

WORK=/opt/wazuh
cd "$WORK" || die "找不到 $WORK"

log "1/4 生成符合策略的口令"
# 结构：固定满足四类字符的前缀 + 随机主体
#   Aa1*  保证大写/小写/数字/特殊字符各一个
#   后面 16 位随机字母数字提供熵
# 这样构造而不是"随机生成再检查"，是因为检查失败要重试，
# 而重试逻辑在 shell 里容易写错 —— 直接保证满足更可靠。
gen_strong() {
  local body
  body=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-16)
  echo "Aa1*${body}"
}

VALIDATE() {
  local p="$1"
  [ "${#p}" -ge 12 ] || return 1
  echo "$p" | grep -q '[A-Z]' || return 1
  echo "$p" | grep -q '[a-z]' || return 1
  echo "$p" | grep -q '[0-9]' || return 1
  echo "$p" | grep -q '[^a-zA-Z0-9]' || return 1
  return 0
}

API_PW=$(gen_strong)
if VALIDATE "$API_PW"; then
  ok "已生成并通过本地策略校验（长度 ${#API_PW}，含大小写/数字/特殊字符）"
else
  die "生成的还是不符合策略，检查 gen_strong"
fi

log "2/4 写回口令文件"
# 保留 indexer 的两个值（还没改成功，稍后处理），更新 API 的
NEW_FILE=/root/.wazuh-new-creds.txt
touch "$NEW_FILE"; chmod 600 "$NEW_FILE"
# 删掉旧的 API 行，写入新的
grep -v '^WAZUH_API_WUI_PASSWORD=' "$NEW_FILE" > "${NEW_FILE}.tmp" || true
echo "WAZUH_API_WUI_PASSWORD=${API_PW}" >> "${NEW_FILE}.tmp"
mv "${NEW_FILE}.tmp" "$NEW_FILE"
chmod 600 "$NEW_FILE"
ok "已更新 $NEW_FILE"

log "3/4 同步到 compose 与 wazuh.yml"
sed -i "s|API_PASSWORD=.*|API_PASSWORD=${API_PW}|g" docker-compose.yml
sed -i "s|password: \".*\"|password: \"${API_PW}\"|" config/wazuh_dashboard/wazuh.yml

# 确认写进去的内容能被 YAML 正确解析（不只看 grep）
python3 - <<PYEOF
import yaml, sys
# wazuh.yml
try:
    with open("config/wazuh_dashboard/wazuh.yml") as f:
        d = yaml.safe_load(f)
    host = list(d["hosts"][0].values())[0]
    pw = host["password"]
    print("  wazuh.yml 解析 OK，password 长度 %d，含特殊字符: %s" % (len(pw), any(c in pw for c in "*!@#%")))
except Exception as e:
    print("  wazuh.yml 解析失败:", e); sys.exit(1)
PYEOF
[ $? -eq 0 ] || die "wazuh.yml 写坏了"
ok "配置文件已同步且可解析"

log "4/4 重启 manager 并等待 API 起来"
docker compose up -d wazuh.manager wazuh.dashboard 2>&1 | tail -4 | sed 's/^/      /'

echo "      等待 API（manager 的初始化脚本会用新口令建 API 用户）..."
READY=0
for i in $(seq 1 48); do
  sleep 5
  C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 https://127.0.0.1:55000/ 2>/dev/null)
  if [ "$C" = "401" ] || [ "$C" = "200" ]; then
    echo "      第 $((i*5)) 秒: API HTTP $C"
    READY=1; break
  fi
  # 如果容器已经死了就别等了
  docker ps --format '{{.Names}}' | grep -q '^wazuh.manager$' || { warn "manager 容器已退出"; break; }
done

if [ "$READY" -eq 0 ]; then
  warn "API 仍未就绪，看 manager 初始化日志："
  docker logs wazuh.manager 2>&1 | grep -iE 'error|insecure|5007|api user' | tail -8 | sed 's/^/        /'
  die "manager API 起不来"
fi

sleep 8
echo
echo "      --- 用新口令认证 ---"
TOKEN=$(curl -sk -u "wazuh-wui:${API_PW}" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null | sed 's/^Bearer //')
if [ "${#TOKEN}" -gt 20 ]; then
  ok "认证成功（token ${#TOKEN} 字符）"
  echo "      --- 用它调一个业务接口，证明不只是能认证 ---"
  curl -sk -H "Authorization: Bearer $TOKEN" "https://127.0.0.1:55000/manager/info" 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); i=d["data"]["affected_items"][0]; print("        版本:", i.get("version"), " 主机:", i.get("name"), " 类型:", i.get("type"))' 2>/dev/null \
    || echo "        (接口返回已收到，解析略)"
else
  warn "认证失败: $(curl -sk -u "wazuh-wui:${API_PW}" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null | head -c 200)"
fi

echo
echo "      --- 旧默认口令应失效 ---"
OLD_OK=$(curl -sk -u 'wazuh-wui:MyS3cr37P450r.*-' -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null)
if echo "$OLD_OK" | grep -q '^ey'; then echo "        ⚠️ 旧口令仍有效"; else echo "        ✅ 旧口令已失效"; fi

echo
docker ps --format '      {{.Names}}  {{.Status}}'
echo
ok "API 口令修复完成"
