#!/usr/bin/env bash
# ============================================================
# 用官方 apt 源安装 Wazuh agent（服务器 2 本机）
# ------------------------------------------------------------
# 为什么最终选原生安装而不是容器：
#   1) Wazuh 没有发布 4.9.2 的 agent 容器镜像（Docker Hub 上没有）
#   2) 更重要的是语义：agent 的职责是"在被监控主机上执行动作"
#      （封 IP 就是往 iptables 插规则）。原生安装时它就是这台机器的
#      一个系统服务，与真实生产环境一致；
#      容器化反而要额外处理 host 网络、NET_ADMIN、netns 这些边界，
#      多一层就可能多一种"看起来成功、实际没生效"的失败模式。
#
# 实测 packages.wazuh.com 现在 800+ KB/s，安装只要十几秒。
# （之前记的 12 KB/s 是另一条链路的情况，已经变了 ——
#   所以"某个源很慢"这种结论也要重新验证，不能一直沿用。）
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\n\033[1;33m  [!] $*\033[0m"; }

DIR=/opt/wazuh-agent

log "1/6 停掉之前那个失败的容器（如果有）"
docker rm -f wazuh-agent 2>/dev/null | sed 's/^/  /' || true

log "2/6 添加 Wazuh 官方 apt 源"
if [ -f /etc/apt/sources.list.d/wazuh.list ]; then
  echo "  源已存在"
else
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
    --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>&1 | tail -2 | sed 's/^/    /'
  chmod 644 /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  ok "已添加"
fi

log "3/6 安装 agent（带上预共享密钥，免去交互式注册）"
AGENT_ID=$(cat "$DIR/agent.id" 2>/dev/null || echo "001")
AGENT_KEY=$(cat "$DIR/agent.key")
echo "  agent id = $AGENT_ID"

export WAZUH_MANAGER='127.0.0.1'
export WAZUH_MANAGER_PORT='1514'
export WAZUH_PROTOCOL='tcp'
export WAZUH_REGISTRATION_SERVER='127.0.0.1'
export WAZUH_AGENT_NAME="srv2-agent"
export WAZUH_AGENT_GROUP='default'

apt-get update -qq 2>&1 | tail -2 | sed 's/^/    /'
DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent 2>&1 | tail -8 | sed 's/^/    /'

if ! command -v /var/ossec/bin/wazuh-control >/dev/null 2>&1 && [ ! -f /var/ossec/bin/wazuh-control ]; then
  warn "安装似乎失败"
fi
echo "  已安装版本:"
dpkg -l wazuh-agent 2>/dev/null | tail -1 | sed 's/^/    /'

log "4/6 写入预共享密钥（这样不用走交互式注册）"
# 关键：client.keys 必须是 <id> <name> <ip> <key> 格式，
# 而且要和 manager 上登记的一致，否则 agent 会一直 never_connected。
install -d -m 750 /var/ossec/etc
printf '%s srv2-agent 127.0.0.1 %s\n' "$AGENT_ID" "$AGENT_KEY" > /var/ossec/etc/client.keys
chown root:wazuh /var/ossec/etc/client.keys 2>/dev/null || true
chmod 640 /var/ossec/etc/client.keys
ok "client.keys 已写入（内容含密钥，不打印）"

log "5/6 启动 agent"
systemctl daemon-reload
systemctl enable wazuh-agent >/dev/null 2>&1
systemctl restart wazuh-agent
sleep 15
echo "  服务状态: $(systemctl is-active wazuh-agent 2>/dev/null)"
echo "  最近日志:"
journalctl -u wazuh-agent -n 12 --no-pager 2>/dev/null | sed 's/^/    /' || tail -12 /var/ossec/logs/ossec.log 2>/dev/null | sed 's/^/    /'

log "6/6 验证 agent 是否连上 manager"
sleep 10
API_PW=$(grep '^WAZUH_API_WUI_PASSWORD=' /root/.wazuh-new-creds.txt | cut -d= -f2)
T=$(curl -sk -u "wazuh-wui:${API_PW}" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null | sed 's/^Bearer //')
curl -sk -H "Authorization: Bearer $T" "https://127.0.0.1:55000/agents?select=id,name,status,version" 2>/dev/null \
  | python3 -c "
import json,sys
d=json.load(sys.stdin).get('data',{})
for a in d.get('affected_items',[]):
    print('  id=%-4s %-14s status=%-16s version=%s' % (a.get('id'), a.get('name'), a.get('status'), a.get('version')))
" 2>&1 | sed 's/^/  /'

echo
echo "  判定：001 的状态若是 active -> 处置链路有了可执行动作的 agent"
