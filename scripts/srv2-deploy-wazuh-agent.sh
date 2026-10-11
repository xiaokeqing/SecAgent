#!/usr/bin/env bash
# ============================================================
# 在服务器 2 上部署 Wazuh agent（D2 处置链路的关键一环）
# ------------------------------------------------------------
# 为什么需要它 —— 这是今天最重要的架构发现
#
# 尝试通过管理 API 下发 active-response（封 IP）时被拒绝：
#   error 1703: Action not available for Manager (agent 000)
#   remediation: make sure you select an agent other than 000
#
# Wazuh 【不允许对 manager 本身下发 AR】。原因很合理：
#   active-response 的语义是"在【被监控的主机】上执行动作"，
#   而 manager 是管理方，不是被监控的主机。
#   没有 agent，就没有"可以执行动作的手"。
#
# 这也意味着：之前 SecAgent 的封禁动作即使配成真实模式，
#   在这套环境里也【必然失败】—— 因为根本没有 agent。
#   现在补上这一环，处置链路才可能真的通。
#
# ------------------------------------------------------------
# 为什么用 host 网络 + NET_ADMIN
#
# firewall-drop 的实质是往宿主机 iptables 里插规则。
# 如果 agent 在 bridge 网络里，它操作的是容器自己的 netns，
# 封禁【只对容器生效、对真实流量无效】—— 看起来"执行成功"、
# 实际外网照样能连进来。这是最坏的一类"假成功"。
# 所以必须 host 网络，让 agent 看到并操作真实网卡与规则表。
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\n\033[1;33m  [!] $*\033[0m"; }

DIR=/opt/wazuh-agent
mkdir -p "$DIR"

log "1/6 检查前置"
if [ ! -f "$DIR/agent.key" ]; then
  echo "  [X] 找不到 $DIR/agent.key —— 先跑注册步骤"
  exit 1
fi
AGENT_ID=$(cat "$DIR/agent.id" 2>/dev/null || echo "001")
AGENT_KEY=$(cat "$DIR/agent.key")
echo "  agent id  = $AGENT_ID"
echo "  key 长度  = ${#AGENT_KEY}"

log "2/6 写 client.keys（agent 的身份凭证）"
# 格式：<id> <name> <ip> <key>
# API 返回的 key 已经是 client.keys 用的那种 base64 格式，直接用。
printf '%s srv2-agent 127.0.0.1 %s\n' "$AGENT_ID" "$AGENT_KEY" > "$DIR/client.keys"
chmod 640 "$DIR/client.keys"
echo "  已写入（内容含密钥，不打印）"

log "3/6 写 agent 配置"
cat > "$DIR/ossec.conf" <<'CFGEOF'
<!--
  Wazuh agent 配置（服务器 2 本机）
  说明：
    · 连本机的 manager（同机部署，所以是 127.0.0.1）
    · 只保留必要项，其余用镜像默认
    · 日志采集仍由 manager 的 localfile 负责（已在那边配好），
      这里不重复配，避免同一条日志被处理两次、告警翻倍
-->
<ossec_config>
  <client>
    <server>
      <address>127.0.0.1</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu22, ubuntu22.04</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <!-- agent 自身的运行日志（排查用） -->
  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
CFGEOF
ok "已写入"

log "4/6 写 compose 并启动"
cat > "$DIR/docker-compose.yml" <<'YAMLEOF'
services:
  wazuh-agent:
    image: wazuh/wazuh-agent:4.9.2
    container_name: wazuh-agent
    restart: unless-stopped
    # host 网络：firewall-drop 要操作宿主机的 iptables。
    # 用 bridge 的话封禁只作用于容器 netns，外网照样能连 —— 假成功。
    network_mode: host
    environment:
      - WAZUH_MANAGER_SERVER=127.0.0.1
      - WAZUH_MANAGER_PORT=1514
      - WAZUH_REGISTRATION_SERVER=127.0.0.1
      - WAZUH_AGENT_NAME=srv2-agent
      - WAZUH_AGENT_GROUP=default
    volumes:
      - ./client.keys:/var/ossec/etc/client.keys:ro
      - ./ossec.conf:/var/ossec/etc/ossec.conf:ro
    cap_add:
      - NET_ADMIN
      - SYS_PTRACE
    mem_limit: 256m
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "2"
YAMLEOF

cd "$DIR"
# 镜像可能已在本地（wazuh 那三个容器就是用同一批镜像拉的）
if ! docker image inspect wazuh/wazuh-agent:4.9.2 >/dev/null 2>&1; then
  echo "  拉取 agent 镜像..."
  docker pull wazuh/wazuh-agent:4.9.2 2>&1 | tail -3 | sed 's/^/    /'
fi
docker compose up -d 2>&1 | tail -4 | sed 's/^/  /'
sleep 20

log "5/6 验证 agent 是否连上 manager"
API_PW=$(grep '^WAZUH_API_WUI_PASSWORD=' /root/.wazuh-new-creds.txt | cut -d= -f2)
T=$(curl -sk -u "wazuh-wui:${API_PW}" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" 2>/dev/null | sed 's/^Bearer //')
echo "  agent 列表:"
curl -sk -H "Authorization: Bearer $T" "https://127.0.0.1:55000/agents?select=id,name,status,lastKeepAlive" 2>/dev/null \
  | python3 -c "
import json,sys
d=json.load(sys.stdin).get('data',{})
for a in d.get('affected_items',[]):
    print('    id=%-4s %-14s status=%-16s lastSeen=%s' % (a.get('id'), a.get('name'), a.get('status'), (a.get('lastKeepAlive') or '')[:19]))
" 2>&1 | sed 's/^/  /'

echo
echo "  agent 容器状态: $(docker inspect --format '{{.State.Status}}' wazuh-agent 2>/dev/null)"
echo "  agent 日志:"
docker logs wazuh-agent 2>&1 | tail -8 | sed 's/^/    /'

log "6/6 结论"
echo "  agent 状态若是 active -> 处置链路有了'执行的手'"
echo "  仍是 never_connected -> 检查 client.keys 和 1514 连通性"
