#!/usr/bin/env bash
# ============================================================
# B3 步骤 3：在服务器 1 上建立并固化到 Wazuh API 的隧道
# ------------------------------------------------------------
# 为什么不能绑 127.0.0.1：
#   SecAgent 跑在容器里，容器内的 127.0.0.1 是容器自己，
#   够不着宿主机上的监听端口。
#
# 为什么也不能绑 0.0.0.0：
#   那等于把 Wazuh 管理 API 暴露到公网 —— 正是这条隧道要避免的事。
#   而且这个项目的整体检查里有一条断言：
#   「没有业务端口暴露在 0.0.0.0」，绑 0.0.0.0 会自己违反自己。
#
# 采用的方案：绑到【docker 网桥的网关 IP】。
#   容器通过 host.docker.internal（= host-gateway = 网桥网关）访问它，
#   而网桥是内部网络，公网不可达。
#   这样"只有容器能访问、外部访问不到"，正好是我们要的。
#
# 持久化：写成 systemd 服务，带 Restart=always，
#   并且 ServerAliveInterval 保证链路断了能自动重连。
#   手工 nohup 起的隧道会在断线后静默死掉 —— 那会导致
#   SecAgent 在某天悄悄降级回 MOCK，而没人知道。
# ============================================================
set -uo pipefail

KEY=/root/.ssh/tunnel_srv2_ed25519
SRV2=43.143.114.79
UNIT=/etc/systemd/system/secagent-wazuh-tunnel.service

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }

log "1/5 找 docker 网桥网关 IP（隧道要绑这个地址）"
# SecAgent 所在的 compose 网络
# 【不要猜这个 IP】
# 第一版猜的是 compose 网络的网关（172.18.0.1），结果绑上去了、容器却够不着 ——
# 因为 extra_hosts 里的 host-gateway 解析到的是【docker0 默认网桥】的网关
# （172.17.0.1），和 compose 网络的网关不是同一个 IP。
# 表现是容器访问 "No route to host"，SecAgent 直接降级 MOCK。
#
# 正确做法：直接问容器"host.docker.internal 解析成什么"，绑到那个地址。
# 这样两边永远一致，也不依赖我对 docker 网络模型的记忆。
# 【不要猜，也不要信 host-gateway】
#
# 踩过的三个坑，都在这一个 IP 上：
#   1) 猜 compose 网络网关（172.18.0.1）—— 容器报 No route to host
#   2) 用 extra_hosts 的 host-gateway —— 它解析成 docker0 默认网桥
#      （172.17.0.1），而容器在 172.18.0.0/16 上，
#      两个 docker 网络之间【没有路由】—— 还是 No route to host
#   3) 绑到 docker0 网关（172.17.0.1）—— 同上
#
# 真正可用的地址是【容器自己的默认网关】：容器的所有出网流量都经过它，
# 所以一定可达。这里直接从容器里读出来，不依赖任何假设。
GW=$(docker exec secagent sh -c "ip route | awk '/^default/{print \$3}'" 2>/dev/null | head -1)
if [ -z "$GW" ]; then
  # 容器里没有 ip 命令时，用 /proc/net/route 解析
  GW=$(docker exec secagent sh -c "awk '\$2==\"00000000\"{printf \"%d.%d.%d.%d\", strtonum(\"0x\"substr(\$3,7,2)), strtonum(\"0x\"substr(\$3,5,2)), strtonum(\"0x\"substr(\$3,3,2)), strtonum(\"0x\"substr(\$3,1,2))}' /proc/net/route" 2>/dev/null | head -1)
fi
echo "  容器自己的默认网关: ${GW:-没找到}"
[ -n "$GW" ] || { echo "  [X] 拿不到容器网关，无法继续"; exit 1; }

log "2/5 先做一次临时隧道，验证链路真的通"
pkill -f 'secagent-wazuh-tunnel' 2>/dev/null || true
pkill -f "${GW}:55000:127.0.0.1:55000" 2>/dev/null || true
sleep 1
# 【必须重定向】ssh -f 会把连接放到后台，但【仍然持有 stdout/管道】，
# 调用方（PowerShell / 上层脚本）会一直等管道关闭 —— 表现为"卡住"。
# 这个坑在本项目已出现三次（nohup 的 sleep、ssh -f 的测试、这次）。
# 规则：任何 fork 到后台的命令，都要显式 </dev/null >/dev/null 2>&1。
ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes \
    -o ConnectTimeout=10 -f -N -L "${GW}:55000:127.0.0.1:55000" "root@${SRV2}" </dev/null >/dev/null 2>&1
sleep 2

echo "  隧道监听情况:"
ss -tlnp 2>/dev/null | grep 55000 | sed 's/^/    /' || echo "    没有监听"

echo "  通过隧道访问 Wazuh API:"
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://${GW}:55000/" 2>/dev/null)
echo "    HTTP $CODE  （401 = API 活着且要求认证，正是期望值）"

if [ "$CODE" != "401" ] && [ "$CODE" != "200" ]; then
  warn "临时隧道验证没通过，先不写 systemd 单元"
  pkill -f "${GW}:55000:127.0.0.1:55000" 2>/dev/null || true
  exit 1
fi
ok "隧道可用"

echo "  顺便清理这条临时隧道（马上会用 systemd 起正式的）"
pkill -f "${GW}:55000:127.0.0.1:55000" 2>/dev/null || true
sleep 1

log "3/5 写 systemd 服务"
cat > "$UNIT" <<UNITEOF
[Unit]
Description=SecAgent -> Wazuh API SSH tunnel
Documentation=https://github.com/xiaokeqing/SecAgent
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=root
# 各选项的作用：
#   -N            不开远程 shell，只做转发（隧道专用）
#   -T            不要 tty
#   ExitOnForwardFailure  转发没建成就退出，让 systemd 重试
#                         （否则会"连上但没隧道"，看起来是活的、实际不通）
#   ServerAliveInterval   每 30 秒探活，防止链路被中间设备静默断掉
#   ServerAliveCountMax   连续 3 次没响应就断开，交给 Restart 重连
ExecStart=/usr/bin/ssh -NT \\
  -i $KEY \\
  -o BatchMode=yes \\
  -o StrictHostKeyChecking=no \\
  -o ExitOnForwardFailure=yes \\
  -o ServerAliveInterval=30 \\
  -o ServerAliveCountMax=3 \\
  -o ConnectTimeout=15 \\
  -L ${GW}:55000:127.0.0.1:55000 \\
  root@${SRV2}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNITEOF
ok "已写入 $UNIT"

log "4/5 启用并启动"
systemctl daemon-reload
systemctl enable secagent-wazuh-tunnel >/dev/null 2>&1
systemctl restart secagent-wazuh-tunnel
sleep 6

echo "  服务状态: $(systemctl is-active secagent-wazuh-tunnel)"
systemctl status secagent-wazuh-tunnel --no-pager 2>&1 | head -8 | sed 's/^/    /'

log "5/5 验证"
echo "  监听:"
ss -tlnp 2>/dev/null | grep 55000 | sed 's/^/    /' || echo "    没有监听"
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://${GW}:55000/" 2>/dev/null)
echo "  通过隧道访问 Wazuh API: HTTP $CODE"
echo "  监听地址是否只在内网: $(ss -tln | grep 55000 | awk '{print $4}' | head -1)"

echo
echo "  记下网关 IP 供 compose 使用:"
echo "$GW" > /opt/secagent/.wazuh-tunnel-gw
echo "    $GW -> /opt/secagent/.wazuh-tunnel-gw"
echo
ok "隧道已固化（systemd，开机自启 + 断线自动重连）"
echo
echo "  注意：compose 里需要用 host.docker.internal 或者这个网关 IP。"
echo "  网关 IP 可能会在 docker 网络重建后变化 —— 那时候隧道要重新生成。"
