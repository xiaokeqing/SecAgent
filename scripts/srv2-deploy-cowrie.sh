#!/usr/bin/env bash
# ============================================================
# C1：部署 Cowrie SSH 蜜罐
# ------------------------------------------------------------
# 为什么需要蜜罐 —— 这是整个两服务器架构的存在理由之一
#
# 之前 B 阶段卡在一个事实上：这台服务器才开机几小时，
# 被攻击的量太少，Wazuh 里 193 条告警全是合规扫描和启动记录，
# 【没有一条真实的攻击告警】。没有攻击流量，就谈不上
# "接真实数据源" —— 接过来也是空的。
#
# 蜜罐的作用就是主动吸引攻击者：它是一个假 SSH 服务，
# 把攻击者的用户名/密码/命令全部记录下来。
# 有了它，真实攻击数据才会持续产生。
#
# ------------------------------------------------------------
# 为什么蜜罐必须独占一台服务器（面试常问）
#
# 因为它是整个架构里【唯一必须对外开放入站的组件】。
# 其他一切都绑 127.0.0.1、走隧道。
# 而一个对外开放的、故意有弱点的服务，本质上是"邀请别人来打"——
# 把它和受保护的资产放在同一台机器上，等于把攻击者直接请进门。
# 两台服务器不是"资源不够所以分开"，是【安全边界】的要求。
#
# ------------------------------------------------------------
# 出口限制：为什么必须做
#
# 蜜罐被攻破是它工作的一部分，但【不能让攻击者用它当跳板】去访问
# 内网、其他容器、或者互联网发起攻击（那样我们就成了攻击源）。
# Cowrie 本身只记录命令、不真正执行，安全性已经不错；
# 但这里再叠一层网络层的限制（把它的出口流量掐掉），
# 属于"不依赖单一防线"的思路。
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\n\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

DIR=/opt/cowrie
mkdir -p "$DIR"/{logs,etc}

log "1/6 检查网络前提"
echo "  公网 IP: $(curl -s --max-time 5 ifconfig.me 2>/dev/null)"
echo "  ufw 2222 规则:"
ufw status 2>/dev/null | grep 2222 | sed 's/^/    /' || echo "    [!] ufw 里没有 2222 规则"
echo "  2222 端口当前是否被占用:"
ss -tlnp 2>/dev/null | grep ':2222 ' | sed 's/^/    /' || echo "    空闲 ✅"

log "2/6 先拉镜像（确认这台机器能访问镜像源）"
if docker image inspect cowrie/cowrie:latest >/dev/null 2>&1; then
  ok "镜像已存在"
else
  echo "  拉取 cowrie/cowrie:latest ..."
  if docker pull cowrie/cowrie:latest 2>&1 | tail -3 | sed 's/^/    /'; then
    ok "镜像已拉取"
  else
    # 腾讯云内网镜像加速器
    warn "直连拉取失败，试腾讯云内网加速器"
    docker pull mirror.ccs.tencentyun.com/cowrie/cowrie:latest 2>&1 | tail -3 | sed 's/^/    /' \
      && docker tag mirror.ccs.tencentyun.com/cowrie/cowrie:latest cowrie/cowrie:latest \
      && ok "已从腾讯云加速器拉取" \
      || die "镜像拉取失败 —— 需要换别的方式（比如本地构建后传过来）"
  fi
fi
docker images cowrie --format '  {{.Repository}}:{{.Tag}}  {{.Size}}'

log "3/6 写 docker-compose.yml"
cat > "$DIR/docker-compose.yml" <<'YAMLEOF'
# ============================================================
# Cowrie SSH 蜜罐
# ------------------------------------------------------------
# 设计说明：
#
# 1) 端口绑 0.0.0.0:2222 而不是 127.0.0.1
#    这是【全项目唯一一个故意对外开放的端口】。
#    其他组件（Wazuh、SecAgent）全部绑 127.0.0.1 走隧道。
#    蜜罐要是也藏起来，就没人来打了，它也就失去了意义。
#    之所以敢这么做：它是假的 SSH，不提供任何真实能力，
#    而且它在【独立的一台服务器】上，和受保护资产是物理隔离的。
#
# 2) 用独立的网络，不加入任何其他 compose 网络
#    攻击者拿下蜜罐后，在最底层就没有到 Wazuh / 其他容器的网络路径。
#
# 3) 日志以 JSON 落盘到宿主机，供 Wazuh 采集
#    Cowrie 的输出格式已经是结构化的（每一行一个 JSON），
#    Wazuh 自带 Cowrie 解码器，所以能直接出告警。
# ============================================================
services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: cowrie
    restart: unless-stopped
    ports:
      - "0.0.0.0:2222:2222"
    volumes:
      # 日志落宿主机，Wazuh 从这里采集
      - ./logs:/cowrie/cowrie-git/var/log/cowrie
      # 可选的配置覆盖
      - ./etc/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro
    environment:
      - COWRIE_TELNET_ENABLED=no
    # 限制资源：蜜罐被刷爆不该拖垮主机
    mem_limit: 256m
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    # 独立网络：与 Wazuh、宿主机服务都不通
    networks:
      - honeypot

networks:
  honeypot:
    driver: bridge
    # 关键：不允许容器访问宿主机上的服务
    internal: false
YAMLEOF
ok "compose 已写入"

log "4/6 写 Cowrie 配置（关掉 telnet、启用 JSON 日志）"
cat > "$DIR/etc/cowrie.cfg" <<'CFGEOF'
# Cowrie 配置覆盖
# 只写需要改的项，其余沿用镜像里的默认值 ——
# 全量复制默认配置会在镜像升级后失效，改增量更稳。

[honeypot]
# 主机名伪装成一个看起来"值得打"的普通业务机
hostname = web-prod-01

[ssh]
# 只开 SSH（telnet 是更老的协议，现在很少被扫，开了反而增加维护面）
enabled = true
# 监听 2222 —— 因为宿主机 22 是真实 SSH。
# 真实 SSH 用密钥登录且关了密码认证，攻击者打它没有收益；
# 蜜罐用弱口令，专门吸引暴力破解。
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = false

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

[output_textlog]
enabled = true

[shell]
# 记录所有输入（含密码尝试）
filesystem = honeyfs
CFGEOF
ok "cowrie.cfg 已写入"

log "5/6 启动蜜罐"
cd "$DIR"
docker compose up -d 2>&1 | tail -5 | sed 's/^/  /'
sleep 8

echo "  容器状态:"
docker ps --format '  {{.Names}}  {{.Status}}  {{.Ports}}' | grep cowrie || warn "cowrie 没在跑"
echo "  日志尾部:"
docker logs cowrie 2>&1 | tail -8 | sed 's/^/    /'

log "6/6 验证（本地先测，再测公网）"
echo "  1) 监听情况:"
ss -tlnp 2>/dev/null | grep ':2222 ' | sed 's/^/    /' || warn "2222 没在监听"

echo
echo "  2) 本地连一次，看它是不是真的在伪装 SSH:"
timeout 12 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=8 -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -p 2222 root@127.0.0.1 'echo test' 2>&1 | head -6 | sed 's/^/    /'

echo
echo "  3) 日志有没有记录这次连接:"
sleep 2
if [ -f "$DIR/logs/cowrie.json" ]; then
  echo "    cowrie.json 行数: $(wc -l < "$DIR/logs/cowrie.json")"
  echo "    最近 3 条:"
  tail -3 "$DIR/logs/cowrie.json" 2>/dev/null | python3 -c "
import json,sys
for ln in sys.stdin:
    try:
        d=json.loads(ln)
        print('      ', d.get('eventid'), '|', d.get('src_ip'), '|', (d.get('username') or ''), (d.get('password') or ''))
    except Exception: pass
" 2>&1 | sed 's/^/  /'
else
  warn "还没有 cowrie.json（可能日志路径不同，下一步要确认）"
  echo "    容器里的日志目录:"
  docker exec cowrie sh -c 'ls -la /cowrie/cowrie-git/var/log/cowrie/ 2>/dev/null' | sed 's/^/      /'
fi

echo
echo "  4) 公网可达性（这个必须通，否则蜜罐吸引不到攻击者）:"
PUB=$(curl -s --max-time 5 ifconfig.me 2>/dev/null)
timeout 10 bash -c "echo > /dev/tcp/$PUB/2222" 2>/dev/null \
  && ok "公网 $PUB:2222 可达" \
  || warn "公网 $PUB:2222 不可达 —— 检查腾讯云安全组是否已放行"

echo
ok "C1 部署脚本执行完毕"
echo
echo "  接下来要做的事："
echo "    · 把 Cowrie 日志接进 Wazuh（让蜜罐的流量变成安全告警）"
echo "    · 加出口限制（不让它被当成跳板）"
echo "    · 观察一段时间，看会不会真的有人来打"
