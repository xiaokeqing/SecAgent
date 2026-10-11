#!/usr/bin/env bash
# ============================================================
# C1 补充：修 Cowrie 日志权限 + 加出口限制 + 接进 Wazuh
# ------------------------------------------------------------
# 要修的三件事：
#
# 1) 日志权限
#    Cowrie 报 builtins.PermissionError: 'var/log/cowrie/audit.log'
#    原因和 SecAgent 数据目录那次【完全一样】：
#    宿主机上的挂载目录属主是 root，而容器里以非 root 用户运行。
#
#    之所以值得单独强调：这个故障的表现是"蜜罐在跑、端口在听、
#    连上去也有反应"，但【日志是空的】——
#    也就是说蜜罐完全没有在工作。如果没有去翻日志，
#    会以为它在正常吸引攻击者，实际上什么记录都没有。
#    这和"审计写失败但 API 返回 success"是同一个病：
#    【失败只发生在日志里，而日志本身没人看】。
#
# 2) 出口限制
#    蜜罐被攻破是它的工作，但不能让它成为攻击者进入内网的跳板，
#    也不能被用来对外发起攻击（那样我们自己就成了攻击源）。
#    Cowrie 本身不真正执行命令，这里再叠一层网络限制。
#
# 3) 接进 Wazuh
#    Cowrie 的日志是结构化 JSON，Wazuh 自带 Cowrie 解码器，
#    配上 localfile 就能自动出告警。
#    这样"蜜罐被攻击"会变成 Wazuh 里的真实安全告警，
#    再流到 SecAgent —— 真实数据链路就通了。
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\n\033[1;33m  [!] $*\033[0m"; }

DIR=/opt/cowrie
cd "$DIR" || exit 1

log "1/5 查容器里 Cowrie 以哪个用户运行"
CID=$(docker inspect --format '{{.Id}}' cowrie 2>/dev/null)
echo "  容器 ID: ${CID:0:12}"
# 这个镜像很精简，没有 sh，所以用宿主机侧的 inspect 拿用户
U=$(docker inspect cowrie --format '{{.Config.User}}' 2>/dev/null)
echo "  Config.User = ${U:-（未设置，用镜像默认）}"
# 从镜像元数据里找
IMGUSER=$(docker image inspect cowrie/cowrie:latest --format '{{.Config.User}}' 2>/dev/null)
echo "  镜像 User   = ${IMGUSER:-（未设置）}"

log "2/5 修日志目录权限"
echo "  修改前:"
ls -ld "$DIR/logs" 2>/dev/null | sed 's/^/    /'
ls -la "$DIR/logs" 2>/dev/null | head -5 | sed 's/^/    /'

# Cowrie 官方镜像里用的是 cowrie 用户，uid 通常是 999。
# 这里不硬编码猜测，而是从容器里实际跑着的进程拿 uid ——
# 用宿主机侧的方式（镜像没有 sh，进不去）。
RUNUID=$(docker top cowrie 2>/dev/null | awk 'NR>1 {print $1}' | sort -u | head -1)
echo "  容器进程实际 uid = ${RUNUID:-未知}"

TARGET_UID="${RUNUID:-999}"
TARGET_GID="${RUNUID:-999}"
chown -R "$TARGET_UID:$TARGET_GID" "$DIR/logs" "$DIR/etc" 2>/dev/null
chmod 750 "$DIR/logs" 2>/dev/null

echo "  修改后:"
ls -ld "$DIR/logs" 2>/dev/null | sed 's/^/    /'

log "3/5 重启蜜罐并验证日志真的能写"
docker compose restart 2>&1 | tail -3 | sed 's/^/  /'
sleep 10

echo "  重启后还有没有权限错误:"
ERRC=$(docker logs cowrie 2>&1 | grep -c 'PermissionError\|Permission denied')
if [ "$ERRC" -eq 0 ]; then
  ok "没有权限错误"
else
  warn "仍有 $ERRC 处权限错误"
  docker logs cowrie 2>&1 | grep 'Permission' | tail -3 | sed 's/^/    /'
fi

echo
echo "  日志文件:"
ls -la "$DIR/logs" 2>/dev/null | sed 's/^/    /'

log "4/5 加出口限制（不让蜜罐成为跳板）"
# 思路：蜜罐允许对外发起连接会带来两类风险
#   a) 攻击者用它当跳板探测内网
#   b) 我们被当成攻击源（对第三方发起攻击）
# 这里用 DOCKER-USER 链约束它的出站：
#   允许回到已建立的连接（否则 SSH 响应都发不出去）
#   允许访问宿主机 DNS（否则解析都做不了）
#   其余出站丢弃
#
# 注意：Cowrie 是被动服务，正常情况下【不需要】主动外连，
# 所以这个限制对功能没有影响。
NETNAME=$(docker inspect cowrie --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null | head -1)
SUBNET=$(docker network inspect "$NETNAME" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)
echo "  蜜罐网络: $NETNAME  子网: $SUBNET"

if [ -n "$SUBNET" ]; then
  # 幂等：先删掉旧规则
  while iptables -C DOCKER-USER -s "$SUBNET" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do
    iptables -D DOCKER-USER -s "$SUBNET" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
  done
  while iptables -C DOCKER-USER -s "$SUBNET" -d 127.0.0.11 -j ACCEPT 2>/dev/null; do
    iptables -D DOCKER-USER -s "$SUBNET" -d 127.0.0.11 -j ACCEPT 2>/dev/null
  done
  while iptables -C DOCKER-USER -s "$SUBNET" -j DROP 2>/dev/null; do
    iptables -D DOCKER-USER -s "$SUBNET" -j DROP 2>/dev/null
  done
  # 按顺序插入（插到最前面会让顺序反过来，所以用 -I 指定位置）
  iptables -I DOCKER-USER 1 -s "$SUBNET" -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -I DOCKER-USER 2 -s "$SUBNET" -d 127.0.0.11 -j ACCEPT
  iptables -I DOCKER-USER 3 -s "$SUBNET" -j DROP
  ok "已在 DOCKER-USER 链上限制 $SUBNET 的出站"
  echo "  当前 DOCKER-USER 链:"
  iptables -L DOCKER-USER -n --line-numbers 2>/dev/null | head -8 | sed 's/^/    /'
  echo
  warn "注意：iptables 规则重启后会丢失。如果这个限制要长期生效，"
  echo "      需要写进 systemd 或 docker 的启动脚本。当前先记在这里。"
else
  warn "拿不到蜜罐子网，跳过出口限制"
fi

log "5/5 把 Cowrie 日志接进 Wazuh"
CONF=/opt/wazuh/config/wazuh_cluster/wazuh_manager.conf
BK="$CONF.bak-cowrie-$(date +%Y%m%d-%H%M%S)"

if grep -q 'cowrie.json' "$CONF" 2>/dev/null; then
  warn "已经配过 Cowrie 日志，跳过"
else
  cp "$CONF" "$BK"
  echo "  已备份到 $BK"
  python3 - "$CONF" "$DIR/logs/cowrie.json" <<'PYEOF'
import sys
path, logfile = sys.argv[1], sys.argv[2]
src = open(path, encoding='utf-8').read()
if 'cowrie' in src:
    print("  已存在，未修改"); sys.exit(0)
block = """
  <!-- ===== 蜜罐日志（Cowrie）===== -->
  <!-- Cowrie 输出的是结构化 JSON，Wazuh 自带 cowrie 解码器，
       所以配上 localfile 就会自动出告警。
       这个文件把"有人在攻击蜜罐"变成 Wazuh 里的真实安全告警，
       再流向 SecAgent —— 真实数据链路就是这样打通的。 -->
  <localfile>
    <log_format>json</log_format>
    <location>%s</location>
  </localfile>

""" % logfile
idx = src.rfind('</ossec_config>')
open(path, 'w', encoding='utf-8').write(src[:idx] + block + src[idx:])
print("  已追加 Cowrie localfile")
PYEOF
  [ $? -eq 0 ] || { warn "追加失败，回滚"; cp "$BK" "$CONF"; }

  # 校验 + 重启
  if python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parseString('<__root__>'+open(sys.argv[1]).read()+'</__root__>')" "$CONF" 2>/dev/null; then
    ok "XML 良构，重启 manager"
    docker restart wazuh.manager >/dev/null 2>&1
    for i in $(seq 1 24); do
      sleep 5
      C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 https://127.0.0.1:55000/ 2>/dev/null)
      [ "$C" = "401" ] && { echo "    manager 就绪（第 $((i*5)) 秒）"; break; }
    done
  else
    warn "XML 有问题，回滚"
    cp "$BK" "$CONF"
  fi
fi

echo
echo "===== 汇总 ====="
echo "  蜜罐状态: $(docker ps --format '{{.Names}} {{.Status}}' | grep cowrie || echo '不在跑')"
echo "  日志文件: $(ls -la $DIR/logs/*.json 2>/dev/null | awk '{print $5" bytes  "$9}' | tr '\n' ' ')"
echo "  Wazuh 是否配了 cowrie: $(grep -c cowrie.json $CONF 2>/dev/null)"
