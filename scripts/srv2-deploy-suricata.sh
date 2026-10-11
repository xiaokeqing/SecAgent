#!/usr/bin/env bash
# ============================================================
# C2：部署 Suricata 网络层检测
# ------------------------------------------------------------
# 为什么需要它（它和 Wazuh 的分工）
#
#   Wazuh  看的是【主机层】：日志、文件完整性、合规基线。
#          它知道"有人登录失败了 100 次"，但看不到网络上的包。
#   Suricata 看的是【网络层】：实际流量里的扫描、爆破、
#          C2 通信特征、漏洞利用尝试。
#          它能知道"有人正在用 nmap 扫我的端口"。
#
# 两者是互补的，不是重复的：
#   同一个攻击，主机层看到的是"后果"（登录失败记录），
#   网络层看到的是"行为"（扫描特征、payload 内容）。
#   只有一层的话，攻击者在网络层的动作就是盲区。
#
# 为什么装在服务器 2（蜜罐那台）而不是服务器 1
#   蜜罐是唯一对外开放入站的组件，所以【所有来自互联网的恶意流量
#   都汇聚在这台机器上】。抓包要挂在真正有流量的地方。
#   服务器 1 只跑一个通过隧道对外提供 HTTPS 的应用，
#   网络层没有多大可看的。
#
# ------------------------------------------------------------
# 一个必须讲清楚的取舍：为什么用 host 网络
#
# Suricata 要抓包，就必须看到真实的网卡（eth0）。
# 如果把容器放进 bridge 网络，它只能看到容器自己的虚拟网卡，
# 抓不到宿主机的真实流量 —— 那就白装了。
#
# 所以这里用 network_mode: host。
# 代价是容器不再有网络隔离；但这个容器【只做被动抓包】，
# 不监听任何端口、不主动外连，风险可控。
# 这类"为了能力必须放弃一部分隔离"的取舍要写清楚，
# 而不是默默用 host 模式。
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\n\033[1;33]  [!] $*\033[0m"; }

DIR=/opt/suricata
mkdir -p "$DIR"/{logs,etc,rules}

log "1/6 检查网卡与前提"
echo "  主网卡:"
ip -o link show 2>/dev/null | awk -F': ' '{print "    "$2}' | head -8
IFACE=$(ip route | awk '/^default/{print $5}' | head -1)
echo "  默认出口网卡: ${IFACE:-没找到}"
[ -n "$IFACE" ] || { echo "  [X] 拿不到网卡名"; exit 1; }

echo "  镜像是否已有:"
docker image inspect jasonish/suricata:latest >/dev/null 2>&1 && echo "    已有" || echo "    需要拉取"

log "2/6 拉镜像"
if ! docker image inspect jasonish/suricata:latest >/dev/null 2>&1; then
  docker pull jasonish/suricata:latest 2>&1 | tail -3 | sed 's/^/  /' || {
    warn "直连拉取失败，试腾讯云加速器"
    docker pull mirror.ccs.tencentyun.com/jasonish/suricata:latest 2>&1 | tail -3 | sed 's/^/  /' \
      && docker tag mirror.ccs.tencentyun.com/jasonish/suricata:latest jasonish/suricata:latest \
      && ok "已从加速器拉取"
  }
fi
docker images jasonish/suricata --format '  {{.Repository}}:{{.Tag}}  {{.Size}}'

log "3/6 下载规则集（ET Open，开源版）"
# ET Open 是 Suricata 社区维护的开源规则集，覆盖常见的扫描/爆破/利用特征。
# 用 suricata-update 从官方源拉取。
if [ -f "$DIR/rules/suricata.rules" ]; then
  echo "  规则已存在: $(wc -l < "$DIR/rules/suricata.rules") 行"
else
  docker run --rm \
    -v "$DIR/rules:/var/lib/suricata/rules" \
    jasonish/suricata:latest \
    suricata-update 2>&1 | tail -8 | sed 's/^/    /'
  [ -f "$DIR/rules/suricata.rules" ] && ok "规则已下载: $(wc -l < "$DIR/rules/suricata.rules") 行" \
    || warn "规则下载失败（没有规则 Suricata 也跑，只是检测能力有限）"
fi

log "4/6 写配置"
cat > "$DIR/etc/suricata.yaml" <<YAMLEOF
%YAML 1.1
---
# Suricata 配置（精简版，只保留本项目需要的部分）
# 不复制官方完整配置：那个上千行，改起来容易出错，
# 而且镜像升级后会不一致。只写要用到的。

vars:
  address-groups:
    HOME_NET: "[$(ip -4 addr show $IFACE 2>/dev/null | awk '/inet /{print $2}' | head -1 | cut -d/ -f1)]"
    EXTERNAL_NET: "!\$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SSH_PORTS: "22,2222"     # 2222 是蜜罐 —— 专门盯它

default-log-dir: /var/log/suricata/

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            # 每条告警带上原始 payload（用于研判和取证）
            payload: yes
            payload-printable: yes
            packet: yes
            metadata: yes
        - http:
            extended: yes
        - dns
        - tls:
            extended: yes
        - flow
        - ssh
  - fast:
      enabled: yes
      filename: fast.log

# 抓包接口
af-packet:
  - interface: $IFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

# 规则文件
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

# 应用层协议解析
app-layer:
  protocols:
    tls:
      enabled: yes
    http:
      enabled: yes
    ssh:
      enabled: yes
    dns:
      enabled: yes

# 日志轮转：蜜罐会吸引大量流量，日志会涨得比较快。
# 不限制的话磁盘会被吃满 —— 而磁盘满是"服务突然全挂"的常见原因。
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: no
    - file:
        enabled: yes
        level: info
        filename: suricata.log
YAMLEOF
ok "配置已写入"

log "5/6 启动 Suricata"
cat > "$DIR/docker-compose.yml" <<'YAMLEOF'
services:
  suricata:
    image: jasonish/suricata:latest
    container_name: suricata
    restart: unless-stopped
    # host 网络：必须看到真实网卡才能抓到宿主机流量。
    # 这个容器只被动抓包、不监听端口、不主动外连。
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_NICE
    volumes:
      - ./etc/suricata.yaml:/etc/suricata/suricata.yaml:ro
      - ./rules:/var/lib/suricata/rules
      - ./logs:/var/log/suricata
    command: -i ${IFACE:-eth0} -c /etc/suricata/suricata.yaml --netmap=no
    mem_limit: 512m
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
YAMLEOF

cd "$DIR"
# 把网卡名传进去
IFACE="$IFACE" docker compose up -d 2>&1 | tail -5 | sed 's/^/  /'
sleep 12

echo "  容器状态:"
docker ps --format '  {{.Names}}  {{.Status}}' | grep suricata || warn "suricata 没在跑"
echo "  日志尾部:"
docker logs suricata 2>&1 | tail -10 | sed 's/^/    /'

log "6/6 验证"
echo "  1) 规则加载数量:"
docker logs suricata 2>&1 | grep -iE 'rules successfully loaded|loading rule' | tail -2 | sed 's/^/    /'
echo "     eve.json 是否生成:"
ls -la "$DIR/logs/eve.json" 2>/dev/null | sed 's/^/    /' || warn "eve.json 还没生成"

echo
echo "  2) 主动制造一点流量，看它抓不抓得到（用蜜罐端口触发 SSH 检测）"
BEFORE=$(wc -l < "$DIR/logs/eve.json" 2>/dev/null || echo 0)
timeout 10 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=6 -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o NumberOfPasswordPrompts=1 -p 2222 root@127.0.0.1 x >/dev/null 2>&1
sleep 6
AFTER=$(wc -l < "$DIR/logs/eve.json" 2>/dev/null || echo 0)
echo "    eve.json 行数: $BEFORE -> $AFTER"
if [ "$AFTER" -gt "$BEFORE" ]; then
  ok "抓到了流量"
  echo "    新增事件类型统计:"
  tail -n $((AFTER-BEFORE)) "$DIR/logs/eve.json" 2>/dev/null \
    | python3 -c "
import json,sys,collections
c=collections.Counter()
for ln in sys.stdin:
    try: c[json.loads(ln).get('event_type','?')]+=1
    except Exception: pass
for k,v in c.most_common(): print('      %-12s x%d'%(k,v))
" 2>&1 | sed 's/^/  /'
else
  warn "没抓到新事件"
fi

echo
echo "  3) 接进 Wazuh:"
CONF=/opt/wazuh/config/wazuh_cluster/wazuh_manager.conf
if grep -q 'eve.json' "$CONF" 2>/dev/null; then
  echo "    已配置"
else
  BK="$CONF.bak-suricata-$(date +%Y%m%d-%H%M%S)"
  cp "$CONF" "$BK"
  python3 - "$CONF" <<'PYEOF'
import sys
path = sys.argv[1]
src = open(path, encoding='utf-8').read()
if 'eve.json' in src:
    print("  已存在"); sys.exit(0)
block = """
  <!-- ===== Suricata 网络层告警 ===== -->
  <!-- 和 Wazuh 主机层日志互补：一个看"后果"，一个看"网络行为"。
       这里用 json 格式读 eve.json，Wazuh 能直接解析其中的 alert 字段。 -->
  <localfile>
    <log_format>json</log_format>
    <location>/opt/suricata/logs/eve.json</location>
  </localfile>

"""
idx = src.rfind('</ossec_config>')
open(path,'w',encoding='utf-8').write(src[:idx] + block + src[idx:])
print("  已追加 Suricata localfile")
PYEOF
  if python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parseString('<__root__>'+open(sys.argv[1]).read()+'</__root__>')" "$CONF" 2>/dev/null; then
    docker restart wazuh.manager >/dev/null 2>&1
    for i in $(seq 1 24); do
      sleep 5
      C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 https://127.0.0.1:55000/ 2>/dev/null)
      [ "$C" = "401" ] && { echo "    manager 就绪"; break; }
    done
  else
    warn "XML 有问题，回滚"; cp "$BK" "$CONF"
  fi
fi

echo
ok "C2 完成"
echo
echo "  两层检测的分工:"
echo "    Wazuh（主机层）  ：登录失败、文件改动、合规基线"
echo "    Suricata（网络层）：扫描特征、payload、C2 通信"
echo
echo "  注意：Suricata 抓包只针对【经过本机网卡】的流量。"
echo "        所以它主要看得见蜜罐（2222）和真实 SSH（22）上的攻击行为。"
