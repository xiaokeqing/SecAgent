#!/usr/bin/env bash
# ============================================================
# srv2：蜜罐隔离的"实测"探针（产生运行态证据，不是看配置）
# ------------------------------------------------------------
# 为什么要有它：
#   光看 `iptables -S DOCKER-USER` 只能证明"规则写着 DROP"，
#   不能证明"包真的出不去"。2026-10-14 就是靠这种探针发现的真洞：
#   DOCKER-USER 里 8 条 `--dport ACCEPT` 排在 `-s 172.19.0.0/16 -j DROP` 之前，
#   于是蜜罐对外连 21/23/1433/3306/6379/8080/8443/27017 是【可以出去】的。
#   （当时实测：蜜罐网段连 1.1.1.1:3306 的 SYN 出现在 eth0，连 :443 则没有。）
#
# 它怎么判：不看"连接成功与否"（目标在国外/被墙会干扰判断），
#   而是在 eth0 上抓包，数"每个目的端口有几个 SYN 真的发出去了"：
#     SYN 出现 → 该端口被放行（隔离有洞）
#     SYN 没有 → 被 DROP（隔离有效）
#   再用【默认网桥】上的同一个镜像做对照组，证明"路径本身是通的"。
#
# 【坑】容器里 python3 -c 的字符串必须纯 ASCII。
#   dionaea 镜像的 locale 是 C，argv 里带中文会报
#     UnicodeEncodeError: 'utf-8' codec can't encode ... surrogates not allowed
#   整个探测就静默失效（表现为所有端口都"没抓到 SYN"，假的通过）。
#
# 用法（srv2，root）：bash srv2-honeypot-egress-probe.sh
# ============================================================
set -uo pipefail
IMG=${PROBE_IMG:-dinotools/dionaea:0.11.0}
PORTS=${PROBE_PORTS:-"21 23 445 1433 3306 6379 8080 8443 27017"}
HONEY_NET=cowrie_honeypot
TARGET=${PROBE_TARGET:-8.8.8.8}
CONTROL_TARGET_IP=${PROBE_CONTROL_IP:-}

C_OK='\033[1;32m'; C_ERR='\033[1;31m'; C_CY='\033[1;36m'; C_0='\033[0m'
CAP=/tmp/egress-probe-cap.txt

[ "$(id -u)" = "0" ] || { echo "需要 root"; exit 1; }

# 对照组目标：优先取 IPv4（IPv6 地址在 eth0 上抓不到，会得出"对照组也失败"的错误结论）
if [ -z "$CONTROL_TARGET_IP" ]; then
  CONTROL_TARGET_IP=$(getent ahostsv4 registry-1.docker.io 2>/dev/null | awk '{print $1}' | head -1)
fi
[ -n "$CONTROL_TARGET_IP" ] || CONTROL_TARGET_IP=223.5.5.5

echo -e "${C_CY}==> 隔离实测探针${C_0}"
echo "  蜜罐网络 : $HONEY_NET"
echo "  探测目标 : $TARGET:{$PORTS}"
echo "  对照目标 : $CONTROL_TARGET_IP:443（默认网桥，应能出网）"
echo

echo -e "${C_CY}==> 1/4 DOCKER-USER 规则原文与顺序判定${C_0}"
NET=$(docker inspect cowrie --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null | head -1)
SUBNET=$(docker network inspect "${NET:-$HONEY_NET}" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)
SUBNET=${SUBNET:-172.19.0.0/16}
echo "  蜜罐网段: $SUBNET"
iptables -S DOCKER-USER | sed 's/^/    /'
DROP_LINE=$(iptables -S DOCKER-USER | grep -n -- "-s $SUBNET -j DROP" | head -1 | cut -d: -f1)
PORT_LINE=$(iptables -S DOCKER-USER | grep -n -- '--dport' | head -1 | cut -d: -f1)
if [ -n "$DROP_LINE" ] && [ -n "$PORT_LINE" ] && [ "$DROP_LINE" -lt "$PORT_LINE" ]; then
  echo -e "    ${C_OK}[OK]${C_0} 网段 DROP 在第 $DROP_LINE 行、端口放行从第 $PORT_LINE 行起 → DROP 在前，顺序正确"
else
  echo -e "    ${C_ERR}[X]${C_0} 网段 DROP 在第 ${DROP_LINE:-?} 行、端口放行从第 ${PORT_LINE:-?} 行起 → 放行在 DROP 之前 = **有洞**"
fi
echo

echo -e "${C_CY}==> 2/4 蜜罐网段容器逐个端口尝试外连（eth0 同时抓包）${C_0}"
rm -f "$CAP"
timeout 120 tcpdump -nn -i eth0 -l "tcp and (host $TARGET or host $CONTROL_TARGET_IP)" > "$CAP" 2>&1 &
TP=$!
sleep 2
for p in $PORTS; do
  docker run --rm --network "$HONEY_NET" --entrypoint python3 "$IMG" -c "
import socket
try:
    s = socket.create_connection(('$TARGET', $p), 2)
    print('  honeypot-net port $p: CONNECTED (egress ALLOWED)')
    s.close()
except Exception as e:
    print('  honeypot-net port $p:', type(e).__name__)
" 2>&1 | sed 's/^/  /'
done
docker run --rm --network bridge --entrypoint python3 "$IMG" -c "
import socket
try:
    s = socket.create_connection(('$CONTROL_TARGET_IP', 443), 4)
    print('  CONTROL bridge port 443: CONNECTED')
    s.close()
except Exception as e:
    print('  CONTROL bridge port 443:', type(e).__name__)
" 2>&1 | sed 's/^/  /'
sleep 3
kill $TP 2>/dev/null; wait $TP 2>/dev/null

echo
echo -e "${C_CY}==> 3/4 抓包统计（eth0 上真正发出的 SYN 数）${C_0}"
echo "  --- 蜜罐网段 -> $TARGET ---"
HOLE=0
for p in $PORTS; do
  n=$(grep -cE "> $TARGET\.$p: Flags \[S" "$CAP" 2>/dev/null || true)
  n=${n:-0}
  if [ "$n" -gt 0 ]; then
    printf "    ${C_ERR}port %-6s SYN=%-4s  <-- egress ALLOWED (hole)${C_0}\n" "$p" "$n"; HOLE=$((HOLE+1))
  else
    printf "    ${C_OK}port %-6s SYN=%-4s  (dropped)${C_0}\n" "$p" "0"
  fi
done
echo "  --- 对照组（默认网桥）-> $CONTROL_TARGET_IP:443 ---"
NC=$(grep -cE "> $CONTROL_TARGET_IP\.443: Flags \[S" "$CAP" 2>/dev/null || true)
echo "    SYN=$NC （>0 = 同镜像在非隔离网络能出网，说明上面的 0 是隔离造成的，不是路径不通）"
echo "  --- 抓包原文 ---"
sed 's/^/    /' "$CAP" | head -30
echo
if [ "$HOLE" -eq 0 ]; then
  echo -e "  ${C_OK}结论：蜜罐网段对外 TCP 全部被 DROP（$HOLE 个端口可出网）${C_0}"
else
  echo -e "  ${C_ERR}结论：有 $HOLE 个端口仍可主动外连 —— 隔离不完整${C_0}"
fi

echo
echo -e "${C_CY}==> 4/4 蜜罐网段容器的 DNS（第 2 条规则故意放行 127.0.0.11）${C_0}"
docker run --rm --network "$HONEY_NET" --entrypoint python3 "$IMG" -c "
import socket
try:
    print('  DNS lookup github.com ->', socket.gethostbyname('github.com'))
except Exception as e:
    print('  DNS lookup FAILED:', type(e).__name__)
" 2>&1 | sed 's/^/  /'
echo "  说明：DNS 放行是有意的（蜜罐要做反向解析），所以「DNS 通、TCP 不通」才是预期状态。"
