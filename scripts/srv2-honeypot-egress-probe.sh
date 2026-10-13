#!/usr/bin/env bash
# ============================================================
# srv2：蜜罐隔离的「实测」探针（产生运行态证据，不是看配置）
# ------------------------------------------------------------
# 为什么要有它：
#   光看 `iptables -S DOCKER-USER` 只能证明「规则写着 DROP」，
#   不能证明「包真的出不去」。2026-10-14 就是靠这种探针发现的真洞：
#   DOCKER-USER 里 8 条 `--dport ACCEPT` 排在 `-s 172.19.0.0/16 -j DROP` 之前，
#   于是蜜罐对外连 21/23/1433/3306/6379/8080/8443/27017 是【可以出去】的。
#   （当时实测：蜜罐网段连 1.1.1.1:3306 的 SYN 出现在 eth0，连 :443 则没有。）
#
# 它怎么判：不看「连接成功与否」（目标在国外/被墙会干扰判断），
#   而是在 eth0 上抓包，数「每个目的端口有几个 SYN 真的发出去了」：
#     SYN 出现 → 该端口被放行（隔离有洞）
#     SYN 没有 → 被 DROP（隔离有效）
#   再用【默认网桥】上的同一个镜像做对照组，证明「路径本身是通的」。
#
# ------------------------------------------------------------
# 【2026-10-14 收口】退出码改成 fail-closed，并接进 srv2 每日巡检：
#
#   0  隔离有效，而且**这次测量被证明是有效的**（见下面「有效性」）
#   1  发现洞：有端口真的把 SYN 发出去了
#   2  **测试无效** —— 不许静默通过（这一条是关键）
#   3  前置条件不满足（非 root / 拿不到网段 / docker 或 tcpdump 不可用）
#
#   为什么要有 2：这个探针的「通过」是「没抓到 SYN」。而「没抓到」至少有两种原因：
#     (a) 真的被 DROP 了；(b) 探测容器根本没起来、或 tcpdump 没装上/没生效。
#   把 (b) 当成 (a) 就是「没数据=安全」的经典错误（本项目已经吃过这个亏）。
#   所以：
#     · 对照组必须在 eth0 上抓到 SYN（证明「能发出去、且我抓得到」）；
#       对照组抓不到 → 2
#     · 每个探测容器必须打印出它自己的结果行（证明它真跑了）；
#       缺行 → 2
#     · tcpdump 不在 → 3
#   也就是说：**只有「对照组证明测量有效 + 所有蜜罐侧端口 SYN=0」才是 exit 0。**
#
# 【坑】容器里 python3 -c 的字符串必须纯 ASCII。
#   dionaea 镜像的 locale 是 C，argv 里带中文会报
#     UnicodeEncodeError: 'utf-8' codec can't encode ... surrogates not allowed
#   整个探测就静默失效（表现为所有端口都「没抓到 SYN」，假的通过）。
#
# 用法（srv2，root）：bash srv2-honeypot-egress-probe.sh
#   PROBE_CONTROL_IP=x.x.x.x  覆盖对照组目标（测试用）
#   PROBE_IMG / PROBE_PORTS / PROBE_TARGET / PROBE_NET  同理
# ============================================================
set -uo pipefail
IMG=${PROBE_IMG:-dinotools/dionaea:0.11.0}
PORTS=${PROBE_PORTS:-"21 23 445 1433 3306 6379 8080 8443 27017"}
HONEY_NET=${PROBE_NET:-cowrie_honeypot}
TARGET=${PROBE_TARGET:-8.8.8.8}
CONTROL_TARGET_IP=${PROBE_CONTROL_IP:-}

C_OK='\033[1;32m'; C_ERR='\033[1;31m'; C_CY='\033[1;36m'; C_0='\033[0m'
# 【2026-10-14 收口】只有 stdout 是终端时才上色。
#   为什么：这个探针被每日巡检调用时，输出会被塞进通知正文
#   （notify.sh 的 body = $(probe 2>&1)）。带 ANSI 转义的话，
#   飞书里看到的是一堆 [1;31m 乱码（实测就是这么发出去的）。
#   管道/重定向时（rc 判定、日志、通知正文）一律输出纯文本。
if [ ! -t 1 ]; then C_OK=''; C_ERR=''; C_CY=''; C_0=''; fi
CAP=$(mktemp /tmp/egress-probe-cap.XXXXXX)
PROBE_OUT=$(mktemp /tmp/egress-probe-out.XXXXXX)
trap 'rm -f "$CAP" "$PROBE_OUT"' EXIT

die_pre() { echo "[X] $*" >&2; exit 3; }

[ "$(id -u)" = "0" ] || die_pre "需要 root（否则抓不到包、也起不了容器）"
command -v docker  >/dev/null 2>&1 || die_pre "没有 docker"
command -v tcpdump >/dev/null 2>&1 || die_pre "没有 tcpdump —— 无法测量，拒绝给「通过」的结论（fail-closed）"

# 对照组目标：优先取 IPv4（IPv6 地址在 eth0 上抓不到，会得出「对照组也失败」的错误结论）
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
[ -n "$SUBNET" ] || die_pre "拿不到蜜罐网段（容器与网络都问不到）—— 拒绝在不知道查哪的情况下给通过"
echo "  蜜罐网段: $SUBNET"
iptables -S DOCKER-USER | sed 's/^/    /'
DROP_LINE=$(iptables -S DOCKER-USER | grep -n -- "-s $SUBNET -j DROP" | head -1 | cut -d: -f1)
PORT_LINE=$(iptables -S DOCKER-USER | grep -n -- '--dport' | head -1 | cut -d: -f1)
ORDER_BAD=0
if [ -z "$DROP_LINE" ]; then
  echo -e "    ${C_ERR}[X]${C_0} DOCKER-USER 里找不到 $SUBNET 的 DROP 规则"
  ORDER_BAD=1
elif [ -n "$PORT_LINE" ] && [ "$DROP_LINE" -gt "$PORT_LINE" ]; then
  echo -e "    ${C_ERR}[X]${C_0} 端口放行自第 $PORT_LINE 行起、早于 DROP（第 $DROP_LINE 行）→ 顺序错 = 有洞"
  ORDER_BAD=1
else
  echo -e "    ${C_OK}[OK]${C_0} 网段 DROP 在第 $DROP_LINE 行、端口放行自第 ${PORT_LINE:-无} 行起 → DROP 在前，顺序正确"
fi
echo

echo -e "${C_CY}==> 2/4 蜜罐网段容器逐个端口尝试外连（eth0 同时抓包）${C_0}"
timeout 150 tcpdump -nn -i eth0 -l "tcp and (host $TARGET or host $CONTROL_TARGET_IP)" > "$CAP" 2>&1 &
TP=$!
sleep 2
MISSING=0
: > "$PROBE_OUT"
for p in $PORTS; do
  docker run --rm --network "$HONEY_NET" --entrypoint python3 "$IMG" -c "
import socket
try:
    s = socket.create_connection(('$TARGET', $p), 2)
    print('  honeypot-net port $p: CONNECTED (egress ALLOWED)')
    s.close()
except Exception as e:
    print('  honeypot-net port $p:', type(e).__name__)
" >> "$PROBE_OUT" 2>&1
  # 容器必须真的打印了它自己的结果行；否则这次测量不算数（不能把「没跑起来」当「被 DROP」）
  if ! grep -q "honeypot-net port $p:" "$PROBE_OUT"; then
    echo "  honeypot-net port $p: <探测容器没有输出 —— 测量无效>"
    MISSING=$((MISSING+1))
  fi
done
docker run --rm --network bridge --entrypoint python3 "$IMG" -c "
import socket
try:
    s = socket.create_connection(('$CONTROL_TARGET_IP', 443), 4)
    print('  CONTROL bridge port 443: CONNECTED')
    s.close()
except Exception as e:
    print('  CONTROL bridge port 443:', type(e).__name__)
" >> "$PROBE_OUT" 2>&1
grep -q 'CONTROL bridge port 443:' "$PROBE_OUT" || { echo "  CONTROL bridge port 443: <探测容器没有输出 —— 测量无效>"; MISSING=$((MISSING+1)); }
sleep 3
kill $TP 2>/dev/null; wait $TP 2>/dev/null
sed 's/^/  /' "$PROBE_OUT"

echo
echo -e "${C_CY}==> 3/4 抓包统计（eth0 上真正发出的 SYN 数）${C_0}"
HOLE=0; HOLE_PORTS=""
echo "  --- 蜜罐网段 -> $TARGET ---"
for p in $PORTS; do
  n=$(grep -cE "> $TARGET\.$p: Flags \[S" "$CAP" 2>/dev/null || true)
  n=${n:-0}
  if [ "$n" -gt 0 ]; then
    printf "    ${C_ERR}port %-6s SYN=%-4s  <-- egress ALLOWED (hole)${C_0}\n" "$p" "$n"
    HOLE=$((HOLE+1)); HOLE_PORTS="$HOLE_PORTS $p"
  else
    printf "    ${C_OK}port %-6s SYN=%-4s  (dropped)${C_0}\n" "$p" "0"
  fi
done
echo "  --- 对照组（默认网桥）-> $CONTROL_TARGET_IP:443 ---"
NC=$(grep -cE "> $CONTROL_TARGET_IP\.443: Flags \[S" "$CAP" 2>/dev/null || true)
NC=${NC:-0}
echo "    SYN=$NC （必须 >0：证明「包能出去 + 我能抓到」；否则本次测量无效）"
if [ "$NC" -gt 0 ]; then
  grep -E "> $CONTROL_TARGET_IP\.443: Flags \[S" "$CAP" | head -3 | sed 's/^/      /'
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

# ---------- 结论 ----------
echo
echo "==================== 结论 ===================="
if [ "$ORDER_BAD" = "1" ]; then
  echo -e "${C_ERR}[FAIL] DOCKER-USER 规则顺序/存在性不对：蜜罐网段的 egress 兜底 DROP 没排在端口放行之前${C_0}"
  echo "       （这一条即使抓包看起来没事也不能放过：顺序错就是洞）"
  exit 1
fi
if [ "$MISSING" != "0" ]; then
  echo -e "${C_ERR}[INVALID] 有 $MISSING 个探测容器没有产出结果 —— 本次测量无效，拒绝给「通过」（fail-closed）${C_0}"
  echo "       修法：确认 $IMG 可用（docker images | grep dionaea），并确认 docker run 能起容器"
  exit 2
fi
if [ "$NC" -le 0 ]; then
  echo -e "${C_ERR}[INVALID] 对照组在 eth0 上没有抓到任何 SYN —— 无法证明「能出网且抓得到」，本次测量无效${C_0}"
  echo "       可能原因：tcpdump 没生效 / 对照组目标 $CONTROL_TARGET_IP 走了异常路径 / 默认网桥容器起不来"
  echo "       **绝不能**把这种情况读成「隔离住了」（这正是「没抓到=安全」的错误）"
  exit 2
fi
if [ "$HOLE" -eq 0 ]; then
  echo -e "${C_OK}[OK] 隔离有效：蜜罐网段对外 TCP 全部被 DROP（0 个端口可出网）${C_0}"
  echo "     测量有效性：对照组 SYN=$NC（>0，证明测量链是通的）；探测容器输出齐全（0 个缺失）"
  exit 0
fi
echo -e "${C_ERR}[FAIL] 隔离不完整：$HOLE 个端口仍可主动外连 ——$HOLE_PORTS${C_0}"
echo "       修法：确认 DOCKER-USER 里 '-s $SUBNET -j DROP' 排在所有 '--dport ... ACCEPT' 之前；"
echo "             端口放行只能用 -A 追加（绝不能用 -I 1），参见 scripts/srv2-cowrie-egress-lock.sh 的注释"
exit 1
