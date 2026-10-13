#!/usr/bin/env bash
# 限制蜜罐容器的出站流量。
# 幂等：先清理旧规则再重新添加，重复执行不会有副作用。
set -uo pipefail

# 找出蜜罐所在网络的子网（不写死 —— 网络重建后子网可能变）
NET=$(docker inspect cowrie --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null | head -1)
[ -n "$NET" ] || { echo "找不到 cowrie 容器，跳过"; exit 0; }
SUBNET=$(docker network inspect "$NET" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)
[ -n "$SUBNET" ] || { echo "拿不到子网，跳过"; exit 0; }

# 清理旧规则（幂等）
while iptables -C DOCKER-USER -s "$SUBNET" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do
  iptables -D DOCKER-USER -s "$SUBNET" -m state --state ESTABLISHED,RELATED -j ACCEPT
done
while iptables -C DOCKER-USER -s "$SUBNET" -d 127.0.0.11 -j ACCEPT 2>/dev/null; do
  iptables -D DOCKER-USER -s "$SUBNET" -d 127.0.0.11 -j ACCEPT
done
while iptables -C DOCKER-USER -s "$SUBNET" -j DROP 2>/dev/null; do
  iptables -D DOCKER-USER -s "$SUBNET" -j DROP
done

# 重新添加：
#   1) 允许回程（否则连 SSH 握手都发不回去，蜜罐等于死了）
#   2) 允许访问 docker 内置 DNS（否则解析不了）
#   3) 其余出站全部丢弃 —— 不让它当跳板，也不让它被用来对外攻击
# 【注意顺序】这三条用 -I 插到链首，是 DOCKER-USER 里唯一正确的 egress 位置。
#   2026-10-13 的教训：srv2-decoy-ports.sh 用 `-I DOCKER-USER 1` 把 8 条
#   `--dport ACCEPT`（不看来源）插到了第 3 条 DROP 的前面，
#   于是蜜罐主动外连这些端口被放行 —— 洞就是这么来的（2026-10-14 已修正）。
#   以后任何脚本都只能 `-A`（追加）端口放行，绝不能 `-I 1`。
iptables -I DOCKER-USER 1 -s "$SUBNET" -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -I DOCKER-USER 2 -s "$SUBNET" -d 127.0.0.11 -j ACCEPT
iptables -I DOCKER-USER 3 -s "$SUBNET" -j DROP
echo "已对 $SUBNET($NET) 应用出口限制"
