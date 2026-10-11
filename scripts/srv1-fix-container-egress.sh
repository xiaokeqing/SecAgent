#!/usr/bin/env bash
# ============================================================
# 修复：让 docker 容器能出网（firewalld 与 docker 的经典冲突）
# ------------------------------------------------------------
# 症状：
#   宿主机出网正常（HTTP 200）
#   容器出网全挂（DNS 解析失败、纯 IP 也连不通）
#   宿主机抓包什么都没抓到（容器的包根本没出去）
#   nat 表里其实【有】MASQUERADE 规则
#
# 根因：
#   firewalld 的 public zone 只挂了 eth0，且 forward/masquerade 都是 no。
#   firewalld 会在 filter 表里插入自己的规则，把 docker 网桥的流量挡在
#   FORWARD 之前 —— 于是 nat 表的 MASQUERADE 规则形同虚设，
#   容器发出的包在第一跳就被丢掉。
#
# 【这个问题比它看起来严重得多】
#   容器出不了网 = SecAgent 调不到 DashScope 大模型
#   = 线上所有 AI 功能（对话、研判、RAG 生成）实际上都是坏的。
#   之前的演示之所以"看着正常"，是因为靶场是纯正则规则、不调模型；
#   而 KB 是启动时预索引好的，也不需要出网。
#   所以这个故障一直存在，却没有被任何检查发现。
#
#   这次的教训：**"服务健康"不等于"功能可用"**。
#   健康接口只能证明进程活着、向量库在内存里，
#   证明不了它能不能真正调用外部依赖。
#
# 修法：把 docker 的网络放进 trusted zone，并开启 masquerade。
#   这是 docker + firewalld 共存的标准做法。
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\n\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

log "1/6 修复前状态（留证）"
echo "  firewalld 活动 zone:"
firewall-cmd --get-active-zones 2>/dev/null | sed 's/^/    /'
echo "  public zone 的 forward/masquerade:"
echo "    forward=$(firewall-cmd --zone=public --query-forward 2>/dev/null)  masquerade=$(firewall-cmd --zone=public --query-masquerade 2>/dev/null)"
echo "  docker 网络:"
docker network ls --format '    {{.Name}}  {{.Driver}}  {{.Scope}}' 2>/dev/null

log "2/6 把 docker 的网络与网桥放进 trusted zone"
# 逐个收集 docker 的网络 CIDR
NETS=$(docker network ls --filter driver=bridge --format '{{.Name}}' 2>/dev/null)
SRCS=""
for n in $NETS; do
  sub=$(docker network inspect "$n" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null)
  for s in $sub; do
    [ -n "$s" ] && SRCS="$SRCS $s"
  done
done
# 兜底：即使没取到，也把两个常见网段加上
SRCS="$SRCS 172.17.0.0/16 172.18.0.0/16"
echo "  要加入 trusted 的网段:"
for s in $(echo "$SRCS" | tr ' ' '\n' | sort -u | grep -v '^$'); do
  echo "    $s"
  firewall-cmd --permanent --zone=trusted --add-source="$s" >/dev/null 2>&1
done

# docker 网桥接口
for i in docker0 $(ls /sys/class/net/ | grep -E '^br-' 2>/dev/null); do
  [ -d "/sys/class/net/$i" ] || continue
  echo "    接口 $i"
  firewall-cmd --permanent --zone=trusted --add-interface="$i" >/dev/null 2>&1
done

log "3/6 开启 trusted zone 的 masquerade"
firewall-cmd --permanent --zone=trusted --add-masquerade >/dev/null 2>&1
ok "已配置"

log "4/6 重载 firewalld"
firewall-cmd --reload 2>&1 | sed 's/^/  /'
sleep 3
echo "  重载后的 trusted zone:"
firewall-cmd --zone=trusted --list-all 2>/dev/null | sed 's/^/    /'

log "5/6 重启 docker（让网络规则重新建立）"
# 为什么必须重启 docker：firewalld 重载会清掉 docker 插入的链，
# 而 docker 不会自动重建，结果是"规则看着有、实际不通"。
systemctl restart docker
echo "    等待容器恢复..."
for i in $(seq 1 24); do
  sleep 5
  H=$(docker inspect --format '{{.State.Health.Status}}' secagent 2>/dev/null || echo none)
  [ "$H" = "healthy" ] && { echo "    第 $((i*5)) 秒 secagent healthy"; break; }
done
docker ps --format '    {{.Names}}  {{.Status}}' | head -5

log "6/6 验证容器出网（这才是真正的判据）"
sleep 5
echo "  --- secagent 容器 ---"
docker exec secagent sh -c 'getent hosts www.baidu.com >/dev/null 2>&1 && echo "    DNS 解析 ✅" || echo "    DNS 解析 ❌"' 2>&1
docker exec secagent sh -c 'curl -s -o /dev/null -w "    https://www.baidu.com  HTTP %{http_code}\n" --max-time 12 https://www.baidu.com/' 2>&1
docker exec secagent sh -c 'curl -s -o /dev/null -w "    https://dashscope.aliyuncs.com  HTTP %{http_code}\n" --max-time 15 https://dashscope.aliyuncs.com/' 2>&1

echo
echo "  --- wazuh-tunnel sidecar ---"
docker ps --format '{{.Names}}' | grep -q wazuh-tunnel && {
  docker exec wazuh-tunnel sh -c 'curl -s -o /dev/null -w "    sidecar -> baidu  HTTP %{http_code}\n" --max-time 12 https://www.baidu.com/' 2>&1
  echo "    sidecar 日志:"
  docker logs wazuh-tunnel 2>&1 | tail -3 | sed 's/^/      /'
}

echo
echo "  --- 宿主机（对照）---"
curl -s -o /dev/null -w "    宿主机 -> baidu  HTTP %{http_code}\n" --max-time 10 https://www.baidu.com/

echo
echo "  结论判据："
echo "    容器 HTTP 200 -> 出网修好了，AI 功能才有可能真的工作"
echo "    仍然 000     -> 还有别的拦截（继续查 FORWARD / 安全组）"
