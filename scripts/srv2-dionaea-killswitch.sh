#!/usr/bin/env bash
# ============================================================
# srv2：Dionaea 的总开关（kill switch）
# ------------------------------------------------------------
# 为什么单独一个脚本：
#   出事时要在【几秒内】把蜜罐彻底摘掉，而不是让人现查 compose 参数。
#   off 会把容器停掉、并且确认它真的不在了（不是"看着 stop 了"）。
#   注意 off 之后，1433/3306 上就【没有监听者】了 —— 那两个端口原本属于诱饵容器，
#   已经移交给 Dionaea；这是有意的取舍：宁可少一个假服务，也不要留一个你不想让它跑的东西。
#   如果要把"有东西应答"这件事也恢复，见 deploy/srv2-dionaea/README.md 的
#   "把 1433/3306 还给诱饵"一节。
#
# 用法（srv2，root）：
#   bash srv2-dionaea-killswitch.sh status   # 只看状态（默认）
#   sudo bash srv2-dionaea-killswitch.sh off # 停（kill switch）
#   sudo bash srv2-dionaea-killswitch.sh on  # 起（会做隔离断言，不通过就再停掉）
# ============================================================
set -uo pipefail
APP=/opt/dionaea
ACT=${1:-status}
C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_CY='\033[1;36m'; C_0='\033[0m'
log()  { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }
ok()   { printf "  ${C_OK}[OK]${C_0} %s\n" "$*"; }
warn() { printf "  ${C_WARN}[!]${C_0}  %s\n" "$*"; }
die()  { printf "  ${C_ERR}[X]${C_0} %s\n" "$*" >&2; exit 1; }

running() { docker ps --format '{{.Names}}' | grep -qx dionaea; }
honey_subnet() {
  local s
  s=$(docker inspect dionaea --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null | head -1)
  [ -n "$s" ] || s=$(docker inspect cowrie --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null | head -1)
  [ -n "$s" ] || return 1
  docker network inspect "$s" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null
}

status() {
  if running; then
    ok "Dionaea 在运行"
    docker ps --filter name=^dionaea$ --format '    {{.Status}}  {{.Ports}}'
    echo "    自启动单元: $(systemctl is-enabled srv2-dionaea.service 2>/dev/null || echo 未安装)"
    echo "    实占内存: $(docker stats --no-stream --format '{{.MemUsage}}' dionaea 2>/dev/null)"
  else
    warn "Dionaea 没在运行"
    docker ps -a --filter name=^dionaea$ --format '    历史容器: {{.Status}}'
  fi
  echo "    宿主内存: $(free -m | awk '/^Mem:/{print "available="$7" MiB"}')"
}

case "$ACT" in
  status) status ;;

  off)
    [ "$(id -u)" = "0" ] || die "需要 root"
    log "摘掉 Dionaea（kill switch）"
    if [ -d "$APP" ]; then
      ( cd "$APP" && docker compose down ) || docker stop dionaea || true
    else
      docker stop dionaea >/dev/null 2>&1 || true
    fi
    sleep 3
    if running; then die "容器还在跑 —— 请人工确认"; fi
    ok "容器已停（docker ps 里已无 dionaea）"
    # 单元也停掉，避免 systemd 又把它拉回来
    systemctl stop srv2-dionaea.service >/dev/null 2>&1 || true
    echo "    端口现状（445/1433/3306 应无人监听）："
    ss -ltnp 2>/dev/null | grep -E ':(445|1433|3306)\b' | sed 's/^/      /' || echo "      三个端口都没有监听者"
    warn "注意：systemd 单元仍处于 enabled，下次开机还会拉起；要彻底关掉请 systemctl disable srv2-dionaea.service"
    echo "    内存: $(free -m | awk '/^Mem:/{print "available="$7" MiB"}')"
    ;;

  on)
    [ "$(id -u)" = "0" ] || die "需要 root"
    log "拉起 Dionaea"
    [ -f "$APP/docker-compose.yml" ] || die "$APP/docker-compose.yml 不存在"
    ( cd "$APP" && docker compose up -d ) || die "compose up 失败"
    sleep 8
    # 先确认真的起来了 —— 否则"容器不在"会被下面的外连测试误判成"隔离良好"
    running || die "容器没起来（docker ps 里没有 dionaea），请查 docker logs dionaea"
    ok "容器已在运行"
    subnet=$(honey_subnet)
    dl=$(iptables -S DOCKER-USER | grep -n -- "-s $subnet -j DROP" | head -1 | cut -d: -f1)
    pl=$(iptables -S DOCKER-USER | grep -n -- '--dport' | head -1 | cut -d: -f1)
    if [ -z "$dl" ] || { [ -n "$pl" ] && [ "$dl" -gt "$pl" ]; }; then
      warn "隔离顺序不对（DROP 第 ${dl:-?} 行 / 端口放行第 ${pl:-?} 行）—— 停掉容器"
      ( cd "$APP" && docker compose down ) >/dev/null 2>&1 || docker rm -f dionaea >/dev/null 2>&1
      die "已停容器：隔离不成立就不允许它跑"
    fi
    if docker exec dionaea python3 -c "
import socket,sys
try:
    socket.create_connection(('1.1.1.1',3306),4); sys.exit(0)
except Exception: sys.exit(1)" 2>/dev/null; then
      warn "容器内能主动外连 —— 隔离失效，停掉容器"
      ( cd "$APP" && docker compose down ) >/dev/null 2>&1 || docker rm -f dionaea >/dev/null 2>&1
      die "已停容器"
    fi
    ok "已拉起，且隔离断言通过（容器内主动外连失败）"
    docker ps --filter name=^dionaea$ --format '    {{.Status}}  {{.Ports}}'
    ;;

  *) die "用法: $0 [status|on|off]" ;;
esac
