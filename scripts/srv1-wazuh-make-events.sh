#!/usr/bin/env bash
# ============================================================
# srv1 主机侧：制造可控事件（用于验证 Wazuh 侧真的收到并告警）
# ------------------------------------------------------------
# 用法: sudo bash -s -- [--sshd] [--unit] [--docker] [--apperror] [--all] [--cleanup]
# 设计原则：每一种事件都不会影响生产
#   · --sshd     从一次性容器打失败登录（被封的是容器 IP，随后解封）
#   · --unit     建一个【故意失败】的单元 secagent-detect-selftest.service 并启动，
#                触发规则 100200；跑完立刻删掉
#   · --docker   起一个一次性容器再删掉，触发 docker 事件
#   · --apperror 对 /api/public/ask 发 GET（没这个路由，应用会记 ERROR），
#                连发 16 次触发 100221 + 100222；不消耗模型额度、不影响数据
# ============================================================
set -uo pipefail
DO_SSHD=0; DO_UNIT=0; DO_DOCKER=0; DO_APP=0; CLEANUP=0
if [ $# -eq 0 ]; then DO_SSHD=1; DO_UNIT=1; DO_DOCKER=1; DO_APP=1; fi
for a in "$@"; do
  case "$a" in
    --sshd) DO_SSHD=1 ;; --unit) DO_UNIT=1 ;; --docker) DO_DOCKER=1 ;;
    --apperror) DO_APP=1 ;; --all) DO_SSHD=1; DO_UNIT=1; DO_DOCKER=1; DO_APP=1 ;;
    --cleanup) CLEANUP=1 ;;
    *) echo "[X] 未知参数 $a"; exit 2 ;;
  esac
done

UNIT=/etc/systemd/system/secagent-detect-selftest.service
NET=secagent_default
C_CY='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_0='\033[0m'
log() { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }
ok()  { printf "  ${C_OK}[OK]${C_0} %s\n" "$*"; }

if [ "$CLEANUP" = 1 ]; then
  log "清理自测痕迹"
  systemctl disable --now secagent-detect-selftest 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload
  docker rm -f secagent-detect-selftest-probe 2>/dev/null || true
  for j in sshd secagent-public-api; do
    for ip in $(fail2ban-client status "$j" 2>/dev/null | awk -F'\t' '/Banned IP list/{print $2}'); do
      case "$ip" in 172.2*|198.51.100.*|203.0.113.*|192.0.2.*)
        echo "  解封 $j -> $ip"; fail2ban-client set "$j" unbanip "$ip" >/dev/null ;; esac
    done
  done
  ok "清理完成"
  exit 0
fi

[ "$(id -u)" = 0 ] || { echo "需要 root"; exit 1; }

if [ "$DO_SSHD" = 1 ]; then
  log "事件 1/4：失败登录（源 = 一次性容器）"
  GW="$(docker network inspect "$NET" --format '{{(index .IPAM.Config 0).Gateway}}')"
  docker rm -f secagent-detect-selftest-probe >/dev/null 2>&1 || true
  docker run -d --name secagent-detect-selftest-probe --network "$NET" --entrypoint /bin/sh \
    secagent-tunnel:local -c 'sleep 300' >/dev/null
  sleep 2
  PIP="$(docker inspect secagent-detect-selftest-probe --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
  echo "  探针 IP: $PIP -> $GW:22，连打 5 次认证失败"
  i=1
  while [ $i -le 5 ]; do
    docker exec secagent-detect-selftest-probe ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=none -o ConnectTimeout=5 \
      root@"$GW" true >/dev/null 2>&1
    i=$((i+1))
  done
  sleep 6
  echo "  fail2ban 判决: $(grep -a '\[sshd\] Ban' /var/log/fail2ban.log | tail -1)"
  docker rm -f secagent-detect-selftest-probe >/dev/null 2>&1 || true
  ok "已制造失败登录（被封 IP 随后由 --cleanup 解封）"
fi

if [ "$DO_UNIT" = 1 ]; then
  log "事件 2/4：一个【故意失败】的 secagent-* 单元"
  cat > "$UNIT" <<'EOF'
[Unit]
Description=SecAgent 检测自测（故意失败，验证 Wazuh 规则 100200）
[Service]
Type=oneshot
ExecStart=/bin/false
EOF
  systemctl daemon-reload
  systemctl start secagent-detect-selftest 2>&1 | head -2 || true
  sleep 2
  echo "  /var/log/messages 里刚出现的行:"
  grep -a 'secagent-detect-selftest' /var/log/messages | tail -3 | sed 's/^/    /'
  ok "已制造单元失败事件（单元文件留着，验证完用 --cleanup 删）"
fi

if [ "$DO_DOCKER" = 1 ]; then
  log "事件 3/4：一次性容器启停（docker 事件）"
  docker run -d --name secagent-detect-selftest-container alpine:3.19 sleep 20 >/dev/null 2>&1
  sleep 3
  docker rm -f secagent-detect-selftest-container >/dev/null 2>&1
  ok "已制造容器启停事件"
fi

if [ "$DO_APP" = 1 ]; then
  log "事件 4/4：应用 ERROR（GET /api/public/ask 没有该路由 -> 记 ERROR）"
  if curl -s -o /dev/null --max-time 5 http://127.0.0.1:9900/; then
    i=1
    while [ $i -le 16 ]; do
      curl -s -o /dev/null --max-time 8 http://127.0.0.1:9900/api/public/ask
      i=$((i+1))
    done
    sleep 3
    echo "  应用日志镜像里 ERROR 行数(近 2 分钟): $(grep -c ' ERROR ' /var/log/secagent/app.log)"
    ok "已制造 16 次应用 ERROR"
  else
    printf '  \033[1;33m[!]\033[0m 应用不可用，跳过这一项\n'
  fi
fi

echo
log "等 20 秒让 agent 把事件送到 manager"
sleep 20
ok "事件已发出；到 srv2 上用 scripts/srv2-check-srv1-alerts.sh 查告警"
