#!/usr/bin/env bash
# ============================================================
# srv2：Dionaea 蜜罐上线（安装 / 拉起 / 回滚）
# ------------------------------------------------------------
# 设计红线（都写在这里的原因：出问题时第一个看的就是这个文件）：
#   · 容器化，不装宿主服务；镜像固定 tag 0.11.0（禁止 latest）
#   · 必须挂在【已有的】cowrie_honeypot 网络上，继承那套 egress DROP
#     —— 并且本脚本会【实测】它真的连不出去，连得出去就把容器停掉（fail-closed）
#   · read_only 根文件系统 + no-new-privileges + mem/cpu/pids 上限
#   · 只发布 445/1433/3306；1433/3306 从 secagent-decoy 手里【移交】过来
#     （先缩 decoy 的端口映射，再起 Dionaea —— 顺序反了会端口冲突起不来）
#   · 9200（真 indexer）永不碰
#   · DOCKER-USER 只允许在【链尾 append】端口放行，绝不 -I 1（那是 2026-10-13 的洞的成因）
#
# 用法（srv2，root）：
#   bash scripts/srv2-dionaea-deploy.sh --plan          # 只读：打印现状与将要做的动作
#   sudo bash scripts/srv2-dionaea-deploy.sh --apply    # 完整安装
#   sudo bash scripts/srv2-dionaea-deploy.sh --up       # 只拉起 + 隔离断言（systemd 用）
#   sudo bash scripts/srv2-dionaea-deploy.sh --rollback # 用最近一次备份回滚
# 可选：--src <仓库根目录>（默认取脚本所在目录的上一级）
# ============================================================
set -uo pipefail

MODE="--plan"
while [ $# -gt 0 ]; do
  case "$1" in
    --plan|--apply|--up|--rollback) MODE="$1"; shift ;;
    --src) SRC_OVERRIDE="$2"; shift 2 ;;
    *) echo "[X] 未知参数：$1"; exit 2 ;;
  esac
done

REPO_ROOT=${SRC_OVERRIDE:-$(cd "$(dirname "$0")/.." && pwd)}
SRC_DEPLOY="$REPO_ROOT/deploy/srv2-dionaea"
APP=/opt/dionaea
DOCKER_NET=cowrie_honeypot
IMAGE=dinotools/dionaea:0.11.0
IMAGE_DIGEST_EXPECT=sha256:6f06d0a6035c865cb60ef51bd96ff3b1f25ee4bfcd852dad3f551bc2d93464ca
PORTS_PUBLISHED="445 1433 3306"
HANDOVER_PORTS="1433 3306"          # 从 secagent-decoy 移交给 Dionaea
DECOY_PORTS_REMAIN="6379 8080 8443 27017 21 23"
NEW_FW_PORT=445                      # 需要新加的防火墙放行（其余端口早就放行了）
SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")

C_CY='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_0='\033[0m'
log()  { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }
ok()   { printf "  ${C_OK}[OK]${C_0} %s\n" "$*"; }
warn() { printf "  ${C_WARN}[!]${C_0}  %s\n" "$*"; }
die()  { printf "  ${C_ERR}[X]${C_0} %s\n" "$*" >&2; exit 1; }
need_root() { [ "$(id -u)" = "0" ] || die "需要 root"; }

# ---------- 隔离断言（fail-closed：连得出去就不放它跑）
honey_subnet() {
  local s
  s=$(docker inspect dionaea --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null | head -1)
  [ -n "$s" ] || s=$(docker inspect cowrie --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null | head -1)
  [ -n "$s" ] || return 1
  docker network inspect "$s" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null
}

assert_isolation() {
  local subnet drop_line port_line rc=0
  # 【必须先确认容器活着】否则 docker exec 失败会被当成"连不出去"→ 死容器伪装成"隔离良好"。
  # 这个假通过是 2026-10-14 实测发现的：docker compose restart 的瞬间正好取样，
  # 容器不在，断言却"通过"了。fail-closed 的前提是"被测对象真的在"。
  if ! docker ps --format '{{.Names}}' | grep -qx dionaea; then
    warn "容器 dionaea 没在运行 —— 隔离断言无意义（死容器当然连不出去）"
    return 1
  fi
  subnet=$(honey_subnet) || { warn "拿不到蜜罐网段，无法断言"; return 1; }
  echo "  蜜罐网段: $subnet"
  drop_line=$(iptables -S DOCKER-USER | grep -n -- "-s $subnet -j DROP" | head -1 | cut -d: -f1)
  port_line=$(iptables -S DOCKER-USER | grep -n -- '--dport' | head -1 | cut -d: -f1)
  if [ -z "$drop_line" ]; then
    warn "DOCKER-USER 里没有 $subnet 的 DROP 规则 —— 隔离不存在"; return 1
  fi
  ok "网段 DROP 在第 $drop_line 行"
  if [ -n "$port_line" ] && [ "$drop_line" -gt "$port_line" ]; then
    warn "端口放行（第 $port_line 行）排在 DROP（第 $drop_line 行）之前 = egress 有洞"; return 1
  fi
  ok "端口放行在 DROP 之后（顺序正确）"

  # 功能实测：容器内主动外连，必须失败
  echo "  --- 容器内主动外连实测（必须失败）---"
  local probe
  for probe in "1.1.1.1 443" "1.1.1.1 3306" "8.8.8.8 1433"; do
    set -- $probe
    if docker exec dionaea python3 -c "
import socket,sys
try:
    s = socket.create_connection(('$1', $2), 4); sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
      warn "容器内成功连上 $1:$2 —— 隔离失效！"; rc=1
    else
      ok "容器内连 $1:$2 失败（已 DROP）"
    fi
  done
  return $rc
}

# ---------- 播种配置（从镜像 template，只做一次）
seed_config() {
  mkdir -p "$APP/etc" "$APP/var"
  if [ ! -d "$APP/etc/dionaea" ]; then
    echo "  首次播种配置（从镜像 template 复制 etc/var）..."
    docker run --rm -v "$APP/etc":/seed/etc -v "$APP/var":/seed/var --entrypoint sh "$IMAGE" -c '
      cp -a /opt/dionaea/template/etc/dionaea /seed/etc/
      cp -a /opt/dionaea/template/lib /seed/var/
      cp -a /opt/dionaea/template/log /seed/var/
      mkdir -p /seed/var/log/dionaea /seed/var/lib/dionaea
      chown -R 1000:1000 /seed/etc /seed/var' || die "播种失败"
    ok "etc/var 已播种"
  else
    ok "配置已存在，跳过播种（不覆盖运行态）"
  fi
  mkdir -p "$APP/var/log/dionaea"

  # 1) 换上我们修过的 log_json.yaml（绝对路径，否则 dionaea.json 根本不产生）
  install -m 0644 -o root -g root "$SRC_DEPLOY/log_json.yaml" \
    "$APP/etc/dionaea/ihandlers-available/log_json.yaml" || die "写 log_json.yaml 失败"
  ln -sfn ../ihandlers-available/log_json.yaml "$APP/etc/dionaea/ihandlers-enabled/log_json.yaml"
  ok "log_json handler 已启用（输出 $APP/var/log/dionaea/dionaea.json）"

  # 2) 去掉 debug 级（实测：all=78KB/15s 空载；去掉 debug=8KB/15s）
  #    否则 collector 会被噪声淹没，真告警看不见。
  if grep -q '^default.levels=all$' "$APP/etc/dionaea/dionaea.cfg" 2>/dev/null; then
    sed -i 's/^default.levels=all$/default.levels=info,message,warning,error,critical/' "$APP/etc/dionaea/dionaea.cfg"
    ok "dionaea.cfg: default.levels 已从 all 改为 info,message,warning,error,critical（去掉 debug）"
  else
    ok "dionaea.cfg: default.levels 已是期望值"
  fi

  # 3) 目录属主（容器里 dionaea 是 uid/gid 1000）
  chown -R 1000:1000 "$APP/var" "$APP/etc/dionaea" 2>/dev/null || true
  chmod 0755 "$APP" "$APP/etc" "$APP/var"

  # 4) 停用"没发布、而且一启动就报错"的服务：SIP
  #    实测依据（2026-10-14）：dionaea-errors.log 里的 traceback 全部来自
  #      File "lib/dionaea/python/dionaea/sip/__init__.py", line 571, in __init__
  #      sqlite3.OperationalError: database is locked   <- SIP 服务自己锁住自己的 accounts.sqlite
  #    而 5060 由站主划定的范围里【不发布】（只暴露 445/1433/3306）。
  #    留着它的唯一效果就是把这份错误日志（它会进 Wazuh）灌满噪声、
  #    顺带让"Wazuh 里 dionaea 的告警"更难看清 —— 所以把 services-enabled 里的符号链接摘掉
  #    （services-available/sip.yaml 保留，随时可以恢复）。
  if [ -L "$APP/etc/dionaea/services-enabled/sip.yaml" ] || [ -e "$APP/etc/dionaea/services-enabled/sip.yaml" ]; then
    rm -f "$APP/etc/dionaea/services-enabled/sip.yaml"
    ok "已停用未发布的 SIP 服务（它启动就报 sqlite 'database is locked'）"
    if docker ps --format '{{.Names}}' | grep -qx dionaea; then
      ( cd "$APP" && docker compose restart ) >/dev/null 2>&1 && ok "已重启容器让配置生效" && sleep 6
    fi
  else
    ok "SIP 服务已处于停用状态"
  fi
}

# ---------- 装仓库落地物
install_artifacts() {
  for f in "$SRC_DEPLOY/docker-compose.yml" "$SRC_DEPLOY/log_json.yaml"; do
    [ -f "$f" ] || die "缺少 $f（--src 指对了吗？）"
  done
  install -m 0644 -o root -g root "$SRC_DEPLOY/docker-compose.yml" "$APP/docker-compose.yml"
  ok "compose -> $APP/docker-compose.yml"
  install -m 0644 -o root -g root "$SRC_DEPLOY/logrotate/secagent-dionaea" /etc/logrotate.d/secagent-dionaea
  ok "logrotate -> /etc/logrotate.d/secagent-dionaea"
  install -m 0644 -o root -g root "$SRC_DEPLOY/cron.d/secagent-dionaea-cleanup" /etc/cron.d/secagent-dionaea-cleanup
  ok "cron -> /etc/cron.d/secagent-dionaea-cleanup"
  # 蜜罐网段隔离的每日实测（一等检查项；非 0 就 notify HIGH；探针 fail-closed）
  install -m 0644 -o root -g root "$SRC_DEPLOY/cron.d/secagent-honeypot-egress" /etc/cron.d/secagent-honeypot-egress
  ok "cron -> /etc/cron.d/secagent-honeypot-egress（每日 09:40 实测隔离，非 0 报警）"
  # Dionaea 协议级健康检查 + 自愈（每 5 分钟；卡死会自己重启并报警）
  install -m 0644 -o root -g root "$SRC_DEPLOY/cron.d/secagent-dionaea-health" /etc/cron.d/secagent-dionaea-health
  ok "cron -> /etc/cron.d/secagent-dionaea-health（每 5 分钟协议级探活 + 自愈）"
  install -m 0644 -o root -g root "$SRC_DEPLOY/srv2-dionaea.service" /etc/systemd/system/srv2-dionaea.service
  ok "unit -> /etc/systemd/system/srv2-dionaea.service"
  for s in srv2-dionaea-deploy.sh srv2-dionaea-check.sh srv2-dionaea-killswitch.sh \
           srv2-dionaea-cleanup.sh srv2-dionaea-wire-wazuh.sh srv2-dionaea-healthcheck.sh \
           srv2-honeypot-egress-probe.sh srv2-honeypot-port-probe.sh; do
    [ -f "$REPO_ROOT/scripts/$s" ] || { warn "缺 $s，跳过"; continue; }
    install -m 0755 -o root -g root "$REPO_ROOT/scripts/$s" "/usr/local/sbin/$s"
    ok "脚本 -> /usr/local/sbin/$s"
  done
  # Cowrie 规则安装器（带 analysisd -t 门禁）。cowrie_rules.xml 以前只存在于服务器，
  # 现在仓库是权威副本 —— 改规则必须走这个脚本，别手改服务器。
  if [ -f "$REPO_ROOT/scripts/srv2-install-cowrie-rules.sh" ]; then
    install -m 0755 -o root -g root "$REPO_ROOT/scripts/srv2-install-cowrie-rules.sh" /usr/local/sbin/srv2-install-cowrie-rules.sh
    ok "脚本 -> /usr/local/sbin/srv2-install-cowrie-rules.sh（Cowrie 规则，带 -t 门禁）"
  fi
  # 诱饵脚本：本次把 1433/3306 移交给 Dionaea，并把放行规则改成"只 -A 追加"
  # （用 -I 1 插到链首就是 2026-10-13 那个 egress 洞的成因，必须让服务器上也拿到新版）
  if [ -f "$REPO_ROOT/scripts/srv2-decoy-ports.sh" ]; then
    install -m 0755 -o root -g root "$REPO_ROOT/scripts/srv2-decoy-ports.sh" /opt/secagent/scripts/srv2-decoy-ports.sh
    ok "脚本 -> /opt/secagent/scripts/srv2-decoy-ports.sh（端口清单 + 只追加放行）"
  fi
  # 蜜罐 egress 锁定脚本：本次只加了注释里的那次事故教训，行为与原来一致
  if [ -f "$REPO_ROOT/scripts/srv2-cowrie-egress-lock.sh" ]; then
    install -m 0755 -o root -g root "$REPO_ROOT/scripts/srv2-cowrie-egress-lock.sh" /usr/local/sbin/cowrie-egress-lock.sh
    ok "脚本 -> /usr/local/sbin/cowrie-egress-lock.sh（注释补充，行为不变）"
  fi
  install -m 0644 -o root -g root "$SRC_DEPLOY/README.md" "$APP/README.md" 2>/dev/null && ok "README -> $APP/README.md"
}

# ---------- 端口移交：把 1433/3306 从诱饵手里拿过来
# 【2026-10-14 修正】原来这里从 `docker inspect .Config.Cmd` 里 grep 数字来判断
#   诱饵占了哪些端口 —— 那是错的：Cmd 里带着 shell 注释，注释里出现过 "1433"
#   这种历史说明文字，于是每次 --apply 都误判"诱饵还占着 1433"，把诱饵容器
#   白白重建一次（6 个诱饵端口短暂中断）。判断依据必须用
#   `.HostConfig.PortBindings`：那才是 Docker 实际的端口映射，没有歧义。
handover_ports() {
  local bindings hit=0 p
  bindings=$(docker inspect secagent-decoy --format '{{range $k,$v := .HostConfig.PortBindings}}{{$k}} {{end}}' 2>/dev/null)
  for p in $HANDOVER_PORTS; do
    case " $bindings " in *" $p/tcp "*) hit=1 ;; esac
  done
  if [ "$hit" = "0" ]; then
    ok "诱饵容器已经没有 $HANDOVER_PORTS（无需移交，幂等跳过）"
    return 0
  fi
  warn "诱饵容器当前占用 $HANDOVER_PORTS，需要移交给 Dionaea"
  echo "  移交后诱饵保留端口：$DECOY_PORTS_REMAIN"
  # 用仓库里那份已改好的诱饵脚本重建（它现在只 -A 追加放行规则、不会破坏 DROP 顺序）
  DECOY_PORTS="$DECOY_PORTS_REMAIN" bash "$REPO_ROOT/scripts/srv2-decoy-ports.sh" --apply \
    || die "诱饵容器重建失败"
  # 验证：1433/3306 不再是诱饵的映射
  local after
  after=$(docker inspect secagent-decoy --format '{{json .HostConfig.PortBindings}}' 2>/dev/null)
  for p in $HANDOVER_PORTS; do
    if echo "$after" | grep -q "\"$p/tcp\""; then die "移交失败：诱饵仍然映射 $p"; fi
  done
  ok "移交完成：诱饵已不再监听 $HANDOVER_PORTS"
}

# ---------- 防火墙：445 放行（只在链尾 append；1433/3306 早就放行了）
open_port_445() {
  need_root
  if iptables -C DOCKER-USER -p tcp --dport "$NEW_FW_PORT" -j ACCEPT >/dev/null 2>&1; then
    ok "DOCKER-USER 已有 tcp/$NEW_FW_PORT 放行"
  else
    # 【只 append】绝不 -I 1：插到链首会排到 egress DROP 前面，重新造出 2026-10-13 那个洞
    iptables -A DOCKER-USER -p tcp --dport "$NEW_FW_PORT" -j ACCEPT
    ok "DOCKER-USER 追加放行 tcp/$NEW_FW_PORT（链尾，在 DROP 之后）"
  fi
  if ufw status 2>/dev/null | head -n1 | grep -qi active; then
    ufw status | grep -q "^$NEW_FW_PORT/tcp" || ufw allow "$NEW_FW_PORT/tcp" >/dev/null 2>&1
    ok "ufw allow $NEW_FW_PORT/tcp"
  fi
  # 落盘（开机恢复单元读 /etc/iptables/rules.v4）
  mkdir -p /var/backups/secagent/iptables
  cp -a /etc/iptables/rules.v4 "/var/backups/secagent/iptables/rules.v4.before-dionaea-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  iptables-save > /etc/iptables/rules.v4 && ok "iptables-save -> /etc/iptables/rules.v4（含新顺序与 445）"
}

compose_up() {
  ( cd "$APP" && docker compose up -d ) || die "compose up 失败"
  ok "compose up 完成"
}

case "$MODE" in
  --plan)
    log "现状（只读）"
    echo "  仓库根: $REPO_ROOT"
    for f in "$SRC_DEPLOY/docker-compose.yml" "$SRC_DEPLOY/log_json.yaml"; do
      [ -f "$f" ] && ok "有 $f" || warn "缺 $f"
    done
    echo "  蜜罐网络 $DOCKER_NET: $(docker network inspect "$DOCKER_NET" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null || echo '不存在')"
    echo "  镜像 $IMAGE: $(docker images -q "$IMAGE" | head -1 | sed 's/^$/（未拉取）/')"
    echo "  现有端口占用："
    for p in $PORTS_PUBLISHED; do
      who=$(docker ps --format '{{.Names}} {{.Ports}}' | grep -E ":$p->" | head -1)
      echo "    tcp/$p -> ${who:-空闲}"
    done
    echo "  现有容器: $(docker ps --format '{{.Names}}' | tr '\n' ' ')"
    echo "  DOCKER-USER:"; iptables -S DOCKER-USER | sed 's/^/    /'
    echo "  当前内存: $(free -m | awk '/^Mem:/{print "total="$2" used="$3" available="$7}')"
    ;;

  --up)
    need_root
    log "拉起 Dionaea + 隔离断言（fail-closed）"
    [ -f "$APP/docker-compose.yml" ] || die "$APP/docker-compose.yml 不存在，先跑 --apply"
    compose_up
    sleep 8
    if assert_isolation; then
      ok "隔离断言通过，容器保持运行"
    else
      warn "隔离断言失败 —— 立刻停掉容器（绝不放一个能主动外连的蜜罐在跑）"
      ( cd "$APP" && docker compose down ) >/dev/null 2>&1 || docker rm -f dionaea >/dev/null 2>&1
      die "已停容器，请修好蜜罐网段 egress DROP 后再 --up"
    fi
    docker ps --filter name=^dionaea$ --format '  {{.Names}}  {{.Status}}  {{.Ports}}'
    ;;

  --apply)
    need_root
    log "1/8 前置检查"
    docker ps --format '{{.Names}}' | grep -qx cowrie || die "cowrie 容器没在跑"
    docker network inspect "$DOCKER_NET" >/dev/null 2>&1 || die "网络 $DOCKER_NET 不存在"
    if ! docker images -q "$IMAGE" | head -1 | grep -q .; then
      echo "  拉取 $IMAGE ..."; docker pull "$IMAGE" || die "拉取失败"
    fi
    GOT=$(docker inspect "$IMAGE" --format '{{index .RepoDigests 0}}' | sed 's/.*@//')
    ok "镜像 $IMAGE"
    echo "    digest: $GOT"
    [ "$GOT" = "$IMAGE_DIGEST_EXPECT" ] || warn "digest 与记录不一致（期望 $IMAGE_DIGEST_EXPECT）—— 请确认镜像没有被替换"
    echo "  内存基线: $(free -m | awk '/^Mem:/{print "available="$7" MiB"}')"

    log "2/8 播种/修正配置"
    seed_config

    log "3/8 安装仓库落地物"
    install_artifacts

    log "4/8 端口移交（$HANDOVER_PORTS 从诱饵给 Dionaea）"
    handover_ports

    log "5/8 防火墙（追加 445 放行 + 落盘）"
    open_port_445

    log "6/8 拉起容器"
    compose_up
    sleep 8

    log "7/8 隔离断言（fail-closed）"
    if assert_isolation; then
      ok "隔离断言通过"
    else
      warn "隔离断言失败 —— 停掉容器"
      ( cd "$APP" && docker compose down ) >/dev/null 2>&1 || docker rm -f dionaea >/dev/null 2>&1
      die "已停容器：Dionaea 必须与 Cowrie 在同一套隔离里，否则不能上线"
    fi

    log "8/8 开机自启 + 状态"
    systemctl daemon-reload
    systemctl enable srv2-dionaea.service >/dev/null 2>&1 && ok "srv2-dionaea.service 已 enable"
    systemctl restart cron >/dev/null 2>&1 || true
    echo "  容器:"; docker ps --filter name=^dionaea$ --format '    {{.Names}}  {{.Status}}  {{.Ports}}'
    echo "  资源限制:"; docker inspect dionaea --format '    mem={{.HostConfig.Memory}} cpus={{.HostConfig.NanoCpus}} pids={{.HostConfig.PidsLimit}} read_only={{.HostConfig.ReadonlyRootfs}} secopt={{.HostConfig.SecurityOpt}} restart={{.HostConfig.RestartPolicy.Name}}'
    echo "  内存（加完之后）: $(free -m | awk '/^Mem:/{print "available="$7" MiB"}')"
    echo "  容器实占: $(docker stats --no-stream --format '{{.MemUsage}}' dionaea 2>/dev/null)"
    echo
    echo "  下一步：接 Wazuh -> sudo bash $REPO_ROOT/scripts/srv2-dionaea-wire-wazuh.sh --apply"
    ;;

  --rollback)
    need_root
    d="$(readlink -f /opt/secagent/backup/dionaea-last 2>/dev/null || true)"
    [ -n "$d" ] && [ -d "$d" ] || die "没有找到 /opt/secagent/backup/dionaea-last"
    log "回滚（用 $d）"
    ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
    systemctl disable srv2-dionaea.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/srv2-dionaea.service
    systemctl daemon-reload
    ok "回滚完成（注意：诱饵容器的端口需要手动恢复，见 $d/restore.sh 的提示）"
    ;;
esac
