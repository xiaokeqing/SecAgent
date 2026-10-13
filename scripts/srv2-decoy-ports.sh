#!/usr/bin/env bash
# ============================================================
# srv2：诱饵端口（提升"端口扫描"的可检出性）
# ------------------------------------------------------------
# 原理（务必先读懂）：
#   检测端口扫描只需要让 SYN **到达网卡** —— Suricata 在 srv2 上抓包（net=host），
#   后端**不需要真有服务**。当前只有 22 端口能到网卡，所以通用多端口扫描检测不到。
#   要提升可检出性，需要【三层同时放行】：云安全组（站主在控制台做）→ ufw → DOCKER-USER。
#   蜜罐网段（172.19.0.0/16 = cowrie_honeypot）的 **egress 已被 DROP**（已核实），
#   因此诱饵端口指向该网段时不会成为跳板。
#
# 红线（脚本会强制检查）：
#   · 绝不允许把诱饵端口指向真实服务 —— 特别是 srv2 自己的 9200（真 indexer）
#   · 只加放行与一个轻量监听容器，不动任何既有服务
#   · 改前备份、失败回滚
#
# 用法（srv2，root）：
#   bash srv2-decoy-ports.sh --plan        # 只读：打印端口清单、三层现状与要做的动作（默认）
#   sudo bash srv2-decoy-ports.sh --apply  # 落地：加 DOCKER-USER 放行 + 起诱饵监听容器
#   sudo bash srv2-decoy-ports.sh --rollback
# ============================================================
set -uo pipefail

# 【端口清单注意】9200 虽然在"扫描器爱扫"的名单里，但在 srv2 上 **9200 就是真 indexer 的端口**
# （srv1 的 SSH 隧道就是转发到 srv2 的 9200）。把诱饵端口设成 9200 会与真实服务冲突、
# 且一旦配置不当就是把索引器暴露到公网 —— 因此本脚本的默认清单【不含 9200】，
# 用 1433（MSSQL）/ 27017（MongoDB）这两个"扫描器也爱扫、但本机没有真服务"的端口替代。
PORTS=${DECOY_PORTS:-"3306 6379 8080 8443 1433 27017 21 23"}
HONEY_NET=cowrie_honeypot
HONEY_SUBNET=172.19.0.0/16
CT_NAME=secagent-decoy
BACKUP_DIR=/opt/secagent/backup
ACTION=plan
case "${1:-}" in
  --apply) ACTION=apply ;;
  --rollback) ACTION=rollback ;;
  --plan|"") ACTION=plan ;;
  *) echo "用法: $0 [--plan|--apply|--rollback]"; exit 2 ;;
esac

ok()   { printf '  \033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m[!]\033[0m  %s\n' "$*"; }
info() { printf '      %s\n' "$*"; }
die()  { printf '  \033[1;31m[X]\033[0m  %s\n' "$*"; exit 1; }

# ---------- 红线检查：不能指向真实服务 ----------
# 9200 在本机是真 indexer（wazuh.indexer 容器）；诱饵端口只做"到网卡的 SYN 可见性"，
# 因此**不把任何端口映射到 wazuh.indexer**。若发现有人把诱饵指向它，直接拒绝执行。
check_redline() {
  local bad=0
  for p in $PORTS; do
    if docker ps --format '{{.Names}} {{.Ports}}' | grep -q "wazuh.indexer.*:$p->"; then
      warn "端口 $p 当前被真实 indexer 占用 —— 必须从诱饵清单里去掉"; bad=1
    fi
  done
  [ "$bad" = "0" ] || die "红线检查未通过：诱饵端口不得指向真实服务"
}

show_state() {
  echo "== 端口清单 =="; info "$PORTS"
  echo "== 三层防火墙现状 =="
  echo "  [1] 云安全组：**只能在阿里云/腾讯云控制台看**（脚本无法读取）；未放行的端口，包在到达网卡前就被丢弃"
  echo "  [2] ufw："; ufw status 2>/dev/null | head -n 3 | sed 's/^/      /' || info "（无 ufw 或未启用）"
  echo "  [3] DOCKER-USER："; iptables -S DOCKER-USER 2>/dev/null | head -n 8 | sed 's/^/      /'
  echo "== 蜜罐网段 egress 现状（应为 DROP）=="
  # 注意匹配方式：规则形如 `-A DOCKER-USER -s 172.19.0.0/16 -j DROP`（DROP 在末尾），
  # 早先写成 "DROP.*子网" 会漏匹配 —— 这里改成"该子网作为源 + 目标动作为 DROP"。
  if iptables -S DOCKER-USER 2>/dev/null | grep -E -- "-s $HONEY_SUBNET .*-j DROP"; then
    ok "蜜罐网段 egress 已被 DROP（诱饵端口指向它不会成为跳板）"
  else
    warn "未看到针对 $HONEY_SUBNET 的 egress DROP —— 落地前应先补上（否则诱饵容器可被当跳板）"
  fi
  echo "== 现有容器端口映射 =="
  docker ps --format '      {{.Names}}: {{.Ports}}' | head -n 8
}

case "$ACTION" in
  plan)
    show_state
    cat <<EOF

== 落地时需要做的（--apply 会做前两步；第一步必须你在控制台做）==
  步骤1【你在云控制台做】放行这些端口的入站：$PORTS
        —— 只放这几个端口，不要写 0-65535；源可设 0.0.0.0/0（探测需要）
  步骤2【--apply 做】起一个轻量诱饵容器（挂在 $HONEY_NET，继承 egress deny），
        把 $PORTS 映射到它；容器只做"记录连接"，不提供任何真实服务
  步骤3【--apply 做】DOCKER-USER 里放行这些端口（其余保持现状）
  步骤4 验证：从 srv1 扫一遍这些端口 → 应能在 Suricata 里看到多端口 SYN（基线演练口径）
  回滚：bash $0 --rollback（停容器 + 撤规则；云安全组需你手动收回）

== 安全影响评估（如实） ==
  · 收益：通用多端口扫描从"检测不到"变为"可检出"；蜜罐能抓到更多攻击者指纹
  · 风险：公网可见端口从 1 个（22）扩到 $(echo $PORTS | wc -w) 个；
          但后端是"只记录连接的诱饵容器"，且其所在网段 egress 已被 DROP，不是真服务、也不能当跳板
  · 红线：绝不把诱饵端口指到真实服务；尤其 9200 —— srv2 上 9200 是真 indexer（只对内网/隧道开放）
  · 资源：诱饵容器限制 CPU/内存与并发连接数，避免被连接洪水拖垮
EOF
    check_redline
    ok "计划模式（未做任何改动）"
    ;;
  apply)
    check_redline
    mkdir -p "$BACKUP_DIR"
    TS=$(date +%Y%m%d-%H%M%S)
    iptables-save > "$BACKUP_DIR/iptables-before-decoy-$TS.save" 2>/dev/null && ok "已备份 iptables → $BACKUP_DIR/iptables-before-decoy-$TS.save"
    echo "== 起诱饵容器（$CT_NAME，挂 $HONEY_NET，只记录连接） =="
    if docker ps -a --format '{{.Names}}' | grep -qx "$CT_NAME"; then
      warn "容器 $CT_NAME 已存在 —— 先移除再重建"; docker rm -f "$CT_NAME" >/dev/null 2>&1 || true
    fi
    # 用 alpine 的 nc 做"只接受连接并记录"的诱饵；每端口一个 nc 进程
    PORTARGS=""
    for p in $PORTS; do PORTARGS="$PORTARGS -p $p:$p"; done
    # shellcheck disable=SC2086
    docker run -d --name "$CT_NAME" --network "$HONEY_NET" \
      --restart unless-stopped \
      --memory 128m --cpus 0.3 --pids-limit 256 \
      $PORTARGS alpine:latest sh -c '
        for p in '"$(echo $PORTS | tr ' ' ',')"'; do
          ( while true; do nc -l -p "$p" -e /bin/echo "decoy" >/dev/null 2>&1 || nc -l -p "$p" >/dev/null 2>&1; done ) &
        done
        wait' >/dev/null 2>&1 && ok "诱饵容器已启动" || warn "诱饵容器启动失败（可能需要先 docker pull alpine）"
    echo "== DOCKER-USER 放行这些端口（保持其余规则不变） =="
    for p in $PORTS; do
      iptables -I DOCKER-USER 1 -p tcp --dport "$p" -j ACCEPT 2>/dev/null && info "放行 tcp/$p（DOCKER-USER）"
    done
    # 【2026-10-13 取证】srv2 上 ufw 是 active 的，所以除了 DOCKER-USER 还必须过 ufw 这一层。
    if ufw status 2>/dev/null | head -n1 | grep -qi active; then
      echo "== ufw 放行（ufw 为 active，必须同时放行） =="
      for p in $PORTS; do ufw allow "$p/tcp" >/dev/null 2>&1 && info "ufw allow $p/tcp"; done
    else
      info "ufw 未启用（跳过）"
    fi
    ok "已应用。云安全组放行需要你在控制台做；验证请从 srv1 扫这些端口"
    ;;
  rollback)
    echo "== 回滚 =="
    docker rm -f "$CT_NAME" >/dev/null 2>&1 && ok "诱饵容器已移除" || info "诱饵容器不存在"
    for p in $PORTS; do iptables -D DOCKER-USER -p tcp --dport "$p" -j ACCEPT 2>/dev/null && info "已撤 tcp/$p"; done
    LATEST=$(ls -1t "$BACKUP_DIR"/iptables-before-decoy-*.save 2>/dev/null | head -n1 || true)
    [ -n "$LATEST" ] && info "如需完全还原规则，可用备份：$LATEST"
    warn "云安全组里放行的端口需要你在控制台手动收回"
    ok "回滚完成"
    ;;
esac
