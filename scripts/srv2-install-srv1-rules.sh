#!/usr/bin/env bash
# ============================================================
# srv2 侧：安装/更新 srv1 相关的 manager 自定义规则（带校验与回滚）
# ------------------------------------------------------------
# 用法（在 srv2 上）：
#   sudo bash -s -- --apply [--src /tmp/srv1_local_rules.xml]
#   sudo bash -s -- --check
#   sudo bash -s -- --rollback
#
# 为什么必须校验：
#   实测踩到：规则里把 <match> 和 <regex> 写在同一 rule 里，
#   wazuh-analysisd 报 "Syntax error on tag 'regex' in rule 100200" 后【直接退出】。
#   也就是说"加一条规则"能把整个 SIEM 弄挂（所有 agent 的告警都停了）。
#   所以这里强制走 wazuh-analysisd -t 门禁，失败就回滚并重启。
# ============================================================
set -uo pipefail

MODE="--apply"; SRC="/tmp/srv1_local_rules.xml"
while [ $# -gt 0 ]; do
  case "$1" in
    --check|--apply|--rollback) MODE="$1"; shift ;;
    --src) SRC="$2"; shift 2 ;;
    *) echo "[X] 未知参数：$1"; exit 2 ;;
  esac
done

HOSTDIR=/opt/wazuh/config/wazuh_cluster/rules
DEST="$HOSTDIR/srv1_local_rules.xml"
BACKUP_ROOT=/var/backups/secagent/wazuh-rules
C_CY='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_0='\033[0m'
log()  { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }
ok()   { printf "  ${C_OK}[OK]${C_0} %s\n" "$*"; }
warn() { printf "  ${C_WARN}[!]${C_0} %s\n" "$*"; }
die()  { printf "  ${C_ERR}[X]${C_0} %s\n" "$*"; exit 1; }

[ "$(id -u)" = "0" ] || die "需要 root"
D="docker exec wazuh.manager"

test_rules() { $D /var/ossec/bin/wazuh-analysisd -t 2>&1; }

bounce() { $D /var/ossec/bin/wazuh-control restart >/dev/null 2>&1; sleep 8; }

case "$MODE" in
  --check)
    log "体检"
    echo "  analysisd 规则语法:"
    test_rules | sed 's/^/    /' || true
    echo "  已安装的 srv1 规则文件:"
    ls -la "$DEST" 2>/dev/null | sed 's/^/    /' || echo "    （未安装）"
    echo "  规则 id 一览:"
    grep -oE 'rule id="[0-9]+" level="[0-9]+"' "$DEST" 2>/dev/null | sed 's/^/    /' || true
    ;;
  --apply)
    log "1/5 前置"
    # 注意：不能用 `wazuh-control status` 的返回码判断存活 ——
    # 默认有几个服务（clusterd/maild/dbd…）本来就不跑，它总会返回非 0。
    docker ps --format '{{.Names}}' | grep -qx wazuh.manager || die "manager 容器没在跑"
    [ -f "$SRC" ] || die "找不到源文件 $SRC"
    grep -q '<group name="secagent,srv1,">' "$SRC" || warn "源文件里没有预期的 group 名（继续，但请看下）"
    ok "源文件 $SRC（$(stat -c %s "$SRC") 字节）"

    log "2/5 备份 + 落盘"
    ts="$(date +%Y%m%d-%H%M%S)"; d="$BACKUP_ROOT/$ts"; mkdir -p "$d"; : > "$d/manifest"
    if [ -e "$DEST" ]; then cp -a "$DEST" "$d/"; printf 'yes\t%s\tsrv1_local_rules.xml\n' "$DEST" >> "$d/manifest"
    else printf 'no\t%s\tsrv1_local_rules.xml\n' "$DEST" >> "$d/manifest"; fi
    ln -sfn "$d" "$BACKUP_ROOT/last"
    cat > "$d/restore.sh" <<'RESTORE'
#!/usr/bin/env bash
set -u
D="$(cd "$(dirname "$0")" && pwd)"
while IFS=$'\t' read -r existed target name; do
  if [ "$existed" = "yes" ]; then install -m 0644 -o root -g root "$D/$name" "$target" && echo "  restored $target"
  else [ -e "$target" ] && rm -f "$target" && echo "  removed  $target"; fi
done < "$D/manifest"
docker exec wazuh.manager /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true
RESTORE
    chmod +x "$d/restore.sh"
    install -m 0644 -o root -g root "$SRC" "$DEST" && ok "写入 $DEST"
    ok "备份在 $d"

    log "3/5 校验规则语法（analysisd -t）"
    if OUT="$(test_rules)"; then
      echo "$OUT" | sed 's/^/    /'
      ok "规则语法通过"
    else
      echo "$OUT" | sed 's/^/    /'
      warn "规则语法不通过 —— 自动回滚（否则 analysisd 起不来，整个 SIEM 停摆）"
      ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
      die "已回滚，请修 $SRC 后重试"
    fi

    log "4/5 重启 manager 生效"
    bounce
    # 注意：wazuh-control status 在"有服务本来就不跑"时会返回非 0，
    # 在 set -o pipefail 下会把这个非 0 传出来，把"其实起来了"误判成失败。
    # 所以先把输出抓成变量再判断。
    ST="$($D /var/ossec/bin/wazuh-control status 2>&1 || true)"
    echo "  wazuh-control status:"
    echo "$ST" | sed 's/^/    /'
    if echo "$ST" | grep -q 'wazuh-analysisd is running'; then
      ok "analysisd 在跑"
    else
      warn "analysisd 没起来 —— 回滚"
      ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
      die "已回滚"
    fi

    log "5/5 规则是否真的加载"
    echo "  manager 日志里关于规则的行:"
    $D sh -c 'grep -aiE "rule|rules" /var/ossec/logs/ossec.log | tail -6' | sed 's/^/    /'
    echo "  当前规则数（analysisd 统计不可直接取，这里看我们的文件已被读入）:"
    $D sh -c "grep -c 'rule id' /var/ossec/etc/rules/srv1_local_rules.xml" | sed 's/^/    srv1 规则条数: /'
    echo
    ok "srv1 规则已装载。改规则后若 agent 掉线，会在 60s 内自动重连。"
    ;;
  --rollback)
    d="$(readlink -f "$BACKUP_ROOT/last" 2>/dev/null || true)"
    [ -n "$d" ] && [ -d "$d" ] || die "没有备份"
    log "回滚到 $d"; ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
    ;;
esac
