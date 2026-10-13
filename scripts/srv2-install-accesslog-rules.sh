#!/usr/bin/env bash
# ============================================================
# srv2 侧：安装/更新"访问日志（URL 级 Web 攻击）"的 manager 规则
# ------------------------------------------------------------
# 用法（在 srv2 上）：
#   sudo bash -s -- --check
#   sudo bash -s -- --apply --src /tmp/srv1_accesslog_rules.xml
#   sudo bash -s -- --rollback
#
# 规则文件：deploy/wazuh/srv1_accesslog_rules.xml（本仓库权威副本）
#   100240  URL 级扫描命中已知恶意路径         level 10
#   100241  其中属于路径穿越形态（升级）        level 12
#   100242  同一 IP 120 秒内 4xx ≥ 40（爆破）  level 8
#
# 【为什么必须走 analysisd -t 门禁】
#   §21.5 实测：规则里语法写错，wazuh-analysisd 报错后【直接退出】——
#   也就是"加一条规则告警，把整个 SIEM 弄停"（所有 agent 的告警全没了）。
#   所以：备份 -> 写 -> `wazuh-analysisd -t` -> 失败自动回滚 -> 重启 -> 断言 analysisd 在跑。
#
# 【为什么用独立文件】
#   srv1_local_rules.xml（§21，100200-100232）目前只在服务器上、未入库。
#   把本次规则写成独立文件，装机时完全不动那个文件：
#   改"已在线上的规则文件"出错 = 整站 SIEM 停摆；新增一个文件出错 = 最多本次规则不生效。
# ============================================================
set -uo pipefail

MODE="--check"; SRC="/tmp/srv1_accesslog_rules.xml"
while [ $# -gt 0 ]; do
  case "$1" in
    --check|--apply|--rollback) MODE="$1"; shift ;;
    --src) SRC="$2"; shift 2 ;;
    *) echo "[X] 未知参数：$1"; exit 2 ;;
  esac
done

HOSTDIR=/opt/wazuh/config/wazuh_cluster/rules
DEST="$HOSTDIR/srv1_accesslog_rules.xml"
BACKUP_ROOT=/var/backups/secagent/wazuh-rules
C_CY='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_0='\033[0m'
log()  { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }
ok()   { printf "  ${C_OK}[OK]${C_0} %s\n" "$*"; }
warn() { printf "  ${C_WARN}[!]${C_0} %s\n" "$*"; }
die()  { printf "  ${C_ERR}[X]${C_0} %s\n" "$*"; exit 1; }

[ "$(id -u)" = "0" ] || die "需要 root"
D="docker exec wazuh.manager"
# logtest 要从 stdin 喂事件，必须带 -i（不带的话容器里立刻 EOF，什么也不输出 —— 实测踩到，
# 表现为"自检段落是空的"，看起来像"规则不命中"，其实是根本没喂进去）
DI="docker exec -i wazuh.manager"

test_rules() { $D /var/ossec/bin/wazuh-analysisd -t 2>&1; }
bounce()     { $D /var/ossec/bin/wazuh-control restart >/dev/null 2>&1; sleep 8; }

# 用 logtest 单测三条规则的关键判据（不依赖线上流量）
logtest_rule() { # $1=JSON行
  printf '%s\n' "$1" | $DI /var/ossec/bin/wazuh-logtest 2>&1
}

case "$MODE" in
  --check)
    log "体检"
    echo "  analysisd 规则语法（-t）:"
    test_rules | sed 's/^/    /' || true
    echo "  已安装的访问日志规则文件:"
    ls -la "$DEST" 2>/dev/null | sed 's/^/    /' || echo "    （未安装）"
    echo "  规则 id 一览:"
    grep -oE 'rule id="[0-9]+" level="[0-9]+"' "$DEST" 2>/dev/null | sed 's/^/    /' || true
    ;;
  --apply)
    log "1/5 前置"
    docker ps --format '{{.Names}}' | grep -qx wazuh.manager || die "manager 容器没在跑"
    [ -f "$SRC" ] || die "找不到源文件 $SRC"
    grep -q '<group name="secagent,srv1,accesslog,web,">' "$SRC" || warn "源文件 group 名与预期不同（继续，但请看下）"
    grep -q 'rule id="100240"' "$SRC" || die "源文件里没有 100240（是不是拿错文件了）"
    ok "源文件 $SRC（$(stat -c %s "$SRC") 字节）"

    log "2/5 备份 + 落盘"
    ts="$(date +%Y%m%d-%H%M%S)"; d="$BACKUP_ROOT/$ts"; mkdir -p "$d"; : > "$d/manifest"
    if [ -e "$DEST" ]; then cp -a "$DEST" "$d/"; printf 'yes\t%s\tsrv1_accesslog_rules.xml\n' "$DEST" >> "$d/manifest"
    else printf 'no\t%s\tsrv1_accesslog_rules.xml\n' "$DEST" >> "$d/manifest"; fi
    ln -sfn "$d" "$BACKUP_ROOT/last-accesslog"
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

    log "3/5 校验规则语法（analysisd -t 门禁）"
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
    ST="$($D /var/ossec/bin/wazuh-control status 2>&1 || true)"
    if echo "$ST" | grep -q 'wazuh-analysisd is running'; then ok "analysisd 在跑"; else
      echo "$ST" | sed 's/^/    /'
      warn "analysisd 没起来 —— 回滚"
      ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
      die "已回滚"
    fi

    log "5/5 logtest 自检（规则真的能命中访问日志行）"
    for line in \
      '{"ts":"2026-10-13T20:31:02.303+08:00","method":"GET","path":"/wp-login.php","queryKeys":"","status":404,"clientIp":"198.51.100.9","ua":"curl/8.0.1","ms":3,"reqId":"t-1"}' \
      '{"ts":"2026-10-13T20:31:06.707+08:00","method":"GET","path":"/etc/passwd","queryKeys":"","status":404,"clientIp":"198.51.100.12","ua":"curl/8.0.1","ms":2,"reqId":"t-2"}' \
      '{"ts":"2026-10-13T20:31:00.101+08:00","method":"GET","path":"/","queryKeys":"","status":200,"clientIp":"198.51.100.9","ua":"Mozilla/5.0","ms":12,"reqId":"t-3"}' ; do
      echo "  --- $line"
      logtest_rule "$line" | grep -aE 'id:|level:|description:|Phase' | head -8 | sed 's/^/      /'
    done
    ok "自检输出在上面（第 1、2 条应命中 100240/100241，第 3 条不应命中）"
    ;;
  --rollback)
    d="$(readlink -f "$BACKUP_ROOT/last-accesslog" 2>/dev/null || true)"
    [ -n "$d" ] && [ -d "$d" ] || die "没有备份"
    log "回滚到 $d"; ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
    ;;
esac
