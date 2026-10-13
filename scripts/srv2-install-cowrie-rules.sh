#!/usr/bin/env bash
# ============================================================
# srv2：安装/更新 Cowrie 蜜罐规则（带 analysisd -t 门禁与自动回滚）
# ------------------------------------------------------------
# 为什么单独一个脚本（而不是手改服务器文件）：
#   cowrie_rules.xml 之前【只存在于 srv2】，仓库里没有 —— 属于"只在服务器上的落地物"
#   （RUNBOOK §28.6 记的那类问题：改坏了没有权威副本可比对）。
#   本脚本把它落成"仓库是权威、服务器是副本"，并且带上：
#     备份 -> 写 -> wazuh-analysisd -t 校验 -> 失败自动回滚 -> 重启 -> logtest 功能自测
#
# 【2026-10-14 这次改的是什么】
#   规则的 <description> 里原来写了 `口令=$(password)`。Wazuh 会把它渲染成明文，
#   而应用侧把 rule.description 当作 title / ruleName 直出 /api/public/alerts ——
#   于是蜜罐抓到的口令原文出公网。这里必须去掉，换成项目既定的隐藏形态 `[口令已隐藏]`。
#
#   为什么规则语法校验（-t）还不够、还要 logtest 功能自测：
#     -t 只能证明"规则文件语法能加载"，不能证明"渲染出来的描述里没有明文"。
#     本脚本的自测会真的喂一条 login.success 事件进规则引擎，
#     然后按项目自己的判据断言：
#       · 描述里出现 `口令=[口令已隐藏]`（隐藏形态在生效）
#       · 描述里不出现"口令=<非[>"形态（没有明文残留）
#       · 用户名/来源仍在（脱敏不是删字段）
#
# 用法（srv2，root）：
#   bash scripts/srv2-install-cowrie-rules.sh --check
#   sudo bash scripts/srv2-install-cowrie-rules.sh --apply [--src <仓库根>]
#   sudo bash scripts/srv2-install-cowrie-rules.sh --rollback
# ============================================================
set -uo pipefail

MODE="--check"; SRC_OVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check|--apply|--rollback) MODE="$1"; shift ;;
    --src) SRC_OVERRIDE="$2"; shift 2 ;;
    *) echo "[X] 未知参数：$1"; exit 2 ;;
  esac
done

REPO_ROOT=${SRC_OVERRIDE:-$(cd "$(dirname "$0")/.." && pwd)}
RULES_SRC="$REPO_ROOT/deploy/wazuh/cowrie_rules.xml"
HOSTDIR=/opt/wazuh/config/wazuh_cluster/rules
DEST="$HOSTDIR/cowrie_rules.xml"
BACKUP_ROOT=/var/backups/secagent/wazuh-rules
D="docker exec wazuh.manager"

C_CY='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_0='\033[0m'
log()  { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }
ok()   { printf "  ${C_OK}[OK]${C_0} %s\n" "$*"; }
warn() { printf "  ${C_WARN}[!]${C_0}  %s\n" "$*"; }
die()  { printf "  ${C_ERR}[X]${C_0} %s\n" "$*" >&2; exit 1; }

test_rules() { $D /var/ossec/bin/wazuh-analysisd -t 2>&1; }
bounce()     { $D /var/ossec/bin/wazuh-control restart >/dev/null 2>&1; sleep 8; }
# 注意：wazuh-control status 的返回码【总是非 0】（clusterd/maild/dbd 本来就不跑），
# 在 set -o pipefail 下会把"活着"判成"死了" —— 必须先抓成变量再匹配。
manager_alive() {
  local st
  st="$($D /var/ossec/bin/wazuh-control status 2>&1 || true)"
  echo "$st" | grep -q 'wazuh-analysisd is running'
}

# ---------- 功能自测：真的喂一条 login.success，断言渲染结果里没有明文 ----------
# 全部用【字面量】判据，不拼变量模式（空模式会把机器跑成死循环，已发生过一次）。
functional_test() {
  local sample out desc i
  sample='{"eventid": "cowrie.login.success", "session": "selftest01", "protocol": "ssh", "src_ip": "203.0.113.77", "src_port": 41234, "dst_ip": "172.19.0.2", "dst_port": 2222, "username": "root", "password": "SuperSecret123", "message": "login attempt [root/SuperSecret123] succeeded"}'
  for i in $(seq 1 18); do
    out=$(printf '%s\n' "$sample" | docker exec -i wazuh.manager /var/ossec/bin/wazuh-logtest 2>&1 || true)
    if echo "$out" | grep -q "100102"; then break; fi
    sleep 5
  done
  desc=$(printf '%s\n' "$out" | grep -oE "description: '.*'" | head -1)
  echo "    渲染出的描述: ${desc#description: }"
  python3 - "$desc" <<'PYEOF'
import re, sys
desc = sys.argv[1] if len(sys.argv) > 1 else ""
HIDDEN = "[口令已隐藏]"
# 项目自己的判据：凭据字段右侧第一个字符不是 '[' => 明文残留
LEAK = re.compile(r"(?i)(口令|密码|password|passwd|pwd)\s*[:=：]\s*([^\s\[][^\s]*)")
problems = []
if not desc:
    problems.append("没有从 logtest 输出里解析到 description（自测没跑成）")
if HIDDEN not in desc:
    problems.append("描述里没有出现隐藏形态 %s" % HIDDEN)
if LEAK.search(desc):
    problems.append("描述里仍有明文口令：匹配到 %r" % LEAK.search(desc).group(0))
if "SuperSecret123" in desc:
    problems.append("哨兵口令原文出现在了描述里")
if "用户=root" not in desc:
    problems.append("用户名被吃掉了（脱敏不该删字段）：找不到 '用户=root'")
if "203.0.113.77" not in desc:
    problems.append("来源地址被吃掉了：找不到 203.0.113.77")
if problems:
    print("    [X] 功能自测失败：")
    for p in problems:
        print("        - %s" % p)
    sys.exit(1)
print("    [OK] 描述里无明文口令、有隐藏形态、用户名与来源保留")
sys.exit(0)
PYEOF
}

save_backup() {
  ts="$(date +%Y%m%d-%H%M%S)"; d="$BACKUP_ROOT/cowrie-rules-$ts"
  mkdir -p "$d"; : > "$d/manifest"
  if [ -e "$DEST" ]; then
    cp -a "$DEST" "$d/"; printf 'yes\t%s\tcowrie_rules.xml\n' "$DEST" >> "$d/manifest"
  else
    printf 'no\t%s\tcowrie_rules.xml\n' "$DEST" >> "$d/manifest"
  fi
  ln -sfn "$d" "$BACKUP_ROOT/cowrie-last"
  cat > "$d/restore.sh" <<'RESTORE'
#!/usr/bin/env bash
set -u
D="$(cd "$(dirname "$0")" && pwd)"
while IFS=$'\t' read -r existed target name; do
  if [ "$existed" = "yes" ]; then install -m 0644 -o root -g root "$D/$name" "$target" && echo "  restored $target"
  else [ -e "$target" ] && rm -f "$target" && echo "  removed  $target"; fi
done < "$D/manifest"
docker exec wazuh.manager /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true
sleep 8
echo "  回滚后 analysisd: $(docker exec wazuh.manager /var/ossec/bin/wazuh-control status 2>&1 | grep -c 'wazuh-analysisd is running') (1=在跑)"
RESTORE
  chmod +x "$d/restore.sh"
}

case "$MODE" in
  --check)
    log "体检"
    echo "  仓库副本: $RULES_SRC  $([ -f "$RULES_SRC" ] && echo "存在（$(stat -c %s "$RULES_SRC") 字节）" || echo "不存在")"
    echo "  服务器副本: $DEST  $([ -f "$DEST" ] && echo "存在（$(stat -c %s "$DEST") 字节）" || echo "不存在")"
    if [ -f "$RULES_SRC" ] && [ -f "$DEST" ]; then
      a=$(sha256sum "$RULES_SRC" | cut -d' ' -f1); b=$(sha256sum "$DEST" | cut -d' ' -f1)
      [ "$a" = "$b" ] && ok "仓库与服务器逐字节一致" || warn "仓库与服务器不一致（应 --apply 同步）"
    fi
    echo "  描述里还有没有 \$(password)："
    grep -n 'password' "$DEST" 2>/dev/null | sed 's/^/    /' || echo "    （没有，已脱敏）"
    echo "  规则语法:"; test_rules | sed 's/^/    /' || true
    echo "  功能自测:"; functional_test || true
    ;;

  --apply)
    [ "$(id -u)" = "0" ] || die "需要 root"
    log "1/5 前置"
    docker ps --format '{{.Names}}' | grep -qx wazuh.manager || die "manager 容器没在跑"
    [ -f "$RULES_SRC" ] || die "找不到 $RULES_SRC（--src 指对了吗？）"
    grep -q '口令=\[口令已隐藏\]' "$RULES_SRC" || die "源文件里没有隐藏形态，拒绝安装（先确认改对了）"
    # 只在 <description> 里找 $(password) —— 注释里会引用这个写法来说明事故，
    # 用全文 grep 会被自己的注释误伤（第一版就是这么误报的）。
    if grep -E '<description>[^<]*\$\(password\)' "$RULES_SRC" >/dev/null 2>&1; then
      die "描述里仍有 \$(password)，拒绝安装"
    fi
    ok "源文件检查通过（$(stat -c %s "$RULES_SRC") 字节；description 里已无 \$(password)）"

    log "2/5 备份 + 落盘"
    save_backup
    ok "备份在 $d"
    install -m 0644 -o root -g root "$RULES_SRC" "$DEST" && ok "写入 $DEST"

    log "3/5 analysisd -t 门禁"
    if OUT="$(test_rules)"; then
      echo "$OUT" | sed 's/^/    /'; ok "规则语法通过"
    else
      echo "$OUT" | sed 's/^/    /'
      warn "规则语法不通过 —— 自动回滚（否则 analysisd 起不来，整个 SIEM 停摆）"
      ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
      die "已回滚，请修 $RULES_SRC 后重试"
    fi

    log "4/5 重启 manager 生效"
    bounce
    if manager_alive; then ok "analysisd 在跑"; else
      warn "analysisd 没起来 —— 回滚"
      ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
      die "已回滚"
    fi

    log "5/5 功能自测（真的喂一条 login.success，看渲染结果里有没有明文）"
    if functional_test; then
      ok "脱敏生效：描述里没有明文口令"
    else
      warn "功能自测没过 —— 回滚（宁可回到旧规则，也不留一个还在漏描述的版本）"
      ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
      die "已回滚"
    fi
    ok "完成。仓库副本 $RULES_SRC 与服务器 $DEST 应逐字节一致"
    ;;

  --rollback)
    [ "$(id -u)" = "0" ] || die "需要 root"
    d="$(readlink -f "$BACKUP_ROOT/cowrie-last" 2>/dev/null || true)"
    [ -n "$d" ] && [ -d "$d" ] || die "没有备份"
    log "回滚到 $d"
    ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
    ok "回滚完成（注意：回滚会把明文口令的描述一起带回来）"
    ;;
esac
