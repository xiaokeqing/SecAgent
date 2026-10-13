#!/usr/bin/env bash
# ============================================================
# srv2：把 Dionaea 接进日志与告警链路（Wazuh manager）
# ------------------------------------------------------------
# 做三件事，每件都带"备份 -> 写 -> 校验 -> 失败回滚"：
#   1) 给 wazuh.manager 容器挂上 Dionaea 日志目录（只读）
#      为什么必须挂：Wazuh 跑在容器里，Dionaea 的日志写在【宿主】/opt/dionaea/var 下。
#      不挂载的话 ossec.conf 里的 localfile 路径在容器内不存在 —— 配置看着完全正确、
#      实际永远读不到。这个坑本项目已经踩过一次（见 override 里 cowrie/suricata 的注释）。
#   2) wazuh_manager.conf 加 localfile：dionaea.json(json) + dionaea.log + dionaea-errors.log
#      —— dionaea.log 是 C 侧文本日志（dionaea.cfg 里 default.levels 已去掉 debug，
#         否则空载就有 ~78KB/15s 的噪声，会淹掉真告警）；errors 是它的告警/错误子集。
#   3) 装规则 srv2_dionaea_rules.xml
#      —— **必须过 wazuh-analysisd -t 门禁**：规则写错会让 analysisd 拒绝启动，
#         也就是"加一条规则把整个 SIEM 弄挂"（本项目已记录的事故教训）。
#         门禁不过就自动回滚并重启，绝不留一个起不来的 SIEM。
#
# 用法（srv2，root）：
#   bash scripts/srv2-dionaea-wire-wazuh.sh --plan
#   sudo bash scripts/srv2-dionaea-wire-wazuh.sh --apply     # 卷 + localfile + 规则 + 重启 + 自测
#   sudo bash scripts/srv2-dionaea-wire-wazuh.sh --check
#   sudo bash scripts/srv2-dionaea-wire-wazuh.sh --rollback
# ============================================================
set -uo pipefail

MODE="--plan"
while [ $# -gt 0 ]; do
  case "$1" in
    --plan|--apply|--check|--rollback) MODE="$1"; shift ;;
    --src) SRC_OVERRIDE="$2"; shift 2 ;;
    *) echo "[X] 未知参数：$1"; exit 2 ;;
  esac
done

REPO_ROOT=${SRC_OVERRIDE:-$(cd "$(dirname "$0")/.." && pwd)}
RULES_SRC="$REPO_ROOT/deploy/wazuh/srv2_dionaea_rules.xml"
COMPOSE_SRC="$REPO_ROOT/deploy/srv2-dionaea/docker-compose.yml"

WAZUH_DIR=/opt/wazuh
CONF="$WAZUH_DIR/config/wazuh_cluster/wazuh_manager.conf"
OVERRIDE="$WAZUH_DIR/docker-compose.override.yml"
HOSTDIR="$WAZUH_DIR/config/wazuh_cluster/rules"
RULES_DEST="$HOSTDIR/srv2_dionaea_rules.xml"
BACKUP_ROOT=/var/backups/secagent/wazuh-rules
LOG_DIR=/opt/dionaea/var/log/dionaea
D="docker exec wazuh.manager"

C_CY='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_0='\033[0m'
log()  { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }
ok()   { printf "  ${C_OK}[OK]${C_0} %s\n" "$*"; }
warn() { printf "  ${C_WARN}[!]${C_0}  %s\n" "$*"; }
die()  { printf "  ${C_ERR}[X]${C_0} %s\n" "$*" >&2; exit 1; }

# analysisd 规则语法门禁（-t 不通过 = 规则会让 SIEM 起不来）
test_rules() { $D /var/ossec/bin/wazuh-analysisd -t 2>&1; }
bounce()     { $D /var/ossec/bin/wazuh-control restart >/dev/null 2>&1; sleep 8; }

# manager 存活判据：不能用 wazuh-control status 的返回码（默认有服务本来就不跑，它总是非 0）
manager_alive() {
  local st
  st="$($D /var/ossec/bin/wazuh-control status 2>&1 || true)"
  echo "$st" | grep -q 'wazuh-analysisd is running'
}

save_backup() { # $1=标签  产出 $d（备份目录）
  ts="$(date +%Y%m%d-%H%M%S)"; d="$BACKUP_ROOT/dionaea-$1-$ts"
  mkdir -p "$d"; : > "$d/manifest"
  for f in "$CONF" "$OVERRIDE" "$RULES_DEST"; do
    if [ -e "$f" ]; then
      cp -a "$f" "$d/$(basename "$f")"
      printf 'yes\t%s\t%s\n' "$f" "$(basename "$f")" >> "$d/manifest"
    else
      printf 'no\t%s\t%s\n' "$f" "$(basename "$f")" >> "$d/manifest"
    fi
  done
  ln -sfn "$d" "$BACKUP_ROOT/dionaea-last"
  cat > "$d/restore.sh" <<'RESTORE'
#!/usr/bin/env bash
# 回滚：把 wazuh manager 的配置恢复到备份时的状态并重启
set -u
D="$(cd "$(dirname "$0")" && pwd)"
while IFS=$'\t' read -r existed target name; do
  if [ "$existed" = "yes" ]; then
    install -m 0644 -o root -g root "$D/$name" "$target" && echo "  restored $target"
  else
    [ -e "$target" ] && rm -f "$target" && echo "  removed  $target"
  fi
done < "$D/manifest"
rm -f /opt/wazuh/config/wazuh_cluster/rules/srv2_dionaea_rules.xml 2>/dev/null || true
( cd /opt/wazuh && docker compose up -d wazuh.manager >/dev/null 2>&1 ) || docker restart wazuh.manager >/dev/null 2>&1 || true
sleep 10
echo "  回滚后 analysisd: $(docker exec wazuh.manager /var/ossec/bin/wazuh-control status 2>&1 | grep -c 'wazuh-analysisd is running') (1=在跑)"
RESTORE
  chmod +x "$d/restore.sh"
}

# ---------- XML 良构性校验（wazuh_manager.conf 是多段 ossec_config，不是单根 XML）
# 这段逻辑来自 scripts/srv2-wazuh-collect-logs.sh（那里记着"用 minidom 直接 parse
# 会把合法的多段文件判成非法"这个坑）。但 2026-10-14 又踩到它的另一面：
#
#   【既有配置文件本身就不满足严格 XML】—— 第 353 行是一条注释里的分隔线
#       ------------------------------------------------------------
#   XML 规范不允许注释里出现 '--'，Expat 直接报
#       not well-formed (invalid token): line 353, column 9
#   而 **Wazuh 自己接受这个文件**（manager 一直跑得好好的）。
#   也就是说："严格 XML 校验"比 Wazuh 真实要求更严 —— 照它判，
#   这台机器上【任何】对 ossec.conf 的改动都会被拦下来，这是个会一直误报的检查器。
#   （本项目已经记录过 6 次"检查器给出错误结论"，这是第 7 种形态：把既有的小毛病
#     当成"你改坏了"。）
#
# 所以这里的口径是：
#   · 先剥掉所有注释再校验 —— 既有的"注释里的 --"不再误报，
#     而真正的结构性错误（标签没闭合、多出字符）照样会被抓到；
#   · 注释没闭合这类真错误，因为剥不掉，仍然会报错；
#   · 最终的安全网仍然是"重启后 analysisd 到底起没起来"（起不来就自动回滚）。
check_xml() {
  python3 - "$CONF" <<'PYEOF'
import sys, re, xml.dom.minidom
p = sys.argv[1]
c = open(p, encoding="utf-8").read()
op, cl = c.count("<ossec_config>"), c.count("</ossec_config>")
if op != cl:
    print("  ossec_config open/close mismatch: %d vs %d" % (op, cl)); sys.exit(1)
if re.search(r"<!--(?:(?!-->).)*--(?:(?!-->).)*-->", c, re.S):
    print("  [note] 文件里已有注释含 '--'（XML 规范不允许，但 Wazuh 接受）:")
    for i, l in enumerate(c.split("\n"), 1):
        if re.match(r"^\s*-{4,}\s*$", l):
            print("         line %d: %s" % (i, l.strip())); break
    print("         校验时已剥离注释，不把这个既有小毛病算成'我们改坏了'")
stripped = re.sub(r"<!--.*?-->", "", c, flags=re.S)
try:
    xml.dom.minidom.parseString("<__root__>" + stripped + "</__root__>")
    print("  XML OK (comments stripped); %d ossec_config sections" % op)
except Exception as e:
    print("  parse failed: %s %s" % (type(e).__name__, str(e)[:150])); sys.exit(1)
PYEOF
}

# ---------- 把 Dionaea 日志目录挂进 wazuh.manager（改 override，不动上游 compose）
wire_volume() {
  python3 - "$OVERRIDE" <<'PYEOF'
import sys
p = sys.argv[1]
src = open(p, encoding="utf-8").read()
want = "      - /opt/dionaea/var:/opt/dionaea/var:ro"
if "/opt/dionaea/var:/opt/dionaea/var:ro" in src:
    print("  volume already present, skip"); sys.exit(0)
lines = src.split("\n")
# 定位 wazuh.manager 段
start = None
for i, l in enumerate(lines):
    if l.strip() == "wazuh.manager:" and not l.startswith("      "):
        start = i; break
if start is None:
    print("  ERROR: wazuh.manager section not found"); sys.exit(1)
# 在它之后找 volumes:，再插到该 list 的末尾
vi = None
for i in range(start + 1, len(lines)):
    l = lines[i]
    if l.strip() and not l.startswith(" ") and not l.startswith("#"):
        break          # 下一个顶层字段，说明该段结束
    if l.strip() == "volumes:":
        vi = i; break
if vi is None:
    print("  ERROR: volumes: not found under wazuh.manager"); sys.exit(1)
j = vi + 1
while j < len(lines) and (lines[j].startswith("      - ") or lines[j].strip() == ""):
    if lines[j].strip() == "":
        break
    j += 1
lines.insert(j, want)
open(p, "w", encoding="utf-8").write("\n".join(lines))
print("  inserted volume at line %d" % (j + 1))
PYEOF
}

# ---------- 加 localfile
wire_localfile() {
  python3 - "$CONF" <<'PYEOF'
import sys
p = sys.argv[1]
src = open(p, encoding="utf-8").read()
if "/opt/dionaea/var/log/dionaea/dionaea.json" in src:
    print("  localfile already present, skip"); sys.exit(0)
block = """
  <!-- ===== 蜜罐日志（Dionaea，srv2 本地）=====
       dionaea.json 是结构化事件（一行一个 JSON，连接结束时落盘），
       规则 srv2_dionaea_rules.xml 就是匹配它的 connection.protocol 字段。
       dionaea.log 是 C 侧文本日志（已在 dionaea.cfg 里去掉 debug 级，
       否则空载 15 秒就 78KB，会把真告警淹掉）；
       dionaea-errors.log 是它自己的 warning/error 子集。
       挂载见 docker-compose.override.yml: /opt/dionaea/var -> 容器内同路径 (ro)。 -->
  <localfile>
    <log_format>json</log_format>
    <location>/opt/dionaea/var/log/dionaea/dionaea.json</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/opt/dionaea/var/log/dionaea/dionaea.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/opt/dionaea/var/log/dionaea/dionaea-errors.log</location>
  </localfile>

"""
idx = src.rfind("</ossec_config>")
if idx == -1:
    print("  ERROR: </ossec_config> not found"); sys.exit(1)
open(p, "w", encoding="utf-8").write(src[:idx] + block + src[idx:])
print("  appended 3 localfile entries")
PYEOF
}

# ---------- 功能自测：规则到底会不会命中（比"配置写对了"更硬）
# 【踩坑】`wazuh-control status` 说 analysisd 在跑，不等于它已经装载完规则并开始服务：
#   wazuh-logtest 要连 analysisd，重启后头几十秒会拿不到结果 ——
#   表现就是"规则明明是对的，自测却报不命中"，很容易把人带去改对的规则。
#   所以这里改成"重试到拿到结果为止"，而不是一把梭。
functional_test() {
  local sample out i
  sample='{"connection": {"protocol": "mysqld", "transport": "tcp", "type": "accept"}, "dst_ip": "172.19.0.4", "dst_port": 3306, "src_hostname": "", "src_ip": "203.0.113.9", "src_port": 51234, "timestamp": "2026-10-14T00:00:00.000000"}'
  for i in $(seq 1 18); do
    # 注意必须是 `docker exec -i`：logtest 从 stdin 读日志行，
    # 少了 -i 它拿不到输入，输出只有两行横幅 —— 看起来像"规则没命中"，
    # 实际是"根本没喂进去"（这个坑让自测白白误报了一轮）。
    out=$(printf '%s\n' "$sample" | docker exec -i wazuh.manager /var/ossec/bin/wazuh-logtest 2>&1)
    if echo "$out" | grep -q "100302"; then
      echo "$out" | grep -E "Phase 2|connection\.protocol|Phase 3|^	id:|^	level:|^	description:" | sed 's/^/    /'
      ok "wazuh-logtest 命中规则 100302（MySQL 连接尝试）—— 字段名与规则都生效（第 $i 次尝试）"
      return 0
    fi
    sleep 5
  done
  warn "18 次重试（90 秒）都没命中 100302 —— 规则或字段名确实有问题"
  echo "$out" | tail -20 | sed 's/^/    /'
  return 1
}

case "$MODE" in
  --plan)
    log "现状（只读）"
    echo "  仓库副本: $RULES_SRC"
    [ -f "$RULES_SRC" ] && ok "规则源文件存在（$(stat -c %s "$RULES_SRC") 字节）" || warn "规则源文件不存在"
    echo "  override 里是否已挂 Dionaea 日志目录: $(grep -c '/opt/dionaea/var' "$OVERRIDE" 2>/dev/null || echo 0)"
    echo "  ossec.conf 里是否已有 Dionaea localfile: $(grep -c 'dionaea/dionaea.json' "$CONF" 2>/dev/null || echo 0)"
    echo "  已装规则文件: $([ -f "$RULES_DEST" ] && echo 有 || echo 无)"
    echo "  日志目录（宿主）: $([ -d "$LOG_DIR" ] && ls -la "$LOG_DIR" | sed 's/^/    /' || echo '    还不存在')"
    echo "  容器内能不能看到日志目录:"
    $D sh -c 'ls -la /opt/dionaea/var/log/dionaea/ 2>&1 | head -5' 2>/dev/null | sed 's/^/    /'
    echo "  analysisd 规则语法现状:"
    test_rules | sed 's/^/    /' || true
    ;;

  --apply)
    log "1/6 前置检查"
    [ "$(id -u)" = "0" ] || die "需要 root"
    docker ps --format '{{.Names}}' | grep -qx wazuh.manager || die "manager 容器没在跑"
    [ -f "$RULES_SRC" ] || die "找不到规则源文件 $RULES_SRC"
    [ -d "$LOG_DIR" ] || die "找不到 Dionaea 日志目录 $LOG_DIR（先把 Dionaea 跑起来）"
    ok "前置通过"

    log "2/6 备份"
    save_backup apply
    ok "备份在 $d"

    log "3/6 挂载 Dionaea 日志目录（改 override，不动上游 compose）"
    cp -a "$OVERRIDE" "$d/docker-compose.override.yml" 2>/dev/null || true
    wire_volume || die "写 override 失败"
    grep -n 'dionaea' "$OVERRIDE" | sed 's/^/    /'

    log "4/6 加 localfile"
    wire_localfile || die "写 localfile 失败"
    if check_xml; then ok "XML 结构校验通过"; else
      warn "XML 校验失败 —— 回滚 conf 与 override"
      cp -a "$d/wazuh_manager.conf" "$CONF"
      cp -a "$d/docker-compose.override.yml" "$OVERRIDE" 2>/dev/null || true
      die "已回滚 ossec.conf 与 override"
    fi
    grep -n 'dionaea' "$CONF" | sed 's/^/    /'

    log "5/6 装规则 + analysisd -t 门禁"
    install -m 0644 -o root -g root "$RULES_SRC" "$RULES_DEST" && ok "写入 $RULES_DEST"
    # 让容器重建（拿到新挂载）后再校验规则语法
    ( cd "$WAZUH_DIR" && docker compose up -d wazuh.manager >/dev/null 2>&1 ) || die "compose up 失败"
    sleep 20
    if OUT="$(test_rules)"; then
      echo "$OUT" | sed 's/^/    /'; ok "规则语法通过（analysisd -t）"
    else
      echo "$OUT" | sed 's/^/    /'
      warn "规则语法不通过 —— 自动回滚（否则 analysisd 起不来，整个 SIEM 停摆）"
      ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
      die "已回滚，请修 $RULES_SRC 后重试"
    fi

    log "6/6 重启 manager 生效 + 自测"
    bounce
    if manager_alive; then ok "analysisd 在跑"; else
      warn "analysisd 没起来 —— 回滚"
      ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
      die "已回滚"
    fi
    echo "  --- 容器内看得见日志了吗（这是"配置对但读不到"的经典坑）---"
    $D sh -c 'ls -la /opt/dionaea/var/log/dionaea/ 2>&1 | head -6' | sed 's/^/    /'
    echo "  --- logcollector 有没有报 Could not open ---"
    $D sh -c 'grep -ai "dionaea" /var/ossec/logs/ossec.log 2>/dev/null | tail -6' | sed 's/^/    /'
    functional_test || warn "功能自测没通过，请检查（规则可能不触发）"
    ok "接入完成"
    ;;

  --check)
    log "体检"
    echo "  override 挂载:"; grep -n 'dionaea' "$OVERRIDE" 2>/dev/null | sed 's/^/    /'
    echo "  localfile:"; grep -n 'dionaea' "$CONF" 2>/dev/null | sed 's/^/    /'
    echo "  容器内可见性:"; $D sh -c 'ls -la /opt/dionaea/var/log/dionaea/ 2>&1 | head -6' 2>/dev/null | sed 's/^/    /'
    echo "  规则文件:"; ls -la "$RULES_DEST" 2>/dev/null | sed 's/^/    /' || echo "    （未安装）"
    echo "  规则语法:"; test_rules | sed 's/^/    /' || true
    echo "  analysisd:"; manager_alive && ok "在跑" || warn "没在跑"
    echo "  功能自测:"; functional_test || true
    ;;

  --rollback)
    log "回滚"
    d="$(readlink -f "$BACKUP_ROOT/dionaea-last" 2>/dev/null || true)"
    [ -n "$d" ] && [ -d "$d" ] || die "没有备份"
    echo "  用备份 $d"
    ( cd "$d" && ./restore.sh ) | sed 's/^/  /'
    ok "回滚完成"
    ;;
esac
