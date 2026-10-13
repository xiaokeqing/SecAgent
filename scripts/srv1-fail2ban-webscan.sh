#!/usr/bin/env bash
# ============================================================
# srv1：URL 级 Web 扫描 jail 的装机 / 状态 / 验证 / 回滚
# ------------------------------------------------------------
# 管的是这两个 jail（应用侧访问日志驱动，见 RUNBOOK §24）：
#   secagent-webscan       已知恶意路径 / 路径穿越（命中 2 次封 4h）
#   secagent-webscan-4xx   单 IP 2 分钟内 4xx ≥ 40（封 1h）
#
# 用法：
#   sudo bash srv1-fail2ban-webscan.sh --plan      # 只读：要动哪些文件、当前状态
#   sudo bash srv1-fail2ban-webscan.sh --apply     # 备份 -> 写 -> fail2ban-client -t -> 失败回滚 -> restart
#   sudo bash srv1-fail2ban-webscan.sh --status    # 现状（含内核链与真实解析能力）
#   sudo bash srv1-fail2ban-webscan.sh --verify    # 端到端：真探针 -> 真日志 -> 真封禁 -> 真解封
#   sudo bash srv1-fail2ban-webscan.sh --rollback  # 撤掉这两个 jail 的配置并恢复现场
#
# 纪律（CLAUDE.md 硬规矩 2）：
#   改配置一律 备份 -> 改 -> 校验 -> 失败自动回滚。
#   校验用 `fail2ban-client -t`（整份配置语法），生效用 `systemctl restart`
#   —— §21.5 实测过：reload 不会重跑 actionstart，新 action 的内核链根本不存在，
#      于是每次都"状态里封了、防火墙里没有"（假成功）。
# 【实测·很重要】本机的 actionstart 【不会】在 jail 启动时把内核链建出来
#   （2026-10-13 20:2x 实测：restart 后盯 70 秒，`iptables -S | grep f2b-` 一行都没有，
#     fail2ban.log 里连 ERROR 都没有 —— 不是失败，是"没做"）。
#   链与 INPUT 跳转是在【第一次真正封禁】时懒建出来的（`fail2ban-client set <jail> banip <ip>`
#   之后立刻出现 `-N f2b-<jail>` + `-A INPUT ... -j f2b-<jail>` + 拒绝规则）。
#   ⇒ 判据必须是"试封一个 RFC5737 地址，断言 链 / INPUT 跳转 / 规则 / 解封 四件事"，
#     而不是"重启后链在不在"。（§21 文档里那条 `iptables -S | grep f2b-` 的判断，
#     之所以当时成立，是因为那时候已经发生过真实封禁。）
# ============================================================
set -uo pipefail

REPO="${REPO:-/opt/secagent}"
JAIL_D=/etc/fail2ban/jail.d
FILTER_D=/etc/fail2ban/filter.d
SAMPLE_D=/etc/fail2ban/sample
BACKUP_ROOT=/etc/secagent/backup
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$BACKUP_ROOT/fail2ban-webscan-$STAMP"
ACCESS_LOG="${ACCESS_LOG:-/opt/secagent/data/access.jsonl}"
JAIL_NAME=secagent-webscan
JAIL_4XX=secagent-webscan-4xx
# 端到端验证用的源 IP：必须是 TEST-NET（RFC5737），保证不可能误封真实来源
PROBE_IP="${PROBE_IP:-198.51.100.9}"
# 第二个 jail 用另一个 TEST-NET 地址：避免两个 jail 的试封互相干扰（同名 IP 会串状态）
PROBE_IP_4XX="${PROBE_IP_4XX:-198.51.100.10}"
APP_URL="${APP_URL:-http://127.0.0.1:9900}"

ok()   { echo "  [OK]   $*"; }
bad()  { echo "  [FAIL] $*"; }
info() { echo "  ...    $*"; }
log()  { echo "==> $*"; }
die()  { echo "  [X] $*" >&2; exit 1; }

require_root() { [ "$(id -u)" = "0" ] || die "需要 root（容器/iptables/fail2ban 都要）"; }

# ------------------------------------------------------------
# 安全闸：只允许对 TEST-NET / 文档用网段做端到端封禁验证。
# 为什么必须有：这个 jail 的 action 是 iptables-allports[chain=INPUT]，
# 也就是【所有端口】。万一探针 IP 填成了自己的公网 IP，
# 下一次 SSH 就连不上了（把自己锁在门外）。
# ------------------------------------------------------------
assert_testnet() {
  case "$1" in
    192.0.2.*|198.51.100.*|203.0.113.*) return 0 ;;
    *) die "拒绝：$1 不是 RFC5737 文档用网段（只允许 192.0.2/24、198.51.100/24、203.0.113/24），
     因为本 jail 封的是 INPUT 全端口，误封自己的公网 IP 会直接把自己 SSH 锁在门外" ;;
  esac
}

paths() {
  echo "$FILTER_D/secagent-webscan.conf $FILTER_D/secagent-webscan-4xx.conf"
  echo "$JAIL_D/secagent-webscan.local"
  echo "$SAMPLE_D/secagent-webscan.sample.jsonl"
}

kernel_chain_has() { # $1=jail $2=ip
  iptables -S "f2b-$1" 2>/dev/null | grep -q -- "$2"
}

input_jump_exists() { # $1=jail   —— INPUT 有没有跳到这个链（没有跳转 = 封了也不生效）
  iptables -S INPUT 2>/dev/null | grep -q -- "-j f2b-$1"
}

# 试封一个 TEST-NET 地址，断言整条封禁路径：链 / INPUT 跳转 / 规则落地 / 解封干净。
# 返回 0 = 通过。
assert_ban_path() { # $1=jail $2=TEST-NET ip
  local j="$1" ip="$2" rc=0
  assert_testnet "$ip"
  fail2ban-client set "$j" banip "$ip" >/dev/null 2>&1 || { bad "$j: banip $ip 命令失败"; return 1; }
  sleep 1
  if kernel_chain_has "$j" "$ip"; then ok "$j: 规则落进内核链 f2b-$j"; else bad "$j: 内核链里没有 $ip（假封禁）"; rc=1; fi
  if input_jump_exists "$j"; then ok "$j: INPUT 已跳到 f2b-$j（封禁才真的生效）"; else bad "$j: INPUT 没有跳到 f2b-$j"; rc=1; fi
  iptables -S "f2b-$j" 2>/dev/null | sed 's/^/      /'
  iptables -S INPUT 2>/dev/null | grep -- "-j f2b-$j" | sed 's/^/      /'
  fail2ban-client set "$j" unbanip "$ip" >/dev/null 2>&1
  sleep 1
  if kernel_chain_has "$j" "$ip"; then bad "$j: 解封后规则还在"; rc=1; else ok "$j: 解封后规则已消失"; fi
  return $rc
}

status() {
  log "1/6 fail2ban 服务"
  echo "    服务: $(systemctl is-active fail2ban 2>/dev/null) ｜ 版本: $(fail2ban-client --version 2>/dev/null | head -1)"
  log "2/6 装机文件"
  local f
  for f in $FILTER_D/secagent-webscan.conf $FILTER_D/secagent-webscan-4xx.conf $JAIL_D/secagent-webscan.local; do
    if [ -f "$f" ]; then
      ok "$f  md5=$(md5sum "$f" | cut -d' ' -f1)"
    else
      bad "$f 不存在"
    fi
  done
  log "3/6 jail 状态"
  local j
  for j in $JAIL_NAME $JAIL_4XX; do
    if fail2ban-client status "$j" >/dev/null 2>&1; then
      fail2ban-client status "$j" | sed 's/^/    /'
    else
      bad "jail $j 不存在（未装机或配置被拒）"
    fi
  done
  log "4/6 内核链与 INPUT 跳转（封禁真的落地了没有）"
  echo "    注：链只在【发生过封禁】之后才存在（actionstart 在本机是懒建的，见脚本头实测记录）"
  iptables -S 2>/dev/null | grep -E "f2b-($JAIL_NAME|$JAIL_4XX)|-j f2b-($JAIL_NAME|$JAIL_4XX)" | sed 's/^/    /'
  input_jump_exists "$JAIL_NAME" && ok "INPUT -> f2b-$JAIL_NAME 跳转存在" \
    || info "INPUT -> f2b-$JAIL_NAME 还没有（本 jail 尚未封过任何 IP）"
  log "5/6 日志来源"
  if [ -f "$ACCESS_LOG" ]; then
    ok "$ACCESS_LOG 存在，$(wc -l < "$ACCESS_LOG") 行，最后修改 $(date -r "$ACCESS_LOG" '+%F %T')"
  else
    bad "$ACCESS_LOG 不存在 —— 应用侧访问日志没开（APP_ACCESSLOG_ENABLED=false？）或还没写第一行"
  fi
  log "6/6 过滤器对真实日志的解析能力"
  if [ -s "$ACCESS_LOG" ]; then
    for j in "$JAIL_NAME:$FILTER_D/secagent-webscan.conf" "$JAIL_4XX:$FILTER_D/secagent-webscan-4xx.conf"; do
      local name="${j%%:*}" filt="${j##*:}"
      [ -f "$filt" ] || continue
      echo "    --- $name ---"
      fail2ban-regex "$ACCESS_LOG" "$filt" 2>/dev/null | grep -E "^\s*(Lines|Matched|Missed)" | sed 's/^/    /'
    done
  else
    info "日志为空，跳过（先跑 --verify 造几条）"
  fi
}

plan() {
  log "计划（只读，不改任何东西）"
  echo "  仓库副本 : $REPO"
  echo "  装机     : $JAIL_D/secagent-webscan.local"
  echo "             $FILTER_D/secagent-webscan.conf"
  echo "             $FILTER_D/secagent-webscan-4xx.conf"
  echo "  日志来源 : $ACCESS_LOG"
  echo "  封禁动作 : iptables-allports[chain=INPUT]（§21.5：firewalld 系动作在本机是假成功）"
  echo "  备份到   : $BACKUP_ROOT/fail2ban-webscan-<时间戳>/"
  status
}

apply() {
  require_root
  [ -d "$REPO/deploy/fail2ban" ] || die "找不到 $REPO/deploy/fail2ban（仓库副本不完整？）"
  mkdir -p "$BACKUP" "$SAMPLE_D"
  log "1/6 备份现场"
  local f
  for f in $(paths); do
    if [ -f "$f" ]; then
      cp -a "$f" "$BACKUP/$(basename "$f")"
      ok "备份 $f"
    fi
  done
  { echo "stamp=$STAMP"; echo "repo=$REPO";
    for f in $(paths); do [ -f "$f" ] && echo "before $(basename "$f") $(md5sum "$f" | cut -d' ' -f1)"; done; } > "$BACKUP/MANIFEST"
  ok "备份目录 $BACKUP（回滚用 --rollback，或手工把这里的文件放回去）"

  log "2/6 写装机文件"
  install -m 0644 "$REPO/deploy/fail2ban/filter.d/secagent-webscan.conf"     "$FILTER_D/secagent-webscan.conf"
  install -m 0644 "$REPO/deploy/fail2ban/filter.d/secagent-webscan-4xx.conf" "$FILTER_D/secagent-webscan-4xx.conf"
  install -m 0644 "$REPO/deploy/fail2ban/jail.d/secagent-webscan.local"      "$JAIL_D/secagent-webscan.local"
  install -m 0644 "$REPO/deploy/fail2ban/sample/secagent-webscan.sample.jsonl" "$SAMPLE_D/secagent-webscan.sample.jsonl"
  for f in $(paths); do ok "$f md5=$(md5sum "$f" | cut -d' ' -f1)"; done

  log "3/6 校验配置（fail2ban-client -t）"
  if ! fail2ban-client -t >/tmp/f2b-t.out 2>&1; then
    bad "配置校验失败，自动回滚"
    sed 's/^/    /' /tmp/f2b-t.out
    rollback_from_backup
    die "已回滚（现场与改动前一致）"
  fi
  ok "配置语法通过"

  log "4/6 重启 fail2ban（必须 restart，不是 reload —— 见脚本头注释）"
  systemctl restart fail2ban || { bad "重启失败，回滚"; rollback_from_backup; die "回滚完成"; }
  sleep 3
  systemctl is-active --quiet fail2ban || { bad "fail2ban 没起来，回滚"; rollback_from_backup; systemctl restart fail2ban; die "回滚完成"; }
  ok "fail2ban active"

  log "5/6 断言 jail 与封禁路径真实可用（试封一个 RFC5737 地址）"
  local fail=0
  if fail2ban-client status "$JAIL_NAME" >/dev/null 2>&1; then ok "jail $JAIL_NAME 已加载"; else bad "jail $JAIL_NAME 未加载"; fail=1; fi
  if fail2ban-client status "$JAIL_4XX" >/dev/null 2>&1; then ok "jail $JAIL_4XX 已加载"; else bad "jail $JAIL_4XX 未加载"; fail=1; fi
  [ "$fail" = 0 ] && { assert_ban_path "$JAIL_NAME" "$PROBE_IP" || fail=1; }
  [ "$fail" = 0 ] && { assert_ban_path "$JAIL_4XX" "$PROBE_IP_4XX" || fail=1; }
  [ "$fail" = 0 ] || { bad "封禁路径没打通，回滚"; rollback_from_backup; systemctl restart fail2ban; die "回滚完成"; }

  log "6/6 用样本文件做过滤器自检（阳性 + 阴性对照）"
  verify_regex_only || bad "过滤器自检未达预期（见上）"
  echo
  ok "装机完成。下一步：sudo bash $0 --verify"
}

rollback_from_backup() {
  local f
  for f in "$JAIL_D/secagent-webscan.local" "$FILTER_D/secagent-webscan.conf" "$FILTER_D/secagent-webscan-4xx.conf" "$SAMPLE_D/secagent-webscan.sample.jsonl"; do
    local b="$BACKUP/$(basename "$f")"
    if [ -f "$b" ]; then cp -a "$b" "$f"; info "恢复 $f"; else rm -f "$f"; info "删除本次新增的 $f"; fi
  done
}

rollback() {
  require_root
  # 优先用最近一次备份；没有备份就按"本次新增"处理（直接删）
  local latest
  latest="$(ls -1d "$BACKUP_ROOT"/fail2ban-webscan-* 2>/dev/null | sort | tail -1)"
  if [ -n "$latest" ]; then BACKUP="$latest"; info "使用备份 $BACKUP"; else info "没有备份目录，按'本次新增'直接删除"; fi
  local j
  for j in $JAIL_NAME $JAIL_4XX; do
    fail2ban-client set "$j" unbanip "$PROBE_IP" >/dev/null 2>&1 || true
    fail2ban-client set "$j" unbanip "$PROBE_IP_4XX" >/dev/null 2>&1 || true
  done
  rollback_from_backup
  systemctl restart fail2ban
  sleep 3
  for j in $JAIL_NAME $JAIL_4XX; do
    if fail2ban-client status "$j" >/dev/null 2>&1; then bad "jail $j 仍然存在（回滚不彻底）"; else ok "jail $j 已移除"; fi
    if iptables -S 2>/dev/null | grep -q "f2b-$j"; then bad "内核链 f2b-$j 仍在"; else ok "内核链 f2b-$j 已消失"; fi
  done
  ok "回滚完成（fail2ban 已按原配置重启）"
}

# 只用样本文件测过滤器：阳性/阴性对照 + 日期模板命中数。
# 返回值 0 = 全部符合预期。
# 为什么连"日期模板命中数"也要断言：fail2ban 先用 datepattern 解析时间戳，
# 解析失败会退化成"用当前时间"（findtime 窗口就不准了）。命中数 = 行数
# 才说明我们的 ISO 时间戳真被认出来了。
verify_regex_only() {
  local sample="$SAMPLE_D/secagent-webscan.sample.jsonl"
  [ -f "$sample" ] || { bad "样本文件不存在: $sample"; return 1; }
  local out1 out2 m1 m2 d1 n1
  out1=$(fail2ban-regex "$sample" "$FILTER_D/secagent-webscan.conf" 2>/dev/null)
  out2=$(fail2ban-regex "$sample" "$FILTER_D/secagent-webscan-4xx.conf" 2>/dev/null)
  m1=$(echo "$out1" | grep -oE '[0-9]+ matched' | head -1 | awk '{print $1}')
  m2=$(echo "$out2" | grep -oE '[0-9]+ matched' | head -1 | awk '{print $1}')
  d1=$(echo "$out1" | grep -oE '^[|`]  \[[0-9]+\]' | head -1 | tr -dc '0-9')
  n1=$(echo "$out1" | grep -oE '^Lines: [0-9]+' | head -1 | awk '{print $2}')
  echo "    样本行数=${n1:-?}｜日期模板命中=${d1:-?}（必须等于行数）"
  echo "$out1" | grep -E '^Lines:' | sed 's/^/    [恶意路径过滤器] /'
  echo "$out2" | grep -E '^Lines:' | sed 's/^/    [4xx 过滤器]     /'
  echo "    期望：恶意路径过滤器 5 matched（/wp-login.php /.env /.git/config /phpmyadmin /etc/passwd）"
  echo "          4xx 过滤器     7 matched（上面 5 条 + /assets/old-image.png + /blog/some-post）"
  if [ "${m1:-0}" = "5" ] && [ "${m2:-0}" = "7" ] && [ "${d1:-0}" = "${n1:-9}" ]; then
    ok "阳性/阴性对照与日期解析都符合预期（4 条正常请求未被恶意路径过滤器命中）"
    return 0
  fi
  bad "过滤器自检没达到预期（先看样本文件是否被改过；若是 fail2ban 行为变化，本脚本会拒绝装机）"
  return 1
}

# 端到端：真探针 -> 真访问日志 -> 真封禁 -> 内核规则 -> 真解封
verify() {
  require_root
  assert_testnet "$PROBE_IP"
  echo "  探针源 IP（只写进 CF-Connecting-IP 头，不做任何伪造路由）: $PROBE_IP"
  echo "  目标: $APP_URL（本机回环 —— 这条路径正是'绕过 Cloudflare 直连源站'的形状）"
  echo

  log "1/6 过滤器对样本文件的对照"
  verify_regex_only || info "（不阻断后续步骤，但必须在报告里说明）"

  log "2/6 真探针：让应用自己记下 URL 级探测"
  local before after
  before=$(wc -l < "$ACCESS_LOG" 2>/dev/null || echo 0)
  local p
  for p in /wp-login.php /.env "/.git/config" "/phpmyadmin/index.php"; do
    curl -s -o /dev/null -m 5 -H "CF-Connecting-IP: $PROBE_IP" -H "User-Agent: secagent-webscan-selftest" \
      "$APP_URL$p" || true
  done
  sleep 1
  after=$(wc -l < "$ACCESS_LOG" 2>/dev/null || echo 0)
  if [ "$after" -gt "$before" ]; then
    ok "访问日志新增 $((after-before)) 行（应用真的把 URL 级探测记下来了）"
    echo "    --- 新增的最后 4 行（原样，未脱敏；含 TEST-NET 探针 IP）---"
    tail -n 4 "$ACCESS_LOG" | sed 's/^/    /'
  else
    die "访问日志没有新增行 —— 应用侧访问日志没生效（先看 RUNBOOK §24 的关闭/降级排查）"
  fi

  log "3/6 等待 fail2ban 按真实日志行触发封禁（maxretry=2）"
  local i banned=0
  for i in $(seq 1 20); do
    if fail2ban-client status "$JAIL_NAME" 2>/dev/null | grep -q "$PROBE_IP"; then banned=1; break; fi
    sleep 1
  done
  if [ "$banned" = 1 ]; then
    ok "fail2ban 已封禁 $PROBE_IP（来源=它自己读到的访问日志行）"
    fail2ban-client status "$JAIL_NAME" | sed 's/^/    /'
  else
    bad "没有触发封禁。诊断信息："
    echo "    --- jail 状态 ---"; fail2ban-client status "$JAIL_NAME" 2>&1 | sed 's/^/    /'
    echo "    --- 真实日志的过滤器命中数 ---"
    fail2ban-regex "$ACCESS_LOG" "$FILTER_D/secagent-webscan.conf" 2>/dev/null | grep -E "Matched|Missed|Lines" | sed 's/^/    /'
    echo "    --- fail2ban.log 尾部 ---"; tail -n 20 /var/log/fail2ban.log | sed 's/^/    /'
    die "封禁链路断了（别改结论，先把上面三段贴给站主）"
  fi

  log "4/6 内核规则落地（封禁不是只记在 fail2ban 状态里）"
  if kernel_chain_has "$JAIL_NAME" "$PROBE_IP"; then
    ok "iptables 链 f2b-$JAIL_NAME 里确实有 $PROBE_IP"
    iptables -S "f2b-$JAIL_NAME" | sed 's/^/    /'
  else
    die "fail2ban 说封了，但内核里没有这条规则 = 假成功（§21.5 的坑）。检查 action 与 restart"
  fi
  # 链里有规则还不够：INPUT 必须跳到这条链，否则规则永远不会被命中（另一种假成功）
  if input_jump_exists "$JAIL_NAME"; then
    ok "INPUT 链已跳到 f2b-$JAIL_NAME（这一段才是「封了真生效」的判据）"
    iptables -S INPUT | grep -- "-j f2b-$JAIL_NAME" | sed 's/^/    /'
  else
    die "回环：规则在 f2b-$JAIL_NAME 里，但 INPUT 没有跳到它 —— 封禁不会生效（假成功）"
  fi

  log "5/6 解封（unban）"
  fail2ban-client set "$JAIL_NAME" unbanip "$PROBE_IP" | sed 's/^/    /'
  sleep 1
  if kernel_chain_has "$JAIL_NAME" "$PROBE_IP"; then
    die "解封后内核规则还在（这就是'封了再也没解'的那类事故）"
  fi
  ok "内核规则已消失"
  fail2ban-client status "$JAIL_NAME" | sed 's/^/    /'

  log "6/6 留痕核对"
  echo "    --- /var/log/fail2ban.log 里的封禁/解封（供给 Wazuh 与事后审计）---"
  grep -E "($JAIL_NAME).*(Ban|Unban) $PROBE_IP" /var/log/fail2ban.log | tail -n 4 | sed 's/^/    /'
  grep -qE "Ban $PROBE_IP" /var/log/fail2ban.log && ok "fail2ban.log 有 Ban 留痕" || bad "fail2ban.log 里没有 Ban 留痕"
  grep -qE "Unban $PROBE_IP" /var/log/fail2ban.log && ok "fail2ban.log 有 Unban 留痕" || bad "fail2ban.log 里没有 Unban 留痕"
  echo
  ok "端到端验证完成：真探针 -> 真日志行 -> 真封禁 -> 内核规则 -> 真解封"
  echo
  echo "  ⚠️ 边界（务必一起理解，别把它当成'公网扫描被封住了'）："
  echo "     srv1 的公网入站是 cloudflared 隧道，真实访客流量从 Cloudflare 边缘进来。"
  echo "     本 jail 封的是应用日志里的真实访客 IP，在 srv1 上做 L3 封禁【挡不住该访客经 CF 的后续流量】。"
  echo "     它的价值是：检测+留痕+进 SIEM、以及挡住'绕过 CF 直连源站'。见 RUNBOOK §24 / §21.6。"
}

case "${1:---status}" in
  --plan)     plan ;;
  --apply)    apply ;;
  --status)   require_root; status ;;
  --verify)   verify ;;
  --rollback) rollback ;;
  *) echo "用法: $0 [--plan|--apply|--status|--verify|--rollback]"; exit 2 ;;
esac
