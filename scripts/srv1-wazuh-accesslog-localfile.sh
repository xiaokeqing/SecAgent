#!/usr/bin/env bash
# ============================================================
# srv1：给 Wazuh agent 加"访问日志 JSONL"的 localfile（带备份/校验/回滚）
# ------------------------------------------------------------
# 要做的事只有一件：让 agent 采集
#     /opt/secagent/data/access.jsonl
# 这个文件是应用侧访问日志（RUNBOOK §24），也是 URL 级扫描在 srv1 上
# 【唯一】的落点（§21.2 第 1 条：应用日志里根本没有这些请求）。
#
# 用法（在 srv1 上）：
#   sudo bash srv1-wazuh-accesslog-localfile.sh --plan
#   sudo bash srv1-wazuh-accesslog-localfile.sh --apply
#   sudo bash srv1-wazuh-accesslog-localfile.sh --status
#   sudo bash srv1-wazuh-accesslog-localfile.sh --rollback
#
# 【为什么用 log_format=json 而不是 multi-line-regex + out_format】
#   §21 对 app.log 用的是 multi-line-regex + out_format（因为那种日志行首是 ISO 时间戳，
#   级别词会在预解码阶段被吃掉，必须靠 out_format 把整行塞进正文）。
#   访问日志每一行本身就是【合法 JSON 对象】，用 json 格式让 manager 的内置 json 解码器
#   解出 data.ts/data.path/data.status/data.clientIp 等字段，
#   于是 manager 侧规则可以直接写 <field name="path">，不必再写"从自由文本抠 IP"的正则。
#   ⚠️ 也因此【不能】给这个 localfile 加 out_format：加了前缀就不再是 JSON，
#      内置 json 解码器立刻失效（规则会一条都不命中，而且不会有任何报错）。
#
# 【为什么改文件而不是整份覆盖 ossec.conf】
#   /var/ossec/etc/ossec.conf 是 §21 的产物（含 docker-listener 关闭、syscheck 收窄等
#   现场决策），当前只有服务器上有权威副本。整份覆盖的风险远大于"追加一段"：
#   这里做的是"幂等追加一个带标记的块"，并在失败时恢复备份。
# ============================================================
set -uo pipefail

MODE="--status"
BACKUP_ROOT=/etc/secagent/backup
CONF=/var/ossec/etc/ossec.conf
MARK="secagent-accesslog-jsonl"
ACCESS_LOG="${ACCESS_LOG:-/opt/secagent/data/access.jsonl}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR=""

ok()   { echo "  [OK]   $*"; }
bad()  { echo "  [FAIL] $*"; }
info() { echo "  ...    $*"; }
log()  { echo "==> $*"; }
die()  { echo "  [X] $*" >&2; exit 1; }
require_root() { [ "$(id -u)" = "0" ] || die "需要 root"; }

block() {
cat <<EOF
  <!-- $MARK：应用侧访问日志（URL 级扫描的落点，见 /opt/secagent/RUNBOOK.md §24）
       为什么是 json 格式：每行本身就是一个 JSON 对象，manager 用内置 json 解码器
       解出 data.* 字段供规则使用（<field name="path">/<field name="status">）。
       ⚠️ 不要给它加 out_format —— 加了前缀就不是 JSON 了，解码器会静默失效。 -->
  <localfile>
    <log_format>json</log_format>
    <location>$ACCESS_LOG</location>
    <only-future-events>yes</only-future-events>
  </localfile>
EOF
}

configtest() {
  # 依次尝试几个能校验配置的二进制；拿不到就如实说"没有校验手段"，
  # 而不是假装校验过了（§21 的纪律：没有证据就不要说"应该没问题"）。
  local bin
  for bin in wazuh-logcollector wazuh-agentd; do
    if [ -x "/var/ossec/bin/$bin" ]; then
      if "/var/ossec/bin/$bin" -t >/tmp/wazuh-t.out 2>&1; then
        echo "    [$bin -t] $(tail -n 1 /tmp/wazuh-t.out)"
        return 0
      else
        echo "    [$bin -t] 失败："
        sed 's/^/      /' /tmp/wazuh-t.out
        return 1
      fi
    fi
  done
  info "本机没有可用的 agent 配置校验二进制（-t）"
  return 2
}

status() {
  log "1/4 agent 状态"
  echo "    wazuh-agent: $(systemctl is-active wazuh-agent 2>/dev/null) ｜ $(/var/ossec/bin/wazuh-control info 2>/dev/null | grep WAZUH_VERSION | head -1)"
  log "2/4 ossec.conf 里的访问日志 localfile"
  if grep -q "$MARK" "$CONF" 2>/dev/null; then
    ok "已配置（标记 $MARK 存在）"
    grep -A6 "$MARK" "$CONF" | sed 's/^/    /'
  else
    bad "未配置 —— URL 级扫描不会进 SIEM"
  fi
  log "3/4 配置文件校验"
  configtest || bad "校验未通过（或没有校验手段）"
  log "4/4 agent 是否真的在读这个文件"
  if grep -q "$ACCESS_LOG" /var/ossec/logs/ossec.log 2>/dev/null; then
    grep "$ACCESS_LOG" /var/ossec/logs/ossec.log | tail -n 3 | sed 's/^/    /'
  else
    info "agent 日志里还没有关于 $ACCESS_LOG 的行（重启 agent 后才会出现）"
  fi
  [ -f "$ACCESS_LOG" ] && ok "$ACCESS_LOG 存在（$(wc -l < "$ACCESS_LOG") 行）" || bad "$ACCESS_LOG 不存在"
}

apply() {
  require_root
  [ -f "$CONF" ] || die "找不到 $CONF"

  # 【实测踩到的坑，务必保留这三行】原始属主/权限必须原样保留：
  #   /var/ossec/etc/ossec.conf 是 root:wazuh 0640，而 wazuh-agentd 以 uid 995(wazuh) 读它。
  #   我第一版用 `install -m 0600 -o root -g root` 写回 → 文件变成 root:root 0600 →
  #   agentd 报 "ERROR: (1226): Error reading XML file 'etc/ossec.conf': (line 0)"
  #   （注意 detail 是空的：这不是语法错，是【打不开】），systemd 单元直接 failed，
  #   srv1 的主机侧上报整条链路停摆。
  #   教训：改别人的系统配置文件时，属主/权限是配置的一部分，不是"顺手设一下"的装饰。
  ORIG_MODE="$(stat -c '%a' "$CONF")"
  ORIG_USER="$(stat -c '%U' "$CONF")"
  ORIG_GROUP="$(stat -c '%G' "$CONF")"

  BACKUP_DIR="$BACKUP_ROOT/wazuh-ossec-$STAMP"
  mkdir -p "$BACKUP_DIR"
  cp -a "$CONF" "$BACKUP_DIR/ossec.conf"
  echo "$CONF" > "$BACKUP_DIR/paths"
  printf 'mode=%s\nuser=%s\ngroup=%s\n' "$ORIG_MODE" "$ORIG_USER" "$ORIG_GROUP" > "$BACKUP_DIR/attrs"
  ok "备份 $CONF -> $BACKUP_DIR/ossec.conf（原始 ${ORIG_USER}:${ORIG_GROUP} ${ORIG_MODE}）"

  if grep -q "$MARK" "$CONF"; then
    ok "已存在标记 $MARK，幂等跳过（如需改路径先 --rollback）"
  else
    cp -a "$CONF" "$CONF.new"
    # 在 </ossec_config> 之前插入
    awk -v blk="$(block)" '
      /<\/ossec_config>/ && !done { print blk; done=1 }
      { print }
    ' "$CONF" > "$CONF.new"
    if ! grep -q "$MARK" "$CONF.new"; then die "插入失败（没找到 </ossec_config>？），未改动原文件"; fi
    install -m "$ORIG_MODE" -o "$ORIG_USER" -g "$ORIG_GROUP" "$CONF.new" "$CONF"
    rm -f "$CONF.new"
    ok "已追加 localfile 块（保持 ${ORIG_USER}:${ORIG_GROUP} ${ORIG_MODE}）"
  fi

  log "校验配置"
  configtest || true
  # 最关键的一条：agentd 是【降权】以 wazuh 用户读配置的，读不到就是起不来。
  if id wazuh >/dev/null 2>&1; then
    if sudo -u wazuh test -r "$CONF"; then
      ok "wazuh 用户可读 $CONF（agentd 降权后读的就是它）"
    else
      bad "wazuh 用户读不了 $CONF —— agentd 会直接起不来，回滚"
      restore_conf "$BACKUP_DIR"
      die "已回滚（原因：属主/权限）"
    fi
  fi

  log "重启 agent"
  systemctl reset-failed wazuh-agent >/dev/null 2>&1 || true
  systemctl restart wazuh-agent
  sleep 5
  if systemctl is-active --quiet wazuh-agent; then ok "wazuh-agent active"; else
    bad "agent 没起来 —— 回滚"
    restore_conf "$BACKUP_DIR"
    systemctl restart wazuh-agent || true
    die "已回滚"
  fi

  log "确认 agent 开始读 $ACCESS_LOG"
  local i
  for i in $(seq 1 10); do
    if grep -q "$ACCESS_LOG" /var/ossec/logs/ossec.log 2>/dev/null; then break; fi
    sleep 1
  done
  if grep -q "$ACCESS_LOG" /var/ossec/logs/ossec.log 2>/dev/null; then
    ok "logcollector 已登记该文件"
    grep "$ACCESS_LOG" /var/ossec/logs/ossec.log | tail -n 2 | sed 's/^/    /'
  else
    bad "agent 日志里没看到 $ACCESS_LOG —— 采集没生效，请人工确认（不要当成成功）"
  fi
  ok "完成。备份目录：$BACKUP_DIR"
}

rollback() {
  require_root
  local d
  d="$(ls -1d "$BACKUP_ROOT"/wazuh-ossec-* 2>/dev/null | sort | tail -1)"
  [ -n "${d:-}" ] || die "没有备份目录 $BACKUP_ROOT/wazuh-ossec-*"
  info "回滚到 $d"
  restore_conf "$d"
  systemctl reset-failed wazuh-agent >/dev/null 2>&1 || true
  systemctl restart wazuh-agent
  sleep 5
  ok "已恢复并重启：$(systemctl is-active wazuh-agent)"
  grep -q "$MARK" "$CONF" && bad "标记仍在（回滚不彻底）" || ok "标记已消失"
}

# 用备份恢复配置，并且【原样恢复属主/权限】（attrs 文件是装机时写下的原始值）。
# 没有 attrs（老备份）时退回 root:wazuh 0640 —— 那是这台机器的实际值。
restore_conf() { # $1=备份目录
  local d="$1" mode=640 user=root group=wazuh
  if [ -f "$d/attrs" ]; then
    # shellcheck disable=SC1090
    . "$d/attrs"
    mode="${mode:-640}"; user="${user:-root}"; group="${group:-wazuh}"
  fi
  install -m "$mode" -o "$user" -g "$group" "$d/ossec.conf" "$CONF"
  info "已恢复 $CONF（${user}:${group} ${mode}）"
}

case "${1:---status}" in
  --plan)     require_root; echo "计划：给 $CONF 追加 localfile（采集 $ACCESS_LOG，json 格式），备份到 $BACKUP_ROOT/wazuh-ossec-<时间戳>/"; status ;;
  --apply)    apply ;;
  --status)   require_root; status ;;
  --rollback) rollback ;;
  *) echo "用法: $0 [--plan|--apply|--status|--rollback]"; exit 2 ;;
esac
