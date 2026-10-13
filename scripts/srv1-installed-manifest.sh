#!/usr/bin/env bash
# ============================================================
# 已安装落点完整性检查（srv1 / srv2 通用）
# ------------------------------------------------------------
# 解决什么问题：仓库里改了脚本，服务器上"装到 /etc 的那些副本"不会自动跟着变；
# 反过来，服务器上有人手改了 unit / jail / wazuh 规则也不会有人知道。
# 今天已经吃过两次亏：① 20 个落地物只存在于服务器 ② 脚本可执行位被 reset 抹掉。
#
# 做法：把一批"安装落点"的 sha256 抓一份基线（--capture），之后每次 --check 比对：
#   缺失（文件没了）/ 变更（内容被改）/ 新增（出现未登记的同名族文件）→ 全部报出来，
#   有任何差异 → exit 1（fail-closed），并写 logs/installed-drift.txt。
# **注意口径**：这是"相对基线"的检查，不是"与仓库比" —— 所以不会有"install 时改了路径"那类假失败。
#
# 用法：bash srv1-installed-manifest.sh --capture     重新做基线（改配置后必须做，并在 RUNBOOK 记一笔）
#       bash srv1-installed-manifest.sh --check       比对（默认）
#       bash srv1-installed-manifest.sh --list        只打印当前会纳入检查的路径
# 环境变量：MANIFEST_STATE（默认 /opt/secagent/state/installed-manifest.sha256）
# ============================================================
set -uo pipefail
APP=/opt/secagent
STATE="${MANIFEST_STATE:-$APP/state/installed-manifest.sha256}"
REPORT="$APP/logs/installed-drift.txt"
MODE="${1:---check}"

# 纳入检查的"安装落点"（用 glob；不存在的跳过，不算失败）
PATTERNS=(
  "/etc/systemd/system/secagent-*.service"
  "/etc/systemd/system/secagent-*.timer"
  "/etc/systemd/system/srv1-*.service"
  "/etc/systemd/system/srv1-*.timer"
  "/etc/systemd/system/srv2-*.service"
  "/etc/systemd/system/srv2-*.timer"
  "/etc/systemd/system/secagent-netfilter-restore.service"
  "/etc/systemd/system/cowrie*.service"
  "/etc/fail2ban/jail.d/*.local"
  "/etc/fail2ban/jail.local"
  "/etc/fail2ban/filter.d/secagent-*.conf"
  "/etc/cron.d/*secagent*"
  "/etc/cron.d/disk-guard"
  "/etc/logrotate.d/secagent-*"
  "/usr/local/sbin/secagent-*"
  "/etc/wazuh-agent/ossec.conf"
  "/var/ossec/etc/ossec.conf"
  "/var/ossec/etc/rules/srv1_local_rules.xml"
  "/opt/wazuh-docker/single-node/config/wazuh_cluster/rules/srv1_local_rules.xml"
  # ===== 2026-10-14 新增：Dionaea 蜜罐（srv2）的落点 =====
  # 为什么这几个要进来：它们都是"手改过 /etc 或 /opt"的落点，
  # 出错时的表现都很隐蔽（规则写错 SIEM 停摆、隔离脚本被改回 -I 1 就又出洞），
  # 所以必须和其他落点一样进基线。
  "/usr/local/sbin/srv2-dionaea-*.sh"          # 安装/自检/启停/清理
  "/usr/local/sbin/srv2-honeypot-egress-probe.sh"  # 隔离实测探针
  "/usr/local/sbin/cowrie-egress-lock.sh"      # 蜜罐网段 egress 锁定（注释里记着那次洞的教训）
  "/opt/dionaea/*.yml"                         # docker-compose.yml
  "/opt/dionaea/etc/dionaea/dionaea.cfg"       # 被 install 脚本改过 default.levels
  "/opt/dionaea/etc/dionaea/ihandlers-available/log_json.yaml"  # 修过路径的 JSON handler
  "/opt/wazuh/config/wazuh_cluster/rules/srv2_dionaea_rules.xml"
)

collect() { # 输出 "sha256  path" 行，按路径排序
  local p f
  for p in "${PATTERNS[@]}"; do
    for f in $p; do
      [ -f "$f" ] || continue
      printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"
    done
  done | sort -k2
}

case "$MODE" in
  --list) collect | sed 's/^/  /'; echo "  共 $(collect | wc -l) 个落点"; exit 0;;
  --capture)
    mkdir -p "$(dirname "$STATE")"
    { echo "# installed-manifest v1  host=$(hostname -s)  captured=$(date '+%F %T %z')"; collect; } > "$STATE"
    chmod 600 "$STATE"
    echo "  已写基线：$STATE（$(grep -vc '^#' "$STATE") 个落点）"
    exit 0;;
  --check) ;;
  *) echo "用法: $0 [--check|--capture|--list]" >&2; exit 2;;
esac

if [ ! -f "$STATE" ]; then
  echo "  [X] 没有基线文件 $STATE —— 先跑 --capture（这是 fail-closed：没有基线就不给'通过'的结论）" >&2
  exit 2
fi

NOW=$(mktemp); trap 'rm -f "$NOW"' EXIT
collect > "$NOW"
BASE_BODY=$(mktemp); grep -v '^#' "$STATE" > "$BASE_BODY" || true

MISSING=$(comm -23 <(awk '{print $2}' "$BASE_BODY" | sort) <(awk '{print $2}' "$NOW" | sort))
ADDED=$(comm -13 <(awk '{print $2}' "$BASE_BODY" | sort) <(awk '{print $2}' "$NOW" | sort))
CHANGED=""
while IFS= read -r line; do
  [ -n "$line" ] || continue
  h=${line%%  *}; p=${line#*  }
  bh=$(awk -v path="$p" '$2==path {print $1}' "$BASE_BODY" | head -n 1)
  [ -n "$bh" ] && [ "$bh" != "$h" ] && CHANGED="$CHANGED$p"$'\n'
done < "$NOW"

CNT_M=$(printf '%s' "$MISSING" | grep -c . || true)
CNT_A=$(printf '%s' "$ADDED" | grep -c . || true)
CNT_C=$(printf '%s' "$CHANGED" | grep -c . || true)
TOTAL=$(wc -l < "$NOW")

{
  echo "installed-manifest check  host=$(hostname -s)  time=$(date '+%F %T')  baseline=$(head -n1 "$STATE" | sed 's/^# //')"
  echo "  files=$TOTAL  missing=$CNT_M  changed=$CNT_C  added=$CNT_A"
  [ "$CNT_M" -gt 0 ] && { echo "  [missing] 基线里有、现在没了（被删/搬走）："; printf '%s\n' "$MISSING" | sed 's/^/    /'; }
  [ "$CNT_C" -gt 0 ] && { echo "  [changed] 内容被改（有人手改了 /etc 下的副本）："; printf '%s\n' "$CHANGED" | grep . | sed 's/^/    /'; }
  [ "$CNT_A" -gt 0 ] && { echo "  [added] 出现未登记的同族文件（新装的没进基线）："; printf '%s\n' "$ADDED" | sed 's/^/    /'; }
} > "$REPORT"
head -n 2 "$REPORT" | sed 's/^/  /'

if [ "$CNT_M" -eq 0 ] && [ "$CNT_C" -eq 0 ] && [ "$CNT_A" -eq 0 ]; then
  echo "  落点完整性: OK（$TOTAL 个落点与基线一致）"
  exit 0
fi
echo "  落点完整性: **有差异** —— 明细：$REPORT"
echo "  处理：① 确认改动是有意的 → 跑 --capture 重做基线并把原因写进 RUNBOOK；② 非预期 → 从仓库 deploy/ 重新安装"
exit 1
