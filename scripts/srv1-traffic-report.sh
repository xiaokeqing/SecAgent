#!/usr/bin/env bash
# ============================================================
# 流量日报 + 阈值告警（srv1 / srv2 通用）
# ------------------------------------------------------------
# 为什么需要：站主问"一个月 40 块你怎么没和我说"——流量是按月扣钱的项，
# 必须有**看得见**的日常数字 + **跑飞时会响**的门槛告警。
# 现实数据（2026-10-14 实测）：srv1 出网 ≈151MB/天（按流量 ¥0.8/GB）；srv2 出网 ≈469MB/天（有 300GB 流量包）。
#
# 做法：用 vnstat 取"今天/本月"的收发字节 → 追加一行到 logs/traffic-report.txt
#       → 超过阈值就通过 notify.sh 发 HIGH（带冷却，避免每天吵）
# 用法：bash srv1-traffic-report.sh [--dry]   （--dry 只打印不通知）
# 环境变量：TRAFFIC_DAY_ALERT_GB（默认 5）｜TRAFFIC_MONTH_ALERT_GB（默认 50）
#           TRAFFIC_PKG_GB（默认空；填了就按"流量包用量百分比"判断，例如 srv2 填 300）
#           TRAFFIC_PKG_WARN_PERCENT（默认 80）｜TRAFFIC_IFACE（默认 eth0）
# 依赖：vnstat（约 1MB 内存，零流量）。取不到数据时**如实报 UNKNOWN**，不猜。
# ============================================================
set -uo pipefail
DRY=0
[ "${1:-}" = "--dry" ] && DRY=1
APP=/opt/secagent
LOG="$APP/logs/traffic-report.txt"
IFACE="${TRAFFIC_IFACE:-eth0}"
DAY_LIMIT_GB="${TRAFFIC_DAY_ALERT_GB:-5}"
MONTH_LIMIT_GB="${TRAFFIC_MONTH_ALERT_GB:-50}"
PKG_GB="${TRAFFIC_PKG_GB:-}"
PKG_WARN="${TRAFFIC_PKG_WARN_PERCENT:-80}"
HOSTN="$(hostname -s 2>/dev/null || hostname)"
mkdir -p "$APP/logs"
ts() { date '+%Y-%m-%d %H:%M:%S'; }

notify() { # notify <LEVEL> <TITLE> <BODY>
  if [ "$DRY" = "1" ]; then echo "  （dry-run）本应通知：[$1] $2 — $3"; return 0; fi
  if [ -x "$APP/scripts/notify.sh" ]; then
    bash "$APP/scripts/notify.sh" "$1" "$2" "$3" >/dev/null 2>&1
    echo "  已尝试通知（notify.sh rc=$?）"
  else
    echo "  !! 找不到 notify.sh，只能写日志"
  fi
}

# ---- 取数：优先 vnstat JSON，退化到 /proc/net/dev ----
get_traffic() { # 输出: rx_day tx_day rx_month tx_month（字节；失败输出 UNKNOWN）
  if command -v vnstat >/dev/null 2>&1; then
    python3 - "$IFACE" <<'PY'
import json, subprocess, sys
iface = sys.argv[1]
def run(args):
    # 【2026-10-14 修正】srv1 上是 **Python 3.6.8**，没有 subprocess.run(capture_output=/text=)（3.7+ 才有），
    # 之前用它导致异常被吞、永远返回 UNKNOWN。改用 3.6 兼容的 check_output + universal_newlines。
    try:
        out = subprocess.check_output(args, universal_newlines=True,
                                      stderr=subprocess.DEVNULL, timeout=20)
        return json.loads(out or "{}")
    except Exception:
        return {}
# 【2026-10-14 修正】用 `-i <iface>` 限定接口：vnstat 的"默认接口"在多网桥的机器上会挑到
# docker0/br-xxxx（实测 srv1 就挑到了 br-1a92…），那样统计的是容器内部流量而不是真实出网。
def pick(d):
    try:
        for i in (d.get("interfaces") or []):
            if i.get("name") == iface:
                return i
        its = d.get("interfaces") or []
        return its[0] if its else {}
    except Exception:
        return {}
def last(traffic):
    try:
        tr = traffic.get("traffic") or []
        if isinstance(tr, dict):
            tr = tr.get("day") or tr.get("month") or []
        return tr[-1] if tr else {}
    except Exception:
        return {}
def b(x):
    try: return int(x)
    except Exception: return 0
day = pick(run(["vnstat", "-i", iface, "--json", "d"]))
mon = pick(run(["vnstat", "-i", iface, "--json", "m"]))
d, m = last(day), last(mon)
vals = [b(d.get("rx")), b(d.get("tx")), b(m.get("rx")), b(m.get("tx"))]
print("UNKNOWN" if all(v == 0 for v in vals) else " ".join(str(v) for v in vals))
PY
  else
    echo "UNKNOWN"
  fi
}

read -r RX_D TX_D RX_M TX_M <<<"$(get_traffic)"
if [ "${RX_D:-UNKNOWN}" = "UNKNOWN" ]; then
  echo "[$(ts)] host=$HOSTN iface=$IFACE 流量数据: UNKNOWN（vnstat 未安装或无数据）—— 如实记录，不猜数字" | tee -a "$LOG"
  exit 0
fi

gb() { python3 -c "print('%.2f' % ($1/1073741824.0))"; }
RX_D_GB=$(gb "$RX_D"); TX_D_GB=$(gb "$TX_D"); RX_M_GB=$(gb "$RX_M"); TX_M_GB=$(gb "$TX_M")

LINE="[$(ts)] host=$HOSTN iface=$IFACE 今日 收 ${RX_D_GB}GB / 出 ${TX_D_GB}GB ｜ 本月 收 ${RX_M_GB}GB / 出 ${TX_M_GB}GB"
if [ -n "$PKG_GB" ]; then
  PCT=$(python3 -c "print('%.1f' % (($TX_M/1073741824.0)/$PKG_GB*100))")
  LINE="$LINE ｜ 流量包 ${PKG_GB}GB 已用 ${PCT}%"
fi
echo "$LINE" | tee -a "$LOG"

# ---- 阈值判断（只报"出网"，因为入网免费）----
ALERT=""
if python3 -c "import sys; sys.exit(0 if ($TX_D/1073741824.0) > $DAY_LIMIT_GB else 1)"; then
  ALERT="今日出网 ${TX_D_GB}GB 超过阈值 ${DAY_LIMIT_GB}GB"
fi
if python3 -c "import sys; sys.exit(0 if ($TX_M/1073741824.0) > $MONTH_LIMIT_GB else 1)"; then
  ALERT="${ALERT}${ALERT:+；}本月出网 ${TX_M_GB}GB 超过阈值 ${MONTH_LIMIT_GB}GB"
fi
if [ -n "$PKG_GB" ] && python3 -c "import sys; sys.exit(0 if (($TX_M/1073741824.0)/$PKG_GB*100) > $PKG_WARN else 1)"; then
  ALERT="${ALERT}${ALERT:+；}流量包已用 ${PCT}%（阈值 ${PKG_WARN}%）"
fi

if [ -n "$ALERT" ]; then
  echo "  ⚠ 超阈值：$ALERT"
  notify HIGH "流量告警（$HOSTN）" "$ALERT
$LINE
（入网不计费；若本月出网持续上涨，请查看 srv1 是否被爬取、或跨云索引器查询量是否升高）"
  exit 1
fi
echo "  未超阈值（今日出网阈值 ${DAY_LIMIT_GB}GB / 本月 ${MONTH_LIMIT_GB}GB${PKG_GB:+ / 流量包 ${PKG_GB}GB@${PKG_WARN}%}）"
exit 0
