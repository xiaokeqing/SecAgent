#!/usr/bin/env bash
# ============================================================
# srv1 每日自检（部署链 + 容量 + 通知通道），失败即通过 notify.sh 告警
# ------------------------------------------------------------
# 为什么需要：deploy-chain-check.sh 以前靠人记得跑；"没人跑"等于没有体检。
# 做法：每天跑一次，结果追加到 /var/log/secagent/daily-check.log，
#       任何一项失败 → notify.sh HIGH（飞书），成功 → 只写日志（不打扰）。
# 用法：bash srv1-daily-check.sh          正常跑
#       bash srv1-daily-check.sh --dry    只打印不通知
# ============================================================
set -uo pipefail
APP=/opt/secagent
LOG=$APP/logs/daily-check.log
STATE=$APP/daily-check-state.json
DRY=0
[ "${1:-}" = "--dry" ] && DRY=1
mkdir -p "$APP/logs"
ts() { date '+%Y-%m-%d %H:%M:%S'; }

say() { echo "[$(ts)] $*" | tee -a "$LOG"; }

notify() { # notify <level> <title> <body>
  local lvl="$1" title="$2" body="$3"
  if [ "$DRY" = "1" ]; then say "（dry-run）本应通知：[$lvl] $title — $body"; return 0; fi
  if [ -f "$APP/scripts/notify.sh" ]; then
    bash "$APP/scripts/notify.sh" "$lvl" "$title" "$body" >/dev/null 2>&1
    say "已尝试通知（notify.sh 退出码=$?）"
  else
    say "!! 找不到 notify.sh，只能写日志（这本身就是个问题）"
  fi
}

FAIL=0
DETAIL=""

# 1) 部署链体检
if [ -f "$APP/scripts/deploy-chain-check.sh" ]; then
  OUT=$(bash "$APP/scripts/deploy-chain-check.sh" --json 2>&1); RC=$?
  if [ $RC -eq 0 ]; then
    HEALTH=$(printf '%s' "$OUT" | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); print("live=%s/%s pointer=%s warnings=%s" % (d.get("liveStatus"), str(d.get("liveCommit"))[:7], str(d.get("pointerRevision"))[:7], d.get("warnings")))
except Exception as e: print("(解析失败) %s" % e)' 2>/dev/null)
    say "deploy-chain: OK  $HEALTH"
  else
    FAIL=1; DETAIL="$DETAIL deploy-chain(rc=$RC);"
    say "deploy-chain: **失败** rc=$RC"
    printf '%s\n' "$OUT" | tail -n 8 | sed 's/^/    /' | tee -a "$LOG"
  fi
else
  FAIL=1; DETAIL="$DETAIL deploy-chain-check.sh 缺失;"; say "deploy-chain-check.sh 不存在"
fi

# 2) 关键单元是否都活着
UNITS="secagent-redeploy.timer secagent-healthwatch.timer srv1-data-backup.timer secagent-capacity-srv1.timer secagent-notify-relay.service fail2ban wazuh-agent"
DEAD=""
for u in $UNITS; do
  st=$(systemctl is-active "$u" 2>/dev/null || echo unknown)
  [ "$st" = "active" ] || DEAD="$DEAD $u=$st"
done
if [ -n "$DEAD" ]; then FAIL=1; DETAIL="$DETAIL 单元异常:$DEAD;"; say "单元异常:$DEAD"; else say "关键单元: 全部 active"; fi

# 3) 容量与水位的粗检（阈值同 capacity-watch.sh：80/90）
DISK=$(df --output=pcent / | tail -1 | tr -dc '0-9')
say "根盘使用率: ${DISK}%"
if [ "${DISK:-0}" -ge 90 ]; then FAIL=1; DETAIL="$DETAIL 磁盘>=90%;"; elif [ "${DISK:-0}" -ge 80 ]; then say "磁盘 >=80%（提醒级，不告警）"; fi

# 3.5) docker-compose.yml 一致性 —— 【2026-10-14 新增】
#   为什么：仓库里改 compose（加挂载/加环境变量透传）**不会自动到服务器** —— 服务器那份是手工维护的。
#   今天就是这么踩的：GeoIP 的 `/opt/geoip` 挂载只改了仓库，部署后端点报 GEO_DB_MISSING，
#   查了半天才发现"服务器 compose 没有这一行"。所以把它变成每天必看的一项。
if [ -d "$APP/.git" ] && git -C "$APP" rev-parse --verify -q HEAD >/dev/null 2>&1; then
  R=$(git -C "$APP" show HEAD:docker-compose.yml 2>/dev/null | tr -d '\r' | sha256sum | cut -c1-16)
  L=$(tr -d '\r' < "$APP/docker-compose.yml" 2>/dev/null | sha256sum | cut -c1-16)
  if [ -n "$R" ] && [ -n "$L" ] && [ "$R" = "$L" ]; then
    say "compose 一致性: OK（仓库 HEAD 与服务器一致 $R）"
  else
    FAIL=1; DETAIL="$DETAIL compose不一致(仓库=$R/服务器=$L);"
    say "compose 一致性: **不一致** 仓库=$R 服务器=$L"
    say "    → 仓库改了 compose 但服务器没跟上（或反过来）。发布链不会同步 compose，需手工对齐；"
    say "      差异：git -C $APP diff HEAD -- docker-compose.yml"
  fi
else
  say "compose 一致性: 跳过（$APP 不是 git 仓库或没有 HEAD）"
fi
# 3.6) 已安装落点完整性（教训：只存在于服务器的落地物会悄悄变/丢）
if [ -f "$APP/scripts/srv1-installed-manifest.sh" ]; then
  OUT=$(bash "$APP/scripts/srv1-installed-manifest.sh" --check 2>&1); RC=$?
  if [ $RC -eq 0 ]; then
    say "落点完整性: OK（$(printf '%s' "$OUT" | grep -o 'OK（.*' | head -n1)）"
  elif [ $RC -eq 2 ]; then
    FAIL=1; DETAIL="$DETAIL 落点基线缺失;"
    say "落点完整性: **没有基线**（先跑 srv1-installed-manifest.sh --capture）"
  else
    FAIL=1; DETAIL="$DETAIL 落点有差异;"
    say "落点完整性: **有差异**"
    grep -E '\[missing\]|\[changed\]|\[added\]' "$APP/logs/installed-drift.txt" 2>/dev/null | head -n 6 | sed 's/^/      /'
  fi
fi
# 4) 通知通道自检（没配 URL 也算失败——否则出事时没人知道）
if [ -f "$APP/scripts/notify.sh" ]; then
  LOW=$(bash "$APP/scripts/notify.sh" INFO "每日自检：通知通道可用性检查" "如果你看到这条，说明通道正常（每天一条）" 2>&1); RC=$?
  case $RC in
    0) say "通知通道: OK" ;;
    3) FAIL=1; DETAIL="$DETAIL 通知未配置(NOTIFY_WEBHOOK_URL 为空);"; say "通知通道: **未配置**" ;;
    4) say "通知通道: 冷却中（视为可用）" ;;
    6) say "通知通道: 夜间静默已抑制本条 INFO 自检（视为可用；HIGH 级仍会发出）" ;;
    *) FAIL=1; DETAIL="$DETAIL 通知发送失败(rc=$RC);"; say "通知通道: 发送失败 rc=$RC  $LOW" ;;
  esac
fi

# 5) 仓库↔服务器 漂移巡检（防"落地物只存在服务器"）
#    为什么进自检：这类损失不会被任何"健康检查"发现 —— 服务器一切正常，
#    只是"这台机器就是唯一副本"（曾经差点丢掉 RUNBOOK §21 与 20 个落地文件）。
#    有【未登记】差异即失败，清单写 /opt/secagent/logs/drift-report.txt。
#    临时关闭：DRIFT_CHECK_DISABLED=1（或把本段注释掉）。
if [ "${DRIFT_CHECK_DISABLED:-0}" = "1" ]; then
  say "漂移巡检: 已关闭（DRIFT_CHECK_DISABLED=1）"
elif [ -f "$APP/scripts/srv1-drift-check.sh" ]; then
  DOUT=$(bash "$APP/scripts/srv1-drift-check.sh" 2>&1); DRC=$?
  DLINE=$(printf '%s\n' "$DOUT" | grep -m1 '^drift:')
  if [ "$DRC" -eq 0 ]; then
    say "漂移巡检: OK  $DLINE"
  else
    FAIL=1; DETAIL="$DETAIL 漂移巡检(rc=$DRC);"
    say "漂移巡检: **失败**  $DLINE"
    printf '%s\n' "$DOUT" | grep -E '^  \[(diff|missing_in_repo|missing_on_server)\]' | head -n 20 | sed 's/^/    /' | tee -a "$LOG"
    say "  完整清单：$APP/logs/drift-report.txt（处理办法见表尾）"
  fi
else
  FAIL=1; DETAIL="$DETAIL srv1-drift-check.sh 缺失;"; say "srv1-drift-check.sh 不存在"
fi

# 6) 结果落盘
python3 - "$STATE" "$FAIL" "$DETAIL" <<'PY'
import json, sys, time
state, fail, detail = sys.argv[1], sys.argv[2], sys.argv[3]
json.dump({"checkedAt": time.strftime("%Y-%m-%d %H:%M:%S"), "ok": fail == "0",
           "detail": detail.strip()}, open(state, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
PY
if [ "$FAIL" = "1" ]; then
  say "== 自检失败 =="
  notify HIGH "srv1 每日自检失败" "失败项：$DETAIL
时间：$(ts)
详见 /opt/secagent/logs/daily-check.log"
  exit 1
fi
say "== 自检全部通过 =="
exit 0
