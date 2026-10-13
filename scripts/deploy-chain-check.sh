#!/usr/bin/env bash
# ============================================================
# 部署链体检（在 srv1 上运行，只读）
# ------------------------------------------------------------
# 一条命令回答四个问题：
#   ① 线上跑的到底是哪个提交？（health 指纹三方是否一致）
#   ② ACR 的发布指针 stable 指向哪个提交？与线上是否一致？
#   ③ 自动发布定时器是否在工作？最近一次检查成功吗？
#   ④ 出事时能不能回滚？last-known-good 是否有效、镜像拉得到吗？（dry-run，不重启容器）
#
# 用法：bash deploy-chain-check.sh            # 体检
#       bash deploy-chain-check.sh --json     # 机器可读输出
# 退出码：0=全绿；1=有告警（不一致/定时器失败/回滚基准无效）
# ============================================================
set -uo pipefail

JSON_MODE=0
[ "${1:-}" = "--json" ] && JSON_MODE=1

VPC=crpi-bhyvm4rwtqasz9y3-vpc.cn-hangzhou.personal.cr.aliyuncs.com
REPO=$VPC/xiaokeqing/secagent
HEALTH_URL=http://127.0.0.1:9900/api/health
LKG=/opt/secagent/last-known-good.json
WARN=0

ok()   { [ "$JSON_MODE" = "0" ] && printf '  \033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { [ "$JSON_MODE" = "0" ] && printf '  \033[1;33m[!]\033[0m  %s\n' "$*"; WARN=1; }
info() { [ "$JSON_MODE" = "0" ] && printf '      %s\n' "$*"; }
die()  { [ "$JSON_MODE" = "0" ] && printf '  \033[1;31m[X]\033[0m  %s\n' "$*"; WARN=1; }

# ---------- ① 线上指纹 ----------
HEALTH_JSON=$(curl -s -m 12 "$HEALTH_URL" 2>/dev/null || true)
if [ -z "$HEALTH_JSON" ]; then
  die "健康接口无响应（$HEALTH_URL）—— 服务可能没起来"
  LIVE_COMMIT=""
  LIVE_STATUS="unknown"
else
  LIVE_STATUS=$(printf '%s' "$HEALTH_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("status","?"))' 2>/dev/null || echo "?")
  LIVE_COMMIT=$(printf '%s' "$HEALTH_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("embeddedGitCommit",""))' 2>/dev/null || echo "")
  LIVE_MISMATCH=$(printf '%s' "$HEALTH_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("fingerprintMismatch","?"))' 2>/dev/null || echo "?")
  LIVE_MD5=$(printf '%s' "$HEALTH_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("artifactMd5",""))' 2>/dev/null || echo "")
  [ "$LIVE_STATUS" = "ok" ] || warn "health status=$LIVE_STATUS（期望 ok）"
  [ "$LIVE_MISMATCH" = "False" ] || [ "$LIVE_MISMATCH" = "false" ] || warn "fingerprintMismatch=$LIVE_MISMATCH（指纹不一致！）"
  ok "线上 health: status=$LIVE_STATUS commit=${LIVE_COMMIT:0:7} artifactMd5=${LIVE_MD5:0:8}"
fi

# ---------- ② 发布指针 ----------
PTR_REV=""
if docker pull -q "$REPO:stable" >/dev/null 2>&1; then
  PTR_REV=$(docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$REPO:stable" 2>/dev/null)
  PTR_MD5=$(docker inspect --format '{{index .Config.Labels "artifact-md5"}}' "$REPO:stable" 2>/dev/null)
  PTR_DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' "$REPO:stable" 2>/dev/null | sed 's/.*@//')
  ok "ACR stable: revision=${PTR_REV:0:7} artifact-md5=${PTR_MD5:0:8} digest=${PTR_DIGEST:0:19}…"
  if [ -n "$LIVE_COMMIT" ] && [ "${PTR_REV:0:7}" != "${LIVE_COMMIT:0:7}" ]; then
    warn "发布指针（${PTR_REV:0:7}）与线上（${LIVE_COMMIT:0:7}）不一致 —— 要么 AI 尚未发布，要么有人手工部署过"
  fi
else
  warn "拉取 ACR 的 stable 失败（凭据或网络）—— 按发布指针部署的能力不可用"
  info "可尝试重新登录：docker login $VPC -u <主账号> --password-stdin"
fi

# ---------- ③ 定时器 ----------
T_ACTIVE=$(systemctl is-active secagent-redeploy.timer 2>/dev/null || echo unknown)
T_ENABLED=$(systemctl is-enabled secagent-redeploy.timer 2>/dev/null || echo unknown)
if [ "$T_ACTIVE" = "active" ] && [ "$T_ENABLED" = "enabled" ]; then
  ok "自动发布定时器：active / enabled"
else
  warn "自动发布定时器：active=$T_ACTIVE enabled=$T_ENABLED（期望 active/enabled）"
fi
LAST_RESULT=$(systemctl show secagent-redeploy.service -p Result --value 2>/dev/null || echo "")
LAST_TS=$(systemctl show secagent-redeploy.service -p ExecMainExitTimestamp --value 2>/dev/null || echo "")
if [ -n "$LAST_RESULT" ]; then
  if [ "$LAST_RESULT" = "success" ]; then
    ok "最近一次发布检查：success（$LAST_TS）"
  else
    warn "最近一次发布检查：$LAST_RESULT（$LAST_TS）—— 看 journalctl -u secagent-redeploy.service"
  fi
fi
NEXT=$(systemctl list-timers secagent-redeploy.timer --no-pager 2>/dev/null | sed -n '2p' | awk '{print $1" "$2" "$3}')
[ -n "$NEXT" ] && info "下次运行：$NEXT"

# ---------- ④ 回滚基准（dry-run，不动容器） ----------
if [ ! -f "$LKG" ]; then
  warn "没有 $LKG —— 出事时无法自动回滚（跑一次 srv1-redeploy.sh 会生成）"
else
  LKG_DIGEST=$(python3 -c 'import json;print(json.load(open("'"$LKG"'")).get("digest",""))' 2>/dev/null || echo "")
  LKG_COMMIT=$(python3 -c 'import json;print(json.load(open("'"$LKG"'")).get("commit",""))' 2>/dev/null || echo "")
  LKG_REF=$(python3 -c 'import json;print(json.load(open("'"$LKG"'")).get("ref",""))' 2>/dev/null || echo "")
  ok "回滚基准：commit=${LKG_COMMIT:0:7} digest=${LKG_DIGEST:0:19}…"
  if [ -n "$LKG_REF" ] && docker pull -q "$LKG_REF" >/dev/null 2>&1; then
    ok "回滚镜像可拉取（dry-run 通过，未重启任何容器）"
  else
    warn "回滚镜像拉取失败 —— 回滚演练会失败，需先修 ACR 凭据"
  fi
fi

# ---------- 汇总 ----------
if [ "$JSON_MODE" = "1" ]; then
  python3 - "$LIVE_STATUS" "${LIVE_COMMIT:-}" "${PTR_REV:-}" "$T_ACTIVE" "$T_ENABLED" "${LKG_COMMIT:-}" "$WARN" <<'PY'
import json, sys
keys = ["liveStatus","liveCommit","pointerRevision","timerActive","timerEnabled","rollbackCommit","warnings"]
print(json.dumps(dict(zip(keys, sys.argv[1:7] + [int(sys.argv[7])])), ensure_ascii=False, indent=2))
PY
else
  echo
  if [ "$WARN" = "0" ]; then
    printf '\033[1;32m部署链体检：全绿（线上指纹一致 / 发布指针就位 / 定时器工作 / 可回滚）\033[0m\n'
  else
    printf '\033[1;33m部署链体检：有告警（见上面 [!] 行）\033[0m\n'
  fi
fi
exit "$WARN"
