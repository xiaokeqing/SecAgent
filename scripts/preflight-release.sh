#!/usr/bin/env bash
# ============================================================
# 发布前体检（preflight）—— 在 srv1 上运行，只读，不改任何东西
# ------------------------------------------------------------
# 背景：开发期为推进 P4，把三个额度池临时放开成 300/200/300（生产值应为 50/60/30）。
#       这种"临时值"最容易在发布时被忘掉 —— 本脚本把它变成一条必须通过的检查。
#
# 检查项（对应夜间清单 U1..U6）：
#   1) 生产额度是否已回收（容器内环境变量 + /opt/secagent/.env + 公开端点回显）
#   2) 代码侧模板是否是生产值（.env.example：50/60/30，且不含 sk- 前缀占位值）
#   3) 线上指纹是否一致（health：status=ok / fingerprintMismatch=false）
#   4) 发布指针与线上是否一致（ACR stable revision == 线上 commit）
#   5) 自动发布/健康看门狗两个 timer 是否在工作
#   6) 回滚基准是否有效（last-known-good 可拉取，dry-run）
#   7) 仓库工作区是否干净（避免把未提交的东西当成"已发布"）
#
# 用法：bash preflight-release.sh             # 人读，有未通过项退出码 1
#       bash preflight-release.sh --allow-dev # 开发期模式：额度未回收只提示不算失败
# 退出码：0=可以发布；1=有阻塞项
# ============================================================
set -uo pipefail

ALLOW_DEV=0
[ "${1:-}" = "--allow-dev" ] && ALLOW_DEV=1

APP_DIR=/opt/secagent
FAIL=0
ok()   { printf '  \033[1;32m[通过]\033[0m %s\n' "$*"; }
bad()  { printf '  \033[1;31m[阻塞]\033[0m %s\n' "$*"; FAIL=1; }
soft() { printf '  \033[1;33m[提示]\033[0m %s\n' "$*"; }
head_() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

head_ "1. 生产额度是否已回收（生产值 用户50 / 评测60 / 公开30）"
ENV_LINES=$(docker exec secagent printenv 2>/dev/null | grep -E '^(APP_QUOTA|DAILY_QUOTA)' || true)
if [ -z "$ENV_LINES" ]; then
  soft "容器里没有 APP_QUOTA_* 环境变量（使用代码默认值）"
else
  printf '%s\n' "$ENV_LINES" | sed 's/^/      /'
fi
DEV_HIT=0
for kv in "APP_QUOTA_DAILY_LIMIT=300" "APP_QUOTA_EVAL_DAILY_LIMIT=200" "APP_QUOTA_PUBLIC_DAILY_LIMIT=300" "DAILY_QUOTA=300"; do
  if printf '%s\n' "$ENV_LINES" | grep -q "^${kv}$"; then DEV_HIT=1; fi
done
if [ "$DEV_HIT" = "1" ]; then
  if [ "$ALLOW_DEV" = "1" ]; then
    soft "检测到开发期临时额度（300/200/300）—— 按 --allow-dev 放行，但【发布前必须改回 50/60/30】"
    soft "改法：/opt/secagent/.env 里三行改为 50/60/30 并重建容器（走 srv1-redeploy.sh，别用 compose up）"
  else
    bad "仍是开发期临时额度（300/200/300）—— 发布前必须回收为 50/60/30"
  fi
else
  ok "容器内额度变量不是开发期临时值"
fi
if [ -f "$APP_DIR/.env" ]; then
  if grep -qE '^(APP_QUOTA_DAILY_LIMIT=300|APP_QUOTA_EVAL_DAILY_LIMIT=200|APP_QUOTA_PUBLIC_DAILY_LIMIT=300|DAILY_QUOTA=300)$' "$APP_DIR/.env"; then
    soft "$APP_DIR/.env 里仍有开发期临时值（第 $(grep -nE '=300|=200' "$APP_DIR/.env" | head -n1 | cut -d: -f1) 行附近）"
  else
    ok "$APP_DIR/.env 未见开发期临时值"
  fi
fi
# 公开端点回显的真实上限（最权威）：取一次 quota.limit
QLIMIT=$(curl -s -m 20 -X POST http://127.0.0.1:9900/api/public/ask -H 'Content-Type: application/json' \
  -d '{"question":"发布前额度体检"}' 2>/dev/null | python3 -c 'import json,sys;print((json.load(sys.stdin).get("data") or {}).get("quota",{}).get("limit",""))' 2>/dev/null || echo "")
if [ -n "$QLIMIT" ]; then
  if [ "$QLIMIT" = "30" ]; then ok "公开端点回显上限 = 30（生产值）"
  else soft "公开端点回显上限 = $QLIMIT（生产值应为 30）"; [ "$ALLOW_DEV" = "1" ] || FAIL=1; fi
else
  soft "拿不到公开端点的额度回显（可能未登录/限流/接口未起）"
fi

head_ "2. 代码侧模板是否是生产值"
TPL="$APP_DIR/.env.example"
if [ -f "$TPL" ]; then
  if grep -qE '^APP_QUOTA_(DAILY|EVAL_DAILY|PUBLIC_DAILY)_LIMIT=(50|60|30)$' "$TPL"; then ok ".env.example 额度为生产值"; else bad ".env.example 额度不是 50/60/30"; fi
  if grep -qE '^\s*[A-Z_]*=\s*sk-' "$TPL"; then bad ".env.example 出现 sk- 前缀值（会被 CI 的 gitleaks 拦下）"; else ok ".env.example 无 sk- 前缀占位值"; fi
else
  soft "找不到 $TPL（跳过模板检查）"
fi

head_ "3. 线上指纹是否一致"
H=$(curl -s -m 12 http://127.0.0.1:9900/api/health 2>/dev/null || true)
if [ -z "$H" ]; then bad "健康接口无响应"; else
  printf '%s' "$H" | python3 -c '
import json,sys
d=json.load(sys.stdin)
def g(k): return d.get(k)
st=str(g("status")); mm=str(g("fingerprintMismatch"))
print("      status=%s commit=%s artifactMd5=%s mismatch=%s vectors=%s" % (st, str(g("embeddedGitCommit"))[:7], str(g("artifactMd5"))[:8], mm, g("documentVectors")))
sys.exit(0 if st=="ok" and mm in ("False","false","None") else 1)
' && ok "指纹一致（status=ok 且 fingerprintMismatch=false）" || bad "指纹不一致或有异常状态"
fi

head_ "4. 发布指针与线上是否一致"
VPC=crpi-bhyvm4rwtqasz9y3-vpc.cn-hangzhou.personal.cr.aliyuncs.com
REPO=$VPC/xiaokeqing/secagent
if docker pull -q "$REPO:stable" >/dev/null 2>&1; then
  PTR=$(docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$REPO:stable" 2>/dev/null)
  LIVE=$(printf '%s' "$H" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("embeddedGitCommit",""))' 2>/dev/null || echo "")
  if [ -n "$PTR" ] && [ "${PTR:0:7}" = "${LIVE:0:7}" ]; then ok "stable=${PTR:0:7} == 线上=${LIVE:0:7}"
  else bad "stable=${PTR:0:7} 与线上=${LIVE:0:7} 不一致（要么还没部署，要么有人手工部署过）"; fi
else
  bad "拉不到 ACR stable（凭据/网络）—— 按指针部署与自动回滚都不可用"
fi

head_ "5. 两个 timer 是否在工作"
for t in secagent-redeploy.timer secagent-healthwatch.timer; do
  A=$(systemctl is-active "$t" 2>/dev/null); E=$(systemctl is-enabled "$t" 2>/dev/null)
  if [ "$A" = "active" ] && [ "$E" = "enabled" ]; then ok "$t: active/enabled"; else bad "$t: active=$A enabled=$E"; fi
done

head_ "6. 回滚基准是否有效"
LKG=$APP_DIR/last-known-good.json
if [ -f "$LKG" ]; then
  REF=$(python3 -c 'import json;print(json.load(open("'"$LKG"'")).get("ref",""))' 2>/dev/null || echo "")
  if [ -n "$REF" ] && docker pull -q "$REF" >/dev/null 2>&1; then ok "last-known-good 镜像可拉取（$(python3 -c 'import json;print(json.load(open("'"$LKG"'")).get("commit","")[:7])' 2>/dev/null)）"
  else bad "last-known-good 的镜像拉不动 —— 回滚会失败"; fi
else
  bad "没有 $LKG —— 无法自动回滚"
fi

head_ "7. 仓库工作区是否干净"
if [ -d "$APP_DIR/.git" ]; then
  DIRTY=$(git -C "$APP_DIR" status --porcelain 2>/dev/null | grep -v '^??' | wc -l)
  if [ "$DIRTY" = "0" ]; then ok "工作区干净（无未提交改动）"; else soft "工作区有 $DIRTY 项未提交改动（发布前确认这些不该进版本库）"; fi
else
  soft "$APP_DIR 不是 git 仓库（跳过）"
fi

echo
if [ "$FAIL" = "0" ]; then
  printf '\033[1;32m发布前体检：全部通过 —— 可以发布\033[0m\n'
else
  printf '\033[1;31m发布前体检：存在阻塞项（见上面 [阻塞]）—— 先处理再发布\033[0m\n'
fi
exit "$FAIL"
