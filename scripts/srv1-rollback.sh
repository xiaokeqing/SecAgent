#!/usr/bin/env bash
# ============================================================
# srv1 一键回滚：读 last-known-good.json → 按 digest 拉取 → 重建 → 校验
# ------------------------------------------------------------
# 为什么需要它：
#   "能回滚"这件事不能只写在文档里。真出事的时候，人最需要的是一个
#   命令 + 一个已经被验证过的目标（last-known-good.json，由每次成功部署写入）。
#   回滚目标必须用 **digest**（不可变），用 tag 回滚等于把事故交给运气。
#
# 与非发布部署的关系：
#   本脚本只做"回到上一次已知良好"，**不会**改 last-known-good.json；
#   它写入自己的留痕 last-rollback.json，避免"回滚又把回滚点覆盖掉"。
#
# 用法：
#   bash srv1-rollback.sh                 # 真实回滚
#   bash srv1-rollback.sh --dry-run       # 只打印将要做的事，不动容器
#   bash srv1-rollback.sh --to <digest>   # 指定 digest（默认读 last-known-good.json）
#   bash srv1-rollback.sh --to <digest> --commit <sha> --md5 <md5>
# 退出码：0 = 回滚后健康核对通过；1 = 失败；3 = 前置条件不满足
# ============================================================
set -uo pipefail

REGISTRY="${SECAGENT_ACR_REGISTRY:-crpi-bhyvm4rwtqasz9y3-vpc.cn-hangzhou.personal.cr.aliyuncs.com}"
REPO="${SECAGENT_ACR_REPO:-xiaokeqing/secagent}"
APP_DIR="${SECAGENT_APP_DIR:-/opt/secagent}"
SERVICE="${SECAGENT_SERVICE:-secagent}"
COMPOSE_FILE="${SECAGENT_COMPOSE_FILE:-docker-compose.yml}"
HEALTH_URL="${SECAGENT_HEALTH_URL:-http://127.0.0.1:9900/api/health}"
LOCK_FILE="${SECAGENT_LOCK_FILE:-/var/lock/secagent-deploy.lock}"
LKG_FILE="${SECAGENT_LKG_FILE:-$APP_DIR/last-known-good.json}"
HEALTH_TIMEOUT="${SECAGENT_HEALTH_TIMEOUT:-300}"
HEALTH_INTERVAL="${SECAGENT_HEALTH_INTERVAL:-5}"

DRY_RUN=0
TO_DIGEST=""
TO_COMMIT=""
TO_MD5=""
LOCK_TIMEOUT="${SECAGENT_LOCK_TIMEOUT:-600}"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  [OK] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  [!] %s\033[0m\n' "$*"; }
info() { printf '      %s\n' "$*"; }
die()  { printf '\033[1;31m  [X] %s\033[0m\n' "$*" >&2; exit "${2:-1}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)      DRY_RUN=1 ;;
    --to)           TO_DIGEST="${2:?--to 需要参数}"; shift ;;
    --commit)       TO_COMMIT="${2:?--commit 需要参数}"; shift ;;
    --md5)          TO_MD5="${2:?--md5 需要参数}"; shift ;;
    --lock-timeout) LOCK_TIMEOUT="${2:?--lock-timeout 需要参数}"; shift ;;
    -h|--help)      sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)              die "未知参数: $1" 3 ;;
  esac
  shift
done

is_digest() { printf '%s' "${1:-}" | grep -Eq '^sha256:[0-9a-f]{64}$'; }
json_value() {
  local json="$1" key="$2"
  printf '%s' "$json" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^,\"}]*\).*/\1/p" | head -1
}

command -v docker >/dev/null 2>&1 || die "找不到 docker" 3
[ -d "$APP_DIR" ] || die "找不到应用目录 $APP_DIR" 3

printf '\033[1;35m=== SecAgent 一键回滚 ===\033[0m\n'
info "应用目录 : $APP_DIR"
info "服务名   : $SERVICE"
info "模式     : $( [ "$DRY_RUN" = 1 ] && echo 'DRY-RUN（不动容器）' || echo '真实回滚' )"

# ---------------- 决定回滚目标 ----------------
if [ -z "$TO_DIGEST" ]; then
  log "0/6 读 last-known-good.json"
  if [ ! -f "$LKG_FILE" ]; then
    warn "last-known-good.json 不存在：$LKG_FILE"
    die "没有可用的回滚目标 —— 拒绝在'不知道回到哪'的情况下动容器（fail-closed）" 3
  fi
  LKG=$(cat "$LKG_FILE")
  TO_DIGEST=$(json_value "$LKG" 'digest')
  TO_COMMIT=$(json_value "$LKG" 'commit')
  TO_MD5=$(json_value "$LKG" 'artifactMd5')
  info "文件内容:"; printf '%s\n' "$LKG" | sed 's/^/      /'
else
  log "0/6 使用命令行指定的回滚目标"
fi
is_digest "$TO_DIGEST" || die "回滚目标 digest 形状不对（'$TO_DIGEST'）—— 拒绝执行（fail-closed）" 3
DIGEST_REF="$REGISTRY/$REPO@$TO_DIGEST"
ok "回滚目标 digest = $TO_DIGEST"
info "回滚目标 commit = ${TO_COMMIT:-（未知，将由镜像 label 自证）}"
info "回滚目标 md5    = ${TO_MD5:-（未知）}"

CUR_ID=$(docker inspect --format '{{.Image}}' "$SERVICE" 2>/dev/null || echo "")
CUR_REF=$(docker inspect --format '{{.Config.Image}}' "$SERVICE" 2>/dev/null || echo "")
info "当前容器镜像 ID : ${CUR_ID:-（容器不存在）}"
info "当前容器引用    : ${CUR_REF:-（不存在）}"
if [ "${CUR_REF##*@}" = "$TO_DIGEST" ]; then
  ok "当前运行的已经是该 digest —— 无需回滚（幂等）"
  [ "$DRY_RUN" = 1 ] || exit 0
fi

if [ "$DRY_RUN" = 1 ]; then
  printf '\n\033[1;33mDRY-RUN 将执行：\033[0m\n'
  info "1) docker pull $DIGEST_REF"
  info "2) 生成 $COMPOSE_FILE.ci-override.yml（image 钉死为该 digest）"
  info "3) docker compose -f $COMPOSE_FILE -f $COMPOSE_FILE.ci-override.yml up -d --no-build $SERVICE"
  info "4) 轮询 $HEALTH_URL 要求 status=ok 且 fingerprintMismatch=false"
  info "5) 写 $APP_DIR/last-rollback.json"
  printf '\n\033[1;32mDRY-RUN 结束：未做任何改动。\033[0m\n'
  exit 0
fi

# ---------------- 串行锁（与 redeploy 共用，绝不并发动容器） ----------------
mkdir -p "$(dirname "$LOCK_FILE")" 2>/dev/null || true
exec 9>"$LOCK_FILE"
if ! flock -w "$LOCK_TIMEOUT" 9; then
  die "等待串行锁 ${LOCK_TIMEOUT}s 超时 —— 有部署/回滚在进行，退出" 2
fi
ok "已取得串行锁（$LOCK_FILE）"

# ---------------- 1. 拉取 ----------------
log "1/6 拉取回滚目标"
if ! docker pull "$DIGEST_REF" 2>&1 | tail -4 | sed 's/^/      /'; then
  die "拉取回滚目标失败：$DIGEST_REF" 1
fi
ok "已拉取 $DIGEST_REF"

# ---------------- 2. 校验回滚目标本身 ----------------
log "2/6 校验回滚目标 label"
LABELS=$(docker image inspect "$DIGEST_REF" --format '{{json .Config.Labels}}' 2>/dev/null || echo "{}")
IMG_REV=$(printf '%s' "$LABELS" | grep -o '"org.opencontainers.image.revision":"[^"]*"' | head -1 | sed 's/.*:"//; s/"$//')
IMG_MD5=$(printf '%s' "$LABELS" | grep -o '"artifact-md5":"[^"]*"' | head -1 | sed 's/.*:"//; s/"$//')
info "镜像 labels = $LABELS"
[ -n "$IMG_REV" ] || die "回滚目标缺少 label org.opencontainers.image.revision —— 拒绝用它回滚（fail-closed）" 1
ok "回滚目标 label revision = $IMG_REV"
if [ -n "$TO_COMMIT" ]; then
  case "$IMG_REV" in
    "$TO_COMMIT"*) : ;;
    *) case "$TO_COMMIT" in "$IMG_REV"*) : ;; *) die "回滚目标 label revision($IMG_REV) ≠ last-known-good.commit($TO_COMMIT)" 1 ;; esac ;;
  esac
fi
if [ -n "$TO_MD5" ] && [ "$TO_MD5" != "unknown" ] && [ -n "$IMG_MD5" ] && [ "$IMG_MD5" != "$TO_MD5" ]; then
  die "回滚目标 label artifact-md5($IMG_MD5) ≠ last-known-good.artifactMd5($TO_MD5)" 1
fi

# ---------------- 3. 用 digest 重建 ----------------
log "3/6 用 digest 重建容器"
CONFIG_BAK="$APP_DIR/releases/$COMPOSE_FILE.bak-rollback-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$APP_DIR/releases"
cp -a "$APP_DIR/$COMPOSE_FILE" "$CONFIG_BAK" && ok "原 compose 已备份：$CONFIG_BAK"
OVERRIDE="$APP_DIR/$COMPOSE_FILE.ci-override.yml"
cat > "$OVERRIDE" <<YAML
# 由 scripts/srv1-rollback.sh 生成（回滚到 last-known-good）
services:
  $SERVICE:
    image: $DIGEST_REF
# 回滚目标：digest=$TO_DIGEST commit=$IMG_REV 生成于 $(date -Is)
YAML
cd "$APP_DIR" || die "无法进入 $APP_DIR" 3
BUILD_SHA="$IMG_REV" ARTIFACT_MD5="${IMG_MD5:-unknown}" \
  docker compose -f "$COMPOSE_FILE" -f "$(basename "$OVERRIDE")" up -d --no-build "$SERVICE" 2>&1 | tail -6 | sed 's/^/      /'
ok "容器已重建（回滚目标）"

# ---------------- 4. 健康核对 ----------------
log "4/6 轮询 $HEALTH_URL 并核对指纹"
HEALTH_OK=0
ELAPSED=0
while [ "$ELAPSED" -lt "$HEALTH_TIMEOUT" ]; do
  J=$(curl -s --max-time 5 "$HEALTH_URL" 2>/dev/null || echo "")
  if [ -n "$J" ]; then
    ST=$(json_value "$J" 'status'); FM=$(json_value "$J" 'fingerprintMismatch')
    EC=$(json_value "$J" 'embeddedGitCommit'); AM=$(json_value "$J" 'artifactMd5')
    if [ "$ST" = "ok" ] && [ "$FM" = "false" ] && [ "$EC" = "$IMG_REV" ]; then
      if [ -n "$IMG_MD5" ] && [ -n "$AM" ] && [ "$AM" != "$IMG_MD5" ]; then
        warn "artifactMd5 不一致（容器=$AM / label=$IMG_MD5）"
      else
        HEALTH_OK=1; break
      fi
    fi
    printf '      [%3ds] status=%s fingerprintMismatch=%s embeddedGitCommit=%s artifactMd5=%s\n' \
      "$ELAPSED" "${ST:-?}" "${FM:-?}" "${EC:-?}" "${AM:-?}"
  else
    printf '      [%3ds] 健康接口尚无响应\n' "$ELAPSED"
  fi
  sleep "$HEALTH_INTERVAL"; ELAPSED=$((ELAPSED + HEALTH_INTERVAL))
done
[ "$HEALTH_OK" = 1 ] || die "回滚后健康核对未通过 —— 需要人工介入" 1
ok "回滚完成且健康核对通过（commit=$IMG_REV digest=$TO_DIGEST）"

# ---------------- 5. 留痕（不改 last-known-good） ----------------
log "5/6 写回滚留痕"
cat > "$APP_DIR/last-rollback.json" <<JSON
{
  "rolledBackFrom": "$CUR_REF",
  "rolledBackFromImageId": "$CUR_ID",
  "digest": "$TO_DIGEST",
  "commit": "$IMG_REV",
  "artifactMd5": "${IMG_MD5:-unknown}",
  "rolledBackAt": "$(date -Is)"
}
JSON
chmod 600 "$APP_DIR/last-rollback.json"
ok "留痕：$APP_DIR/last-rollback.json"

# ---------------- 6. 收尾 ----------------
log "6/6 收尾"
docker ps --format '      {{.Names}}  {{.Status}}  {{.Image}}' | grep -E "$SERVICE" || true
warn "注意：last-known-good.json 未被本次回滚改写 —— 若确认回滚版本就是新的目标，请人工更新它"
exit 0
