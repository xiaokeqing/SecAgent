#!/usr/bin/env bash
# ============================================================
# srv1 按「发布指针」拉取并重启 SecAgent（不 build、不 git pull、无入站端口）
# ------------------------------------------------------------
# 这条链的形状：
#   GitHub Actions --push--> 阿里云 ACR :stable（= 发布指针）
#                                    │  每 5 分钟
#                                    ▼
#   srv1：读 stable 的 digest → 与当前运行 digest 比对 → 不同才 pull+重建
#         → **部署前硬校验闸门** → 健康核对 → 写 last-known-good
#
# 为什么要有"部署前硬校验闸门"：
#   这个项目真实发生过「镜像是新的、代码是旧的」—— 服务健康、接口正常、
#   只有代码是旧的。所以这里不信任"拉下来了"这件事本身，必须证明：
#     ① 镜像 label org.opencontainers.image.revision 存在（无 label = 来源不明）
#     ② 它与"期望 commit"（指针/公告值）一致
#     ③ 容器起来后 /api/health：status=ok 且 fingerprintMismatch=false
#        且 embeddedGitCommit == 该 revision 且 artifactMd5 == 镜像 label
#   任一条不满足 → 回滚到上一个已跑通的镜像并以非 0 退出（绝不"看着成功"）。
#
# 为什么用 digest 而不是 tag 部署：
#   tag 是可变的（任何人 push 一次 stable 就能改变含义）。digest 不可变，
#   于是"这次部署的到底是哪个字节"可复现、可回滚、可审计。
#
# 用法：
#   bash srv1-redeploy.sh                  # 正常一次（idempotent，没变就安静退出）
#   bash srv1-redeploy.sh --dry-run        # 只读取/比对/打印判断，绝不改动任何容器
#   bash srv1-redeploy.sh --tag civtest    # 用别的 tag 当发布指针（演练用）
#   bash srv1-redeploy.sh --expect-commit <sha>   # 额外指定期望 commit（可复现性）
#   bash srv1-redeploy.sh --force          # 即使 digest 相同也重建（排障用）
#   bash srv1-redeploy.sh --lock-timeout 0 # 并发时立刻退出而不是等待（演练用）
#   bash srv1-redeploy.sh --self-test      # 不需要 docker：跑纯函数自测
# 退出码：0 = 已同步/无需变更；1 = 失败（已尽力回滚）；2 = 并发锁未取得；
#        3 = 配置/前置条件错误
# ============================================================
set -uo pipefail

# ---------------- 可覆盖的配置（环境变量优先） ----------------
REGISTRY="${SECAGENT_ACR_REGISTRY:-crpi-bhyvm4rwtqasz9y3-vpc.cn-hangzhou.personal.cr.aliyuncs.com}"
REPO="${SECAGENT_ACR_REPO:-xiaokeqing/secagent}"
POINTER_TAG="${SECAGENT_POINTER_TAG:-stable}"
APP_DIR="${SECAGENT_APP_DIR:-/opt/secagent}"
SERVICE="${SECAGENT_SERVICE:-secagent}"
COMPOSE_FILE="${SECAGENT_COMPOSE_FILE:-docker-compose.yml}"
HEALTH_URL="${SECAGENT_HEALTH_URL:-http://127.0.0.1:9900/api/health}"
LOCK_FILE="${SECAGENT_LOCK_FILE:-/var/lock/secagent-deploy.lock}"
LKG_FILE="${SECAGENT_LKG_FILE:-$APP_DIR/last-known-good.json}"
RELEASES_DIR="$APP_DIR/releases"
HEALTH_TIMEOUT="${SECAGENT_HEALTH_TIMEOUT:-300}"
HEALTH_INTERVAL="${SECAGENT_HEALTH_INTERVAL:-5}"

DRY_RUN=0
FORCE=0
EXPECT_COMMIT=""
LOCK_TIMEOUT="${SECAGENT_LOCK_TIMEOUT:-600}"
ROLLBACK_TO=""
CONFIG_BAK=""
ROLLBACK_REASON=""
SELF_TEST=0

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  [OK] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  [!] %s\033[0m\n' "$*"; }
info() { printf '      %s\n' "$*"; }
die()  { printf '\033[1;31m  [X] %s\033[0m\n' "$*" >&2; exit "${2:-1}"; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)        DRY_RUN=1 ;;
    --force)          FORCE=1 ;;
    --tag)            POINTER_TAG="${2:?--tag 需要参数}"; shift ;;
    --expect-commit)  EXPECT_COMMIT="${2:?--expect-commit 需要参数}"; shift ;;
    --lock-timeout)   LOCK_TIMEOUT="${2:?--lock-timeout 需要参数}"; shift ;;
    --registry)       REGISTRY="${2:?--registry 需要参数}"; shift ;;
    --repo)           REPO="${2:?--repo 需要参数}"; shift ;;
    # 自测用（不需要 docker）：只是让参数解析放行，真正的入口在下面的自测块
    --self-test)      SELF_TEST=1 ;;
    # 内部使用（第 6/7 步失败时调用自己）：把容器换回上一个镜像并恢复配置
    --rollback-to)    ROLLBACK_TO="${2:?--rollback-to 需要参数}"; shift ;;
    --config-bak)     CONFIG_BAK="${2:?--config-bak 需要参数}"; shift ;;
    --reason)         ROLLBACK_REASON="${2:?--reason 需要参数}"; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)                die "未知参数: $1（--help 看用法）" 3 ;;
  esac
  shift
done

POINTER_REF="$REGISTRY/$REPO:$POINTER_TAG"

# ---------------- 纯函数（可被 --self-test 复用，不需要 docker） ----------------
# 短号 vs 全号视为同一提交（与 FingerprintVerifier.sameCommit 同口径）
same_commit() {
  local a b
  a=$(printf '%s' "${1:-}" | tr 'A-Z' 'a-z')
  b=$(printf '%s' "${2:-}" | tr 'A-Z' 'a-z')
  [ -z "$a" ] && return 1
  [ -z "$b" ] && return 1
  [ "$a" = "$b" ] && return 0
  # 只允许"一边是另一边的前缀"，且短的一边 >= 7 位（避免 d0 这种巧合前缀）
  if [ "${#a}" -ge 7 ] && [ "${#a}" -lt "${#b}" ]; then
    case "$b" in "$a"*) return 0 ;; esac
  fi
  if [ "${#b}" -ge 7 ] && [ "${#b}" -lt "${#a}" ]; then
    case "$a" in "$b"*) return 0 ;; esac
  fi
  return 1
}

# 只接受规范的 sha256 digest，杜绝把空值/错值当 digest 用
is_digest() { printf '%s' "${1:-}" | grep -Eq '^sha256:[0-9a-f]{64}$'; }
# 16 进制 commit 形（7~40 位）
is_commitish() { printf '%s' "${1:-}" | grep -Eq '^[0-9a-fA-F]{7,40}$'; }
# label 里的 md5 形（32 位 16 进制）
is_md5() { printf '%s' "${1:-}" | grep -Eq '^[0-9a-f]{32}$'; }

# 从 docker manifest inspect / imagetools inspect 输出里取 digest
parse_manifest_digest() {
  sed -n 's/.*"digest"[[:space:]]*:[[:space:]]*"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' | head -1
}
# 从 "RepoRef@sha256:..." 形式的整串里取 digest
parse_ref_digest() { sed -n 's/.*@\(sha256:[0-9a-f]\{64\}\)$/\1/p' | head -1; }

# 从 docker image inspect 的 label JSON（单行）里取某个 label 的值
label_value() {
  local json="$1" key="$2"
  printf '%s' "$json" | grep -o "\"$key\":\"[^\"]*\"" | head -1 | sed 's/^[^:]*:"//; s/"$//'
}

# 从 /api/health 的 JSON 里取值（srv1 上没有 jq，用 sed，不引入新依赖）
json_value() {
  local json="$1" key="$2"
  printf '%s' "$json" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^,\"}]*\).*/\1/p" | head -1
}

# ---------------- 自测（不需要 docker） ----------------
if [ "${SELF_TEST:-0}" = 1 ]; then
  SELF_FAIL=0
  chk() { if [ "$2" = "$3" ]; then ok "自测 $1"; else SELF_FAIL=1; warn "自测 $1 失败: 期望 '$3' 得到 '$2'"; fi; }
  same_commit abcdef123456 abcdef123456; chk "same_commit 全等" "$?" 0
  same_commit abcdef1 abcdef123456789; chk "same_commit 短前缀" "$?" 0
  if same_commit abcdef1 1234567; then chk "same_commit 不等" 0 1; else chk "same_commit 不等" 1 1; fi
  if same_commit abc 1abcdef; then chk "same_commit 拒绝 <7 位巧合前缀" 0 1; else chk "same_commit 拒绝 <7 位巧合前缀" 1 1; fi
  if same_commit "" ""; then chk "same_commit 拒绝空值" 0 1; else chk "same_commit 拒绝空值" 1 1; fi
  chk "digest 形状校验(合法)" "$(is_digest "sha256:$(printf 'a%.0s' $(seq 1 64))" && echo y || echo n)" "y"
  chk "digest 形状校验(非法)" "$(is_digest "sha256:abc" && echo y || echo n)" "n"
  chk "commit 形状校验" "$(is_commitish dfeae41 && echo y || echo n)" "y"
  chk "md5 形状校验" "$(is_md5 7a2fff72ce97a80eace84d3c264cd6ed && echo y || echo n)" "y"
  chk "label 解析" "$(label_value '{"org.opencontainers.image.revision":"abc1234","artifact-md5":"deadbeef"}' 'artifact-md5')" "deadbeef"
  chk "health JSON 解析(status)" "$(json_value '{"status":"ok","fingerprintMismatch":false,"embeddedGitCommit":"abcdef1"}' 'status')" "ok"
  chk "health JSON 解析(bool)" "$(json_value '{"status":"ok","fingerprintMismatch":false}' 'fingerprintMismatch')" "false"
  chk "health JSON 解析(commit)" "$(json_value '{"embeddedGitCommit":"abcdef1","artifactMd5":"aa"}' 'embeddedGitCommit')" "abcdef1"
  chk "ref digest 解析" "$(printf '%s' "crpi-x/xiaokeqing/secagent@sha256:$(printf 'b%.0s' $(seq 1 64))" | parse_ref_digest)" "sha256:$(printf 'b%.0s' $(seq 1 64))"
  chk "manifest digest 解析" "$(printf '%s' '{"descriptor":{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}' | parse_manifest_digest)" "sha256:$(printf 'c%.0s' $(seq 1 64))"
  if [ "$SELF_FAIL" = 0 ]; then ok "自测全部通过"; exit 0; else die "自测失败"; fi
fi

# ============================================================
# 内部路径：把容器换回上一个镜像（第 6/7 步失败时调用）
# ------------------------------------------------------------
# 为什么回滚用镜像 ID 而不是重新 build：镜像 ID 是本地已存在的、
# 上一次"跑通过"的那个产物，回滚必须比前进更快更确定。
# ============================================================
if [ -n "$ROLLBACK_TO" ]; then
  warn "回滚中：把 $SERVICE 换回 $ROLLBACK_TO（原因：${ROLLBACK_REASON:-未说明}）"
  cd "$APP_DIR" || die "无法进入 $APP_DIR" 3
  if [ -n "$CONFIG_BAK" ] && [ -f "$CONFIG_BAK" ]; then
    cp -a "$CONFIG_BAK" "$APP_DIR/$COMPOSE_FILE"
    ok "已恢复 compose 配置：$CONFIG_BAK → $APP_DIR/$COMPOSE_FILE"
  fi
  OLD_REV=$(docker image inspect "$ROLLBACK_TO" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null || echo "")
  OLD_MD5=$(docker image inspect "$ROLLBACK_TO" --format '{{index .Config.Labels "artifact-md5"}}' 2>/dev/null || echo "")
  BUILD_SHA="${OLD_REV:-unknown}" ARTIFACT_MD5="${OLD_MD5:-unknown}" \
    docker compose -f "$COMPOSE_FILE" up -d --no-build "$SERVICE" 2>&1 | tail -4 | sed 's/^/      /'
  ELAPSED=0
  while [ "$ELAPSED" -lt "$HEALTH_TIMEOUT" ]; do
    J=$(curl -s --max-time 5 "$HEALTH_URL" 2>/dev/null || echo "")
    ST=$(json_value "$J" 'status'); FM=$(json_value "$J" 'fingerprintMismatch')
    if [ "$ST" = "ok" ] && [ "$FM" = "false" ]; then
      ok "回滚成功：status=ok / fingerprintMismatch=false"
      exit 0
    fi
    sleep "$HEALTH_INTERVAL"; ELAPSED=$((ELAPSED + HEALTH_INTERVAL))
  done
  die "回滚后健康核对仍未通过 —— 需要人工介入（容器已是上一版本，但未达 ok）" 1
fi

# ---------------- 前置检查 ----------------
command -v docker >/dev/null 2>&1 || die "找不到 docker" 3
[ -d "$APP_DIR" ] || die "找不到应用目录 $APP_DIR" 3
[ -f "$APP_DIR/$COMPOSE_FILE" ] || die "找不到 $APP_DIR/$COMPOSE_FILE" 3
[ -f "$APP_DIR/.env" ] || die "$APP_DIR/.env 不存在 —— compose 的 env_file 缺失会导致容器起不来" 3

printf '\033[1;35m=== SecAgent 发布指针部署 ===\033[0m\n'
info "发布指针 : $POINTER_REF"
info "应用目录 : $APP_DIR（compose 文件 $COMPOSE_FILE）"
info "服务名   : $SERVICE"
info "模式     : $( [ "$DRY_RUN" = 1 ] && echo 'DRY-RUN（只判断，不改动容器）' || echo '真实执行' )$( [ "$FORCE" = 1 ] && echo ' + FORCE' || true )"

# ============================================================
# 串行锁：绝不允许并发部署
# ------------------------------------------------------------
# 为什么必须有：部署包含「记录当前镜像 → pull → 重建 → 健康核对 → 写
# last-known-good」多步。两个实例交错时，一个正在核对健康、另一个把容器
# 换掉，就会出现"回滚到半截"这种最难查的中间态。
# flock 是内核级锁，进程被 kill 也会自动释放，不需要清理陈旧锁文件。
# ============================================================
mkdir -p "$(dirname "$LOCK_FILE")" 2>/dev/null || true
exec 9>"$LOCK_FILE"
if [ "$LOCK_TIMEOUT" = "0" ]; then
  if ! flock -n 9; then
    warn "另一个部署正在进行（$LOCK_FILE 被占用）—— 立刻退出，不并发部署"
    exit 2
  fi
  ok "已取得串行锁（$LOCK_FILE）"
else
  info "等待串行锁（$LOCK_FILE，最多 ${LOCK_TIMEOUT}s）..."
  T0=$(date +%s)
  if ! flock -w "$LOCK_TIMEOUT" 9; then
    warn "等待 ${LOCK_TIMEOUT}s 仍未取得锁 —— 另一个部署仍在进行，退出（稍后 timer 会再来）"
    exit 2
  fi
  ok "已取得串行锁（等 $(($(date +%s) - T0))s）"
fi

# ============================================================
# 1. 读发布指针 = ACR 里该 tag 的 digest
# ============================================================
log "1/9 读取发布指针（$POINTER_REF 的 digest）"
PTR_DIGEST=""
PTR_SRC=""
rm -f /tmp/secagent-ptr.json /tmp/secagent-ptr.err
if docker manifest inspect "$POINTER_REF" >/tmp/secagent-ptr.json 2>/tmp/secagent-ptr.err; then
  PTR_DIGEST=$(parse_manifest_digest </tmp/secagent-ptr.json)
  PTR_SRC="docker manifest inspect"
fi
if [ -z "$PTR_DIGEST" ] && docker buildx imagetools inspect "$POINTER_REF" >/tmp/secagent-ptr.json 2>>/tmp/secagent-ptr.err; then
  PTR_DIGEST=$(parse_manifest_digest </tmp/secagent-ptr.json)
  PTR_SRC="docker buildx imagetools inspect"
fi
if [ -z "$PTR_DIGEST" ]; then
  # 兜底：pull 后从 RepoDigests 取（需要凭据，srv1 已 docker login）
  warn "manifest 查询拿不到 digest，改用 pull 兜底：$(head -c 200 /tmp/secagent-ptr.err 2>/dev/null)"
  if docker pull "$POINTER_REF" >/tmp/secagent-ptr-pull.log 2>&1; then
    PTR_DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' "$POINTER_REF" 2>/dev/null | parse_ref_digest)
    PTR_SRC="docker pull + inspect RepoDigests"
  else
    die "拉取发布指针失败：$(tail -3 /tmp/secagent-ptr-pull.log 2>/dev/null)" 1
  fi
fi
is_digest "$PTR_DIGEST" || die "发布指针 digest 形状不对（'$PTR_DIGEST'）—— 拒绝继续（fail-closed）" 1
ok "发布指针 digest = $PTR_DIGEST   （来源：$PTR_SRC）"

# 指针里公告的期望 commit（可选增强：清单注解 / 环境变量）
if [ -z "$EXPECT_COMMIT" ]; then
  EXPECT_COMMIT=$(sed -n 's/.*org\.opencontainers\.image\.revision[^0-9a-fA-F]*\([0-9a-fA-F]\{7,40\}\).*/\1/p' /tmp/secagent-ptr.json | head -1)
  [ -n "$EXPECT_COMMIT" ] && info "指针清单内公告 revision = $EXPECT_COMMIT"
fi

# ============================================================
# 2. 记录当前运行状态（回滚基准）
# ============================================================
log "2/9 记录当前运行状态（回滚基准）"
RUNNING_IMAGE_ID=$(docker inspect --format '{{.Image}}' "$SERVICE" 2>/dev/null || echo "")
RUNNING_REF=$(docker inspect --format '{{.Config.Image}}' "$SERVICE" 2>/dev/null || echo "")
RUNNING_DIGEST=$(printf '%s' "$RUNNING_REF" | parse_ref_digest)
STATE_FILE="$RELEASES_DIR/secagent-state.env"
info "当前容器   : $( [ -n "$RUNNING_IMAGE_ID" ] && echo "$RUNNING_IMAGE_ID" || echo '（不存在）' )"
info "当前引用   : ${RUNNING_REF:-（不存在）}"
info "当前 digest: $( [ -n "$RUNNING_DIGEST" ] && echo "$RUNNING_DIGEST" || echo '（不是 digest 引用 / tag 引用）' )"
if [ -n "$RUNNING_IMAGE_ID" ]; then
  info "当前 BUILD_SHA 环境变量: $(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$SERVICE" 2>/dev/null | sed -n 's/^BUILD_SHA=//p')"
fi

# ============================================================
# 3. 与当前运行 digest 比对 —— 相同则什么都不做（幂等、安静退出）
# ============================================================
log "3/9 与当前运行 digest 比对"
NEED_DEPLOY=1
if [ -z "$RUNNING_IMAGE_ID" ]; then
  warn "容器 $SERVICE 不存在 —— 需要部署"
elif [ -n "$RUNNING_DIGEST" ] && [ "$RUNNING_DIGEST" = "$PTR_DIGEST" ]; then
  NEED_DEPLOY=0
  ok "当前运行 digest 与发布指针相同 —— 无需变更，安静退出"
elif [ -n "$RUNNING_IMAGE_ID" ]; then
  # tag 引用（例如遗留的 secagent:local）时，用镜像 ID 反查该 digest 是否已在本地
  LOCAL_FOR_PTR=$(docker image inspect "$REGISTRY/$REPO@$PTR_DIGEST" --format '{{.Id}}' 2>/dev/null || echo "")
  if [ -n "$LOCAL_FOR_PTR" ] && [ "$LOCAL_FOR_PTR" = "$RUNNING_IMAGE_ID" ]; then
    NEED_DEPLOY=0
    ok "当前运行的镜像 ID 已等于发布指针所指产物（引用形式是 tag）—— 无需变更"
  else
    warn "当前运行产物与发布指针不同 —— 需要部署"
    info "  当前 ID     : $RUNNING_IMAGE_ID"
    info "  指针指向 ID : $( [ -n "$LOCAL_FOR_PTR" ] && echo "$LOCAL_FOR_PTR" || echo '（本地尚无此 digest，需 pull 后才能确定）' )"
  fi
fi

if [ "$NEED_DEPLOY" = 0 ] && [ "$FORCE" = 0 ]; then
  printf '\n\033[1;32m结果：已是最新（no-op）。未触碰任何容器。\033[0m\n'
  exit 0
fi
[ "$FORCE" = 1 ] && warn "--force：即使 digest 相同也继续重建"

if [ "$DRY_RUN" = 1 ]; then
  printf '\n\033[1;33mDRY-RUN 判断汇总（未做任何改动）\033[0m\n'
  info "发布指针   : $POINTER_REF"
  info "指针 digest: $PTR_DIGEST"
  info "需要部署   : $NEED_DEPLOY"
  info "期望 commit: ${EXPECT_COMMIT:-（未公告，部署时以镜像 label 自证）}"
  printf '\n\033[1;32mDRY-RUN 结束：不 pull、不重建、不写 last-known-good。\033[0m\n'
  exit 0
fi

# ============================================================
# 4. 拉取不可变产物（按 digest）
# ============================================================
log "4/9 按 digest 拉取镜像（不可变产物）"
DIGEST_REF="$REGISTRY/$REPO@$PTR_DIGEST"
if ! docker pull "$DIGEST_REF" 2>&1 | tail -4 | sed 's/^/      /'; then
  die "按 digest 拉取失败：$DIGEST_REF" 1
fi
ok "已拉取 $DIGEST_REF"

# ============================================================
# 5. 部署前硬校验闸门（label + 期望 commit）
# ============================================================
log "5/9 部署前硬校验闸门"
LABELS=$(docker image inspect "$DIGEST_REF" --format '{{json .Config.Labels}}' 2>/dev/null || echo "{}")
info "镜像 labels = $LABELS"
IMG_REV=$(label_value "$LABELS" 'org.opencontainers.image.revision')
IMG_MD5_LABEL=$(label_value "$LABELS" 'artifact-md5')
if [ -z "$IMG_REV" ] || [ "$IMG_REV" = "<no value>" ]; then
  die "镜像缺少 label org.opencontainers.image.revision —— 来源不明，拒绝部署（fail-closed）" 1
fi
is_commitish "$IMG_REV" || die "label revision 形状不对（'$IMG_REV'）—— 拒绝部署" 1
ok "镜像 label revision = $IMG_REV"
if [ -n "$EXPECT_COMMIT" ]; then
  same_commit "$IMG_REV" "$EXPECT_COMMIT" \
    || die "镜像 label revision($IMG_REV) ≠ 期望 commit($EXPECT_COMMIT) —— 拒绝部署（fail-closed）" 1
  ok "label revision 与期望 commit 一致"
else
  warn "发布指针未公告 commit —— 以镜像 label 自证；容器起来后会核对 jar 内 embeddedGitCommit"
fi
if [ -n "$IMG_MD5_LABEL" ] && [ "$IMG_MD5_LABEL" != "<no value>" ]; then
  is_md5 "$IMG_MD5_LABEL" || die "label artifact-md5 形状不对（'$IMG_MD5_LABEL'）—— 拒绝部署" 1
  ok "镜像 label artifact-md5 = $IMG_MD5_LABEL"
else
  warn "镜像没有 artifact-md5 label —— 健康核对里 artifactMd5 会缺失（degraded）"
fi

# ============================================================
# 6. 用 digest 重建容器（compose 覆盖文件；绝不用可变 tag 部署）
# ============================================================
log "6/9 用 digest 重建容器"
OVERRIDE="$APP_DIR/$COMPOSE_FILE.ci-override.yml"
mkdir -p "$RELEASES_DIR"
CONFIG_BAK="$RELEASES_DIR/$COMPOSE_FILE.bak-$(date +%Y%m%d-%H%M%S)"
cp -a "$APP_DIR/$COMPOSE_FILE" "$CONFIG_BAK" && ok "原 compose 已备份：$CONFIG_BAK"

cat > "$OVERRIDE" <<YAML
# 由 scripts/srv1-redeploy.sh 自动生成 —— 不要手改（改完下次部署会被覆盖）
# 目的只有一个：把镜像钉死成【不可变 digest】，不再引用任何可变 tag。
# 生效方式：docker compose -f docker-compose.yml -f docker-compose.yml.ci-override.yml up -d
services:
  $SERVICE:
    image: $DIGEST_REF
# 生成信息：digest=$PTR_DIGEST commit=$IMG_REV artifactMd5=${IMG_MD5_LABEL:-unknown} 生成于 $(date -Is)
YAML
ok "已生成 digest 覆盖文件：$OVERRIDE"

# BUILD_SHA 与 ARTIFACT_MD5 是容器启动时注入的环境变量（compose 的 ${BUILD_SHA:-unknown}）。
# 若不显式传给 compose，重建后的容器会拿到 "unknown" → /api/health 立刻 degraded。
# 取值口径很关键：**一律以镜像 label 为准**（那才是这次部署真正要跑的东西）。
# 若沿用容器里旧值，出现"新镜像 + 旧 BUILD_SHA"就会让 health 报 mismatch ——
# 那正是最该被排除的状态，不能由部署脚本自己制造。
DEPLOY_BUILD_SHA="$IMG_REV"
DEPLOY_ARTIFACT_MD5="${IMG_MD5_LABEL:-unknown}"
CUR_BUILD_SHA=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$SERVICE" 2>/dev/null | sed -n 's/^BUILD_SHA=//p' | head -1)
info "BUILD_SHA: 当前容器=${CUR_BUILD_SHA:-（无）} → 本次注入=$DEPLOY_BUILD_SHA（来自镜像 label）"
info "ARTIFACT_MD5: 本次注入=$DEPLOY_ARTIFACT_MD5（来自镜像 label）"

cd "$APP_DIR" || die "无法进入 $APP_DIR" 3
if ! BUILD_SHA="$DEPLOY_BUILD_SHA" ARTIFACT_MD5="$DEPLOY_ARTIFACT_MD5" \
     docker compose -f "$COMPOSE_FILE" -f "$(basename "$OVERRIDE")" up -d --no-build "$SERVICE" 2>&1 | tail -6 | sed 's/^/      /'; then
  warn "compose 重建失败，直接回滚"
  "$0" --rollback-to "$RUNNING_IMAGE_ID" --config-bak "$CONFIG_BAK" --reason "compose 重建失败" || true
  die "compose 重建失败（已尝试回滚）" 1
fi
ok "容器已重建"

# ============================================================
# 7. 健康核对（三方一致才算成功）
# ============================================================
log "7/9 轮询 $HEALTH_URL 并做指纹核对"
HEALTH_JSON=""
HEALTH_OK=0
ELAPSED=0
while [ "$ELAPSED" -lt "$HEALTH_TIMEOUT" ]; do
  HEALTH_JSON=$(curl -s --max-time 5 "$HEALTH_URL" 2>/dev/null || echo "")
  if [ -n "$HEALTH_JSON" ]; then
    ST=$(json_value "$HEALTH_JSON" 'status')
    FM=$(json_value "$HEALTH_JSON" 'fingerprintMismatch')
    EC=$(json_value "$HEALTH_JSON" 'embeddedGitCommit')
    AM=$(json_value "$HEALTH_JSON" 'artifactMd5')
    if [ "$ST" = "ok" ] && [ "$FM" = "false" ] && is_commitish "$EC" && same_commit "$EC" "$IMG_REV"; then
      if [ -n "$IMG_MD5_LABEL" ] && [ -n "$AM" ] && [ "$AM" != "$IMG_MD5_LABEL" ]; then
        warn "artifactMd5 不一致（容器=$AM / label=$IMG_MD5_LABEL）—— 不判通过"
      else
        HEALTH_OK=1
        break
      fi
    fi
    printf '      [%3ds] status=%s fingerprintMismatch=%s embeddedGitCommit=%s artifactMd5=%s\n' \
      "$ELAPSED" "${ST:-?}" "${FM:-?}" "${EC:-?}" "${AM:-?}"
  else
    printf '      [%3ds] 健康接口尚无响应（容器可能还在启动）\n' "$ELAPSED"
  fi
  sleep "$HEALTH_INTERVAL"
  ELAPSED=$((ELAPSED + HEALTH_INTERVAL))
done

if [ "$HEALTH_OK" != 1 ]; then
  warn "健康核对未通过，开始回滚"
  printf '      最后响应: %s\n' "$(printf '%s' "$HEALTH_JSON" | head -c 600)"
  "$0" --rollback-to "$RUNNING_IMAGE_ID" --config-bak "$CONFIG_BAK" --reason "健康/指纹核对未通过" || true
  die "部署失败（已尝试回滚到 $RUNNING_IMAGE_ID）" 1
fi
ok "健康核对通过：status=ok / fingerprintMismatch=false / embeddedGitCommit=$IMG_REV / artifactMd5=${IMG_MD5_LABEL:-unknown}"

# ============================================================
# 8. 写 last-known-good（供一键回滚）
# ============================================================
log "8/9 写 last-known-good"
TMP_LKG="$LKG_FILE.tmp.$$"
cat > "$TMP_LKG" <<JSON
{
  "digest": "$PTR_DIGEST",
  "ref": "$DIGEST_REF",
  "commit": "$IMG_REV",
  "artifactMd5": "${IMG_MD5_LABEL:-unknown}",
  "deployedAt": "$(date -Is)",
  "previousImageId": "$RUNNING_IMAGE_ID",
  "composeFile": "$COMPOSE_FILE",
  "pointerTag": "$POINTER_TAG"
}
JSON
python3 -m json.tool "$TMP_LKG" >/dev/null 2>&1 || { rm -f "$TMP_LKG"; die "last-known-good JSON 不合法" 1; }
mv -f "$TMP_LKG" "$LKG_FILE"
chmod 600 "$LKG_FILE"
ok "已写 $LKG_FILE"
sed 's/^/      /' "$LKG_FILE"

cat > "$STATE_FILE" <<STATEEOF
# 由 srv1-redeploy.sh 生成：本次成功部署留下的现场
DEPLOYED_AT=$(date -Is)
DEPLOYED_DIGEST=$PTR_DIGEST
DEPLOYED_COMMIT=$IMG_REV
DEPLOYED_ARTIFACT_MD5=${IMG_MD5_LABEL:-unknown}
PREVIOUS_IMAGE_ID=$RUNNING_IMAGE_ID
PREVIOUS_REF=$RUNNING_REF
CONFIG_BACKUP=$CONFIG_BAK
STATEEOF
ok "状态快照：$STATE_FILE"

# ============================================================
# 9. 收尾
# ============================================================
log "9/9 收尾"
# 只保留最近 10 份 compose 备份，避免历史备份把磁盘吃满
ls -1t "$RELEASES_DIR"/"$COMPOSE_FILE".bak-* 2>/dev/null | tail -n +11 | xargs -r rm -f
docker ps --format '      {{.Names}}  {{.Status}}  {{.Image}}' | grep -E "$SERVICE" || true
printf '\n\033[1;32m部署成功：commit=%s digest=%s\033[0m\n' "$IMG_REV" "$PTR_DIGEST"
exit 0
