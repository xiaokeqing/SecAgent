#!/usr/bin/env bash
# ============================================================
# 服务器侧构建镜像并重启（**不再依赖任何人的本机 Docker**）
# ------------------------------------------------------------
# 为什么这样分工：
#   本机只需要 JDK+Maven 产出 jar（几十 MB，不需要 Docker、不吃 C 盘镜像空间），
#   镜像构建交给服务器 1 自己（它有 Docker 26 + 24GB 余量）。
#   原来的做法是「本机 docker build → docker save 311MB → scp」——
#   于是【本机没 Docker / C 盘满 / 没梯子】就完全发不了版（实测踩过：C 盘满导致瘫痪）。
#
# --network=host 的原因：实测服务器上 docker build 的 apt-get 阶段曾报
#   "failed to create endpoint ... network bridge does not exist"；
#   用 host 网络构建可绕开容器网络创建问题。
#
# 用法：build-on-server.sh <jar路径> <buildSha>     # buildSha = 部署脚本算出的【目标 commit】
#      ALLOW_DIRTY=1 bash build-on-server.sh ...   # 显式承认服务器工作区是脏的
#
# 【fail-closed】本脚本做的第一件事不是放 jar，而是校验源码：
#   ① 目标 commit 必须在服务器仓库里真实存在（sha 写错一个字符就别想继续）
#   ② 工作区 HEAD 必须正好等于目标 commit（不等 → 就是用旧源码构建）
#   ③ 工作区必须干净（有未提交改动 → 源码无法用 commit 唯一定位）
#   任一不满足 → 非零退出，且【不产生镜像、不重启容器】。
#
# 【部署后硬校验】容器起来之后还要证明「它跑的就是本次构建的镜像、跑的就是本次上传的 jar」：
#   ① 部署前记录 docker image ls 的镜像 ID；构建后取本次镜像 ID；
#      `docker inspect -f '{{.Image}}' secagent` 必须等于它，不等就 exit 7。
#      （防 compose 复用/回退旧 image —— 真实事故里 build 成功，但 compose 起的是 ACR 旧镜像）
#   ② `docker exec secagent md5sum /app/app.jar` 必须等于上传 jar 的 MD5，不等就 exit 8。
#      （防"镜像里的 app.jar 不是本次上传的产物" —— 曾经只能靠人肉 docker cp 才发现）
#   ③ 轮询 /api/health（最多 120s、每 3s）直到 status=ok 且 embeddedGitCommit=目标 sha；
#      超时才 exit 6，并打印最后一次 health 全量 JSON。
#      （原先读一次就判，容器还在 starting 时会读到旧版本指纹而误判失败）
#   ④ 若 secagent-redeploy.timer 处于 active，打印醒目警告与建议命令，但**不自动停**：
#      它每 5 分钟按 ACR digest 巡检，会把手工部署滚回旧镜像（实测 6994a3d → 69aff26）。
# ============================================================
set -euo pipefail

# 从 health JSON 里取字段（服务器上不保证有 jq；health 是单行紧凑 JSON）。
# json_str 取带引号的字符串值，json_raw 取布尔/数字等裸值。
json_str() {
  printf '%s' "${1:-}" \
    | grep -oE "\"${2}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 \
    | sed -E 's/^[^:]*:[[:space:]]*"//; s/"$//' || true
}
json_raw() {
  printf '%s' "${1:-}" \
    | grep -oE "\"${2}\"[[:space:]]*:[[:space:]]*(true|false|-?[0-9]+)" | head -1 \
    | sed -E 's/^[^:]*:[[:space:]]*//' || true
}

# ============================================================
# 【冲突检测】secagent-redeploy.timer 每 5 分钟按 ACR stable digest 巡检：
#   只要发布指针与当前运行 digest 不同，它就会 pull + 重建，把容器滚回 ACR 镜像。
#   实测后果：手工部署做到 6994a3d，几分钟后它把 embeddedGitCommit 退回 69aff26。
#   只警告、不自动停：停 timer 是有副作用的决定（可能正等 CI 的正式版本）。
# ============================================================
warn_timer_conflict() {
  command -v systemctl >/dev/null 2>&1 || return 0
  local timer svc
  timer="$(systemctl is-active secagent-redeploy.timer 2>/dev/null || true)"
  svc="$(systemctl is-active secagent-redeploy.service 2>/dev/null || true)"
  if [ "$timer" != "active" ] && [ "$svc" != "active" ]; then
    echo "  [OK] secagent-redeploy.timer/service 均未激活（不会被 ACR 巡检滚回旧镜像）"
    return 0
  fi
  printf '\n\033[1;41;97m'
  printf '  !!! 警告：ACR 巡检定时器正在运行，可能覆盖本次手工部署  !!!'
  printf '\033[0m\n'
  echo "       secagent-redeploy.timer   = $timer"
  echo "       secagent-redeploy.service = $svc"
  echo "       它每 5 分钟按 ACR stable digest 巡检；一旦触发重建，容器会被换回 ACR 里的镜像"
  echo "       （实测 embeddedGitCommit 从 6994a3d 退回 69aff26，手工部署被覆盖）。"
  echo "       本脚本【不会自动停】它。若要保证本次部署不被覆盖，请先执行："
  printf '           \033[1;33msudo systemctl stop secagent-redeploy.timer\033[0m\n'
  echo "       部署并核对完成后，按需恢复："
  echo "           sudo systemctl start secagent-redeploy.timer"
  printf '\n'
}

JAR="${1:-/tmp/sec-agent.jar}"
SHA="${2:-unknown}"
APP=/opt/secagent
cd "$APP"

if [ ! -f "$JAR" ]; then
  echo "[X] 找不到 jar: $JAR"
  exit 2
fi
if [ ! -f Dockerfile.runtime ]; then
  echo "[X] 找不到 Dockerfile.runtime: $APP/Dockerfile.runtime"
  echo "    本脚本只认 Dockerfile.runtime（单阶段、直接 COPY 上传的 runtime/app.jar）；"
  echo "    绝不能用多阶段的 Dockerfile（它会在镜像内用服务器源码重编，产物与上传 jar 不一致）。"
  exit 2
fi

# ============================================================
# 0/4 【fail-closed】源码校验 —— 必须在放 jar / 构建镜像 / 重启容器之前
# ------------------------------------------------------------
# 为什么放在最前面而且失败即非零退出：
#   老 Dockerfile 是多阶段构建，会在镜像内用**服务器上的 src** 编译；
#   只要服务器源码是旧的，就会产出「指纹是新的、代码是旧的」镜像 ——
#   这正是真实事故的形状。所以「源码树干净且正好是目标 commit」是硬前置条件：
#   不满足就连 jar 都不放、镜像不建、容器不动。
#
# 为什么用 git rev-parse --verify 而不是字符串比较短号：
#   短号/全号长度不同、写错一个字符（deadbeef）在字符串比较里都只是"不一致"，
#   但真正要区分的是「这个 commit 在本仓库里根本不存在」——
#   那说明部署的人和服务器根本不是同一份历史，比"不一致"更严重。
# ============================================================
ALLOW_DIRTY="${ALLOW_DIRTY:-0}"

echo "==> 0/4 源码校验（fail-closed：不满足就绝不构建）"
if [ -z "$SHA" ] || [ "$SHA" = "unknown" ]; then
  echo "  [X] 没有目标 commit（第 2 个参数为空/unknown）—— 无法校验源码版本，中止"
  exit 4
fi
if ! git -C "$APP" rev-parse --git-dir >/dev/null 2>&1; then
  echo "  [X] $APP 不是 git 工作区 —— 无法校验源码版本，中止"
  exit 4
fi
TARGET_FULL="$(git -C "$APP" rev-parse --verify --quiet "${SHA}^{commit}" || true)"
if [ -z "$TARGET_FULL" ]; then
  echo "  [X] 目标 commit '$SHA' 在服务器仓库里不存在 —— 不能证明源码就是它编的，中止"
  exit 4
fi
HEAD_FULL="$(git -C "$APP" rev-parse HEAD)"
if [ "$TARGET_FULL" != "$HEAD_FULL" ]; then
  echo "  [X] 源码 commit 不一致：工作区 HEAD=${HEAD_FULL} ≠ 目标 ${TARGET_FULL}（$SHA）"
  echo "      继续构建就会产出『指纹是新的、代码是旧的』镜像 —— 中止（绝不继续用旧源码构建）"
  exit 4
fi
DIRTY_LINES="$(git -C "$APP" status --porcelain)"
if [ -n "$DIRTY_LINES" ]; then
  if [ "$ALLOW_DIRTY" = "1" ]; then
    echo "  [!] 工作区有未提交改动，但显式传了 ALLOW_DIRTY=1 → 放行（产物不能等价于任何 commit）"
    echo "$DIRTY_LINES" | head -10 | sed 's/^/      /'
  else
    echo "  [X] 服务器工作区不干净（有未提交改动）—— 源码无法用 commit 唯一定位，中止"
    echo "$DIRTY_LINES" | head -10 | sed 's/^/      /'
    echo "      确认无误可显式放行：ALLOW_DIRTY=1 bash $0 <jar> $SHA"
    exit 5
  fi
fi
echo "  [OK] 源码校验通过：HEAD=$HEAD_FULL == 目标 commit，工作区$([ -n "$DIRTY_LINES" ] && echo '脏（已显式放行）' || echo '干净')"

# 【部署前】检测 ACR 巡检 timer 是否会覆盖本次部署（只警告，不自动停）
warn_timer_conflict

echo "==> 1/4 放置 jar（放 runtime/ —— target/ 被 .dockerignore 排除，会导致 COPY 失败）"
mkdir -p runtime
install -m 644 "$JAR" runtime/app.jar
ls -lh runtime/app.jar | tail -1

echo "==> 2/4 服务器侧构建镜像（Dockerfile.runtime：直接用上传的 jar，不在镜像内编译源码）"
JAR_MD5="$(md5sum runtime/app.jar | awk '{print $1}')"
ARTIFACT_MD5="$JAR_MD5"        # 供 /api/health 暴露（compose 映射为 APP_BUILD_ARTIFACT_MD5）
export ARTIFACT_MD5
# SOURCE_SHA 必须在 compose up 之前算好，否则注入进容器的还是空值（踩过）
SOURCE_SHA="$(git -C "$APP" rev-parse --short HEAD 2>/dev/null || echo unknown)"
export SOURCE_SHA
echo "  上传 jar MD5 = $JAR_MD5"
# 【为什么必须打 label】srv1-redeploy.sh 第 5/9 步是 fail-closed 闸门：镜像没有
# org.opencontainers.image.revision 就拒绝部署（"来源不明"）。2026-10-22 实测踩到：
# 用本脚本建出的镜像缺 label → 推到 ACR stable 后 redeploy 直接被拒，
# 而 secagent-redeploy.timer 每 5 分钟还会把容器换回 ACR 里那版旧镜像。
# 所以镜像必须自证身份：revision = 完整 commit，artifact-md5 = 上传 jar 的 MD5。
# 【部署前】记录现有镜像：部署后用容器 .Image 与「本次构建的镜像 ID」对比，
# 才能证明 compose 没有复用旧 image / 回退到 ACR 镜像。
PRE_IMAGE_ID="$(docker image inspect secagent:local --format '{{.Id}}' 2>/dev/null || true)"
echo "  部署前 secagent:local 镜像 ID = ${PRE_IMAGE_ID:-<不存在>}"
echo "  部署前 docker image ls（secagent 相关）："
docker image ls --no-trunc --format '    {{.Repository}}:{{.Tag}}  {{.ID}}  {{.CreatedSince}}' 2>/dev/null \
  | grep -i secagent || echo "    <无>"
docker build --network=host -f Dockerfile.runtime \
  --label "org.opencontainers.image.revision=$TARGET_FULL" \
  --label "artifact-md5=$JAR_MD5" \
  -t secagent:local . 2>&1 | tail -6

# 【构建后】取本次产出的镜像 ID —— 这是后面证明"容器跑的就是它"的唯一依据。
BUILT_IMAGE_ID=""
if ! BUILT_IMAGE_ID="$(docker image inspect secagent:local --format '{{.Id}}' 2>/dev/null)"; then
  echo "  [X] 构建后取不到 secagent:local 的镜像 ID —— 构建没有产出镜像，中止"
  exit 7
fi
if [ -z "$BUILT_IMAGE_ID" ]; then
  echo "  [X] 本次构建的镜像 ID 为空 —— 检索失败，中止"
  exit 7
fi
echo "  本次构建镜像 ID = $BUILT_IMAGE_ID"
if [ -n "$PRE_IMAGE_ID" ] && [ "$PRE_IMAGE_ID" = "$BUILT_IMAGE_ID" ]; then
  echo "  [!] 本次构建镜像 ID 与部署前相同 —— 内容未变化（Docker 层缓存命中）；"
  echo "      若刚改过 jar，说明 build context 或 Dockerfile.runtime 没把新 jar 拷进去，请检查。"
fi

# 【硬校验】镜像内产物必须等于上传的 jar。
# 不加这一步就会重演实测过的坑：多阶段 Dockerfile 在镜像内用【服务器旧源码】编译，
# 结果 BUILD_SHA 显示新版本、容器里跑的是旧代码（app.jar MD5 与上传 jar 不符）。
# 实现方式：docker create + docker cp 把产物【当文件拷出来】再算哈希。
# 踩过的三个坑，逐个说明：
#   ① `docker cp <cid>:/app/app.jar -` 输出的是 **tar 流**，md5 必然与 jar 不符；
#   ② `docker run` 在这台机器上已不可用（内置 bridge 网络损坏，建端点失败）→ 不能用 run；
#   ③ `docker create` 不启动容器、不建网络端点，因此在网络损坏时仍可用。
CID="$(docker create secagent:local 2>/dev/null || true)"
if [ -n "$CID" ]; then
  docker cp "$CID:/app/app.jar" /tmp/artifact-check.jar >/dev/null 2>&1 || true
  IMAGE_MD5="$(md5sum /tmp/artifact-check.jar 2>/dev/null | awk '{print $1}')"
  docker rm -f "$CID" >/dev/null 2>&1 || true
  [ -z "$IMAGE_MD5" ] && IMAGE_MD5="unavailable"
else
  IMAGE_MD5="cannot-create-container"
fi
echo "  镜像内 jar MD5 = $IMAGE_MD5"
if [ "$JAR_MD5" != "$IMAGE_MD5" ]; then
  echo "  [X] 镜像内产物与上传 jar 不一致（或无法校验）—— 中止部署（防『部署旧代码』）"
  exit 3
fi
echo "  [OK] 产物校验通过：镜像内 jar == 上传 jar"

echo "==> 3/4 写入版本指纹并重建容器"
echo -n "$SHA" > /root/build-sha.txt
export BUILD_SHA="$SHA"
# 产物指纹交给 /api/health 暴露（P0-4）：compose 里映射为 APP_BUILD_* 两个变量
export ARTIFACT_MD5
export SOURCE_SHA
# 【部署前复检】timer 若仍是 active，此刻提醒（部署后它随时可能把容器滚回 ACR 镜像）
warn_timer_conflict
# --no-build：禁止 compose 回退去用 build.dockerfile（多阶段旧 Dockerfile）重新构建，
# 也避免它在 image 缺失时自行 build 产出与本次产物不同的镜像。
docker compose up -d --force-recreate --no-build secagent 2>&1 | tail -3
# 这里不盲目 sleep：下面 3.6/4 与 4/4 会分别校验 jar 与 health，直到新版本真的在服务

# ============================================================
# 3.5/4 【硬校验】容器实际跑的镜像 == 本次构建产出的镜像 ID
# ------------------------------------------------------------
# 真实事故 B（2026-10-18）：build 明明产出了 secagent:local，`docker compose up -d`
# 起来的却是 ACR 旧镜像（digest 4ecf4741…）—— 原因是 compose 里 image: 指向别处、
# 或已有容器没被真正重建。当时是靠人肉 `md5sum /app/app.jar` 才发现"线上是旧代码"。
# 这里的判据不可反驳：容器 .Image（它真正使用的镜像 ID）必须等于
# 本次构建后取到的 BUILT_IMAGE_ID。不等就当场 exit 7。
# 另外显式用容器名 secagent 而不是 `docker compose ps -q`：compose 的 -q 可能给空，
# 空字符串喂给 docker inspect 只会报错，掩盖真正原因。
# 为什么用 if ! 形式取命令替换：set -e **不会**捕获 $(...) 内部的失败，
# 直接 `X="$(docker ...)"` 在取不到值时只会得到空串继续往下跑 —— 于是校验变成
# 永远通过的空比较。if ! 显式判断退出码，取不到也算失败。
# ============================================================
echo "==> 3.5/4 校验容器实际镜像 == 本次构建镜像"
ACTUAL_IMAGE_ID=""
if ! ACTUAL_IMAGE_ID="$(docker inspect -f '{{.Image}}' secagent 2>/dev/null)"; then
  echo "  [X] 取不到容器 secagent 的实际镜像 ID（容器没起来？）—— 中止"
  exit 7
fi
if [ -z "$ACTUAL_IMAGE_ID" ]; then
  echo "  [X] 容器 secagent 的镜像 ID 为空 —— 检索失败，中止"
  exit 7
fi
echo "  期望镜像ID(本次构建) = $BUILT_IMAGE_ID"
echo "  实际镜像ID(容器)     = $ACTUAL_IMAGE_ID"
if [ "$BUILT_IMAGE_ID" != "$ACTUAL_IMAGE_ID" ]; then
  echo "  [X] 容器跑的不是本次构建的镜像 —— 起了旧镜像，中止（不再靠人肉发现）"
  echo "      期望（本次构建）: $BUILT_IMAGE_ID"
  echo "      实际（容器）    : $ACTUAL_IMAGE_ID"
  exit 7
fi
echo "  [OK] 镜像一致：容器实际镜像 == 本次构建镜像"

# ============================================================
# 3.6/4 【硬校验】容器内 /app/app.jar 必须就是本次上传的 jar
# ------------------------------------------------------------
# 事故形态：镜像里的 app.jar 不是本次上传产物（构建上下文不对 / compose 复用旧 image），
# 当时只能靠人肉 `docker cp` 才发现"线上是旧代码"。这里直接进容器算 MD5 对比。
# 先等容器进入 Running：--force-recreate 刚返回时 exec 可能撞上 "container is restarting"。
# ============================================================
echo "==> 3.6/4 校验容器内 jar（docker exec secagent md5sum /app/app.jar）"
CONTAINER_RUNNING=""
for _ in $(seq 1 30); do
  CONTAINER_RUNNING="$(docker inspect -f '{{.State.Running}}' secagent 2>/dev/null || true)"
  [ "$CONTAINER_RUNNING" = "true" ] && break
  sleep 2
done
if [ "$CONTAINER_RUNNING" != "true" ]; then
  echo "  [X] 容器 secagent 在 60s 内没有进入 Running（当前=${CONTAINER_RUNNING:-<空>}）—— 中止"
  docker ps -a --filter name=secagent --format '  {{.Names}} | {{.Status}}' || true
  exit 8
fi
CONTAINER_MD5="$(docker exec secagent md5sum /app/app.jar 2>/dev/null | awk '{print $1}')" || true
echo "  上传 jar MD5   = $JAR_MD5"
echo "  容器内 jar MD5 = ${CONTAINER_MD5:-<取不到>}"
if [ -z "$CONTAINER_MD5" ] || [ "$CONTAINER_MD5" != "$JAR_MD5" ]; then
  echo "  [X] 容器内 /app/app.jar 与本次上传的 jar 不一致 —— 中止（镜像里的 jar 不是本次产物）"
  exit 8
fi
echo "  [OK] jar 一致：容器内 /app/app.jar == 上传 jar"

echo "==> 4/4 双指纹落盘 + 健康检查"
# SOURCE_SHA 已在步骤 2 算好并 export（必须在 compose up 之前，否则容器里是 unknown）
# 必须先 fetch：实测发现服务器上的 origin/main ref 同样是陈旧的，
# 直接拿它比等于没比（本地 HEAD 与陈旧 origin 相等 → 误判为"已同步"）。
if git -C "$APP" fetch --quiet origin main 2>/dev/null; then
  ORIGIN_SHA="$(git -C "$APP" rev-parse --short origin/main 2>/dev/null || echo unknown)"
  FETCH_STATE="ok"
else
  ORIGIN_SHA="fetch-failed"     # 连不上 GitHub → 无法验证是否同步，如实标注，不假装
  FETCH_STATE="failed"
fi
{
  echo "deployed_at=$(date -Is)"
  echo "BUILD_SHA=${SHA}"
  echo "SOURCE_SHA=$SOURCE_SHA"
  echo "ORIGIN_MAIN_SHA=$ORIGIN_SHA"
  echo "fetch_state=$FETCH_STATE"
  echo "build_mode=on-server(--network=host)"
} > "$APP/DEPLOY-FINGERPRINTS.txt"
echo "  指纹: BUILD=${SHA} SOURCE=$SOURCE_SHA ORIGIN=$ORIGIN_SHA (fetch=$FETCH_STATE)"
if [ "$FETCH_STATE" = "failed" ]; then
  echo "  [!] 无法从 GitHub fetch（网络问题）→ 源码同步状态【无法验证】，请人工确认"
elif [ "$SOURCE_SHA" != "$ORIGIN_SHA" ]; then
  echo "  [!] 源码【未】同步到 origin/main（$SOURCE_SHA ≠ $ORIGIN_SHA）—— 用的是旧源码，请确认符合预期"
fi
docker ps --format '  {{.Names}} | {{.Status}}' | head -3

# ============================================================
# 4/4 【fail-closed】轮询 health 直到「新版本真的在服务」
# ------------------------------------------------------------
# 为什么必须轮询：--force-recreate 返回时新容器才刚刚开始启动（Spring 40~90s）。
# 立刻读 /api/health 会读到旧容器的应答（旧版本指纹）或空 ——
# 于是把"新容器其实已经起来"误判成失败，fail-closed 中止。
# 判据：status=ok 且 embeddedGitCommit=目标 sha；最多 120 秒、每 3 秒一次。
# 超时才失败，并打印最后一次 health 全量 JSON（含 fingerprintIssues 等排查信息）。
# ============================================================
HEALTH_JSON=""
HEALTH_STATUS=""
HEALTH_COMMIT=""
HEALTH_OK=0
DEADLINE=$(( $(date +%s) + 120 ))
ATTEMPT=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  ATTEMPT=$((ATTEMPT + 1))
  HEALTH_JSON="$(curl -s -m 10 http://127.0.0.1:9900/api/health 2>/dev/null || true)"
  if [ -n "$HEALTH_JSON" ]; then
    HEALTH_STATUS="$(json_str "$HEALTH_JSON" status)"
    HEALTH_COMMIT="$(json_str "$HEALTH_JSON" embeddedGitCommit)"
    echo "  第 ${ATTEMPT} 次健康检查：status=${HEALTH_STATUS:-?} embeddedGitCommit=${HEALTH_COMMIT:-?}"
    if [ "$HEALTH_STATUS" = "ok" ] && [ "$HEALTH_COMMIT" = "$SHA" ]; then
      HEALTH_OK=1
      break
    fi
  fi
  sleep 3
done
if [ "$HEALTH_OK" != "1" ]; then
  echo "  [X] 120s 内没有等到 status=ok 且 embeddedGitCommit=$SHA"
  if [ -n "$HEALTH_JSON" ]; then
    echo "  最后一次 /api/health 全量 JSON："
    echo "  $HEALTH_JSON"
  else
    echo "  最后一次 /api/health：无响应（120s 内 curl 没拿到任何 JSON）"
  fi
  exit 6
fi
echo "  health: $HEALTH_JSON"
POST_FAILED=0
HEALTH_BUILD_SHA="$(json_str "$HEALTH_JSON" buildSha)"
[ "$HEALTH_BUILD_SHA" = "$SHA" ] \
  || { echo "  [X] buildSha=$HEALTH_BUILD_SHA != $SHA（容器环境变量 BUILD_SHA 没注入对，compose 可能没生效）"; POST_FAILED=1; }
HEALTH_MISMATCH="$(json_raw "$HEALTH_JSON" fingerprintMismatch)"
[ "$HEALTH_MISMATCH" = "false" ] \
  || { echo "  [X] fingerprintMismatch=$HEALTH_MISMATCH != false（见 health 的 fingerprintIssues / fingerprintMismatchReason）"; POST_FAILED=1; }
HEALTH_STATUS="$(json_str "$HEALTH_JSON" status)"
[ "$HEALTH_STATUS" = "ok" ] \
  || { echo "  [X] status=$HEALTH_STATUS != ok（见 health 的 fingerprintIssues）"; POST_FAILED=1; }
HEALTH_ARTIFACT_MD5="$(json_str "$HEALTH_JSON" artifactMd5)"
if [ -n "$HEALTH_ARTIFACT_MD5" ] && [ "$HEALTH_ARTIFACT_MD5" != "$JAR_MD5" ]; then
  echo "  [X] health.artifactMd5=$HEALTH_ARTIFACT_MD5 != 上传 jar MD5=$JAR_MD5（容器里不是本次上传产物）"
  POST_FAILED=1
fi
if [ "$POST_FAILED" != "0" ]; then
  echo "  [X] 部署后核对未通过 —— 以非零退出（别把『看起来成功』当成功）"
  exit 6
fi
echo "  [OK] 部署后核对通过：embeddedGitCommit = buildSha = $SHA，fingerprintMismatch=false，status=ok，artifactMd5=${HEALTH_ARTIFACT_MD5:-<未暴露>}"
