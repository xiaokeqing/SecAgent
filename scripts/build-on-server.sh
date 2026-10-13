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
# ============================================================
set -euo pipefail

JAR="${1:-/tmp/sec-agent.jar}"
SHA="${2:-unknown}"
APP=/opt/secagent
cd "$APP"

if [ ! -f "$JAR" ]; then
  echo "[X] 找不到 jar: $JAR"
  exit 2
fi
if [ ! -f Dockerfile ]; then
  echo "[X] 找不到 Dockerfile: $APP/Dockerfile"
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
docker build --network=host -f Dockerfile.runtime -t secagent:local . 2>&1 | tail -6

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
docker compose up -d --force-recreate secagent 2>&1 | tail -3
# 这里不盲目 sleep：下面 4/4 会轮询 health，一直到容器真的报出目标 commit 为止

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

# 部署后独立核对（不靠"看起来成功"）：
#   等到 health 报出【目标 commit】，再断言 fingerprintMismatch=false、status=ok。
# 为什么不能只 curl 一下就算过：事故形态就是"接口 200、一切正常"。
HEALTH_JSON=""
for _ in $(seq 1 36); do
  HEALTH_JSON="$(curl -s -m 10 http://127.0.0.1:9900/api/health || true)"
  if echo "$HEALTH_JSON" | grep -q "\"embeddedGitCommit\":\"${SHA}\""; then
    break
  fi
  sleep 5
done
echo "  health: $HEALTH_JSON"
POST_FAILED=0
echo "$HEALTH_JSON" | grep -q "\"embeddedGitCommit\":\"${SHA}\"" \
  || { echo "  [X] embeddedGitCommit != $SHA（jar 内固化的 commit 与本次发布的目标 commit 不一致）"; POST_FAILED=1; }
echo "$HEALTH_JSON" | grep -q '"fingerprintMismatch":false' \
  || { echo "  [X] fingerprintMismatch != false（见 health 的 fingerprintMismatchReason）"; POST_FAILED=1; }
echo "$HEALTH_JSON" | grep -q '"status":"ok"' \
  || { echo "  [X] status != ok（见 health 的 fingerprintIssues）"; POST_FAILED=1; }
if [ "$POST_FAILED" != "0" ]; then
  echo "  [X] 部署后核对未通过 —— 以非零退出（别把『看起来成功』当成功）"
  exit 6
fi
echo "  [OK] 部署后核对通过：embeddedGitCommit = $SHA，fingerprintMismatch=false，status=ok"
