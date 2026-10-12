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
# 用法：build-on-server.sh <jar路径> <buildSha>
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

echo "==> 1/4 放置 jar（Dockerfile 期望路径 target/）"
mkdir -p target
install -m 644 "$JAR" target/sec-agent-1.0-SNAPSHOT.jar
ls -lh target/*.jar | tail -1

echo "==> 2/4 服务器侧构建镜像（docker build --network=host）"
docker build --network=host -t secagent:local . 2>&1 | tail -6

echo "==> 3/4 写入版本指纹并重建容器"
echo -n "$SHA" > /root/build-sha.txt
export BUILD_SHA="$SHA"
docker compose up -d --force-recreate secagent 2>&1 | tail -3
sleep 30

echo "==> 4/4 双指纹落盘 + 健康检查"
SOURCE_SHA="$(git -C "$APP" rev-parse --short HEAD 2>/dev/null || echo unknown)"
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
curl -s -m 15 http://127.0.0.1:9900/api/health | head -c 260
echo ""
