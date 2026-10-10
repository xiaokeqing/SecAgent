#!/usr/bin/env bash
# ============================================================
# SecAgent 服务器部署脚本
# ------------------------------------------------------------
# 用法（在服务器上）：sudo bash server-deploy.sh
#
# 前置条件：
#   1. 已执行 server-setup.sh（Docker 已安装）
#   2. 镜像包已上传到 /root/secagent-image.tar
#   3. .env 已上传到 /root/secagent.env（含真实凭据）
#
# 为什么用「镜像包 + git clone」而不是直接在服务器上构建：
#   这台机器只有 2 核 2G，跑 mvn package 很容易 OOM。
#   镜像在开发机或 CI 上构建好再传过来，是低配服务器的标准做法。
# ============================================================
set -euo pipefail

APP_DIR=/opt/secagent
REPO_URL=https://github.com/xiaokeqing/SecAgent.git
IMAGE_TAR=/root/secagent-image.tar
ENV_SRC=/root/secagent.env

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请用 root 运行"
command -v docker >/dev/null || die "Docker 未安装，请先跑 server-setup.sh"

# ------------------------------------------------------------
log "1/5 载入镜像"
# ------------------------------------------------------------
[[ -f $IMAGE_TAR ]] || die "找不到镜像包 $IMAGE_TAR"
docker load -i "$IMAGE_TAR"
docker images secagent --format '  {{.Repository}}:{{.Tag}}  {{.Size}}'

# ------------------------------------------------------------
log "2/5 拉取源码"
# ------------------------------------------------------------
# 只需要 docker-compose.yml、security-docs/ 和 data/vector-store.json。
# 源码在这里不参与构建，但放一份便于排查与更新。
if [[ -d $APP_DIR/.git ]]; then
  git -C "$APP_DIR" fetch --all --quiet
  git -C "$APP_DIR" reset --hard origin/main --quiet
  ok "已更新到最新 main"
else
  mkdir -p "$(dirname $APP_DIR)"
  git clone --depth 1 "$REPO_URL" "$APP_DIR" --quiet
  ok "已克隆到 $APP_DIR"
fi

# ------------------------------------------------------------
log "3/5 写入凭据"
# ------------------------------------------------------------
[[ -f $ENV_SRC ]] || die "找不到凭据文件 $ENV_SRC"
install -m 600 "$ENV_SRC" "$APP_DIR/.env"
ok ".env 已就位（权限 600）"
# 部署用的凭据副本用完就删，避免在 /root 下多留一份
shred -u "$ENV_SRC" 2>/dev/null || rm -f "$ENV_SRC"

# ------------------------------------------------------------
log "4/5 启动服务"
# ------------------------------------------------------------
cd "$APP_DIR"
# --no-build：镜像已经载入，不要在 2C2G 的机器上触发构建
docker compose up -d --no-build

# ------------------------------------------------------------
log "5/5 等待健康检查"
# ------------------------------------------------------------
for i in $(seq 1 30); do
  sleep 5
  status=$(docker compose ps --format '{{.Status}}' 2>/dev/null | head -1)
  echo "    [$i] $status"
  if echo "$status" | grep -q healthy; then
    ok "容器已健康"
    break
  fi
  if echo "$status" | grep -qE 'Restarting|Exited'; then
    echo
    echo "  容器异常，最近日志："
    docker compose logs --tail 40
    die "启动失败"
  fi
done

# ------------------------------------------------------------
log "完成"
# ------------------------------------------------------------
echo
curl -s http://127.0.0.1:9900/api/health | head -c 400
echo
echo
docker compose ps
echo
docker stats --no-stream --format '  {{.Name}}  CPU={{.CPUPerc}}  内存={{.MemUsage}}'
echo
echo "  服务只监听 127.0.0.1:9900，外网无法直连。"
echo "  下一步：配置隧道对外提供 HTTPS 访问。"
