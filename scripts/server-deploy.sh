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
# warn 曾经漏定义：脚本里调用了它，但只在另一个脚本（server-setup.sh）里定义过。
# 表现是部署日志里冒出一行 "warn: command not found" —— 因为刚好在 set +e 的
# 区间里，不影响流程，所以很容易被忽略。函数定义必须和调用对齐。
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
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
log "2/5 更新配置（从上传的文件，不依赖 git）"
# ------------------------------------------------------------
# ⚠️ 为什么配置走 scp 而不是 git pull —— 这是踩坑之后改的。
#
# 原来的做法：docker-compose.yml 靠 `git pull` 从 GitHub 拉。
# 实测阿里云杭州这台机器访问 github.com 时好时坏，于是出现这个组合：
#     镜像更新成功了（走 scp）
#     配置没更新（走 git，失败了）
#     -> 容器用旧 compose 起来，新加的环境变量压根没被引用
#
# 而【这一切是静默的】：部署日志里只有一行「拉取源码失败，沿用现有版本」，
# 然后健康检查照样通过、服务照样正常 —— 只是配置没生效。
# 我因此白折腾了一轮（buildSha 一直是 unknown，查了半天才发现 compose 是旧的）。
#
# 教训：既然镜像走 scp 是可靠的，配置也该走 scp。
#      【不要让同一次部署里的两个依赖项用两种可靠性不同的传输方式。】
#
# 源码仍然拉一份（便于在服务器上排查），但它【失败不影响配置】。
if [[ -f /root/deploy-compose.yml ]]; then
  cp /root/deploy-compose.yml "$APP_DIR/docker-compose.yml"
  ok "docker-compose.yml 已从上传文件更新"
else
  warn "没找到 /root/deploy-compose.yml，沿用现有 compose（可能与仓库不一致）"
fi

set +e
if [[ -d $APP_DIR/.git ]]; then
  if git -C "$APP_DIR" fetch --all --quiet 2>/dev/null \
     && git -C "$APP_DIR" reset --hard origin/main --quiet 2>/dev/null; then
    ok "源码已更新到最新 main"
  else
    warn "拉取源码失败（GitHub 连接问题）—— 不影响配置，继续部署"
  fi
else
  mkdir -p "$(dirname $APP_DIR)"
  if git clone --depth 1 "$REPO_URL" "$APP_DIR" --quiet 2>/dev/null; then
    ok "已克隆到 $APP_DIR"
  else
    warn "克隆源码失败，跳过（镜像和配置都已就位，不影响启动）"
  fi
fi
set -e

# ------------------------------------------------------------
# ⚠️【必须放在源码同步之后】再覆盖一次 compose
# ------------------------------------------------------------
# 原因（2026-10-11 实际踩到）：$APP_DIR 是个活的 git 仓库，
# 上面那句 `git reset --hard origin/main` 会把刚 scp 上来的
# docker-compose.yml 一起回退成 GitHub 上的版本。
# 那天上传的是「修好隧道密钥挂载」的 compose，reset 把它换回了带缺陷的旧版本 ——
# 隧道随即崩溃循环（restart 一路涨），应用启动时连不上 Wazuh、静默降级 MOCK，
# 而部署日志里两步都显示 [OK]，光看日志根本发现不了。
#
# 结论：源码同步在前、配置覆盖在后 —— 配置永远是最后一次写入。
if [[ -f /root/deploy-compose.yml ]]; then
  cp /root/deploy-compose.yml "$APP_DIR/docker-compose.yml"
  ok "docker-compose.yml 已在源码同步之后重新覆盖（配置以本机上传为准）"
fi

# ------------------------------------------------------------
log "3/5 写入凭据"
# ------------------------------------------------------------
# 这个脚本要支持两种场景：
#   首次部署 —— 凭据由 /root/secagent.env 提供，装完就删掉副本
#   重复部署 —— 凭据已经在 $APP_DIR/.env 里了，不该也不需要重新提供
# 初版只处理了第一种，导致第二次部署直接 die 在「找不到凭据文件」上。
if [[ -f $ENV_SRC ]]; then
  install -m 600 "$ENV_SRC" "$APP_DIR/.env"
  ok ".env 已更新（权限 600）"
  # 部署用的凭据副本用完就删，避免在 /root 下多留一份
  shred -u "$ENV_SRC" 2>/dev/null || rm -f "$ENV_SRC"
elif [[ -f $APP_DIR/.env ]]; then
  chmod 600 "$APP_DIR/.env"
  ok ".env 已存在，沿用（权限已校正为 600）"
else
  die "既没有 $ENV_SRC 也没有 $APP_DIR/.env，无法确定凭据"
fi

# ------------------------------------------------------------
# ⚠️ 修正数据目录属主 —— 这一步是踩坑之后固化进来的。
# 容器以 secagent(uid 999) 运行。bind mount 的宿主机目录如果属主是 root，
# 容器就写不进去；而写失败只在日志里，API 照样返回 success ——
# 结果是"审计与封禁记录全是空的，但功能看起来完全正常"。
# 现在 StorageGuard 会在启动时检查可写性并拒绝启动（fail-closed），
# 所以漏了这一步的后果从"静默失效"变成"起不来"—— 后者安全得多。
# 把当次代码版本写进环境变量，供健康接口返回。
# 这样"改了代码但没重新部署"会自己暴露 —— 整体检查会比对
# 线上 buildSha 与仓库 HEAD，不一致就报错。
# （这个机制是被一次真实的部署漂移逼出来的：代码改了、提交了，
#   但忘了部署，线上仍是旧的有缺陷版本，而从外部完全看不出来。）
#
# 版本号优先取【上传文件】里写的 —— 那是开发机上的真实 HEAD。
# 退回到服务器 git 的话，如果 git pull 恰好失败，就会把一个
# 旧版本号报成"当前版本"，反而掩盖了漂移。
if [[ -f /root/build-sha.txt ]]; then
  export BUILD_SHA="$(tr -d '[:space:]' < /root/build-sha.txt)"
  ok "BUILD_SHA=$BUILD_SHA（来自上传文件，即开发机 HEAD）"
else
  export BUILD_SHA="$(git -C "$APP_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  warn "BUILD_SHA=$BUILD_SHA（取自服务器 git，可能不是当次部署的版本）"
fi
export BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 容器自己的默认网关 —— compose 的 extra_hosts 需要它来指向宿主机的隧道。
# 不能用 docker 的 host-gateway：那是 docker0 的网关（172.17.0.1），
# 而容器在 compose 自建网络上，两个网络之间没有路由。
if [[ -f /root/wazuh-host-ip.txt ]]; then
  export WAZUH_HOST_IP="$(tr -d '[:space:]' < /root/wazuh-host-ip.txt)"
  ok "WAZUH_HOST_IP=$WAZUH_HOST_IP（容器默认网关）"
else
  warn "没有 /root/wazuh-host-ip.txt，compose 会用默认值（可能连不上 Wazuh）"
fi
chown -R 999:999 /opt/secagent/data /opt/secagent/uploads 2>/dev/null || warn "chown 数据目录失败"
chmod 750 /opt/secagent/data /opt/secagent/uploads 2>/dev/null || true
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
# ------------------------------------------------------------
# 双指纹落盘 + 源码陈旧显式告警（B：源码同步健壮化）
# 背景：上面的源码同步（git fetch/reset）失败时只 warn 一句就继续部署，
# 于是可能出现「镜像是新版、服务器源码是旧版」而没人知道 —— 属静默降级。
SOURCE_SHA="$(git -C "$APP_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
ORIGIN_SHA="$(git -C "$APP_DIR" rev-parse --short origin/main 2>/dev/null || echo unknown)"
{
  echo "deployed_at=$(date -Is)"
  echo "BUILD_SHA=${BUILD_SHA:-unknown}"
  echo "SOURCE_SHA=$SOURCE_SHA"
  echo "ORIGIN_MAIN_SHA=$ORIGIN_SHA"
} > /opt/secagent/DEPLOY-FINGERPRINTS.txt
ok "指纹落盘 DEPLOY-FINGERPRINTS.txt → BUILD=${BUILD_SHA:-unknown} SOURCE=$SOURCE_SHA ORIGIN=$ORIGIN_SHA"
if [ "$SOURCE_SHA" != "$ORIGIN_SHA" ] && [ "$ORIGIN_SHA" != "unknown" ]; then
  warn "源码【未】同步到 origin/main（服务器 $SOURCE_SHA ≠ 远端 $ORIGIN_SHA）—— 本次用的是旧源码，请确认符合预期"
fi

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
