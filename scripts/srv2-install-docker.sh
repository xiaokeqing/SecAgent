#!/usr/bin/env bash
# ============================================================
# 服务器 2 安装 Docker + 测试镜像拉取速度
# ------------------------------------------------------------
# 为什么要测速再决定：
#   packages.wazuh.com 从上海只有 12 KB/s，官方 apt 源路线已经废了。
#   剩下的路是 Docker 镜像。但 Docker Hub 在国内也可能很慢，
#   而腾讯轻量有【内网】registry 加速（mirror.ccs.tencentyun.com）——
#   如果它能用，拉 Wazuh 镜像会很快；如果不能用，就走「本地拉 + save + 传」。
#   两条路的成本差很多，所以先花两分钟测。
# ============================================================
set -euo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

log "1/5 安装 Docker（用腾讯内网 apt 源）"
if command -v docker >/dev/null 2>&1; then
  ok "Docker 已安装：$(docker --version)"
else
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl gnupg lsb-release

  install -m 0755 -d /etc/apt/keyrings
  if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL --max-time 60 https://mirrors.tencent.com/docker-ce/linux/ubuntu/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
  fi

  ARCH=$(dpkg --print-architecture)
  CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")
  # 用腾讯内网镜像，比 download.docker.com 快得多
  echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.gpg] https://mirrors.tencent.com/docker-ce/linux/ubuntu $CODENAME stable" \
    > /etc/apt/sources.list.d/docker.list

  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  ok "已安装：$(docker --version)"
fi

log "2/5 配置镜像加速"
mkdir -p /etc/docker
# 腾讯轻量【内网】registry 加速。内网意味着不走公网流量、不吃 300G 流量包。
cat > /etc/docker/daemon.json <<'EOF'
{
  "registry-mirrors": ["https://mirror.ccs.tencentyun.com"],
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "data-root": "/var/lib/docker"
}
EOF
systemctl daemon-reload
systemctl enable docker >/dev/null 2>&1
systemctl restart docker
sleep 5
ok "daemon.json 已写入，docker 已重启"
echo "    镜像加速: $(docker info 2>/dev/null | grep -A2 'Registry Mirrors' | tail -1 | xargs)"
echo "    日志轮转: 10m x 3（防止容器日志把 40G 盘写满）"

log "3/5 测速：小镜像（alpine，约 3MB）"
T0=$(date +%s)
if timeout 180 docker pull alpine:3.19 >/dev/null 2>&1; then
  T1=$(date +%s)
  D=$((T1 - T0))
  [ "$D" -eq 0 ] && D=1
  SIZE_MB=3
  SPEED=$((SIZE_MB * 1024 / D))
  ok "alpine 拉取成功，耗时 ${D}s （约 ${SPEED} KB/s）"
  SMALL_OK=1
else
  warn "alpine 拉取失败或超时"
  SMALL_OK=0
fi

log "4/5 测速：Wazuh 管理端镜像（约 1GB 的真实目标）"
if [ "$SMALL_OK" -eq 1 ]; then
  echo "    开始拉 wazuh/wazuh-manager:4.9.2（这步最能说明问题）"
  T0=$(date +%s)
  if timeout 600 docker pull wazuh/wazuh-manager:4.9.2 2>&1 | tail -3; then
    T1=$(date +%s)
    ok "wazuh-manager 拉取完成，耗时 $((T1 - T0))s"
    WAZUH_OK=1
  else
    warn "wazuh-manager 拉取失败或超时（10 分钟）"
    WAZUH_OK=0
  fi
else
  warn "小镜像都不通，跳过"
  WAZUH_OK=0
fi

log "5/5 结论与决策依据"
echo
echo "    磁盘:"
df -h / | tail -1 | sed 's/^/      /'
echo
echo "    Docker 镜像占用:"
docker system df 2>/dev/null | sed 's/^/      /' || true
echo
if [ "${WAZUH_OK:-0}" -eq 1 ]; then
  ok "【可以直接在服务器上拉 Wazuh 镜像】—— 不用本地中转"
else
  warn "【需要走本地中转】—— 在开发机拉镜像 -> docker save -> scp -> docker load"
  echo "       这条路我在部署 SecAgent 到阿里云时验证过，约 3.2 MB/s 可用"
fi
