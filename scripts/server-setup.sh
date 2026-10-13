#!/usr/bin/env bash
# ============================================================
# SecAgent 服务器初始化脚本
# ------------------------------------------------------------
# 适用：Alibaba Cloud Linux 3 / RHEL 8 系（dnf）
# 用法：sudo bash server-setup.sh
#
# 本脚本只做「让服务能跑起来」的准备，不含 SSH 加固。
# SSH 加固单独放在 harden-ssh.sh，因为改端口需要同步改安全组，
# 顺序搞错会把自己锁在外面。
#
# 做四件事：
#   1. 加 2G Swap —— 2G 内存的机器上这是保命的
#   2. 安装 Docker CE（经阿里云镜像源）
#   3. 配置 Docker 日志轮转，防止日志把 40G 磁盘写满
#   4. 安装 git 与基础工具
# ============================================================
set -euo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }

if [[ $EUID -ne 0 ]]; then
  echo "请用 root 运行：sudo bash $0" >&2
  exit 1
fi

# ------------------------------------------------------------
log "1/4 配置 Swap"
# ------------------------------------------------------------
# 2G 内存跑 JVM 应用 + Docker，不加 Swap 很容易被 OOM Killer 干掉。
# swappiness 调低，让内核尽量用物理内存，Swap 只作为兜底。
if swapon --show | grep -q '/swapfile'; then
  ok "Swap 已存在，跳过"
else
  if [[ ! -f /swapfile ]]; then
    fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
    chmod 600 /swapfile
    mkswap /swapfile
  fi
  swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  sysctl -w vm.swappiness=10 >/dev/null
  grep -q '^vm.swappiness' /etc/sysctl.conf || echo 'vm.swappiness=10' >> /etc/sysctl.conf
  ok "Swap 已启用"
fi
free -m | grep -E 'Mem|Swap' | sed 's/^/    /'

# ------------------------------------------------------------
log "2/4 安装 Docker CE"
# ------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
  ok "Docker 已安装：$(docker --version)"
else
  dnf install -y dnf-utils >/dev/null
  # 用阿里云镜像源，国内直连 Docker 官方源基本不可用
  dnf config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo >/dev/null
  dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now docker
  ok "Docker 安装完成：$(docker --version)"
fi

# ------------------------------------------------------------
log "3/4 配置 Docker（日志轮转 + 镜像加速）"
# ------------------------------------------------------------
# 默认 json-file 日志不轮转，跑一段时间能把磁盘写满。
# 这台机器只有 40G 系统盘，必须限制。
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://docker.1ms.run"
  ],
  "live-restore": true
}
EOF
systemctl restart docker
ok "daemon.json 已写入并重启 Docker"

# ------------------------------------------------------------
log "4/4 安装基础工具"
# ------------------------------------------------------------
dnf install -y git curl wget vim tar >/dev/null 2>&1
ok "git: $(git --version)"

# ------------------------------------------------------------
log "完成"
# ------------------------------------------------------------
echo
echo "  系统      : $(grep -E '^NAME=' /etc/os-release | cut -d= -f2 | tr -d '\"')"
echo "  Docker    : $(docker --version)"
echo "  Compose   : $(docker compose version --short 2>/dev/null || echo '未安装')"
echo "  内存      : $(free -m | awk '/Mem:/{print $2" MB"}')"
echo "  Swap      : $(free -m | awk '/Swap:/{print $2" MB"}')"
echo "  磁盘可用  : $(df -h / | awk 'NR==2{print $4}')"
echo
echo "  下一步：把镜像传上来并启动服务。"
