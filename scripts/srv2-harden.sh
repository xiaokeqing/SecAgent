#!/usr/bin/env bash
# ============================================================
# 服务器 2 加固（腾讯云轻量 · Ubuntu 22.04）
# ------------------------------------------------------------
# 用法：bash srv2-harden.sh
#
# 和服务器 1 的区别，以及为什么：
#   服务器 1 是 Alibaba Cloud Linux 3（RHEL 系），踩了两个坑：
#     1) sshd_config 里没有 Include -> /etc/ssh/sshd_config.d/ 的 drop-in 静默失效
#     2) systemd 239 < 240 -> 不支持 StandardOutput=append:
#   Ubuntu 22.04 两个都没有（已实测确认：Include 有 1 条、systemd 249）。
#   所以这里可以放心用 drop-in 写 sshd 配置。
#
# 但【仍然】要用 sshd -T 验证 —— 因为这是"这个发行版有没有 Include"的问题，
# 不是"这次写对了没有"的问题。养成习惯比记住哪个发行版有什么特性可靠。
#
# 安全顺序（重要）：
#   ufw 必须【先放行 22 再启用】，否则会把自己关在外面。
#   同理 sshd 配置要先 sshd -t 验证语法，再 reload。
# ============================================================
set -euo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

SWAP_SIZE="${SWAP_SIZE:-4G}"

log "1/7 配置 Swap"
if swapon --show | grep -q '/swapfile'; then
  ok "Swap 已存在，跳过创建"
else
  if [ -f /swapfile ]; then
    warn "/swapfile 已存在但未启用，先清掉重建"
    swapoff /swapfile 2>/dev/null || true
    rm -f /swapfile
  fi
  # fallocate 比 dd 快得多。有些文件系统不支持 fallocate 生成的文件当 swap，
  # 所以创建后再 mkswap 验证一次。
  fallocate -l "$SWAP_SIZE" /swapfile
  chmod 600 /swapfile
  if ! mkswap /swapfile >/dev/null 2>&1; then
    warn "fallocate 生成的文件不能当 swap，改用 dd"
    rm -f /swapfile
    dd if=/dev/zero of=/swapfile bs=1M count=4096 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
  fi
  swapon /swapfile
  ok "已创建并启用 $SWAP_SIZE Swap"
fi

# fstab 幂等
if ! grep -q '^/swapfile' /etc/fstab; then
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
  ok "已写入 /etc/fstab（开机自动挂载）"
else
  ok "/etc/fstab 已有条目"
fi

log "2/7 内核参数"
# swappiness=10：默认 60 会让内核在内存还空着时就提前把页换到磁盘，
#   在磁盘慢的服务器上纯属平白变慢。10 表示"真不够了才用"。
cat > /etc/sysctl.d/99-secagent.conf <<'EOF'
# SecAgent 服务器调优
#
# swappiness 默认 60 太激进：内核会按"成本收益"提前把冷页换出，
# 在内存够用时也照换，磁盘一慢就整体变慢。10 = 真不够才换。
vm.swappiness = 10

# 这个项目跑 Wazuh indexer（Lucene/OpenSearch），它大量依赖 mmap 文件映射。
# 默认值 10 在某些内核版本上会导致索引性能抖动，官方建议 Wazuh 场景设成 1。
vm.max_map_count = 262144
EOF
sysctl --system >/dev/null 2>&1
ok "swappiness=$(cat /proc/sys/vm/swappiness)  max_map_count=$(cat /proc/sys/vm/max_map_count)"

log "3/7 SSH 加固"
# Ubuntu 22.04 的 sshd_config 有 Include（已确认），所以 drop-in 会生效。
# 但这里仍然用 sshd -T（看合并后的实际配置）来验收，而不是 sshd -t（只看语法）。
cat > /etc/ssh/sshd_config.d/99-secagent-hardening.conf <<'EOF'
# SecAgent 加固配置
# 说明：Ubuntu 22.04 的 /etc/ssh/sshd_config 里有 Include sshd_config.d/*.conf，
#      所以这个文件会被读取。验证方式是 `sshd -T`（输出合并后的实际配置），
#      不是 `sshd -t`（只检查语法，drop-in 没被读取时它照样通过）。
#
# 密钥登录：保持开启（这是我们唯一的进入方式）
PubkeyAuthentication yes
# 密码登录：腾讯镜像默认已关，这里显式再关一次，避免镜像行为变化
PasswordAuthentication no
# 键盘交互认证也是一条密码路径，必须一起关
KbdInteractiveAuthentication no
# root 只允许密钥登录（不接受密码）
PermitRootLogin prohibit-password
# 单次连接最多尝试 3 次（默认 6，给爆破留的余地太大）
MaxAuthTries 3
# 登录宽限时间（默认 120 秒太长，给爆破留了时间窗）
LoginGraceTime 30
# X11 转发用不到，关掉减少攻击面
X11Forwarding no
# 禁止客户端传环境变量
PermitUserEnvironment no
# 空闲断开（配合客户端保活）
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

chmod 644 /etc/ssh/sshd_config.d/99-secagent-hardening.conf
sshd -t || die "sshd 配置语法错误，已中止（没有 reload，原配置仍生效）"
ok "sshd 配置语法通过"
systemctl reload ssh
ok "已 reload ssh"

log "4/7 给 root 配置同一把密钥"
# 目的：两台服务器用同一套管理方式（都走 root + 同一把密钥），
# 脚本不用关心"这台是 ubuntu 还是 root"。
# PermitRootLogin 已是 prohibit-password，所以这只是开一条【仅密钥】的路。
UBUNTU_KEY=/home/ubuntu/.ssh/authorized_keys
if [ -f "$UBUNTU_KEY" ]; then
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  touch /root/.ssh/authorized_keys
  # 把 ubuntu 已有的公钥同步给 root（不覆盖已有内容）
  while IFS= read -r line; do
    case "$line" in
      ssh-*|ecdsa-*|sk-*)
        if ! grep -qF "$line" /root/.ssh/authorized_keys 2>/dev/null; then
          echo "$line" >> /root/.ssh/authorized_keys
        fi
        ;;
    esac
  done < "$UBUNTU_KEY"
  chmod 600 /root/.ssh/authorized_keys
  ok "root 已有 $(grep -c 'ssh-' /root/.ssh/authorized_keys) 个密钥"
else
  warn "找不到 $UBUNTU_KEY，跳过（root 密钥没配）"
fi

log "5/7 安装并配置 fail2ban"
if command -v fail2ban-client >/dev/null 2>&1; then
  ok "fail2ban 已安装"
else
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban
  ok "已安装"
fi

cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
# Ubuntu 22.04 的日志走 systemd journal，用 systemd backend 比读文件可靠
backend = systemd
# 封禁 1 小时
bantime  = 3600
# 统计窗口
findtime = 600
# 窗口内失败 4 次就封
maxretry = 3
# 只封 IPv4（IPv6 后面如果要单独处理再说）
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
mode    = aggressive
port    = 22,2222
EOF

systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban
sleep 3
if systemctl is-active --quiet fail2ban; then
  ok "fail2ban 运行中：$(fail2ban-client status sshd 2>/dev/null | grep -E 'Currently failed|Total failed' | tr '\n' ' ')"
else
  warn "fail2ban 未正常运行，检查 /var/log/fail2ban.log"
fi

log "6/7 主机防火墙 ufw"
# ⚠️ 顺序很重要：先放行 22 再 enable，否则会把自己关在外面。
#
# ⚠️ 安全网：启用 ufw 之前挂一个后台任务，5 分钟后自动关闭 ufw。
#    万一规则顺序有问题把自己关在外面，不需要你去控制台 VNC 救 ——
#    等 5 分钟它自己就恢复了。
#
#    【这里踩过一次坑，记下来】
#    第一版写的是 `nohup bash -c 'sleep 300; ufw --force disable' &` 再 `kill $PID`。
#    结果 kill 只杀了父 bash，`sleep 300` 变成【孤儿进程】继续跑，
#    验收脚本报「安全网进程残留」。
#    实测确认 ufw 没被关（父 bash 死了，`ufw disable` 不会执行），
#    但留孤儿进程是脏的，而且会让校验误判 —— 一个会误报的校验比没有校验更糟。
#
#    正确做法：用 setsid 让子进程成为【独立进程组组长】，
#    取消时 `kill -- -$PID` 杀【整个进程组】，sleep 一起带走。
#    PID 落到文件里，万一脚本被中断，下次运行也能清掉上次的残留。
ROLLBACK_PIDFILE=/run/srv2-harden-rollback.pid
setsid bash -c 'sleep 300; ufw --force disable' >/dev/null 2>&1 &
ROLLBACK_PID=$!
echo "$ROLLBACK_PID" > "$ROLLBACK_PIDFILE"
ok "安全网已挂（进程组 $ROLLBACK_PID，5 分钟后自动关闭 ufw）"

# ⚠️ 另一个必须知道的点：Docker 会直接写 iptables 的 DOCKER 链，
#    【绕过 ufw】。所以 ufw 对"容器发布的端口"是无效的。
#    这也是为什么我们的容器必须继续只绑定 127.0.0.1 ——
#    不能指望 ufw 挡住容器的暴露端口。
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp comment 'SSH 管理（后续 22 会留给蜜罐）' >/dev/null
ufw allow 2222/tcp comment 'SSH 管理备用端口' >/dev/null
ufw --force enable >/dev/null
ok "ufw 已启用"
ufw status numbered 2>/dev/null | sed 's/^/    /'

# 规则已生效，取消安全网：杀【整个进程组】，再兜底清孤儿
if [ -f "$ROLLBACK_PIDFILE" ]; then
  RP=$(cat "$ROLLBACK_PIDFILE" 2>/dev/null || echo "")
  # 负号表示进程组。setsid 建的新组 ID 就等于子进程 PID。
  if [ -n "$RP" ]; then
    kill -- -"$RP" 2>/dev/null || true
    kill "$RP" 2>/dev/null || true
  fi
  rm -f "$ROLLBACK_PIDFILE"
fi
# 兜底：确认没有残留的 sleep 会在稍后动 ufw
pkill -f 'sleep 300; ufw' 2>/dev/null || true
pkill -f 'sleep 300' 2>/dev/null || true
sleep 1

if [ "$(ps aux | grep -c '[s]leep 300')" -eq 0 ]; then
  ok "安全网已彻底取消（含孤儿进程），无残留"
else
  warn "仍有残留进程，请手工检查：ps aux | grep sleep"
fi

# 最后确认 ufw 真的还开着（安全网没把自己也关掉）
if systemctl is-active --quiet ufw && ufw status | grep -q 'Status: active'; then
  ok "ufw 确认运行中"
else
  die "ufw 没在运行！规则可能有问题"
fi

log "7/7 验证"
echo
echo "  --- Swap ---"
free -m | sed 's/^/    /'
echo
echo "  --- sshd 生效配置（sshd -T 是权威，不是 sshd -t）---"
sshd -T 2>/dev/null | grep -E '^(port|maxauthtries|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|x11forwarding|logingracetime)' | sed 's/^/    /'
echo
echo "  --- 服务状态 ---"
for s in ssh fail2ban ufw; do
  printf "    %-12s %s\n" "$s" "$(systemctl is-active $s 2>/dev/null || echo unknown)"
done
echo
echo "  --- 监听端口 ---"
ss -tlnp 2>/dev/null | tail -n +2 | awk '{print "    "$1" "$4}' | sort -u
echo
echo "  --- 内存占用 Top5（看腾讯 agent 吃多少）---"
ps aux --sort=-%mem 2>/dev/null | head -6 | awk '{printf "    %-8s %5s%%  %s\n", $1, $4, $11}'

echo
ok "加固完成"
echo
echo "  下一步验证（在开发机上执行）："
echo "    ssh secagent-srv2 'echo ok'          # ubuntu 用户"
echo "    ssh -l root secagent-srv2 'echo ok'  # root 用户"
echo
warn "ufw 对 Docker 发布的端口【无效】—— Docker 直接写 iptables 绕过它。"
warn "所以容器必须继续只绑定 127.0.0.1，不能依赖 ufw 挡。"
