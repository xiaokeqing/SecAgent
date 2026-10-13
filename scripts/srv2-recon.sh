#!/usr/bin/env bash
# 服务器 2 侦察：摸清现状再动手
# 重点确认「我在服务器 1 踩过的两个 RHEL 系坑」在 Ubuntu 上是否存在

echo "========== 1. 系统与版本 =========="
grep -E 'PRETTY|VERSION_ID' /etc/os-release
echo "  内核:    $(uname -r)"
echo "  systemd: $(systemctl --version | head -1)"
echo "  Python:  $(python3 --version 2>&1)"
echo "  SSH:     $(ssh -V 2>&1)"

echo
echo "========== 2. 关键差异确认（服务器 1 踩过的两个坑）=========="
INC=$(grep -c '^Include' /etc/ssh/sshd_config 2>/dev/null || echo 0)
echo "  sshd_config 里 Include 指令数: $INC"
if [ "$INC" -gt 0 ]; then
  echo "    -> 有 Include，drop-in 会生效（服务器 1 是 0，写进去等于没写）"
else
  echo "    -> 警告：没有 Include，drop-in 会静默失效"
fi
echo "  sshd_config.d 目录内容:"
ls -1 /etc/ssh/sshd_config.d/ 2>/dev/null | sed 's/^/    /' || echo "    (空)"

SDV=$(systemctl --version | head -1 | awk '{print $2}')
echo "  systemd 版本号: $SDV"
if [ "$SDV" -ge 240 ]; then
  echo "    -> >=240，支持 StandardOutput=append:"
else
  echo "    -> 警告：<240，不支持 append: 语法"
fi

echo
echo "========== 3. 资源 =========="
free -m
echo
df -h / | tail -1
echo "  CPU 核数: $(nproc)"
echo "  CPU 型号: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"

echo
echo "========== 4. 当前用户与权限 =========="
echo "  当前用户: $(whoami)"
printf "  sudo 免密: "
if sudo -n true 2>/dev/null; then echo "是(NOPASSWD)"; else echo "需要密码"; fi
echo "  所属组: $(groups)"

echo
echo "========== 5. 网络监听 =========="
ss -tlnp 2>/dev/null | tail -n +2 | awk '{print "    "$1" "$4}' | sort -u

echo
echo "========== 6. 已装组件 =========="
for c in docker nginx apache2 mysql ufw fail2ban git curl wget python3 pip3; do
  printf "  %-12s " "$c"
  if command -v "$c" >/dev/null 2>&1; then echo "已装"; else echo "未装"; fi
done

echo
echo "========== 7. apt 源与架构 =========="
grep -rhE '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | head -4 | sed 's/^/    /'
echo "  架构: $(dpkg --print-architecture)"

echo
echo "========== 8. 时区 =========="
timedatectl 2>/dev/null | head -3 | sed 's/^/    /'

echo
echo "========== 9. 内核保留参数（后面调 swappiness 用）=========="
echo "  当前 swappiness: $(cat /proc/sys/vm/swappiness)"
echo "  当前 overcommit: $(cat /proc/sys/vm/overcommit_memory)"

echo
echo "========== 10. 有没有别人动过的痕迹（新机器应该很干净）=========="
echo "  非系统用户（UID>=1000）:"
awk -F: '$3>=1000 && $3<65534 {print "    "$1" (uid "$3")"}' /etc/passwd
echo "  authorized_keys:"
for f in /root/.ssh/authorized_keys /home/ubuntu/.ssh/authorized_keys; do
  if [ -f "$f" ]; then
    echo "    $f  ($(grep -c 'ssh-' "$f" 2>/dev/null || echo 0) 个密钥)"
  fi
done
echo "  crontab(root): $(sudo crontab -l 2>/dev/null | grep -vc '^#' || echo 0) 条"
echo "  最近登录:"
last -n 5 2>/dev/null | head -5 | sed 's/^/    /'
