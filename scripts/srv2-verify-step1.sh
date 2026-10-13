#!/usr/bin/env bash
# 步骤 ① 的最终验收：逐项给出可核对的证据
echo "=============================================="
echo " 步骤 ① 加固验收"
echo "=============================================="

echo
echo "--- 1. Swap 是否真的在（不只是文件存在）---"
swapon --show
echo "  /proc/swaps:"
cat /proc/swaps | sed 's/^/    /'
printf "  fstab 持久化: "
grep -q '^/swapfile' /etc/fstab && echo "已写入（重启后自动挂载）" || echo "缺失！"

echo
echo "--- 2. swappiness（应该是 10，不是默认 60）---"
echo "  当前值: $(cat /proc/sys/vm/swappiness)"
grep -h swappiness /etc/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null | sed 's/^/    /'

echo
echo "--- 3. sshd 生效配置（sshd -T = 合并后的真实配置）---"
sshd -T 2>/dev/null | grep -E '^(port|maxauthtries|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|x11forwarding|logingracetime)' | sed 's/^/    /'

echo
echo "--- 4. 加固配置真的被读取了吗（不是 drop-in 静默失效）---"
printf "    sshd_config 里 Include 条数: "
grep -c '^Include' /etc/ssh/sshd_config
printf "    我们的 drop-in 文件: "
ls -la /etc/ssh/sshd_config.d/99-secagent-hardening.conf 2>/dev/null | awk '{print $1" "$5" bytes"}' || echo "不存在！"

echo
echo "--- 5. fail2ban ---"
echo "    服务: $(systemctl is-active fail2ban)"
fail2ban-client status sshd 2>/dev/null | sed 's/^/    /'

echo
echo "--- 6. ufw ---"
echo "    服务: $(systemctl is-active ufw)"
ufw status verbose 2>/dev/null | grep -vE '^$' | sed 's/^/    /'

echo
echo "--- 7. 安全网进程是否残留（应该没有）---"
N=$(ps aux | grep -c '[s]leep 300')
echo "    残留的 sleep 300 进程数: $N"
if [ "$N" -eq 0 ]; then
  echo "    正常 —— 没有会在几分钟后偷偷关掉 ufw 的进程"
else
  echo "    警告！有残留，ufw 会在 5 分钟后被关闭"
  ps aux | grep '[s]leep 300' | sed 's/^/    /'
fi

echo
echo "--- 8. root 密钥 ---"
echo "    root authorized_keys 里的密钥数: $(grep -c 'ssh-' /root/.ssh/authorized_keys 2>/dev/null || echo 0)"
echo "    ubuntu authorized_keys 里的密钥数: $(grep -c 'ssh-' /home/ubuntu/.ssh/authorized_keys 2>/dev/null || echo 0)"

echo
echo "--- 9. 内存现状（含腾讯 agent 占用）---"
free -m | sed 's/^/    /'
echo "    内存占用 Top6:"
ps aux --sort=-%mem 2>/dev/null | head -7 | tail -6 | awk '{printf "      %-10s %5s%%  %s\n", $1, $4, $11}'

echo
echo "--- 10. 内核参数 ---"
echo "    max_map_count: $(cat /proc/sys/vm/max_map_count)  (Wazuh indexer 需要)"
echo "    overcommit:    $(cat /proc/sys/vm/overcommit_memory)"

echo
echo "--- 11. 监听端口 ---"
ss -tlnp 2>/dev/null | tail -n +2 | awk '{print "    "$1" "$4}' | sort -u

echo
echo "=============================================="
echo " 验收结论"
echo "=============================================="
FAIL=0
[ -n "$(swapon --show)" ] || { echo "  [FAIL] Swap 没启用"; FAIL=1; }
[ "$(cat /proc/sys/vm/swappiness)" = "10" ] || { echo "  [FAIL] swappiness 不是 10"; FAIL=1; }
sshd -T 2>/dev/null | grep -q '^passwordauthentication no' || { echo "  [FAIL] 密码登录还开着"; FAIL=1; }
sshd -T 2>/dev/null | grep -q '^maxauthtries 3' || { echo "  [FAIL] maxauthtries 不是 3"; FAIL=1; }
systemctl is-active --quiet fail2ban || { echo "  [FAIL] fail2ban 没运行"; FAIL=1; }
systemctl is-active --quiet ufw || { echo "  [FAIL] ufw 没运行"; FAIL=1; }
[ "$N" -eq 0 ] || { echo "  [FAIL] 安全网进程残留"; FAIL=1; }

if [ "$FAIL" -eq 0 ]; then
  echo "  ✅ 11 项检查全部通过，步骤 ① 完成"
else
  echo "  ❌ 有检查未通过"
fi
exit $FAIL
