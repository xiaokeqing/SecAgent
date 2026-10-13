#!/usr/bin/env bash
# 安全网事件的复盘：确认现状 + 找出残留
echo "=== 时间 ==="
date '+%H:%M:%S'
echo

echo "=== ufw 是否还活着（最关键）==="
echo "  服务状态: $(systemctl is-active ufw)"
echo "  规则状态: $(ufw status | head -1)"
echo

echo "=== 残留进程（应该为空）==="
ps aux | grep -E '[s]leep 300|[u]fw --force disable' | sed 's/^/  /'
N=$(ps aux | grep -cE '[s]leep 300|[u]fw --force disable')
echo "  残留数: $N"
echo

echo "=== ufw 的 iptables 规则确实生效了吗 ==="
iptables -L ufw-user-input -n 2>/dev/null | head -8 | sed 's/^/  /'
echo

echo "=== 结论 ==="
if [ "$(systemctl is-active ufw)" = "active" ] && [ "$N" -eq 0 ]; then
  echo "  ✅ ufw 正常运行，无残留进程"
  exit 0
else
  echo "  ⚠️ 需要处理"
  exit 1
fi
