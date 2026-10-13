#!/usr/bin/env bash
# 服务器运行状态快照
echo "--- 系统 ---"
uptime | sed 's/^/  /'
free -m | head -2 | sed 's/^/  /'
df -h / | tail -1 | sed 's/^/  /'
echo
echo "--- systemd 服务 ---"
for s in docker secagent-tunnel sshd fail2ban firewalld; do
  printf "  %-18s %s\n" "$s" "$(systemctl is-active "$s" 2>/dev/null || echo unknown)"
done
echo
echo "--- 容器 ---"
docker stats --no-stream --format '  {{.Name}}  CPU={{.CPUPerc}}  内存={{.MemUsage}}' 2>/dev/null
docker compose -f /opt/secagent/docker-compose.yml ps --format '  {{.Name}}  {{.Status}}' 2>/dev/null
echo
echo "--- 健康检查 ---"
curl -s --max-time 8 http://127.0.0.1:9900/api/health | sed 's/^/  /'
echo
echo
echo "--- 隧道地址 ---"
grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /var/log/cloudflared.log 2>/dev/null | tail -1 | sed 's/^/  /'
echo
echo "--- 部署目录 ---"
ls -la /opt/secagent 2>/dev/null | head -12 | sed 's/^/  /'
echo
echo "--- 向量库 ---"
ls -la /opt/secagent/data/vector-store.json 2>/dev/null | sed 's/^/  /'
echo
echo "--- 安全配置 ---"
sshd -T 2>/dev/null | grep -iE '^(passwordauthentication|permitrootlogin|maxauthtries)' | sed 's/^/  /'
firewall-cmd --list-services 2>/dev/null | sed 's/^/  firewalld 放行: /'
fail2ban-client status sshd 2>/dev/null | grep -E 'Currently banned|Total banned' | sed 's/^/  /'
