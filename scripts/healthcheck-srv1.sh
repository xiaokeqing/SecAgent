#!/usr/bin/env bash
# 服务器 1 健康检查：输出 KEY=VALUE 行，由调用方解析
# 【必须以 root 运行】docker / sshd -T 在普通用户下会静默失败，
# 检查脚本会把"没输出"误解成"状态不对"，产生误报。
if [ "$(id -u)" != "0" ]; then
  echo "IS_ROOT=no"
  echo "FATAL=必须以 root 运行（docker/sshd -T 需要）"
  exit 1
fi
echo "IS_ROOT=yes"
echo "OS=$(grep -oP '(?<=PRETTY_NAME=")[^"]+' /etc/os-release 2>/dev/null)"
echo "UPTIME=$(uptime -p 2>/dev/null)"

# --- 容器 ---
echo "C_STATUS=$(docker inspect --format '{{.State.Status}}' secagent 2>/dev/null)"
echo "C_HEALTH=$(docker inspect --format '{{.State.Health.Status}}' secagent 2>/dev/null)"
echo "C_STARTED=$(docker inspect --format '{{.State.StartedAt}}' secagent 2>/dev/null | cut -c1-19)"

# --- 应用健康 ---
echo "HAPI=$(curl -s --max-time 8 http://127.0.0.1:9900/api/health 2>/dev/null)"

# --- 安全组件状态（从启动日志取证，不靠猜） ---
echo "WL=$(docker logs secagent 2>&1 | grep -o '保护白名单 [0-9]* 条' | tail -1)"
echo "WL51=$(docker logs secagent 2>&1 | grep -o '白名单 [0-9]* 条' | tail -1)"
echo "SG=$(docker logs secagent 2>&1 | grep -o '存储可写性校验通过.*' | tail -1)"
echo "CG=$(docker logs secagent 2>&1 | grep -o '凭据强度校验通过.*' | tail -1)"
echo "WRITEFAIL=$(docker logs secagent 2>&1 | grep -c '写回失败')"

# --- 数据落盘 ---
echo "AUDIT_N=$(ls -1 /opt/secagent/data/*.json 2>/dev/null | wc -l)"
echo "AUDIT_LIST=$(ls -1 /opt/secagent/data/*.json 2>/dev/null | xargs -n1 basename 2>/dev/null | tr '\n' ',')"
echo "AUDIT_OWNER=$(stat -c '%u:%g' /opt/secagent/data 2>/dev/null)"

# --- 系统加固 ---
echo "SSHPW=$(sshd -T 2>/dev/null | grep -c '^passwordauthentication no')"
echo "MAXAUTH=$(sshd -T 2>/dev/null | grep '^maxauthtries' | awk '{print $2}')"
echo "ROOTLOGIN=$(sshd -T 2>/dev/null | grep '^permitrootlogin' | awk '{print $2}')"
echo "F2B=$(systemctl is-active fail2ban 2>/dev/null)"
echo "F2BBAN=$(fail2ban-client status sshd 2>/dev/null | grep -o 'Total banned:[[:space:]]*[0-9]*' | tr -dc '0-9')"

# --- 资源 ---
echo "MEM=$(free -m | awk '/Mem:/{print $3"/"$2}')"
echo "SWAP=$(free -m | awk '/Swap:/{print $2}')"
echo "DISK=$(df -h / | tail -1 | awk '{print $5}')"

# --- 端口暴露（0.0.0.0 上的业务端口应为 0） ---
echo "EXPOSED=$(ss -tlnp 2>/dev/null | grep -cE '0\.0\.0\.0:(80|443|3306|6379|9200|9900)')"

# --- 备份 ---
echo "BACKUP_N=$(ls -1 /opt/secagent-backups/*.tar.gz 2>/dev/null | wc -l)"
echo "BACKUP_LAST=$(ls -1t /opt/secagent-backups/*.tar.gz 2>/dev/null | head -1 | xargs -n1 basename 2>/dev/null)"
echo "CRON=$(crontab -l 2>/dev/null | grep -c backup.sh)"

# --- 隧道 ---
echo "TUNNEL=$(systemctl is-active cloudflared 2>/dev/null)"
# --- 【今天新增】容器出网能力 ---
# 为什么必须单独查这一项：
#   今天发现服务器 1 的 firewalld 破坏了 docker 容器的出网能力，
#   而【所有常规检查都是绿的】：容器 healthy、健康接口 ok、
#   向量库有数据、域名 200 —— 看起来一切正常。
#   但容器实际上调不到 dashscope，也就是说【线上 AI 功能全是坏的】。
#   之所以一直没暴露：靶场是纯规则的不调模型，KB 是启动时预索引好的。
#
#   教训："服务健康"不等于"功能可用"。健康接口只能证明进程活着、
#   数据在内存里，证明不了它能不能调通外部依赖。
#   所以这一项要直接测真实的出网请求。
EG=$(docker exec secagent sh -c 'curl -s -o /dev/null -w "%{http_code}" --max-time 12 https://dashscope.aliyuncs.com/ 2>/dev/null' 2>/dev/null)
echo "EGRESS=${EG:-000}"

# --- Wazuh 对接模式（REAL / MOCK / OFF）---
# 同样重要：连不上 Wazuh 时系统会【自动降级为 MOCK】，
# 页面照常显示，只是数据变成假的了 —— 从外部完全看不出来。
WM=$(docker logs secagent 2>&1 | grep -oE '（(REAL|MOCK) 模式）|降级为内置样本（MOCK）' | tail -1)
echo "WAZUH_LOG=${WM:-未知}"
'TUNNEL=''$(docker ps --format '{{.Names}}' | grep -c wazuh-tunnel)''