#!/usr/bin/env bash
# ============================================================
# srv2：Dionaea 自检（跑态证据，不是看配置文件）
# ------------------------------------------------------------
# 它回答的问题：
#   · 容器在不在跑？资源上限/只读根/no-new-privileges 是否真的生效？
#   · 它是不是在 cowrie_honeypot 这套隔离网络里？
#   · 它到底能不能主动外连？（实测，不是看规则）
#   · 三个协议端口有没有在监听？从外面连得上吗？
#   · 日志在不在写？Wazuh 那边读得到吗？规则会不会命中？
#   · 磁盘/内存水位如何？
#
# 用法（srv2，root）：bash srv2-dionaea-check.sh
# 退出码：0=全过；1=有 FAIL（可以直接接进巡检）
# ============================================================
set -uo pipefail
APP=/opt/dionaea
IMAGE=dinotools/dionaea:0.11.0
PORTS="445 1433 3306"
PASS=0; FAIL=0; WARN=0
C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_CY='\033[1;36m'; C_0='\033[0m'
item() { printf "  %-42s %s\n" "$1" "$2"; }
ok()   { PASS=$((PASS+1)); item "$1" "${C_OK}PASS${C_0}"; }
bad()  { FAIL=$((FAIL+1)); item "$1" "${C_ERR}FAIL${C_0}"; }
warn() { WARN=$((WARN+1)); item "$1" "${C_WARN}WARN${C_0}"; }
log()  { printf "\n${C_CY}==> %s${C_0}\n" "$*"; }

# 蜜罐网段：优先问 dionaea 容器在哪个网络，其次问 cowrie
honey_subnet() {
  local s
  s=$(docker inspect dionaea --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null | head -1)
  [ -n "$s" ] || s=$(docker inspect cowrie --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null | head -1)
  [ -n "$s" ] || return 1
  docker network inspect "$s" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null
}

echo "Dionaea 自检  host=$(hostname -s)  $(date '+%F %T')"

log "1. 容器与硬约束"
if docker ps --format '{{.Names}}' | grep -qx dionaea; then
  ok "容器 dionaea 在运行"
  docker ps --filter name=^dionaea$ --format '    {{.Status}}  {{.Ports}}'
else
  bad "容器 dionaea 没在运行"
fi
insp=$(docker inspect dionaea 2>/dev/null || echo '[]')
chk() { # $1=描述 $2=jsonpath $3=期望
  local got; got=$(echo "$insp" | python3 -c "
import sys,json
d=json.load(sys.stdin)
try: print(eval('d[0]'+sys.argv[1]))
except Exception as e: print('ERR')
" "$2" 2>/dev/null)
  [ "$got" = "$3" ] && ok "$1 = $got" || bad "$1 = $got （期望 $3）"
}
chk "mem_limit = 384MiB"        "['HostConfig']['Memory']" "402653184"
chk "cpus = 0.5 核"             "['HostConfig']['NanoCpus']" "500000000"
chk "pids_limit = 256"          "['HostConfig']['PidsLimit']" "256"
chk "read_only 根文件系统"       "['HostConfig']['ReadonlyRootfs']" "True"
chk "no-new-privileges"         "['HostConfig']['SecurityOpt']" "['no-new-privileges:true']"
chk "restart = unless-stopped"  "['HostConfig']['RestartPolicy']['Name']" "unless-stopped"
chk "镜像固定 tag 0.11.0"        "['Config']['Image']" "$IMAGE"

log "2. 隔离网络与 egress 实测"
subnet=$(honey_subnet 2>/dev/null)
NET=$(echo "$insp" | python3 -c "
import sys,json
d=json.load(sys.stdin); print(','.join(d[0]['NetworkSettings']['Networks'].keys()))" 2>/dev/null)
if [ "$NET" = "cowrie_honeypot" ]; then ok "网络 = cowrie_honeypot（与 Cowrie 同一套）"; else bad "网络 = $NET（期望 cowrie_honeypot）"; fi
echo "    网段: $subnet"
dl=$(iptables -S DOCKER-USER | grep -n -- "-s $subnet -j DROP" | head -1 | cut -d: -f1)
pl=$(iptables -S DOCKER-USER | grep -n -- '--dport' | head -1 | cut -d: -f1)
if [ -n "$dl" ]; then ok "DOCKER-USER 有 $subnet 的 DROP（第 $dl 行）"; else bad "没有 $subnet 的 DROP 规则"; fi
if [ -n "$dl" ] && [ -n "$pl" ]; then
  if [ "$dl" -lt "$pl" ]; then ok "DROP 在端口放行之前（第 $pl 行起）"; else bad "端口放行排在 DROP 之前 = egress 有洞"; fi
fi
for probe in "1.1.1.1 443" "1.1.1.1 3306" "8.8.8.8 1433"; do
  set -- $probe
  if docker exec dionaea python3 -c "
import socket,sys
try:
    socket.create_connection(('$1',$2),4); sys.exit(0)
except Exception:
    sys.exit(1)" 2>/dev/null; then
    bad "容器内可外连 $1:$2（隔离失效）"
  else
    ok "容器内连 $1:$2 失败（已 DROP）"
  fi
done
if docker exec dionaea python3 -c "
import socket,sys
try:
    socket.gethostbyname('github.com'); sys.exit(0)
except Exception: sys.exit(1)" 2>/dev/null; then
  ok "容器内 DNS 仍可用（127.0.0.11 放行，预期）"
else
  warn "容器内 DNS 不可用（可能是故意的；但会影响反向解析）"
fi

log "3. 端口监听与对外可达"
for p in $PORTS; do
  if docker port dionaea 2>/dev/null | grep -q ":$p$"; then ok "宿主 tcp/$p 已映射"; else bad "宿主 tcp/$p 未映射"; fi
done
# 【为什么不用"能连上 TCP"来判断】2026-10-14 实测：dionaea 会卡死 ——
#   MySQL 服务不再处理新连接，但 TCP 握手照样成功（内核 accept 队列回 SYN-ACK），
#   `exec 3<>/dev/tcp/127.0.0.1/3306` 会【成功】、docker ps 也显示 Up，
#   而它已经不再记任何事件。所以这里按协议要应答（3306 要 MySQL 握手包 /
#   1433 要 TDS prelogin 响应 / 445 要 SMB1 negotiate 响应），
#   宁可慢一点，也不能给出假的"正常"。
if [ -x /usr/local/sbin/srv2-dionaea-healthcheck.sh ]; then
  if HOUT=$(bash /usr/local/sbin/srv2-dionaea-healthcheck.sh 2>&1); then
    echo "$HOUT" | sed 's/^/    /'
    ok "协议级健康：3306/1433/445 都有正确应答"
  else
    echo "$HOUT" | sed 's/^/    /'
    bad "协议级健康检查未通过（端口可能连得上但服务已不响应）"
  fi
else
  warn "缺 /usr/local/sbin/srv2-dionaea-healthcheck.sh，跳过协议级检查"
fi

log "4. 日志与磁盘"
for f in dionaea.log dionaea.json dionaea-errors.log; do
  if [ -f "$APP/var/log/dionaea/$f" ]; then
    ok "$f 存在（$(stat -c %s "$APP/var/log/dionaea/$f") 字节, 属主 $(stat -c %U:%G "$APP/var/log/dionaea/$f")）"
  else
    warn "$f 不存在"
  fi
done
if [ -f "$APP/var/log/dionaea/dionaea.json" ] && [ -s "$APP/var/log/dionaea/dionaea.json" ]; then
  echo "    --- dionaea.json 最后一条 ---"
  tail -1 "$APP/var/log/dionaea/dionaea.json" | cut -c1-220 | sed 's/^/    /'
fi
if [ -f /etc/logrotate.d/secagent-dionaea ]; then ok "logrotate 配置已装"; else bad "缺 /etc/logrotate.d/secagent-dionaea"; fi
if [ -f /etc/cron.d/secagent-dionaea-cleanup ]; then ok "磁盘清理 cron 已装"; else bad "缺 /etc/cron.d/secagent-dionaea-cleanup"; fi
bs=$(du -sh "$APP/var/lib/dionaea/bistreams" 2>/dev/null | awk '{print $1}')
echo "    bistreams 占用: ${bs:-0}（$(df -h / | awk 'NR==2{print "根分区可用 "$4}')）"

log "5. 接进 Wazuh 了吗"
OV=/opt/wazuh/docker-compose.override.yml
CF=/opt/wazuh/config/wazuh_cluster/wazuh_manager.conf
grep -q '/opt/dionaea/var' "$OV" 2>/dev/null && ok "override 已挂 Dionaea 日志目录" || bad "override 未挂 Dionaea 日志目录"
grep -q 'dionaea/dionaea.json' "$CF" 2>/dev/null && ok "ossec.conf 已有 dionaea.json localfile" || bad "ossec.conf 没有 dionaea localfile"
if docker exec wazuh.manager sh -c 'test -f /opt/dionaea/var/log/dionaea/dionaea.json' 2>/dev/null; then
  ok "容器内看得见 dionaea.json（挂载生效）"
else
  bad "容器内看不见 dionaea.json（挂载没生效 —— 配了也读不到）"
fi
if [ -f /opt/wazuh/config/wazuh_cluster/rules/srv2_dionaea_rules.xml ]; then
  ok "规则文件已装（$(grep -c 'rule id' /opt/wazuh/config/wazuh_cluster/rules/srv2_dionaea_rules.xml) 条）"
else
  bad "规则文件未安装"
fi
# 【踩坑】这里原来写成 `wazuh-control status | grep -q 'analysisd is running'`，
# 结果明明 analysisd 在跑却报 FAIL。原因：wazuh-control status 的返回码
# 【总是非 0】（clusterd/maild/dbd 等本来就 not running），而脚本是 set -o pipefail，
# 于是管道把那个非 0 当成 grep 的结果传出来 —— 把"活着"判成"死了"。
# 这个坑本项目已经记录过（srv2-install-srv1-rules.sh 的注释里），我又犯了一次。
# 正确做法：先把输出抓进变量（`|| true` 吃掉返回码），再对变量做匹配。
WST=$(docker exec wazuh.manager /var/ossec/bin/wazuh-control status 2>&1 || true)
if echo "$WST" | grep -q 'wazuh-analysisd is running'; then
  ok "wazuh-analysisd 在跑"
else
  bad "wazuh-analysisd 没在跑（SIEM 停摆）"
  echo "$WST" | sed 's/^/      /'
fi
# 功能自测：规则真的会命中吗（同样先把输出抓成变量，避免 pipefail 误判）
sample='{"connection": {"protocol": "smbd", "transport": "tcp", "type": "accept"}, "dst_ip": "172.19.0.4", "dst_port": 445, "src_hostname": "", "src_ip": "203.0.113.9", "src_port": 51234, "timestamp": "2026-10-14T00:00:00.000000"}'
LTOUT=$(printf '%s\n' "$sample" | docker exec -i wazuh.manager /var/ossec/bin/wazuh-logtest 2>&1 || true)
if echo "$LTOUT" | grep -q "100300"; then
  ok "wazuh-logtest 命中 100300（SMB 规则有效）"
else
  bad "wazuh-logtest 未命中 100300（规则不生效）"
  echo "$LTOUT" | tail -12 | sed 's/^/      /'
fi
n=$(docker exec wazuh.manager sh -c 'grep -ac "dionaea" /var/ossec/logs/alerts/alerts.json 2>/dev/null' 2>/dev/null || echo 0)
echo "    alerts.json 里 dionaea 相关告警行数: ${n:-0}"

log "6. 水位"
free -m | sed 's/^/    /'
docker stats --no-stream --format '    {{.Name}}  {{.MemUsage}}  {{.CPUPerc}}' 2>/dev/null | grep -E 'dionaea|suricata|wazuh.manager|cowrie|decoy' || true

echo
echo "===== 结果：PASS=$PASS  FAIL=$FAIL  WARN=$WARN ====="
[ "$FAIL" -eq 0 ] && { printf "${C_OK}自检通过${C_0}\n"; exit 0; } || { printf "${C_ERR}有 $FAIL 项失败${C_0}\n"; exit 1; }
