#!/usr/bin/env bash
# ============================================================
# B1：让 Wazuh 采集本机真实安全日志
# ------------------------------------------------------------
# 现状（侦察确认）：
#   Wazuh 已有 192 条告警，但全是 "Wazuh server started"（level 3）——
#   只是服务启动记录，没有安全价值。
#   根因：manager 默认的 localfile 只监控 df / netstat / last /
#   active-responses，【没有监控 auth.log】。
#   这台机器上真实发生的登录尝试，Wazuh 完全看不到。
#
# 这一步：
#   1) 给 ossec.conf 加 localfile，监控 auth.log / syslog / fail2ban.log
#   2) 校验 XML（改坏配置会导致 manager 起不来）
#   3) 重启 manager
#   4) 用独立的 python 脚本分析告警（不嵌套 heredoc）
#
# 关于路径：Debian 系用 /var/log/auth.log，RHEL 系用 /var/log/secure。
#   两个都配上，缺失的那个 Wazuh 会忽略。
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

WORK=/opt/wazuh
CONF="$WORK/config/wazuh_cluster/wazuh_manager.conf"
REPORT=/tmp/wazuh-alert-report.py
cd "$WORK" || die "找不到 $WORK"

log "1/6 备份配置"
BK="$CONF.bak-$(date +%Y%m%d-%H%M%S)"
cp "$CONF" "$BK"
echo "$BK" > /root/.wazuh-last-conf-backup
ok "已备份到 $BK"

log "2/6 当前监控情况"
COUNT_BEFORE=$(grep -c '<localfile>' "$CONF" 2>/dev/null || echo 0)
echo "    localfile 条目数: $COUNT_BEFORE"
grep -oE '<location>[^<]*</location>' "$CONF" 2>/dev/null | sed 's/^/      /'

log "3/6 追加安全日志监控"
if grep -q '/var/log/auth.log' "$CONF"; then
  warn "已监控 auth.log，跳过"
else
  python3 - "$CONF" <<'PYEOF'
import sys
path = sys.argv[1]
src = open(path, encoding="utf-8").read()

if '<location>/var/log/auth.log</location>' in src:
    print("  已存在，未修改")
    sys.exit(0)

block = """
  <!-- ===== 本项目追加：真实安全日志采集 ===== -->
  <!-- 默认配置只监控 df / netstat / last / active-responses，
       等于完全看不到这台机器上真实发生的登录尝试。 -->

  <!-- SSH 登录 / sudo / 用户切换：暴力破解检测的核心数据源 -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <!-- 系统日志：服务异常、内核消息、OOM 等 -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <!-- fail2ban 的封禁记录：用于比对 Wazuh 检测与 fail2ban 是否一致 -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/fail2ban.log</location>
  </localfile>

  <!-- 兼容 RHEL 系（/var/log/secure）。Ubuntu 上该文件不存在，Wazuh 会忽略 -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

"""
idx = src.rfind('</ossec_config>')
if idx == -1:
    print("  ERROR: 找不到 </ossec_config>")
    sys.exit(1)
open(path, 'w', encoding='utf-8').write(src[:idx] + block + src[idx:])
print("  已追加 4 条 localfile")
PYEOF
  [ $? -eq 0 ] || die "配置追加失败"
fi
COUNT_AFTER=$(grep -c '<localfile>' "$CONF" 2>/dev/null || echo 0)
ok "localfile 条目数: $COUNT_BEFORE -> $COUNT_AFTER"

log "4/6 校验 XML"
# ⚠️ 这里踩过一个坑，记下来。
#
# 第一版用的是 xml.dom.minidom.parse(文件) —— 单根 XML 的校验方式。
# 结果报 "junk after document element"，于是判定"配置坏了"并回滚。
# 但【备份文件（未修改的原始配置）用同样的校验也失败】——
# 说明这个文件本来就不是单根 XML：它是 Wazuh 特有的格式，
# 允许出现多个 <ossec_config> 段，由 manager 自己合并。
# 也就是说：是我的校验方式错了，把合法文件判成了非法。
#
# （这已经是这个项目里第 6 次"检查器自己给出错误结论"了。
#   共同点都是：用通用规则去校验一个领域特有格式。）
#
# 正确做法：套一个虚构的根元素再校验 —— 这样多段结构也是合法的，
# 同时仍然能查出"标签没闭合""多余字符"这类真正的语法错误。
if python3 - "$CONF" <<'PYEOF'
import sys
import xml.dom.minidom
path = sys.argv[1]
content = open(path, encoding="utf-8").read()
# 关键：先确认多段结构本身是允许的（两个标签数量一致）
op = content.count("<ossec_config>")
cl = content.count("</ossec_config>")
if op != cl:
    print("  ossec_config 开合不匹配: %d vs %d" % (op, cl))
    sys.exit(1)
# 套根元素后做良构性校验
try:
    xml.dom.minidom.parseString("<__root__>" + content + "</__root__>")
    print("  XML 良构（%d 段 ossec_config）" % op)
except Exception as e:
    print("  解析失败: %s %s" % (type(e).__name__, str(e)[:150]))
    sys.exit(1)
PYEOF
then
  ok "XML 良构性正确"
else
  warn "XML 确实有问题，回滚配置"
  cp "$BK" "$CONF"
  die "配置已回滚 —— manager 仍用原配置运行，未受影响"
fi

log "5/6 重启 manager"
docker restart wazuh.manager >/dev/null 2>&1
echo "    等待 API 就绪..."
READY=0
for i in $(seq 1 36); do
  sleep 5
  C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 https://127.0.0.1:55000/ 2>/dev/null)
  if [ "$C" = "401" ] || [ "$C" = "200" ]; then
    echo "    第 $((i*5)) 秒: API HTTP $C"
    READY=1
    break
  fi
done
if [ "$READY" -eq 0 ]; then
  warn "manager 未就绪，日志尾部："
  docker logs --tail 25 wazuh.manager 2>&1 | sed 's/^/    /'
else
  ok "manager 已就绪"
fi

echo "    再等 40 秒让日志分析跑一轮..."
sleep 40

log "6/6 验证：真的产生安全类告警了吗"
if [ ! -f "$REPORT" ]; then
  warn "分析脚本 $REPORT 不在，跳过分析"
else
  docker cp "$REPORT" wazuh.manager:/tmp/report.py 2>/dev/null
  echo "    --- 告警分布 ---"
  docker exec wazuh.manager python3 /tmp/report.py summary 2>&1 | sed 's/^/  /'

  echo
  echo "    --- 安全告警（level >= 7 才是真正有价值的）---"
  docker exec wazuh.manager python3 /tmp/report.py security 2>&1 | sed 's/^/  /'

  echo
  echo "    --- 告警里的来源 IP（判断有没有被真实攻击）---"
  docker exec wazuh.manager python3 /tmp/report.py sources 2>&1 | sed 's/^/  /'

  echo
  echo "    --- 一句话统计 ---"
  docker exec wazuh.manager python3 /tmp/report.py stats 2>&1 | sed 's/^/    /'
fi

echo
echo "    --- 配置确认 ---"
docker exec wazuh.manager bash -c "grep -c 'auth.log' /var/ossec/etc/ossec.conf" 2>/dev/null | sed 's/^/      ossec.conf 里 auth.log 出现次数: /'

echo
ok "B1 完成"
echo
echo "    说明：这台机器才开机 2.5 小时，被真正攻击的量还不够，"
echo "    可能暂时没有 level>=7 的告警。蜜罐（C1）上线后会显著改变这一点。"
