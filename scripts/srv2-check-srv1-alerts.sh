#!/usr/bin/env bash
# ============================================================
# srv2 侧：查 srv1（agent 005/srv1-host）产生的告警
# ------------------------------------------------------------
# 用法（srv2）：sudo bash -s -- [--since 30m] [--rule 1002xx] [--raw]
# 直接读 manager 容器里的 /var/ossec/logs/alerts/alerts.json
# （不依赖 indexer/API，也就不会被"indexer 还没索引"这种时序问题干扰）
# ============================================================
set -uo pipefail
SINCE="30m"; RULE=""; RAW=0
while [ $# -gt 0 ]; do
  case "$1" in
    --since) SINCE="$2"; shift 2 ;;
    --rule) RULE="$2"; shift 2 ;;
    --raw) RAW=1; shift ;;
    *) echo "[X] 未知参数 $1"; exit 2 ;;
  esac
done
D="sudo -n docker exec wazuh.manager"
C_CY='\033[1;36m'; C_OK='\033[1;32m'; C_0='\033[0m'
log(){ printf "\n${C_CY}==> %s${C_0}\n" "$*"; }

log "agent 状态"
$D /var/ossec/bin/agent_control -l 2>&1 | sed 's/^/  /'

log "最近 $SINCE 的告警（按规则分组计数）——只看 srv1 这台 agent"
$D sh -c "python3 - <<'PY'
import json, collections, datetime, os
p='/var/ossec/logs/alerts/alerts.json'
if not os.path.exists(p):
    print('  alerts.json 不存在'); raise SystemExit
cnt=collections.Counter(); first={}
n=0
with open(p, errors='replace') as f:
    for line in f:
        line=line.strip()
        if not line: continue
        try: d=json.loads(line)
        except Exception: continue
        if d.get('agent',{}).get('name') not in ('srv1-host',): continue
        rid=str(d.get('rule',{}).get('id'))
        cnt[(rid, d.get('rule',{}).get('level'), d.get('rule',{}).get('description','')[:60])]+=1
        n+=1
        if rid not in first: first[rid]=d
print('  srv1-host 告警条数（本次读取全量 alerts.json）:', n)
for (rid,lvl,desc),c in sorted(cnt.items(), key=lambda x:-x[1]):
    print('  rule %-7s level=%-3s x%-4d %s' % (rid,lvl,c,desc))
print()
print('  --- 每个规则的第一条关键字段 ---')
for rid,d in first.items():
    r=d.get('rule',{}); print('  rule %s: %s | location=%s | full_log=%s' % (
        rid, r.get('description'), d.get('location'), (d.get('full_log') or '')[:160].replace(chr(10),' ')))
PY" 2>&1 | sed 's/^/  /'

if [ -n "$RULE" ] || [ "$RAW" = 1 ]; then
  log "原始 JSON 片段"
  $D sh -c "grep -a '\"id\":\"$RULE\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -3" | sed 's/^/  /'
fi
