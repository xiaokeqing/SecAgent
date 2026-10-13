#!/usr/bin/env bash
# ============================================================
# collect.sh · 演练证据采集（在 srv1 上跑）
# ------------------------------------------------------------
# 输入：runId 或时间窗（开始-结束，带时区）
# 输出：JSON（默认 /tmp/drill-<runId>.json）+ 可直接贴进报告的可读摘要
#
# 采集口径：
#   索引 = wazuh-alerts-*（字段 @timestamp / rule.description / rule.groups / agent.name / data.*）
#   时间 = 脚本侧 start-5s ~ end+窗口 秒；@timestamp 是索引侧 UTC 时间
#   检测时延 = 首条相关告警的 @timestamp − 剧本开始时间（秒）
#   相关判据（两种，脚本会明确写出用了哪一种）：
#     A) runId 标记：full_log / rule.description 里出现 runId（最精确）
#     B) 源IP+时间窗：data.src_ip == 演练源 IP（扫描类流量没有载荷时只能用这个）
#
# 用法：
#   ./collect.sh --run-id DRILL-sim-01-20261012T201500 \
#                --start 2026-10-12T20:15:00+08:00 --end 2026-10-12T20:15:20+08:00 \
#                --src-ip 58.19.99.193 --label sim-01 [--out /tmp/x.json] [--window 120]
# ============================================================
set -uo pipefail

RUN_ID=""
START=""
END=""
SRC_IP=""
LABEL=""
OUT=""
WINDOW=120
SIZE=200

while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) RUN_ID="$2"; shift 2 ;;
    --start)  START="$2";  shift 2 ;;
    --end)    END="$2";    shift 2 ;;
    --src-ip) SRC_IP="$2"; shift 2 ;;
    --label)  LABEL="$2";  shift 2 ;;
    --out)    OUT="$2";    shift 2 ;;
    --window) WINDOW="$2"; shift 2 ;;
    --size)   SIZE="$2";   shift 2 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

[ -n "$START" ] && [ -n "$END" ] || { echo "必须提供 --start 与 --end" >&2; exit 2; }
[ -n "$RUN_ID" ] || RUN_ID="manual-$(date -u +%Y%m%dT%H%M%SZ)"
[ -n "$LABEL" ]  || LABEL="$RUN_ID"
[ -n "$OUT" ]    || OUT="/tmp/drill-$RUN_ID.json"

# ---- 时间换算（统一成 UTC ISO，索引里 @timestamp 是 UTC） ----
# 注意：srv1 的 python3 较老（3.6），不能用 datetime.fromisoformat，故手写解析
read -r Q_FROM Q_TO START_UTC END_UTC <<EOF
$(python3 - "$START" "$END" "$WINDOW" <<'PY'
import sys, re, datetime

def parse(s):
    s = s.strip()
    m = re.match(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$', s)
    if not m:
        raise SystemExit('时间格式无法解析（示例 2026-10-12T20:15:00+08:00）: %s' % s)
    y, mo, d, h, mi, se = [int(x) for x in m.groups()[:6]]
    tz = m.group(8)
    if tz in (None, ''):
        off = 8 * 3600          # 不带时区就按本地（东八区）
    elif tz == 'Z':
        off = 0
    else:
        sign = 1 if tz[0] == '+' else -1
        tt = tz[1:].replace(':', '')
        off = sign * (int(tt[:2]) * 3600 + int(tt[2:4]) * 60)
    return datetime.datetime(y, mo, d, h, mi, se, tzinfo=datetime.timezone(datetime.timedelta(seconds=off)))

start, end, window = parse(sys.argv[1]), parse(sys.argv[2]), int(sys.argv[3])
fmt = lambda x: x.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')
print(fmt(start - datetime.timedelta(seconds=5)), fmt(end + datetime.timedelta(seconds=window)), fmt(start), fmt(end))
PY
)
EOF
[ -n "$Q_FROM" ] && [ -n "$Q_TO" ] || { echo "[错误] 时间换算失败，脚本中止（不产生半截证据）" >&2; exit 4; }

echo "======================= 演练证据采集 ======================="
echo "  剧本/标签    : $LABEL"
echo "  runId        : $RUN_ID"
echo "  剧本时间窗   : $START  ~  $END   (本地 ISO)"
echo "  查询时间窗   : $Q_FROM  ~  $Q_TO   (UTC，含 -5s / +${WINDOW}s 余量)"
echo "  演练源 IP    : ${SRC_IP:-<未指定，按时间窗匹配>}"
echo "  索引         : wazuh-alerts-*"
echo "==========================================================="

# ---- 组装查询（JSON 经 stdin 送进容器，避免引号地狱） ----
build_query() {
  python3 - "$Q_FROM" "$Q_TO" "$SRC_IP" "$RUN_ID" "$1" "$SIZE" <<'PY'
import json, sys
q_from, q_to, src_ip, run_id, mode, size = sys.argv[1:7]
must = [{"range": {"@timestamp": {"gte": q_from, "lte": q_to, "format": "strict_date_optional_time"}}}]
if src_ip:
    must.append({"term": {"data.src_ip": src_ip}})
q = {"query": {"bool": {"must": must}}, "size": int(size),
     "sort": [{"@timestamp": {"order": "asc"}}],
     "_source": ["@timestamp", "rule.description", "rule.groups", "rule.id", "rule.level",
                 "agent.name", "data.src_ip", "data.eventid", "data.username", "data.version",
                 "data.dest_port", "data.alert.signature", "full_log", "location"]}
if mode == "marker" and run_id:
    q["query"]["bool"]["must"].append({"bool": {"should": [
        {"wildcard": {"full_log": "*%s*" % run_id}},
        {"wildcard": {"rule.description": "*%s*" % run_id}}
    ], "minimum_should_match": 1}})
print(json.dumps(q, ensure_ascii=False))
PY
}

QUERY_BASE=$(build_query base)
QUERY_MARK=$(build_query marker)

ES_CALL='docker exec -i secagent sh -c '"'"'curl -sk -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" -H "Content-Type: application/json" "https://wazuh-tunnel:9200/wazuh-alerts-*/_search" -d @-'"'"''

echo "$QUERY_BASE" | eval "$ES_CALL" > /tmp/drill-base.json 2>/tmp/drill-base.err
if [ ! -s /tmp/drill-base.json ]; then
  echo "[错误] 索引查询失败：$(cat /tmp/drill-base.err)" >&2; exit 3
fi
echo "$QUERY_MARK" | eval "$ES_CALL" > /tmp/drill-mark.json 2>/dev/null

python3 - "$RUN_ID" "$LABEL" "$START" "$END" "$START_UTC" "$END_UTC" "$Q_FROM" "$Q_TO" "$SRC_IP" "$OUT" /tmp/drill-base.json /tmp/drill-mark.json <<'PY'
import json, sys, re, datetime
(run_id, label, start_l, end_l, start_u, end_u, q_from, q_to, src_ip, out) = sys.argv[1:11]
base = json.load(open(sys.argv[11]))
mark = json.load(open(sys.argv[12]))

def ts(x):
    """手写 ISO8601 解析（srv1 的 python3.6 没有 fromisoformat）"""
    if not x:
        return None
    m = re.match(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$', x.strip())
    if not m:
        return None
    y, mo, d, h, mi, se = [int(v) for v in m.groups()[:6]]
    tz = m.group(8) or 'Z'
    if tz == 'Z':
        off = 0
    else:
        sign = 1 if tz[0] == '+' else -1
        tt = tz[1:].replace(':', '')
        off = sign * (int(tt[:2]) * 3600 + int(tt[2:4]) * 60)
    return datetime.datetime(y, mo, d, h, mi, se, tzinfo=datetime.timezone(datetime.timedelta(seconds=off)))

def norm(hits):
    out = []
    for h in hits:
        s = h.get("_source", {})
        r = s.get("rule", {}) or {}
        a = s.get("agent", {}) or {}
        d = s.get("data", {}) or {}
        alert = d.get("alert", {}) or {}
        out.append({
            "timestamp": s.get("@timestamp"),
            "rule_id": r.get("id"),
            "rule_level": r.get("level"),
            "rule_description": r.get("description"),
            "rule_groups": r.get("groups"),
            "agent_name": a.get("name"),
            "src_ip": d.get("src_ip"),
            "dest_port": d.get("dest_port"),
            "eventid": d.get("eventid"),
            "username": d.get("username"),
            "signature": alert.get("signature"),
            "location": s.get("location"),
            "index": h.get("_index"),
        })
    return out

alerts = norm(base.get("hits", {}).get("hits", []))
marker_alerts = norm(mark.get("hits", {}).get("hits", []))
total_base = base.get("hits", {}).get("total", {}).get("value", len(alerts))
total_mark = mark.get("hits", {}).get("total", {}).get("value", len(marker_alerts))
if "hits" not in base:
    print("[错误] 索引返回的不是正常搜索结果：%s" % json.dumps(base, ensure_ascii=False)[:500])
    sys.exit(5)

start_dt = ts(start_u)
first = None
basis = "无"
if marker_alerts:
    first, basis = marker_alerts[0]["timestamp"], "runId 标记（full_log/描述里出现 runId）"
elif alerts:
    first, basis = alerts[0]["timestamp"], "源IP+时间窗（该剧本流量无载荷，只能用 IP 与时间对齐）"
latency = None
if first and start_dt:
    f = ts(first)
    if f:
        latency = round((f - start_dt).total_seconds(), 3)

def by(key):
    agg = {}
    for a in alerts:
        k = a.get(key)
        if isinstance(k, list):
            k = ",".join(k)
        agg[k] = agg.get(k, 0) + 1
    return dict(sorted(agg.items(), key=lambda kv: -kv[1]))

result = {
    "label": label, "runId": run_id,
    "scenarioStartLocal": start_l, "scenarioEndLocal": end_l,
    "scenarioStartUtc": start_u, "scenarioEndUtc": end_u,
    "queryFromUtc": q_from, "queryToUtc": q_to,
    "srcIpFilter": src_ip or None,
    "indexPattern": "wazuh-alerts-*",
    "totalHitsBase": total_base,
    "totalHitsRunIdMarker": total_mark,
    "alertCount": len(alerts),
    "firstAlertTimestamp": first,
    "latencyBasis": basis,
    "detectionLatencySeconds": latency,
    "byRule": by("rule_description"),
    "byGroups": by("rule_groups"),
    "byAgent": by("agent_name"),
    "alerts": alerts,
    "runIdMatchedAlerts": marker_alerts,
    "generatedAtUtc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)

print()
print("----------------------- 采集结果 -----------------------")
print("  命中告警条数      : %d  (索引侧 total=%s)" % (len(alerts), total_base))
print("  其中带 runId 标记 : %d  (索引侧 total=%s)" % (len(marker_alerts), total_mark))
print("  首条告警时间(@ts) : %s" % (first or "<无>"))
print("  时延基准          : %s" % basis)
print("  检测时延(秒)      : %s" % ("<无法计算>" if latency is None else latency))
print()
if alerts:
    print("  按规则分布：")
    for k, v in list(result["byRule"].items())[:15]:
        print("    %6d  %s" % (v, k))
    print("  按 agent 分布：")
    for k, v in result["byAgent"].items():
        print("    %6d  %s" % (v, k))
    print()
    print("  告警明细（时间升序，最多 60 条）：")
    for i, a in enumerate(alerts[:60], 1):
        print("   %2d. %s | %s | [%s] | agent=%s | src=%s | rule=%s" % (
            i, a["timestamp"], a["rule_description"],
            ",".join(a["rule_groups"] or []) if isinstance(a["rule_groups"], list) else a["rule_groups"],
            a["agent_name"], a["src_ip"], a["rule_id"]))
else:
    print("  （该时间窗内没有与演练源相关的新告警）")
print()
print("  JSON 证据 : %s" % out)
print("===========================================================")
PY
