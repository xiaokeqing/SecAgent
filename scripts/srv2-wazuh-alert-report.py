#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wazuh 告警分析（在服务器上运行）

为什么单独一个文件而不是塞进 shell 的 heredoc：
  原来那版把 python 代码用 `docker exec bash -c 'python3 - <<PYEOF ... PYEOF'`
  嵌在 shell 里，形成了【heredoc 套 heredoc 套单引号】的结构，
  结果 shell 解析直接报 unexpected EOF，而且很难看出是哪里断的。
  拆成独立文件后，两边都变清楚了 ——
  排查"引号地狱"的成本远高于多传一个文件。
"""
import json
import sys
import collections

ALERTS = "/var/ossec/logs/alerts/alerts.json"


def load_alerts(limit=None):
    try:
        with open(ALERTS, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        print("  告警文件不存在（还没产生过告警）")
        sys.exit(0)
    if limit:
        lines = lines[-limit:]
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except Exception:
            continue
    return out


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "summary"
    alerts = load_alerts(limit=500)
    print("  可解析的告警条数: %d" % len(alerts))

    if mode == "summary":
        c = collections.Counter()
        lv = {}
        for d in alerts:
            r = d.get("rule", {})
            desc = r.get("description", "?")
            c[desc] += 1
            lv[desc] = r.get("level", 0)
        print("")
        print("  告警分布（Top 15）:")
        for desc, n in c.most_common(15):
            print("    %-48s x%-4d level=%s" % (desc[:48], n, lv.get(desc)))

    elif mode == "security":
        # level >= 7 才是真正有价值的安全告警（Wazuh 的分级惯例）
        found = 0
        for d in reversed(alerts):
            r = d.get("rule", {})
            if r.get("level", 0) >= 7:
                if found == 0:
                    print("")
                    print("  安全告警（level >= 7）:")
                print("    [level %s] %s" % (r.get("level"), r.get("description", "?")[:58]))
                src = d.get("data", {})
                extra = ""
                if src.get("srcip"):
                    extra = "  来源IP=%s" % src.get("srcip")
                print("      规则%s%s" % (r.get("id", "?"), extra))
                fl = (d.get("full_log") or "").replace("\n", " ")[:120]
                if fl:
                    print("      %s" % fl)
                found += 1
                if found >= 8:
                    break
        if found == 0:
            print("")
            print("  （没有 level>=7 的告警）")

    elif mode == "sources":
        # 统计告警涉及的来源 IP —— 用于判断"到底有没有被真实攻击"
        ips = collections.Counter()
        for d in alerts:
            dt = d.get("data", {})
            ip = dt.get("srcip") or dt.get("src_ip")
            if ip:
                ips[ip] += 1
        print("")
        if ips:
            print("  告警里出现的来源 IP（Top 10）:")
            for ip, n in ips.most_common(10):
                print("    %-20s x%d" % (ip, n))
        else:
            print("  告警里没有任何来源 IP —— 说明目前的告警都不涉及网络攻击")

    elif mode == "stats":
        # 一句话统计，给脚本做判断用
        total = len(alerts)
        sec = sum(1 for d in alerts if d.get("rule", {}).get("level", 0) >= 7)
        print("TOTAL=%d SECURITY=%d" % (total, sec))


if __name__ == "__main__":
    main()
