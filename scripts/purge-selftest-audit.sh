#!/usr/bin/env bash
# ============================================================================
# purge-selftest-audit.sh — 清理「开发期自测」写进封禁留痕的 18 条记录
# ----------------------------------------------------------------------------
# 问题：公开面 GET /api/public/audit.js 的 blocks[] 里有 18 条自测 IP
#       （1.2.3.4×8、45.83.91.55×4、45.83.91.66/77/88/12×5、198.18.0.9×1），
#       全部 unblocked=true（60/30/10/5 min 到期自动解封）。它们不是真实攻击处置，
#       但 PublicAuditReader 只过滤「评测记录」（evalRunId / actor 以 eval- 开头），
#       自测记录写的时候没有这两个标记 ⇒ 原样出现在公开留痕里。
#
# ★★ 边界（本脚本的全部权利范围）★★
#   · 只处理这 18 条：blocked-ips.json 里必须 id ∈ 18 个 BLK id 且 ip ∈ 7 个明确 IP
#     （双键同时命中才删；单键命中一律不动、只报告）。
#   · 不做通配删除：不按网段、不按前缀、不按时间范围、不按 actor/source 批量删，
#     不删 45.83.91.0/24，不删 198.18.0.0/15，不删「所有 60 分钟的记录」。
#   · 不碰其它文件；不重启、不重部署、不改配置（进程内存里的副本由站主决定何时重启释放）。
#
# 用法（srv1 上必须 root/ sudo：data/ mode=750 owner=999:999 → 容器内 uid 999）：
#   sudo ./scripts/purge-selftest-audit.sh                    # 默认 dry-run，只报告
#   sudo ./scripts/purge-selftest-audit.sh --apply            # 真删（先自动备份）
#   sudo ./scripts/purge-selftest-audit.sh --apply --with-audit   # 连 response-audit.json 一并清
#   sudo ./scripts/purge-selftest-audit.sh --data-dir ./data  # 换目录（本机演练）
# 其它开关：--no-backup  --force（命中数≠--expect 时仍继续） --expect N（默认 18）
#
# 幂等：第二次跑命中 0 条 → 打印「没有可清理的记录」，不写文件，exit 0。
# 退出码：0 正常（含「已经清过」）｜2 命中数与预期不符且未加 --force｜1 环境/文件错误
# ============================================================================
set -uo pipefail

DATA_DIR="${PS_DATA_DIR:-/opt/secagent/data}"
MODE="dry-run"
WITH_AUDIT=0
BACKUP=1
FORCE=0
EXPECT=18

die() { echo "错误：$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)     MODE="dry-run" ;;
    --apply)       MODE="apply" ;;
    --with-audit)  WITH_AUDIT=1 ;;
    --data-dir)    shift; [ $# -gt 0 ] || die "--data-dir 需要一个目录"; DATA_DIR="$1" ;;
    --data-dir=*)  DATA_DIR="${1#*=}" ;;
    --no-backup)   BACKUP=0 ;;
    --force)       FORCE=1 ;;
    --expect)      shift; [ $# -gt 0 ] || die "--expect 需要一个整数"; EXPECT="$1" ;;
    --expect=*)    EXPECT="${1#*=}" ;;
    -h|--help)     sed -n '2,40p' "$0"; exit 0 ;;
    *)             die "未知参数：$1（--help 看用法）" ;;
  esac
  shift
done

command -v python3 >/dev/null 2>&1 || die "需要 python3（srv1 自带）"

export PS_DATA_DIR="$DATA_DIR"
export PS_APPLY=0; [ "$MODE" = "apply" ] && PS_APPLY=1
export PS_WITH_AUDIT="$WITH_AUDIT"
export PS_BACKUP="$BACKUP"
export PS_FORCE="$FORCE"
export PS_EXPECT="$EXPECT"

exec python3 - <<'PY'
import json, os, shutil, sys, time

DATA_DIR   = os.environ["PS_DATA_DIR"]
APPLY      = os.environ["PS_APPLY"] == "1"
WITH_AUDIT = os.environ["PS_WITH_AUDIT"] == "1"
BACKUP     = os.environ["PS_BACKUP"] == "1"
FORCE      = os.environ["PS_FORCE"] == "1"
EXPECT     = int(os.environ["PS_EXPECT"])

# ---- 唯一的匹配依据（写死，不从文件里推断） --------------------------------
SELFTEST_IPS = ["1.2.3.4", "45.83.91.55", "45.83.91.66", "45.83.91.77",
                "45.83.91.88", "45.83.91.12", "198.18.0.9"]

BLOCK_IDS = ["BLK-d9ffbf76", "BLK-de3a4697", "BLK-d54bb366", "BLK-b4b2c756",
             "BLK-44a6a0d7", "BLK-d8be0cc2", "BLK-46d4fa20", "BLK-0095dd35",
             "BLK-475c2bbe", "BLK-dfd09ba5", "BLK-98ec35b5", "BLK-8141473c",
             "BLK-7e468e5c", "BLK-833b0aa5", "BLK-cbf04fb3", "BLK-66e10a47",
             "BLK-82e62e2b", "BLK-f32f0e37"]

AUDIT_ACTIONS = {"block-ip", "unblock-ip"}
TS = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())

def load(path):
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    if not raw.strip():
        return None, raw
    root = json.loads(raw)
    arr = root if isinstance(root, list) else root.get("records")
    if not isinstance(arr, list):
        raise ValueError("%s 既不是 JSON 数组，也没有 records 数组" % path)
    return arr, raw

def write_atomic(path, arr, raw_before):
    """同目录临时文件 + os.replace，保留原 mode/uid/gid（容器内 uid=999 才读得到）。"""
    st = os.stat(path)
    tmp = path + ".purge-tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(arr, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.chmod(tmp, st.st_mode & 0o7777)
    try:
        os.chown(tmp, st.st_uid, st.st_gid)
    except PermissionError:
        print("  注意：保留不了 owner（需要 root），已保持 mode=%o" % (st.st_mode & 0o7777))
    os.replace(tmp, path)

def warn_restart(hit_n, before, after, audit_n):
    """收尾：命中 0 条时说「什么都没改」，否则说清效果 + 内存回写风险。"""
    if hit_n == 0:
        print("效果：本次一条都没删（幂等空跑），两个文件都没改动。")
        return
    if audit_n:
        print("效果：公开面 audit.js 的 summary.blockTotal %d → %d、executedActions 减少 %d"
              "（cacheSeconds=45，等 ≥60s 再取）" % (before, after, audit_n))
    else:
        print("效果：公开面 audit.js 的 summary.blockTotal %d → %d"
              "（cacheSeconds=45，等 ≥60s 再取；executedActions 未减少，因为没加 --with-audit）"
              % (before, after))
    print("⚠ 进程内存里仍有这 %d 条封禁记录（BlockRecordStore 启动时全量载入、persist() 从内存整体回写）："
          % hit_n)
    print("   下一次任意封禁/解封都会把 blocked-ips.json 覆盖回现在的样子。要让清理站稳，需要一次重启（本脚本不重启）。")

def main():
    print("== purge-selftest-audit（清理开发期自测封禁留痕）==")
    print("模式        : %s" % ("APPLY（真删，先备份）" if APPLY else "DRY-RUN（默认，只报告不写）"))
    print("数据目录    : %s" % DATA_DIR)
    print("只处理      : %d 条，必须 id ∈ %d 个 BLK id 且 ip ∈ 下面 %d 个明确 IP（双键同时命中）"
          % (len(BLOCK_IDS), len(BLOCK_IDS), len(SELFTEST_IPS)))
    print("             " + "  ".join(SELFTEST_IPS))
    print("不做        : 不通配/不按网段/不按时间窗/不按 actor 批量删；不删 45.83.91.0/24 或 198.18.0.0/15")
    if WITH_AUDIT:
        print("附加(--with-audit): response-audit.json 里 target 精确等于上面 7 个 IP 且 action ∈ %s"
              % sorted(AUDIT_ACTIONS))
    else:
        print("附加        : 默认不动 response-audit.json（要一起清加 --with-audit）")
    print()

    blocks_path = os.path.join(DATA_DIR, "blocked-ips.json")
    audit_path  = os.path.join(DATA_DIR, "response-audit.json")
    rc = 0

    # ---------------- 1) blocked-ips.json ----------------
    print("[1/2] %s" % blocks_path)
    if not os.path.isfile(blocks_path):
        print("  不存在 —— 这台机器没有封禁留痕文件，什么都不做")
        return 1
    if not os.access(blocks_path, os.R_OK):
        print("  不可读（多半要 sudo：data/ mode=750 owner=999:999）")
        return 1
    blocks, _ = load(blocks_path)
    if blocks is None:
        blocks = []
    ipset = set(SELFTEST_IPS)
    idb = set(BLOCK_IDS)
    hit, ip_only, id_only = [], [], []
    for r in blocks:
        ip = str(r.get("ip", "")).strip()
        rid = str(r.get("id", "")).strip()
        if rid in idb and ip in ipset:
            hit.append(r)
        elif ip in ipset:
            ip_only.append(r)
        elif rid in idb:
            id_only.append(r)

    print("  现有记录 %d 条 → 命中 %d 条，保留 %d 条" % (len(blocks), len(hit), len(blocks) - len(hit)))
    for r in hit:
        print("    命中 %s  %-13s %s  %smin  unblocked=%s" %
              (r.get("id"), r.get("ip"), r.get("createdAt"), r.get("durationMinutes"),
               str(r.get("unblocked")).lower()))
    if ip_only:
        print("    跳过 %d 条（ip 在清单但 id 不同 → 不动）：%s"
              % (len(ip_only), ", ".join("%s@%s" % (r.get("id"), r.get("ip")) for r in ip_only)))
    if id_only:
        print("    跳过 %d 条（id 在清单但 ip 不同 → 不动）：%s"
              % (len(id_only), ", ".join("%s@%s" % (r.get("id"), r.get("ip")) for r in id_only)))

    if not hit:
        print("  → 没有可清理的记录（已经清过 / 或不是这台机器）—— 按幂等处理，不写文件")
        rc = 0
    elif len(hit) != EXPECT and not FORCE:
        print("  → 命中 %d 条 ≠ 预期 %d 条，拒绝动手（如确认真要删这 %d 条，加 --force）"
              % (len(hit), EXPECT, len(hit)))
        return 2
    elif APPLY:
        if BACKUP:
            bak = "%s.bak-selftest-%s" % (blocks_path, TS)
            shutil.copy2(blocks_path, bak)
            print("  已备份 → %s" % bak)
        keep = {id(r) for r in blocks} - {id(r) for r in hit}
        write_atomic(blocks_path, [r for r in blocks if id(r) in keep], None)
        print("  已写回：%d → %d 条" % (len(blocks), len(blocks) - len(hit)))
    else:
        print("  [dry-run] 将写回 %d → %d 条（未改动文件；加 --apply 执行）"
              % (len(blocks), len(blocks) - len(hit)))

    # ---------------- 2) response-audit.json ----------------
    print()
    print("[2/2] %s" % audit_path)
    if not WITH_AUDIT:
        print("  跳过（未加 --with-audit）：处置流水里的 block-ip/unblock-ip 仍会带这 7 个 IP")
        print()
        warn_restart(len(hit), len(blocks), len(blocks) - len(hit), 0)
        return rc

    if not os.path.isfile(audit_path):
        print("  不存在 —— 跳过")
        return rc
    if not os.access(audit_path, os.R_OK):
        print("  不可读（多半要 sudo）")
        return 1
    audit, _ = load(audit_path)
    if audit is None:
        audit = []
    ahit = [r for r in audit
            if str(r.get("target", "")).strip() in ipset
            and str(r.get("action", "")).strip() in AUDIT_ACTIONS]
    print("  现有记录 %d 条 → 命中 %d 条，保留 %d 条" % (len(audit), len(ahit), len(audit) - len(ahit)))
    for r in ahit:
        print("    命中 %s  %s  %-11s %-13s %s" %
              (r.get("id"), r.get("time"), r.get("action"), r.get("target"), r.get("mode")))
    if not ahit:
        print("  → 没有可清理的记录（已清过）—— 不写文件")
    elif APPLY:
        if BACKUP:
            bak = "%s.bak-selftest-%s" % (audit_path, TS)
            shutil.copy2(audit_path, bak)
            print("  已备份 → %s" % bak)
        keep = {id(r) for r in audit} - {id(r) for r in ahit}
        write_atomic(audit_path, [r for r in audit if id(r) in keep], None)
        print("  已写回：%d → %d 条" % (len(audit), len(audit) - len(ahit)))
    else:
        print("  [dry-run] 将写回 %d → %d 条（未改动文件）" % (len(audit), len(audit) - len(ahit)))

    print()
    warn_restart(len(hit), len(blocks), len(blocks) - len(hit), len(ahit))
    return rc

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("失败：%s: %s" % (type(e).__name__, e), file=sys.stderr)
        sys.exit(1)
PY
