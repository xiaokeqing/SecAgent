#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把蜜罐日志里的「明文口令」变成一份**只有 SHA-256 与计数**的索引文件。

【为什么有这一步】
`/api/public/password` 不能在运行时读 Cowrie 日志：日志在 srv2 上、每天几十万行，
而且里面有**明文口令** —— 把读取放进请求路径，等于让明文进入应用内存与日志上下文。
所以这项工作离线做一次，运行时只加载输出（本脚本的产物）：

    蜜罐 JSON 日志 --(本脚本，本地)--> data/password-hashes.json --(只读)--> 端点

明文只在本进程的内存里出现一次，不写盘、不进日志、不进产物；
产物里的每个值都是 SHA-256 的片段。

【产物格式】（与服务端 PasswordDictionaryService 的类注释是同一份契约）
{
  "generatedAt": "2026-10-18T09:00:00+08:00",
  "totalAttempts": 128934,
  "unique": 41234,
  "buckets": {
    "a1b2c": {                                  # 完整 SHA-256 的前 5 位（小写 hex）
      "count": 37,                              # 该桶内所有「蜜罐真实口令」的合计尝试次数
      "lastSeen": "2026-10-18T09:00:00+08:00",
      "hashes": ["<剩余 59 位>", ...],          # 蜜罐里真实出现过的口令（只存 hash）
      "listed": ["<剩余 59 位>", ...]           # 只在公开弱口令榜里的（蜜罐没抓到过）
    }
  }
}
`hashes` 与 `listed` **刻意分开**：把"榜上有名"渲染成"被攻击者试过 N 次"就是撒谎。
空桶也不会出现（count 恒 ≥1）；`listed` 让 count 可以为 0 的桶不存在 ——
榜单口令单独记账，只写进 `listed`，不掺进 count。

【用法】
    python -X utf8 scripts/password-dict-build.py \
        --log '/opt/secagent/logs/cowrie.json*' \
        --wordlist docs/wordlists/weak-top1000.txt \
        --out data/password-hashes.json

    # 只看最近 24 小时（默认；0 = 全部历史）
    python -X utf8 scripts/password-dict-build.py --log '...' --window-hours 24

【安全约定】
* 不接受口令出现在命令行参数里（那会进 shell 历史与进程列表）；只从日志/榜单读；
* 不打印明文，也不打印任何能反推明文的东西；只打印桶数/hash 数/次数这类聚合；
* 产物用 0640 落盘、原子替换（写 .tmp 再 os.replace），写坏了不会留下半个字典。
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple

PREFIX_CHARS = 5
SUFFIX_CHARS = 59
# 单条口令的长度上限：Cowrie 会记录超长输入（攻击者常发 4KB 垃圾），
# 它们天然是唯一的，进字典只会把 unique 虚高、把页面误导成"你的口令被试过"。
MAX_PASSWORD_CHARS = 256


def sha256_hex(plain: str) -> str:
    return hashlib.sha256(plain.encode("utf-8", "surrogatepass")).hexdigest()


def parse_ts(value: object) -> Optional[datetime]:
    """Cowrie 的 timestamp 是 ISO8601（带 +00:00 或 Z 或 .123Z）；解析不了就返回 None。"""
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone().isoformat(timespec="seconds") if dt else None


def iter_log_lines(patterns: Iterable[str]) -> Iterable[Tuple[str, str]]:
    """按行产出 (文件路径, 行)。文件缺失只警告，不中断 —— 少一个日志就少一份计数，
    但这**不会**被当成"没发生过"（产物里的 totalAttempts 会跟着变小，页面据此自证范围）。"""
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            if not os.path.isfile(path):
                continue
            try:
                # utf-8-sig：蜜罐日志被 Windows 侧工具经手过后常带 BOM，带 BOM 的第一行会解析失败
                with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            yield path, line
            except OSError as exc:
                print(f"[warn] 读不了 {path}: {exc}", file=sys.stderr)
    for pattern in patterns:
        if not glob.glob(pattern):
            print(f"[warn] 没有匹配到日志：{pattern}", file=sys.stderr)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="从蜜罐日志生成只含 SHA-256 的口令字典索引（离线，一次性）")
    ap.add_argument("--log", action="append", default=[], metavar="GLOB",
                    help="蜜罐 JSON 日志的 glob（可重复）。例：--log '/opt/secagent/logs/cowrie.json*'")
    ap.add_argument("--wordlist", action="append", default=[], metavar="FILE",
                    help="公开弱口令榜（每行一个口令）；只进 listed[]，不计入 count（可重复）")
    ap.add_argument("--out", default="data/password-hashes.json", metavar="FILE",
                    help="产物路径（默认 data/password-hashes.json，与服务端默认配置同路径）")
    ap.add_argument("--window-hours", type=float, default=24.0, metavar="H",
                    help="只统计最近 H 小时的日志（默认 24；0 = 全部历史）。注意它只影响 count/hashes，"
                         "listed 不受时间影响（榜单本身没有时间语义）")
    ap.add_argument("--max-suffixes-per-bucket", type=int, default=5000, metavar="N",
                    help="单桶在产物里最多保留多少条 suffix（默认 5000；端点侧另有 200 条下发上限，"
                         "产物留更宽是为了让「截断」发生在下发、而不是在存储）")
    args = ap.parse_args(argv)

    if not args.log and not args.wordlist:
        print("至少要给 --log 或 --wordlist 之一（否则产物会是空字典）", file=sys.stderr)
        return 2

    since = None
    if args.window_hours and args.window_hours > 0:
        since = datetime.now(timezone.utc) - timedelta(hours=args.window_hours)

    # bucket -> {"count": int, "lastSeen": datetime, "hashes": {suffix: count}, "listed": {suffix}}
    buckets: Dict[str, Dict[str, object]] = {}
    total_attempts = 0
    seen_lines = 0
    skipped_bad = 0
    skipped_window = 0
    skipped_long = 0

    for _path, line in iter_log_lines(args.log):
        seen_lines += 1
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            skipped_bad += 1
            continue
        if not isinstance(event, dict):
            skipped_bad += 1
            continue
        plain = event.get("password")
        if not isinstance(plain, str) or not plain:
            continue
        if len(plain) > MAX_PASSWORD_CHARS:
            skipped_long += 1
            continue
        ts = parse_ts(event.get("timestamp"))
        if since is not None and (ts is None or ts < since):
            skipped_window += 1
            continue

        hexd = sha256_hex(plain)
        prefix, suffix = hexd[:PREFIX_CHARS], hexd[PREFIX_CHARS:]
        b = buckets.get(prefix)
        if b is None:
            b = buckets[prefix] = {"count": 0, "lastSeen": None, "hashes": defaultdict(int), "listed": set()}
        b["count"] += 1
        b["hashes"][suffix] += 1  # type: ignore[index]
        if ts is not None:
            prev = b["lastSeen"]
            if prev is None or ts > prev:  # type: ignore[operator]
                b["lastSeen"] = ts
        total_attempts += 1

    # 公开弱口令榜：只进 listed（蜜罐没抓到过 ≠ 没被抓到过，但文案必须写清是"榜上没有"这一类）
    listed_words = 0
    for pattern in args.wordlist:
        for path in sorted(glob.glob(pattern)):
            if not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                for raw in fh:
                    plain = raw.rstrip("\r\n")
                    if not plain or len(plain) > MAX_PASSWORD_CHARS:
                        continue
                    hexd = sha256_hex(plain)
                    prefix, suffix = hexd[:PREFIX_CHARS], hexd[PREFIX_CHARS:]
                    b = buckets.get(prefix)
                    if b is None:
                        b = buckets[prefix] = {"count": 0, "lastSeen": None, "hashes": defaultdict(int), "listed": set()}
                    if suffix in b["hashes"]:  # type: ignore[operator]
                        continue  # 蜜罐里真的出现过：以 hashes 为准，不重复放 listed
                    b["listed"].add(suffix)  # type: ignore[union-attr]
                    listed_words += 1
        if not glob.glob(pattern):
            print(f"[warn] 没有匹配到榜单：{pattern}", file=sys.stderr)

    # 落盘：按桶排序（稳定产物 → git diff 可读；但产物本身在 .gitignore 里，不登仓）
    out_buckets: Dict[str, Dict[str, object]] = {}
    unique_hashes = 0
    for prefix in sorted(buckets):
        b = buckets[prefix]
        hashes = b["hashes"]  # type: ignore[assignment]
        # 保留尝试次数最高的 N 条（高频口令更可能命中用户口令，也更能说明"攻击者在试什么"）
        ordered = sorted(hashes.items(), key=lambda kv: (-kv[1], kv[0]))  # type: ignore[union-attr]
        cap = max(1, args.max_suffixes_per_bucket)
        kept = [s for s, _ in ordered[:cap]]
        listed = sorted(b["listed"])[:cap]  # type: ignore[arg-type]
        if b["count"] == 0 and not listed:
            continue  # 空桶不写：写了会被读成"有这么个桶，但没次数"
        item: Dict[str, object] = {"count": int(b["count"])}
        last = iso(b["lastSeen"])  # type: ignore[arg-type]
        if last:
            item["lastSeen"] = last
        if kept:
            item["hashes"] = kept
        if listed:
            item["listed"] = listed
        out_buckets[prefix] = item
        unique_hashes += len(kept) + len(listed)

    doc = {
        "generatedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "totalAttempts": total_attempts,
        "unique": unique_hashes,
        "windowHours": args.window_hours,
        "source": "cowrie-json-logs+public-wordlist",
        "buckets": out_buckets,
    }

    out_path = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".password-hashes.", suffix=".tmp", dir=os.path.dirname(out_path) or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
            fh.write("\n")
        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, out_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    # 只打聚合数字：这些数不包含、也反推不出任何明文
    print(json.dumps({
        "out": out_path,
        "buckets": len(out_buckets),
        "hashes": sum(len(v.get("hashes", [])) for v in out_buckets.values()),  # type: ignore[union-attr]
        "listedFromWordlist": listed_words,
        "bucketCountSum": total_attempts,
        "linesRead": seen_lines,
        "skipped": {"badJson": skipped_bad, "outsideWindow": skipped_window, "tooLong": skipped_long},
        "windowHours": args.window_hours,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
