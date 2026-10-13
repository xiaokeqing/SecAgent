#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
引用溯源 / 幻觉率逐条定性工具 —— 与指标计算【同源】。

## 为什么需要它（问题陈述）

同一个东西（引用可溯源率）此前有两套口径：

  · 指标侧：`scripts/eval-papers.mjs` 里内联的 `citationCheck()`（打分、只吐数字）
  · 复核侧：`scripts/analyze-citations.mjs`（另一套词表：exact / prefix-only / not-found）
  · `scripts/eval-papers.py`（服务器上 cron 实际在跑的那份）**根本没有引用指标**

三套口径、两套词表，"指标说 92%、工具说 30%"时无法判定谁对。本工具把它收敛成
**一个实现**：`eval-papers.py` 直接 import 本模块的 `classify_record()` / `summarize()`，
结果文件里的每条判定与独立跑本 CLI 得到的判定**逐字一致**。

## 唯一证据源

回答里的 `UNTRUSTED_DATA` 证据块（RAG 检索片段 / 日志 / 告警都包在这里）。
`eval-papers.mjs` 第三版已改为这个口径（见其注释），本工具把它固定下来并显式落盘：

  · `evidence_blocks(text)` —— 抽取所有 `<UNTRUSTED_DATA ...>…</UNTRUSTED_DATA>`
  · 兜底：没有该标记时，取"知识库参考（未经 AI 加工）"标题之后的正文（标注 fallback=true）

## 三类判定（对应三种完全不同的责任）

  A. 引用条目级（回答的"**证据引用**"区，或公开端点返回的 citations 数组）
       traceable               —— 引用能在证据块里原样找到 → 引用可溯源
       partial                 —— 只有前缀对得上（截断/改写）→ 度量/展示问题
       unverifiable-truncated  —— 证据块可能被 clip 截断，无法证伪 → 需人看原文
       unsupported             —— 前缀也对不上 → **幻觉候选**（引用无出处）
       question-echo           —— 只出现在用户问题里（引用的是输入，不是检索证据）
  B. 关键结论级（回答正文里带"硬事实"的断言：IP / CVE / 哈希 / 端口 / 文件名 / 版本 / 数字）
       backed                  —— 硬事实在证据块里能找到出处
       backed-by-question-only —— 硬事实来自用户问题（复述输入，不算编造）
       partially-backed        —— 部分硬事实有出处
       unbacked                —— 硬事实在证据块与问题里都找不到 → **无依据的断言**
  C. 记录级
       citation-missing        —— 有硬事实断言，却既无引用条目、又无证据块 → 引用缺失

## 判定必须可复现

每条判定都带 `evidence`：命中的**证据块序号 + 原文片段（含前后各 60 字）+ 字符偏移**。
不是黑箱打分：拿着同一份响应 JSON，任何人跑一遍都得到同样的片段与结论。

## 用法

```bash
# 逐条复核 + 汇总（可一次给多个结果文件）
python3 scripts/citation_audit.py eval-runs/eval-quality-*.json public-samples/raw/*.json
python3 scripts/citation_audit.py --in-dir public-samples --out-dir audit-out
python3 scripts/citation_audit.py --self-test          # 已知答案的小样例自测
```

退出码：0 正常 / 1 自测失败 / 2 用法或输入错误 / 3 无可用输入。
"""

from __future__ import print_function  # 兼容服务器上的 /usr/bin/python3（3.6.8）

import argparse
import datetime
import glob
import json
import os
import re
import sys

# ---------------------------------------------------------------- 常量与口径

# 证据块被 clip 到该长度即视为"可能被截断"（RAG 路径 clip(rag, 800)；留余量取 500）
CLIP_DEFAULT = 500

# 前缀逐步缩短的阶梯（与 eval-papers.mjs 完全一致，保证两版数字可比）
PREFIX_LADDER = (24, 16, 12, 8, 6, 4)

EVIDENCE_RE = re.compile(r"<UNTRUSTED_DATA\b[^>]*>(.*?)</UNTRUSTED_DATA>", re.S | re.I)
EVIDENCE_TAG_RE = re.compile(r"</?UNTRUSTED_DATA\b[^>]*>", re.I)
EVIDENCE_SOURCE_RE = re.compile(r'<UNTRUSTED_DATA\b[^>]*\bsource="([^"]*)"', re.I)
CITATION_SECTION_RE = re.compile(r"\*\*证据引用\*\*[:：]([\s\S]*?)(?=\n\*\*|\n> |\n---|$)")
KB_HEADING = "知识库参考"

# 硬事实（可被证据检验的"具体断言"）
HARD_PATTERNS = [
    ("ipv4", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)),
    ("hash", re.compile(r"\b[a-f0-9]{32,64}\b", re.I)),
    ("file", re.compile(r"\b[\w.\-]+\.(?:php|jsp|jspx|asp|aspx|sh|exe|dll|py|jar|yml|yaml|json|pem|key|log|txt)\b", re.I)),
    ("port", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b|\bport\s*\d{2,5}\b|端口\s*\d{2,5}")),
    ("version", re.compile(r"\bv?\d+\.\d+\.\d+\b")),
    ("count", re.compile(r"\d+\s*(?:次|秒|分钟|小时|天|条|台|个|GB|MB|KB|%)")),
    ("quote", re.compile(r"[「『]([^」』]{4,40})[」』]")),
]

# 一行里可能有**多个**结论项（实测形态：`**攻击类型**：Brute Force Attack　**置信度**：0.95　**严重度**：HIGH`），
# 因此不能"整行锚定一条"，要在行内 finditer 全部抽出（值取到下一个 `**` 之前）。
CLAIM_KEY_RE = re.compile(r"\*\*(?P<key>[^*\n]{2,24})\*\*\s*[:：]\s*(?P<val>(?:(?!\*\*)[^\n])*)")
SENTENCE_SPLIT_RE = re.compile(r"[。；;\n]")
STATE_IN_ANSWER_RE = re.compile(r">\s*state=([a-z\-]+)")

# 明显的系统提示词泄漏形态（不是普通讨论"提示词"）
PROMPT_LEAK_RE = re.compile(
    r"你是\s*SecAgent[^\n]{0,60}(调度员|PLANNER|规划器)"
    r"|系统提示词(?:原文|如下|内容|：\s*\n)"
    r"|SYSTEM\s*PROMPT\s*[:：]",
    re.I,
)


# ---------------------------------------------------------------- 基础工具


def decode_html(s):
    """HTML 实体 + JSON 转义反解（与 eval-papers.mjs 同一套，保证结果可比）。"""
    s = "" if s is None else str(s)
    s = (s.replace("&quot;", '"').replace("&lt;", "<").replace("&gt;", ">")
          .replace("&#39;", "'").replace("&amp;", "&").replace('\\"', '"'))
    return s


NORM_DROP_RE = re.compile(r"[#*`\"“”'’\s\\]")


def norm_with_map(s):
    """归一化并保留"归一化后每个字符 → 原文下标"的映射，用于回指原文片段。"""
    out = []
    idx = []
    for i, ch in enumerate(s):
        if NORM_DROP_RE.match(ch):
            continue
        out.append(ch)
        idx.append(i)
    return "".join(out), idx


def norm(s):
    return norm_with_map(s)[0]


def text_of_block(b):
    return decode_html(b.get("text") or "")


# ---------------------------------------------------------------- 证据源

EVIDENCE_TAG_ANY_RE = re.compile(r"<UNTRUSTED_DATA\b([^>]*)>|</UNTRUSTED_DATA>", re.I)
# 公开端点出海前，PublicOutputGuard 会把 `UNTRUSTED_DATA` 这个词替换成占位符
# （属性与位置都保留）。于是一份"已脱敏"的公开回答里，证据块的边界变成了：
#   <[内部标记已脱敏] note="…" source="…">  …证据…  </[内部标记已脱敏]>
# 若不认这个形态，公开回答里的大段日志会被当成"模型正文"，逐条变成假的"无依据断言"。
SANITIZED_MARKER_ANY_RE = re.compile(r"</?\[内部标记已脱敏\]([^>]*)>")
SOURCE_ATTR_RE = re.compile(r'\bsource="([^"]*)"', re.I)


def _scan_tags(text, tag_re):
    """栈式配对：返回 (blocks, narrative)，blocks=[(outer_attrs, raw_body)]。"""
    stack, blocks, keep, last = [], [], [], 0
    for m in tag_re.finditer(text):
        token = m.group(0)
        if token.startswith("</"):
            if stack:
                attrs, start = stack.pop()
                if not stack:
                    keep.append(text[last:start])
                    blocks.append((attrs, text[start:m.start()]))
                    last = m.end()
        else:
            attrs = (m.group(1) if m.groups() else "") or ""
            stack.append((attrs, m.end()))
    if stack:  # 未闭合（响应被截断）→ 如实当作证据
        attrs, start = stack[0]
        keep.append(text[last:start])
        blocks.append((attrs, text[start:]))
        last = len(text)
    keep.append(text[last:])
    return blocks, "".join(keep)


def scan_evidence(text):
    """
    切出证据区与正文。两种边界都认：
      ① 原始形态 `<UNTRUSTED_DATA ...>…</UNTRUSTED_DATA>`
      ② 已脱敏形态 `<[内部标记已脱敏] ...>…</[内部标记已脱敏]>`（公开端点出海后的样子）
    用<b>栈</b>配对而不是非贪婪正则：实际回答是"外层包裹套内层 RAG 块"的双层形态，
    非贪婪正则会提前收口，把内层开标签当成证据正文的一部分。
    """
    text = text or ""
    blocks, narrative = _scan_tags(text, EVIDENCE_TAG_ANY_RE)
    if not blocks:
        blocks, narrative = _scan_tags(text, SANITIZED_MARKER_ANY_RE)
    return blocks, narrative


def evidence_blocks(answer, clip=CLIP_DEFAULT):
    """
    唯一证据源：回答里的证据块（UNTRUSTED_DATA，或其脱敏后的等价形态）。

    返回 [{index, source, text, length, truncated, fallback}]
    兜底：无标记时取"知识库参考（未经 AI 加工）"之后的正文（fallback=True）。
    """
    text = answer or ""
    raw_blocks, _ = scan_evidence(text)
    blocks = []
    for attrs, raw_body in raw_blocks:
        inner_tags = EVIDENCE_TAG_RE.findall(raw_body) or SANITIZED_MARKER_ANY_RE.findall(raw_body)
        src_m = None
        for m in SOURCE_ATTR_RE.finditer(attrs + " " + raw_body):
            src_m = m  # 取最后一个 source（内层更具体）
        body = EVIDENCE_TAG_RE.sub("\n", raw_body)
        body = SANITIZED_MARKER_ANY_RE.sub("\n", body)
        blocks.append(dict(index=len(blocks),
                           source=(src_m.group(1) if src_m else None),
                           text=body, length=len(body),
                           truncated=len(body) >= clip, fallback=False,
                           nested_markers=bool(inner_tags)))
    if not blocks:
        i = text.find(KB_HEADING)
        if i >= 0:
            body = text[i:]
            blocks.append(dict(index=0, source="(知识库参考区·兜底抽取)", text=body,
                               length=len(body), truncated=len(body) >= clip, fallback=True,
                               nested_markers=False))
    return blocks


def evidence_corpus(blocks):
    """归一化语料（引用条目比对用）。"""
    return norm("\n---\n".join(text_of_block(b) for b in blocks))


def locate(blocks, needle):
    """
    在证据块原文里定位 needle（先归一化匹配，再回指原文）。
    返回 {block, offset, snippet} 或 None —— snippet 就是"可复现的证据片段"。
    """
    n_needle = norm(needle)
    if not n_needle:
        return None
    for b in blocks:
        text = text_of_block(b)
        n_text, idx = norm_with_map(text)
        hit = n_text.find(n_needle)
        if hit >= 0:
            start = idx[hit]
            end = idx[hit + len(n_needle) - 1] + 1
            return dict(block=b["index"], source=b.get("source"),
                        offset=start, match=text[start:end],
                        snippet=text[max(0, start - 60):end + 60])
    return None


# ---------------------------------------------------------------- 引用条目


def _citation_fields(c):
    return [str(c.get(k) or "") for k in ("title", "snippet", "sourceType", "id") if str(c.get(k) or "").strip()]


def extract_citations(answer, api_citations=None):
    """
    引用条目的两个来源（任一命中即算有引用）：
      ① 回答里的 `**证据引用**：` 区（内部 /api/chat 路径：模型自己写的引用）
      ② 接口返回的 citations 数组（公开端点路径）

    重要区别（口径）：② 是**检索证据本身**（公开端点在做答前先检索，返回的就是
    检索片段），不是"模型的引用声明"，因此它的判定不是"可溯源/不可溯源"，而是
    status=evidence-source；对公开回答真正有意义的检验落在**关键结论级**。
    """
    items = []
    m = CITATION_SECTION_RE.search(answer or "")
    if m:
        for line in m.group(1).split("\n"):
            s = re.sub(r"^[-*\s]+", "", line).strip()
            if s and "模型未给出引用" not in s:
                items.append(dict(item=s, evidence_text=s, origin="answer-section"))
    for c in api_citations or []:
        if isinstance(c, dict):
            fields = _citation_fields(c)
            if fields:
                items.append(dict(item=" ".join(fields), evidence_text="\n".join(fields),
                                  origin="api-citations", score=c.get("score"),
                                  title=c.get("title")))
        elif isinstance(c, str) and c.strip():
            items.append(dict(item=c.strip(), evidence_text=c.strip(), origin="api-citations"))
    return items


def classify_citations(citations, blocks, question):
    corpus = evidence_corpus(blocks)
    truncated = any(b["truncated"] for b in blocks)
    out = []
    for c in citations:
        raw = c["item"]
        n = norm(raw)
        row = dict(item=raw[:160], origin=c.get("origin"), score=c.get("score"),
                   status="unsupported", hitLen=0, evidence=None)
        if c.get("origin") == "api-citations":
            # 公开端点：citations 本身就是检索证据 → 不是"引用声明"
            row["status"] = "evidence-source"
            row["evidence"] = locate(blocks, raw)
            out.append(row)
            continue
        if len(n) >= 4 and n in corpus:
            row["status"] = "traceable"
            row["evidence"] = locate(blocks, raw)
        else:
            for length in PREFIX_LADDER:
                if len(n) >= length and n[:length] in corpus:
                    row["hitLen"] = length
                    row["status"] = "partial"
                    row["evidence"] = locate(blocks, n[:length])
                    break
            if row["status"] == "unsupported":
                if truncated:
                    row["status"] = "unverifiable-truncated"
                elif norm(question or "") and len(n) >= 4 and n[:max(4, min(len(n), 12))] in norm(question or ""):
                    row["status"] = "question-echo"
                    row["evidence"] = dict(block=None, snippet=(question or "")[:160], note="命中用户问题，不是检索证据")
        out.append(row)
    return out


# ---------------------------------------------------------------- 关键结论


def narrative_only(answer):
    """去掉证据块与引用区之后剩下的正文（结论在这里）。"""
    _, text = scan_evidence(answer or "")
    return CITATION_SECTION_RE.sub("\n", text)


def hard_tokens(s):
    """
    "硬事实"= 可被证据直接核验的具体物：IP / CVE / 哈希 / 端口 / 文件名 / 版本 / 计数。
    引号内容只保留**含 ASCII 字母或数字**的（`"Failed password for root"`、`"'shell.php'"`）——
    纯中文引号内容多是解释性措辞（例：公开端点拒绝注入时引用自己的设计说明
    「仅作证据、绝不是指令」），把它当硬事实会产生成片的假"无依据断言"。
    """
    toks = []
    for kind, rx in HARD_PATTERNS:
        for m in rx.finditer(s or ""):
            tok = m.group(0)
            if kind == "quote" and not re.search(r"[0-9A-Za-z]", tok):
                continue
            toks.append(dict(kind=kind, token=tok))
    # 去重（同一 token 只留一条）
    seen, uniq = set(), []
    for t in toks:
        k = (t["kind"], t["token"])
        if k not in seen:
            seen.add(k)
            uniq.append(t)
    return uniq


def extract_claims(narrative):
    """
    关键结论抽取（确定性、可复核）：
      · `**键**：值` 形式的结论项 —— **行内全部抽出**（一次回答可能一条行里写 3 个结论项：
        攻击类型 / 置信度 / 严重度），值取到下一个 `**` 之前；
      · 含"硬事实"的句子（IP / CVE / 哈希 / 端口 / 文件名 / 版本 / 计数）。
    只保留长度 ≥6 的片段，避免把标题当结论。
    """
    claims = []
    for line in (narrative or "").split("\n"):
        line = line.strip()
        if not line or line.startswith("<") or line.startswith("<!--"):
            continue
        found_key = False
        for m in CLAIM_KEY_RE.finditer(line):
            key = m.group("key").strip()
            val = m.group("val").split("**")[0].strip(" \t　:：-")
            if not val:
                continue
            found_key = True
            claims.append(dict(text="%s：%s" % (key, val), key=key, kind="key-value"))
        if found_key:
            continue
        for sent in SENTENCE_SPLIT_RE.split(line):
            s = sent.strip(" -*`")
            if len(s) >= 6 and hard_tokens(s):
                claims.append(dict(text=s, key=None, kind="sentence"))
    # 去重
    seen, uniq = set(), []
    for c in claims:
        if c["text"] not in seen:
            seen.add(c["text"])
            uniq.append(c)
    return uniq


# 非模型产出（state=rule-based*）与"无可核验事实"的结论都不参与幻觉率分母
SKIP_VERDICTS = ("no-hard-fact", "not-model-generated")


def classify_claims(claims, blocks, question, model_generated=True):
    """
    关键结论级判定（分两类，分母不混算）：

    · **硬事实类**（IP / CVE / 哈希 / 端口 / 文件名 / 版本 / 计数）：
        必须能在【证据块】或【用户问题】里找到出处；两处都没有 → `unbacked`（无依据的断言）。
    · **研判项类**（`**键**：值`，值里没有可核验的具体物，如"严重度：HIGH"）：
        逐字能对上 → `backed`；对不上 → `unverifiable-no-fact`
        （**语义等价无法用逐字匹配证明**，交人工看，不自动计入幻觉率）。

    `state=rule-based*` 的回答由代码产出（模型不参与拍板），一律 `not-model-generated`：
    把护栏自己的白名单 CIDR（例如"192.0.2.0/24"）算成"无依据断言"是度量假阳性。
    """
    corpus = evidence_corpus(blocks)
    qn = norm(question or "")
    out = []
    for c in claims:
        row = dict(text=c["text"][:300], key=c.get("key"), kind=c.get("kind"),
                   verdict="no-hard-fact", tokens=[], valueInEvidence=None, claimClass="none")
        if not model_generated:
            row["verdict"] = "not-model-generated"
            out.append(row)
            continue
        toks = hard_tokens(c["text"])
        rows = []
        for t in toks:
            nt = norm(t["token"])
            in_ev = bool(nt) and nt in corpus
            in_q = bool(nt) and nt in qn
            rows.append(dict(kind=t["kind"], token=t["token"],
                             in_evidence=in_ev, in_question=in_q,
                             evidence=locate(blocks, t["token"]) if in_ev else None))
        row["tokens"] = rows
        if toks:
            row["claimClass"] = "hard"
            if all(r["in_evidence"] for r in rows):
                row["verdict"] = "backed"
            elif all(r["in_evidence"] or r["in_question"] for r in rows):
                row["verdict"] = "backed-by-question-only"
            elif any(r["in_evidence"] for r in rows):
                row["verdict"] = "partially-backed"
            else:
                row["verdict"] = "unbacked"
        elif c.get("kind") == "key-value":
            row["claimClass"] = "judgment"
            val = c["text"].split("：", 1)[-1]
            nv = norm(val)
            hit = bool(nv) and (nv in corpus or (len(nv) >= 6 and nv[:4] in corpus))
            qhit = bool(nv) and (nv in qn or (len(nv) >= 6 and nv[:4] in qn))
            row["valueInEvidence"] = hit
            if hit:
                row["verdict"] = "backed"
            elif qhit:
                row["verdict"] = "backed-by-question-only"
            else:
                row["verdict"] = "unverifiable-no-fact"
        out.append(row)
    return out


# ---------------------------------------------------------------- 记录级复核


def audit_record(rec, clip=CLIP_DEFAULT):
    """
    复核一条问答记录。

    rec 支持三种形态（自动识别）：
      · 评测结果条目：{id, question, answer|answerFull|answerExcerpt, state, citation, refBlockSnapshot}
      · 单次原始响应：{answer, question, citations, state, ...}
      · 公开端点响应：{data:{answer, citations, state, ...}}
    """
    answer = rec.get("answerFull") or rec.get("answer") or rec.get("answerExcerpt") or ""
    api_cits = rec.get("citations")
    if not api_cits and isinstance(rec.get("data"), dict):
        api_cits = rec["data"].get("citations")
    question = rec.get("question") or (rec.get("data") or {}).get("question") or ""
    state = rec.get("state") or (rec.get("data") or {}).get("state")
    if isinstance(state, list):
        state = ",".join(state)
    if not state:
        # 兜底：从回答正文里读机读标记（评测结果里 state 是字段，抽检原始响应里也是；
        # 这里只是防止第三方结果文件没有该字段）
        hits = STATE_IN_ANSWER_RE.findall(answer)
        state = ",".join(sorted(set(hits))) if hits else None

    blocks = evidence_blocks(answer, clip=clip)
    # 兼容：老结果文件只留了 refBlockSnapshot（且答案被截断）
    if not blocks and rec.get("refBlockSnapshot"):
        blocks = [dict(index=0, source="(refBlockSnapshot)", text=rec["refBlockSnapshot"],
                       length=len(rec["refBlockSnapshot"]),
                       truncated=len(rec["refBlockSnapshot"]) >= clip, fallback=True,
                       nested_markers=False)]
    # 公开端点：回答里没有 UNTRUSTED_DATA，但接口返回的 citations 就是本次检索证据
    evidence_from_api = False
    if not blocks and api_cits:
        synth = "\n---\n".join(_citation_fields(c) and "\n".join(_citation_fields(c)) or ""
                               for c in api_cits if isinstance(c, dict))
        if synth.strip():
            evidence_from_api = True
            blocks = [dict(index=0, source="(公开端点 citations=本次检索证据)", text=synth,
                           length=len(synth), truncated=len(synth) >= clip, fallback=False,
                           nested_markers=False)]
    cits = extract_citations(answer, api_cits)
    cit_rows = classify_citations(cits, blocks, question)
    model_generated = not re.search(r"rule-based", state or "", re.I)
    claims = classify_claims(extract_claims(narrative_only(answer)), blocks, question,
                             model_generated=model_generated)

    def cls(name, *verdicts):
        return [c for c in claims if c.get("claimClass") == name and c["verdict"] in verdicts]

    hard_claims = [c for c in claims if c.get("claimClass") == "hard"]
    judge_claims = [c for c in claims if c.get("claimClass") == "judgment"]
    unbacked = cls("hard", "unbacked")
    missing = bool(hard_claims) and not cits and not blocks

    def cnt(status):
        return len([c for c in cit_rows if c["status"] == status])

    rec_audit = dict(
        id=rec.get("id") or rec.get("name") or rec.get("case") or "(unnamed)",
        question=question[:200], state=state, modelGenerated=model_generated,
        blocksTotal=len(blocks),
        blockSources=[b.get("source") for b in blocks],
        evidenceTruncated=any(b["truncated"] for b in blocks),
        evidenceFromApi=evidence_from_api,
        citations=cit_rows,
        claims=claims,
        citationMissing=missing,
        counts=dict(
            citationTotal=len(cit_rows), traceable=cnt("traceable"), partial=cnt("partial"),
            unverifiable=cnt("unverifiable-truncated"), unsupported=cnt("unsupported"),
            questionEcho=cnt("question-echo"), evidenceSource=cnt("evidence-source"),
            claimTotal=len(claims),
            claimHard=len(hard_claims),
            claimHardBacked=len(cls("hard", "backed", "backed-by-question-only")),
            claimUnbacked=len(unbacked),
            claimPartial=len(cls("hard", "partially-backed")),
            claimJudgment=len(judge_claims),
            claimJudgmentBacked=len(cls("judgment", "backed", "backed-by-question-only")),
            claimJudgmentNoEvidence=len(cls("judgment", "unverifiable-no-fact")),
            claimNotModelGenerated=len([c for c in claims if c["verdict"] == "not-model-generated"]),
        ),
        unbackedClaims=[c["text"] for c in unbacked],
    )
    # 自证：结果文件里若已带指标侧写入的 audit，就现场重算一遍比对。
    # "同一实现、同一份证据源"这句话必须能被验证，而不是只能被相信。
    if isinstance(rec.get("audit"), dict):
        emb = {k: v for k, v in rec["audit"].items() if k != "embeddedAuditMatch"}
        rec_audit["embeddedAuditMatch"] = (
            json.dumps(emb, ensure_ascii=False, sort_keys=True)
            == json.dumps(rec_audit, ensure_ascii=False, sort_keys=True))
    else:
        rec_audit["embeddedAuditMatch"] = None
    return rec_audit


# ---------------------------------------------------------------- 指标（与工具同源）


def wilson(k, n, z=1.96):
    """Wilson 置信区间（与 eval-papers.py / .mjs 同一实现）。"""
    if not n:
        return [0.0, 0.0]
    p = float(k) / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    s = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return [max(0.0, (c - s) / d), min(1.0, (c + s) / d)]


def _metric(k, n):
    return dict(k=k, n=n, rate=(float(k) / n if n else None), ci=wilson(k, n))


def summarize(audits):
    """
    汇总指标。**eval-papers.py 直接调用本函数**，因此"指标数字"与
    "工具逐条判定"不可能各说各话（同一个实现、同一份证据块）。
    """
    cits_all = [c for a in audits for c in a["citations"]]
    # 口径说明：公开端点返回的 citations 就是检索证据本身（status=evidence-source），
    # 不参与"引用可溯源率"的分母 —— 否则会得到一个恒等于 100% 的假指标。
    cits = [c for c in cits_all if c["status"] != "evidence-source"]
    all_claims = [c for a in audits for c in a["claims"]]
    # 硬事实类 / 研判项类分开算分母（混算会把"严重度：HIGH 逐字对不上"混进幻觉率）
    cl_hard = [c for c in all_claims if c.get("claimClass") == "hard"]
    cl_judge = [c for c in all_claims if c.get("claimClass") == "judgment"]
    hard_records = [a for a in audits if a["counts"]["claimHard"] > 0]
    missing = [a for a in hard_records if a["citationMissing"]]
    n_cit, n_hard, n_judge = len(cits), len(cl_hard), len(cl_judge)

    def ck(status):
        return len([c for c in cits if c["status"] == status])

    def ch(*verdicts):
        return len([c for c in cl_hard if c["verdict"] in verdicts])

    def cj(*verdicts):
        return len([c for c in cl_judge if c["verdict"] in verdicts])

    return dict(
        records=len(audits),
        evidenceBlocks=sum(a["blocksTotal"] for a in audits),
        citationTraceableRate=_metric(ck("traceable"), n_cit),
        citationPartialRate=_metric(ck("partial"), n_cit),
        citationUnverifiableRate=_metric(ck("unverifiable-truncated"), n_cit),
        citationHallucinationRate=_metric(ck("unsupported"), n_cit),
        citationQuestionEchoRate=_metric(ck("question-echo"), n_cit),
        claimHardBackedRate=_metric(ch("backed", "backed-by-question-only"), n_hard),
        claimHardPartialRate=_metric(ch("partially-backed"), n_hard),
        claimHardUnbackedRate=_metric(ch("unbacked"), n_hard),
        claimJudgmentBackedRate=_metric(cj("backed", "backed-by-question-only"), n_judge),
        claimJudgmentNoEvidenceRate=_metric(cj("unverifiable-no-fact"), n_judge),
        citationMissingRate=_metric(len(missing), len(hard_records)),
        counts=dict(citations=n_cit,
                    citationsEvidenceSource=len(cits_all) - len(cits),
                    claimsHard=n_hard, claimsJudgment=n_judge,
                    recordsWithHardClaims=len(hard_records),
                    recordsCitationMissing=len(missing),
                    claimsNotModelGenerated=len([c for c in all_claims
                                                 if c["verdict"] == "not-model-generated"]),
                    recordsRuleBased=len([a for a in audits if not a.get("modelGenerated", True)]),
                    embeddedAuditChecked=len([a for a in audits if a.get("embeddedAuditMatch") is not None]),
                    embeddedAuditMismatch=len([a for a in audits if a.get("embeddedAuditMatch") is False])),
    )


# ---------------------------------------------------------------- 输入装载


def _records_from_obj(obj, path):
    """
    把各种 JSON 形态展开成记录列表（保留 question/answer/citations/state 等字段）。
    """
    out = []
    if isinstance(obj, list):
        for i, it in enumerate(obj):
            if isinstance(it, dict):
                out.extend(_records_from_obj(it, "%s[%d]" % (path, i)))
        return out

    if isinstance(obj, dict) and isinstance(obj.get("results"), list):
        for r in obj["results"]:
            if isinstance(r, dict):
                r = dict(r)
                r.setdefault("id", "%s/%s" % (obj.get("runId", os.path.basename(path)), r.get("id")))
                out.append(r)
        return out

    if isinstance(obj, dict) and isinstance(obj.get("data"), dict) and (
            obj["data"].get("answer") or obj["data"].get("citations")):
        d = dict(obj["data"])
        d.setdefault("id", obj.get("id") or os.path.basename(path))
        out.append(d)
        return out

    # 抽检脚本落盘的原始响应：{id, question, response:{code,data:{...}}}
    if isinstance(obj, dict) and isinstance(obj.get("response"), dict):
        inner = obj["response"]
        if isinstance(inner.get("data"), dict):
            d = dict(inner["data"])
            d.setdefault("id", obj.get("id") or os.path.basename(path))
            d.setdefault("question", obj.get("question"))
            out.append(d)
            return out

    if isinstance(obj, dict) and (obj.get("answer") or obj.get("answerFull")):
        d = dict(obj)
        d.setdefault("id", d.get("id") or os.path.basename(path))
        out.append(d)
        return out
    return out


def load_records(path):
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    return _records_from_obj(obj, path)


# ---------------------------------------------------------------- 渲染


def _fmt_snippet(ev):
    if not ev:
        return "-"
    if ev.get("block") is None:
        return "问题内命中：%s" % (ev.get("snippet", "")[:80])
    return "块#%s 偏移%d …%s…" % (ev.get("block"), ev.get("offset", -1),
                                  (ev.get("snippet") or "").replace("\n", " ")[:180])


def render_markdown(audits, metrics, inputs):
    L = []
    L.append("# 引用溯源 / 幻觉率逐条复核")
    L.append("")
    L.append("- 生成时间：%s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    L.append("- 证据源（唯一）：回答里的 `UNTRUSTED_DATA` 证据块（无标记时兜底取『知识库参考』标题后正文）")
    L.append("- 输入：%s" % ", ".join(os.path.basename(p) for p in inputs))
    L.append("")
    L.append("## 汇总（同一实现也用于指标计算）")
    L.append("")
    L.append("| 指标 | k/n | 率 | Wilson 95% CI |")
    L.append("|---|---|---|---|")
    names = [
        ("citationTraceableRate", "引用可溯源率"),
        ("citationPartialRate", "引用部分可溯源率（截断/改写）"),
        ("citationUnverifiableRate", "引用无法验证率（证据块疑似被截断）"),
        ("citationHallucinationRate", "幻觉候选率（引用无出处）"),
        ("citationQuestionEchoRate", "引用仅命中问题率（复述输入）"),
        ("claimHardBackedRate", "硬事实结论有出处率"),
        ("claimHardPartialRate", "硬事实结论部分有出处率"),
        ("claimHardUnbackedRate", "无依据断言率（硬事实在图/问之外）"),
        ("claimJudgmentBackedRate", "研判项逐字有出处率"),
        ("claimJudgmentNoEvidenceRate", "研判项逐字无出处率（交人工语义核对）"),
        ("citationMissingRate", "引用缺失率（有硬事实断言但无引用无证据）"),
    ]
    for key, label in names:
        m = metrics[key]
        rate = "n/a" if m["rate"] is None else "%.1f%%" % (m["rate"] * 100)
        ci = "n/a" if not m["n"] else "[%.3f, %.3f]" % (m["ci"][0], m["ci"][1])
        L.append("| %s | %d/%d | %s | %s |" % (label, m["k"], m["n"], rate, ci))
    L.append("")
    L.append("计数：记录 %d 条｜证据块 %d 个｜引用条目 %d 条（另有 %d 条是公开端点检索证据本身，不计入分母）"
             "｜硬事实结论 %d 条｜引用缺失记录 %d 条"
             % (metrics["records"], metrics["evidenceBlocks"], metrics["counts"]["citations"],
                metrics["counts"]["citationsEvidenceSource"],
                metrics["counts"]["claimsHard"], metrics["counts"]["recordsCitationMissing"]))
    L.append("")
    L.append("> 口径：公开端点（`/api/public/ask`）返回的 `citations` 是**本次检索证据本身**，"
             "其条目判定为 `evidence-source`，不参与『引用可溯源率』分母（否则该指标恒为 100%，是假指标）；"
             "对公开回答真正有意义的检验是**关键结论级**（回答里的硬事实能否在那批检索片段里找到）。")
    L.append("")
    L.append("> 口径：`state=rule-based*` 的回答由**代码**产出（模型不参与拍板，"
             "本轮 %d 条），其结论一律 `not-model-generated`，不参与幻觉率分母 —— "
             "否则护栏自己的白名单 CIDR（如 `192.0.2.0/24`）会被算成『无依据断言』，是度量假阳性。"
             % metrics["counts"].get("recordsRuleBased", 0))
    L.append("")
    L.append("> 口径：结论分**硬事实类**（IP/CVE/哈希/端口/文件名/版本/计数，可逐字核验）与"
             "**研判项类**（`**键**：值` 且值里没有可核验的具体物）。两类分母分开，"
             "研判项逐字对不上只进『交人工』桶，不自动判编造。")
    L.append("")
    if metrics["counts"].get("embeddedAuditChecked"):
        L.append("> 同源自证：输入里有 %d 条记录自带指标侧写入的 `audit`，本工具现场重算后逐字比对，"
                 "**不一致 %d 条** —— 为 0 才说明『指标与复核工具同源』这句话成立。"
                 % (metrics["counts"]["embeddedAuditChecked"],
                    metrics["counts"]["embeddedAuditMismatch"]))
        L.append("")

    for a in audits:
        L.append("## %s" % a["id"])
        L.append("")
        L.append("- state=%s｜证据块 %d 个（%s）｜疑似截断=%s｜引用缺失=%s%s"
                 % (a["state"], a["blocksTotal"], ", ".join([s or "-" for s in a["blockSources"]]) or "-",
                    a["evidenceTruncated"], a["citationMissing"],
                    "｜证据来自公开端点 citations" if a.get("evidenceFromApi") else ""))
        if a["question"]:
            L.append("- 问题：%s" % a["question"].replace("\n", " "))
        L.append("")
        if a["citations"]:
            L.append("| 引用条目 | 判定 | 命中前缀 | 可复现证据片段 |")
            L.append("|---|---|---|---|")
            for c in a["citations"]:
                L.append("| %s | %s | %s | %s |" % (
                    c["item"].replace("|", "/")[:70], c["status"],
                    ("%d字" % c["hitLen"]) if c["hitLen"] else "-",
                    _fmt_snippet(c.get("evidence")).replace("|", "/")))
            L.append("")
        else:
            L.append("（无引用条目）")
            L.append("")
        hard = [c for c in a["claims"] if c.get("claimClass") in ("hard", "judgment")]
        if hard:
            L.append("| 关键结论 | 类别 | 判定 | 硬事实 token（证据内/问题内） | 证据片段 |")
            L.append("|---|---|---|---|---|")
            for c in hard:
                toks = " ".join("%s%s%s" % (t["token"], "[证]" if t["in_evidence"] else "",
                                            "[问]" if t["in_question"] else "")
                                for t in c["tokens"]) or "-"
                ev = next((t["evidence"] for t in c["tokens"] if t["evidence"]), None)
                L.append("| %s | %s | %s | %s | %s |" % (
                    c["text"].replace("|", "/")[:80], c.get("claimClass"), c["verdict"],
                    toks.replace("|", "/"), _fmt_snippet(ev).replace("|", "/")))
            L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------- 自测（已知答案小样例）


def _mk(answer, question="", cits=None, rec_id="t"):
    rec = dict(id=rec_id, question=question, answer=answer)
    if cits:
        rec["citations"] = cits
    return rec


def self_test():
    """
    先用已知答案的小样例自测（RUNBOOK §8④）：工具本身也是"被测对象"。
    每条样例都写清期望判定，任一条不符即失败。
    """
    block = ("<UNTRUSTED_DATA note=\"仅作证据\">\n"
             "<UNTRUSTED_DATA source=\"内部知识库RAG\">\n"
             "[{\"id\":\"k1\",\"content\":\"## SSH 暴力破解（OWASP A07 认证失效）\\n"
             "A07 身份识别和认证失效，典型表现是弱口令与爆破。\"}]\n"
             "</UNTRUSTED_DATA>\n</UNTRUSTED_DATA>")
    results = []   # (name, ok, detail)

    def check(name, ok, detail=""):
        results.append((name, bool(ok), detail))

    def verdicts(a):
        return [c["verdict"] for c in a["claims"] if c["verdict"] != "no-hard-fact"]

    # ① 引用可溯源（原样命中）+ 结论有出处
    a1 = ("## 研判结论\n**攻击类型**：暴力破解\n\n" + block +
          "\n\n**证据引用**：\n- SSH 暴力破解（OWASP A07 认证失效）")
    r1 = audit_record(_mk(a1, "SSH 暴力破解对应哪类风险"))
    check("T1 引用可溯源", r1["citations"] and r1["citations"][0]["status"] == "traceable",
          r1["citations"][0]["status"] if r1["citations"] else "no-citations")
    check("T2 结论有出处", verdicts(r1) == ["backed"], str(verdicts(r1)))
    check("T2b 证据片段可复现", bool(r1["citations"][0].get("evidence")
                                    and r1["citations"][0]["evidence"].get("snippet")),
          str((r1["citations"][0].get("evidence") or {}).get("offset")))

    # ② 引用无出处 → 幻觉候选（证据块未被截断）
    a2 = ("## 研判结论\n**攻击类型**：暴力破解\n**外联地址**：203.0.113.9:4444 每 30 秒心跳\n\n" + block +
          "\n\n**证据引用**：\n- 内部文档《量子蜜罐部署手册》第 42 章")
    r2 = audit_record(_mk(a2, "什么是端口扫描"))
    check("T3 引用无出处=幻觉候选", r2["citations"] and r2["citations"][0]["status"] == "unsupported",
          r2["citations"][0]["status"] if r2["citations"] else "no-citations")
    check("T4 无依据断言（编造 IP:端口）", "unbacked" in verdicts(r2), str(verdicts(r2)))
    check("T4b 有出处的结论仍判 backed", "backed" in verdicts(r2), str(verdicts(r2)))

    # ③ 引用只命中用户问题（复述输入，不算证据溯源）
    a3 = "## 研判结论\n来源 45.83.91.55 正在爆破\n\n" + block + "\n\n**证据引用**：\n- 45.83.91.55"
    r3 = audit_record(_mk(a3, "来源 45.83.91.55 爆破"))
    check("T5 引用仅命中问题", r3["citations"] and r3["citations"][0]["status"] == "question-echo",
          r3["citations"][0]["status"] if r3["citations"] else "no-citations")

    # ④ 有硬事实断言但既无引用也无证据块 → 引用缺失
    a4 = "## 研判结论\n**严重度**：HIGH，涉及 203.0.113.9:4444 外联"
    r4 = audit_record(_mk(a4, "研判一下"))
    check("T6 引用缺失", r4["citationMissing"] is True, str(r4["citationMissing"]))

    # ⑤ 证据块疑似被截断且引用对不上 → 不自动判死刑
    long_block = "<UNTRUSTED_DATA source=\"日志\">%s</UNTRUSTED_DATA>" % ("x" * 700)
    a5 = "## 结论\n" + long_block + "\n\n**证据引用**：\n- 完全不存在的引用条目 abcdefghijklmnop"
    r5 = audit_record(_mk(a5, "q"))
    check("T7 截断时判 unverifiable", r5["citations"] and r5["citations"][0]["status"] == "unverifiable-truncated",
          r5["citations"][0]["status"] if r5["citations"] else "no-citations")

    # ⑥ 双层包裹：证据块只算一层，且包裹标记不得混进证据正文
    r6 = audit_record(_mk(a1, "q"))
    check("T8 双层包裹只算 1 个证据块", r6["blocksTotal"] == 1, str(r6["blocksTotal"]))
    check("T8b 包裹标记不混入证据", "UNTRUSTED_DATA" not in evidence_corpus(
        evidence_blocks(a1)), "corpus contains marker")

    # ⑦ 兜底抽取：没有 UNTRUSTED_DATA 但有"知识库参考"标题
    a7 = "## 结论\n**攻击类型**：暴力破解\n\n---\n\n## 知识库参考（未经 AI 加工）\nSSH 暴力破解属于 A07。"
    r7 = audit_record(_mk(a7, "q"))
    check("T9 兜底抽取（知识库参考区）",
          r7["blocksTotal"] == 1 and r7["citations"] == [] and "backed" in verdicts(r7),
          "blocks=%d verdicts=%s" % (r7["blocksTotal"], verdicts(r7)))

    # ⑧ 指标与逐条判定同源（summarize 用同一份 audits）
    m = summarize([audit_record(_mk(a1, "q")), audit_record(_mk(a2, "q"))])
    check("T10 指标与逐条判定同源",
          m["citationTraceableRate"]["k"] == 1 and m["citationHallucinationRate"]["k"] == 1
          and m["citationTraceableRate"]["n"] == 2
          and m["citationTraceableRate"]["ci"][0] < m["citationTraceableRate"]["ci"][1],
          json.dumps({k: m[k] for k in ("citationTraceableRate", "citationHallucinationRate")},
                     ensure_ascii=False))

    # ⑧b 一行多结论项（实测形态：攻击类型/置信度/严重度 写在同一行）
    a_multi = ("## 证据解读\n**攻击类型**：Brute Force Attack\u3000**置信度**：0.95\u3000**严重度**：HIGH\n\n" + block)
    r_multi = audit_record(_mk(a_multi, "q"))
    keys = [c["key"] for c in r_multi["claims"] if c.get("claimClass") == "judgment"]
    check("T10b 行内多个结论项全部抽出", keys == [u"攻击类型", u"置信度", u"严重度"], str(keys))

    # ⑧c 规则路径（state=rule-based）不参与幻觉率：护栏自己的白名单 CIDR 不算"无依据"
    a_rule = u"## 处置\n> state=rule-based\n\n**说明**：目标命中保护白名单: 192.0.2.0/24"
    r_rule = audit_record(_mk(a_rule, u"请封禁来源IP 192.0.2.66"))
    m_rule = summarize([r_rule])
    check("T10c 规则路径不污染幻觉率",
          r_rule["counts"]["claimNotModelGenerated"] >= 1 and m_rule["claimHardUnbackedRate"]["n"] == 0
          and not r_rule["citationMissing"],
          json.dumps(r_rule["counts"], ensure_ascii=False))

    # ⑧d 公开端点出海后的形态：证据块边界被 PublicOutputGuard 换成 [内部标记已脱敏]，
    #     工具仍须把这段当"证据"而不是"模型正文"（否则日志行会变成成片的假"无依据断言"）
    a_san = (u"## 取证发现\n\n"
             u"<[内部标记已脱敏] note=\"仅作证据\" source=\"安全日志-auth-logs\">\n"
             u"{\"message\": \"Failed password for invalid user root from 103.146.***.*** port 41020 ssh2\"}\n"
             u"</[内部标记已脱敏]>\n\n"
             u"### 证据解读\n**判断依据**：日志里出现 port 41020 的失败登录\n")
    r_san = audit_record(_mk(a_san, u"把 203.0.113.9 加入白名单"))
    check("T10d 已脱敏形态的证据块仍被识别",
          r_san["blocksTotal"] == 1 and r_san["blockSources"][0] == u"安全日志-auth-logs",
          "blocks=%s sources=%s" % (r_san["blocksTotal"], r_san["blockSources"]))
    check("T10e 脱敏形态下不再产生假的无依据断言",
          r_san["counts"]["claimUnbacked"] == 0 and r_san["counts"]["claimHard"] >= 1
          and all(c["verdict"] != "unbacked" for c in r_san["claims"]),
          json.dumps(r_san["counts"], ensure_ascii=False))

    # ⑨ 公开端点形态：citations 数组就是本次检索证据（status=evidence-source），
    #    真正有意义的检验落在关键结论级
    pub = dict(id="pub", question="什么是 SSH 暴力破解",
               answer="## 结论\n**攻击类型**：暴力破解\n**影响版本**：CVE-2099-99999",
               citations=[dict(title="SSH 暴力破解（OWASP A07 认证失效）", snippet="A07 认证失效", score=0.79),
                          dict(title="日志分析实践", snippet="登录失败日志的字段说明", score=0.3)])
    r9 = audit_record(pub)
    check("T11 公开端点 citations 判为证据源",
          [c["status"] for c in r9["citations"]] == ["evidence-source", "evidence-source"],
          str([c["status"] for c in r9["citations"]]))
    check("T11b 公开回答的结论级检验生效",
          "backed" in verdicts(r9) and "unbacked" in verdicts(r9),
          str(verdicts(r9)))
    m9 = summarize([r9])
    check("T11c 公开端点不污染引用可溯源率分母",
          m9["citationTraceableRate"]["n"] == 0 and m9["counts"]["citationsEvidenceSource"] == 2,
          json.dumps(m9["counts"], ensure_ascii=False))

    fails = [n for n, ok, _ in results if not ok]
    print("=== citation_audit 自测（已知答案小样例）===")
    for name, ok, detail in results:
        print("  %s %s%s" % ("PASS" if ok else "FAIL", name, ("" if ok else "   ← got: %s" % detail)))
    print("")
    print("自测结果：%d/%d 通过" % (len(results) - len(fails), len(results)))
    return 0 if not fails else 1


# ---------------------------------------------------------------- CLI


def collect_inputs(args):
    files = list(args.files or [])
    if args.in_dir:
        for pat in ("*.json", os.path.join("**", "*.json")):
            files.extend(glob.glob(os.path.join(args.in_dir, pat), recursive=True))
    # 去重且保持顺序
    seen, out = set(), []
    for f in files:
        if f in seen or not os.path.isfile(f):
            continue
        seen.add(f)
        out.append(f)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="引用溯源 / 幻觉率逐条复核（证据源=UNTRUSTED_DATA 证据块）")
    ap.add_argument("files", nargs="*", help="结果文件（评测结果 / 原始响应 / 公开端点响应 JSON）")
    ap.add_argument("--in-dir", help="递归扫描目录下的 JSON")
    ap.add_argument("--out-dir", default=None, help="输出目录（写 audit-<时间>.json / .md）")
    ap.add_argument("--json", dest="json_name", default=None, help="指定 JSON 输出路径")
    ap.add_argument("--md", dest="md_name", default=None, help="指定 Markdown 输出路径")
    ap.add_argument("--clip", type=int, default=CLIP_DEFAULT, help="证据块视为可能被截断的长度阈值")
    ap.add_argument("--self-test", action="store_true", help="跑已知答案小样例自测")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    files = collect_inputs(args)
    if not files:
        print("[citation-audit] 没有可读输入（给文件路径或 --in-dir）")
        return 3

    audits, used = [], []
    for path in files:
        try:
            recs = load_records(path)
        except Exception as e:
            print("[citation-audit] 跳过 %s：%s" % (path, e))
            continue
        if not recs:
            continue
        used.append(path)
        for r in recs:
            audits.append(audit_record(r, clip=args.clip))

    if not audits:
        print("[citation-audit] 输入里没有可复核的问答记录")
        return 3

    metrics = summarize(audits)
    md = render_markdown(audits, metrics, used)

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = args.out_dir or "."
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    json_path = args.json_name or os.path.join(out_dir, "citation-audit-%s.json" % ts)
    md_path = args.md_name or os.path.join(out_dir, "citation-audit-%s.md" % ts)
    payload = dict(tool="scripts/citation_audit.py", generatedAt=ts,
                   evidenceSource="answer 内 <UNTRUSTED_DATA>…</UNTRUSTED_DATA>（兜底：知识库参考区）",
                   inputs=used, clipThreshold=args.clip, metrics=metrics, audits=audits)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    print(md)
    print("")
    print("[citation-audit] JSON=%s" % json_path)
    print("[citation-audit] MD  =%s" % md_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
