#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把「离线检索回归评测集」的查询向量固化下来（只跑一次，之后 CI 完全离线）。

为什么要把查询向量写进仓库：
  评测集要进 CI 当门禁，而 CI 里没有 DASHSCOPE_API_KEY、也不该为一次单测花钱。
  但查询向量又必须是**真实模型**产出的，否则"改完检索有没有变好"就无从谈起。
  所以：查询向量在**本地一次性生成**（用与线上同一模型 text-embedding-v4，1024 维），
  随仓库提交；CI 与本地单测只做"加载 + 余弦"，零网络、零费用、结果完全确定。

生成物：
  src/test/resources/rag-eval/retrieval-queries.json
    { model, dimension, corpus, note, queries: [ {id, bucket, query, vector, fileAny, evidenceAny} ] }

用法（在仓库根目录，需要 .env 里有真实 DASHSCOPE_API_KEY）：
  python3 scripts/rag-eval/build-query-fixture.py
  python3 scripts/rag-eval/build-query-fixture.py --dry-run   # 只校验查询集，不调接口

⚠️ 改查询集（增删 query / 改期望）后必须重跑本脚本，否则向量与查询对不上。
⚠️ 换 embedding 模型（dashscope.embedding.model）后也必须重跑。
"""

import argparse
import datetime
import json
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "src", "test", "resources", "rag-eval", "retrieval-queries.json")
CORPUS = os.path.join(ROOT, "data", "vector-store.json")
ENDPOINT = "https://dashscope.aliyuncs.com/api/v1/services/embeddings/text-embedding/text-embedding"
MODEL = "text-embedding-v4"
DIM = 1024

# =====================================================================
# 查询集（28 条）与期望
#
# 两个口径，分别回答两个不同的问题：
#   fileAny     —— 期望命中的**文档**（关键词取自 ground truth 文档的文件名/小节名）。
#                  量的是"找对没找对那一篇"。
#   evidenceAny —— 期望命中的**片段正文**必须包含的确切证据（罕见标识 / 术语）。
#                  量的是"给模型的这段引用到底能不能支撑回答"——这正是"引用更可信"的
#                  可核对形式：一条不含问题所问标识的片段，哪怕来自对的文档，也无法溯源。
#
# 期望是**先写死、再跑分**的，不回头按结果调整（口径写在库里，谁都能核对）。
# 分三桶，避免拿"对稀疏有利的题"当成整体提升：
#   A 概念/改述（稠密强项，10 条）
#   B 精确标识/罕见词（稀疏强项，12 条）：CWE 编号、函数名、配置项、命令行特征
#   C 运维配置类（混合，6 条）
# 每条 evidence 关键词都能在 data/vector-store.json 里定位到唯一/少数分片（脚本会校验）。
# =====================================================================
QUERIES = [
    # ---- A：概念 / 改述（稠密强项）----
    ("q01", "A", u"路径穿越漏洞怎么防御？", [[u"路径穿越"]], [[u"路径穿越"]]),
    ("q02", "A", u"SQL 注入如何检测与修复？", [[u"SQL注入"]], [[u"sql 注入"], [u"sql注入"], [u"sqli"]]),
    ("q03", "A", u"文件上传 GetShell 要怎么拦截？", [[u"文件上传"]], [[u"文件上传"]]),
    ("q04", "A", u"XSS 跨站脚本的攻击原理与防御措施", [[u"XSS"]], [[u"xss"]]),
    ("q05", "A", u"命令注入漏洞是怎么产生的", [[u"命令注入"]], [[u"命令注入"]]),
    ("q06", "A", u"越权访问与权限绕过怎么排查", [[u"越权"]], [[u"越权"]]),
    ("q07", "A", u"SSRF 服务端请求伪造的利用与防护", [[u"SSRF"]], [[u"ssrf"]]),
    ("q08", "A", u"XXE 与反序列化漏洞的利用方式", [[u"XXE"], [u"反序列化"]], [[u"xxe"], [u"反序列化"]]),
    ("q09", "A", u"CSRF 跨站请求伪造如何防护", [[u"CSRF"]], [[u"csrf"]]),
    ("q10", "A", u"弱口令与暴力破解的认证加固", [[u"弱口令"]], [[u"弱口令"]]),

    # ---- B：精确标识 / 罕见词（稀疏强项）----
    ("q11", "B", u"CWE-918 对应哪一类漏洞？", [[u"SSRF"]], [[u"cwe-918"]]),
    ("q12", "B", u"CWE-611 是什么漏洞？", [[u"XXE"]], [[u"cwe-611"]]),
    ("q13", "B", u"CWE-502 不安全反序列化怎么防？", [[u"XXE"], [u"反序列化"]], [[u"cwe-502"]]),
    ("q14", "B", u"disallow-doctype-decl 怎么配才能防 XXE？", [[u"XXE"]], [[u"disallow-doctype-decl"]]),
    ("q15", "B", u"DocumentBuilder 解析 XML 要注意什么？", [[u"XXE"]], [[u"documentbuilder"]]),
    ("q16", "B", u"DOMPurify 在 XSS 防御里怎么用？", [[u"XSS"]], [[u"dompurify"]]),
    ("q17", "B", u"dev/tcp/ip/4444 这种反弹 Shell 特征怎么识别？",
     [[u"SSH"], [u"暴力破解"]], [[u"dev/tcp/ip/4444"], [u"dev/tcp"]]),
    ("q18", "B", u"binwalk 解包 cramfs 固件怎么做？", [[u"固件"]], [[u"binwalk", u"cramfs"]]),
    ("q19", "B", u"auditd 怎么做日志与完整性审计？", [[u"加固基线"]], [[u"auditd"]]),
    ("q20", "B", u"bash_history 与 antp、auxf 是什么可疑痕迹？",
     [[u"SSH暴力破解"], [u"应急响应"]], [[u"antp"]]),
    ("q21", "B", u"buuctf 有哪些推荐的靶场？", [[u"靶场"]], [[u"buuctf"]]),
    ("q22", "B", u"用 abuseipdb 与 AlienVault 查 IOC 威胁情报", [[u"KillChain"]],
     [[u"abuseipdb", u"alienvault"]]),

    # ---- C：运维配置类（混合）----
    ("q23", "C", u"PHP 里用 bindParam 能不能防 SQL 注入？", [[u"PHP代码审计"]], [[u"bindparam"]]),
    ("q24", "C", u"display_errors 为什么要关掉？", [[u"PHP代码审计"]], [[u"display_errors"]]),
    ("q25", "C", u"Java defaultTyping 反序列化的风险怎么规避？",
     [[u"反序列化"]], [[u"defaulttyping"]]),
    ("q26", "C", u"Nginx autoindex 打开有什么风险？", [[u"数据库与中间件"]], [[u"autoindex"]]),
    ("q27", "C", u"content-disposition 响应头怎么防文件下载漏洞？",
     [[u"文件上传"], [u"文件包含"]], [[u"content-disposition"]]),
    ("q28", "C", u"docker cap-drop 怎么减少容器权限？", [[u"加固基线"]], [[u"cap-drop"]]),
]


def read_env(path):
    env = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except Exception as e:
        print("[fixture] 读取 %s 失败: %s" % (path, e))
    return env


def embed(texts, api_key):
    body = json.dumps({"model": MODEL,
                       "input": {"texts": texts},
                       "parameters": {"dimension": DIM}}).encode("utf-8")
    req = urllib.request.Request(ENDPOINT, data=body, method="POST",
                                 headers={"Authorization": "Bearer " + api_key,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        payload = json.loads(r.read().decode("utf-8"))
    return [it["embedding"] for it in payload["output"]["embeddings"]]


def group_in(groups, text):
    """groups 是「或」的组，组内是「与」的关键词；返回是否命中"""
    for g in groups:
        if all(k.lower() in text for k in g):
            return True
    return False


def selfcheck():
    """
    跑分前先自检两件事，避免"期望根本不可能被满足"这种假失败：
      fileAny 的每组关键词在语料里至少有一条分片（标题/文件名/来源路径）能命中；
      evidenceAny 的每组关键词在语料里至少有一条分片正文能命中。
    自检不过 = 评测集写错了（不是检索错了），直接退出。
    """
    with open(CORPUS, "r", encoding="utf-8") as f:
        records = json.load(f)["records"]
    bad = []
    for qid, bucket, q, file_any, ev_any in QUERIES:
        # 组之间是「或」：只要有一组能被满足，期望就是可达的（不可达 = 评测集写错了）
        ok_file = False
        for group in file_any:
            for r in records:
                m = r.get("metadata") or {}
                where = ("%s | %s | %s" % (m.get("title"), m.get("_file_name"), m.get("_source"))).lower()
                if all(k.lower() in where for k in group):
                    ok_file = True
                    break
            if ok_file:
                break
        if not ok_file:
            bad.append("%s fileAny 期望在语料里不存在: %s" % (qid, file_any))
        ok_ev = any(all(k.lower() in r["content"].lower() for k in group)
                    for group in ev_any for r in records)
        if not ok_ev:
            bad.append("%s evidenceAny 期望在语料里不存在: %s" % (qid, ev_any))
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="只自检查询集，不调用 embedding 接口")
    ap.add_argument("--batch", type=int, default=10, help="单次 embedding 请求的文本条数")
    ap.add_argument("--skip-selfcheck", action="store_true")
    args = ap.parse_args()

    ids = [q[0] for q in QUERIES]
    assert len(ids) == len(set(ids)), "查询 id 重复"
    print("[fixture] 查询 %d 条（A=%d / B=%d / C=%d）" % (
        len(QUERIES),
        len([q for q in QUERIES if q[1] == "A"]),
        len([q for q in QUERIES if q[1] == "B"]),
        len([q for q in QUERIES if q[1] == "C"])))

    if not args.skip_selfcheck:
        bad = selfcheck()
        if bad:
            print("[fixture] 评测集自检失败（期望无法被满足）：")
            for b in bad:
                print("   " + b)
            return 2
        print("[fixture] 自检通过：每条期望在 data/vector-store.json 里都有对应分片")

    if args.dry_run:
        for qid, bucket, q, file_any, ev_any in QUERIES:
            print("%s\t%s\t%s\tfile=%s\tevidence=%s" % (qid, bucket, q, file_any, ev_any))
        return 0

    env = read_env(os.path.join(ROOT, ".env"))
    key = env.get("DASHSCOPE_API_KEY", "")
    if not key:
        print("[fixture] .env 里没有 DASHSCOPE_API_KEY，无法生成查询向量")
        return 1

    out = []
    for i in range(0, len(QUERIES), args.batch):
        chunk = QUERIES[i:i + args.batch]
        vecs = embed([q for _, _, q, _, _ in chunk], key)
        if len(vecs) != len(chunk):
            print("[fixture] 返回条数不匹配：%d != %d" % (len(vecs), len(chunk)))
            return 1
        for (qid, bucket, q, file_any, ev_any), v in zip(chunk, vecs):
            out.append({"id": qid, "bucket": bucket, "query": q,
                        "vector": [round(float(x), 6) for x in v],
                        "fileAny": file_any, "evidenceAny": ev_any})
        print("[fixture] 已向量化 %d/%d" % (len(out), len(QUERIES)))

    doc = {"model": MODEL,
           "dimension": DIM,
           "corpus": "data/vector-store.json",
           "note": "查询向量由 scripts/rag-eval/build-query-fixture.py 用线上同一 embedding 模型一次性生成并入库，"
                   "目的是让 CI 里的检索回归门禁离线、确定、零费用。改查询集或换模型后必须重跑该脚本。",
           "generatedAt": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
           "queries": out}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    print("[fixture] 已写入 %s（%d 条）" % (OUT, len(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
