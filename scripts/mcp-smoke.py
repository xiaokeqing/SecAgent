#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mcp-smoke.py —— 对 xk-lab MCP server 做一次真实的 stdio 冒烟。

做的事（全部只用 Python 标准库，不装任何包）：
  1. 起 server 子进程：``java -jar target/sec-agent-1.0-SNAPSHOT-mcp.jar``；
  2. 走 JSON-RPC：``initialize`` → ``notifications/initialized`` → ``tools/list`` → 6 个工具各调一次；
  3. 打印每个工具返回的 ``available`` 与键名，任何一步失败都明确报错并以非 0 退出。

两种数据源模式：
  * 默认：连**真的**平台 ``http://127.0.0.1:9900``（平台没起时工具会老实返回 ``available:false``，
    这正是要验证的"不编数"分支）；
  * ``--stub-upstream``：脚本自己在 127.0.0.1 的随机端口上起一个只读桩，返回形状正确的固定 payload，
    用来验证 ``available:true`` 那条分支（不碰真平台、不需要平台在跑）。

用法：
    python -X utf8 scripts/mcp-smoke.py                     # 连真平台
    python -X utf8 scripts/mcp-smoke.py --stub-upstream     # 用桩，验证 available:true
    python -X utf8 scripts/mcp-smoke.py --dry               # 只打印将发送的报文，不起进程
"""

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_JAR = os.path.join(REPO_ROOT, "target", "sec-agent-1.0-SNAPSHOT-mcp.jar")
DEFAULT_BASE_URL = "http://127.0.0.1:9900"
SITE_DIR = os.path.join("F:" + os.sep, "7AAA", "AI", "blog")

PROTOCOL_VERSION = "2025-06-18"

# (工具名, 参数) —— 六个工具各一次；参数取默认值的语义（limit 默认值也在这一步显式写出）
TOOLS = [
    ("xk_health", {}),
    ("xk_alerts_recent", {"minutes": 60, "limit": 20}),
    ("xk_ip_profile", {"ip": "45.205.1.230"}),
    ("xk_audit_blocks", {"limit": 5}),
    ("xk_honeypot_summary", {}),
    ("xk_detections", {}),
]


def protocol_messages():
    """按发送顺序产出全部 JSON-RPC 报文（--dry 与实际发送用的是同一份）。"""
    yield {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-smoke", "version": "1.0"},
        },
    }
    yield {"jsonrpc": "2.0", "method": "notifications/initialized"}
    yield {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    for index, (name, arguments) in enumerate(TOOLS, start=3):
        yield {
            "jsonrpc": "2.0",
            "id": index,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }


# ==================== 上游桩（--stub-upstream） ====================

def _now():
    return datetime.now()


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _stub_payloads():
    """桩返回的是**平台的外壳形状** {"code":200,"message":"success","data":{…}}。

    故意的：真平台就是这么包的，server 端要先拆壳。桩如果直接给裸 JSON，
    就测不到拆壳这条路径（曾经真的因此在真平台上拿到空壳当"没有告警"）。
    """
    fresh = _fmt(_now() - timedelta(minutes=3))
    return {
        "/api/health": {
            "status": "ok",
            "application": "SecAgent",
            "buildSha": "stub0000000000000000000000000000000000b",
            "artifactMd5": "00000000000000000000000000000000",
            "uptimeMs": 98765,
            "buildTime": _fmt(_now()),
            "fingerprintMismatch": False,
        },
        "/api/public/alerts": {
            "generatedAt": _fmt(_now()),
            "cacheSeconds": 30,
            "dataSource": {"wazuhMode": "stub", "degraded": False, "note": "stub 上游"},
            "windowMinutes": 60,
            "windowSize": 200,
            "total": 1,
            "rawTotal": 1,
            "aggregated": True,
            "list": [
                {
                    "aggId": "stub-agg-1",
                    "count": 3,
                    "title": "STUB：SSH 暴力破解",
                    "ruleName": "XK-LAB SSH brute force",
                    "attck": {"tactic": "TA0006", "technique": "T1110"},
                    "srcIp": "45.205.***.***",
                    "occurredAt": fresh,
                    "severity": "high",
                    "status": "open",
                }
            ],
        },
        "/api/public/ip": {
            "generatedAt": _fmt(_now()),
            "available": True,
            "reason": "OK",
            "query": "45.205.***.***",
            "ipVersion": "IPv4",
            "window": "168h",
            "windowHours": 168,
            "firstSeen": _fmt(_now() - timedelta(days=3)),
            "lastSeen": fresh,
            "events": 42,
            "byKind": {"ssh_login": 30, "honeypot": 12},
            "ports": [22, 2222],
            "credStructure": ["root / 6 位·纯数字·弱口令"],
            "geo": {"country": "stub"},
            "banned": {"count": 1, "active": True},
            "sources": {"indexer": {"status": "OK"}, "audit": {"status": "OK"}},
            "limits": {"windowHours": 168, "topKinds": 10, "ipv4Only": True},
            "notes": [],
            "note": "stub 上游",
        },
        "/api/public/audit": {
            "generatedAt": _fmt(_now()),
            "readOnly": True,
            "summary": {"blockTotal": 1, "blockActive": 1},
            "blocks": [
                {
                    "id": 1,
                    "ip": "45.205.1.230",
                    "durationMinutes": 60,
                    "source": "stub",
                    "actor": "smoke",
                    "auditId": "audit-stub-1",
                    "createdAt": fresh,
                    "expiresAt": _fmt(_now() + timedelta(hours=1)),
                    "unblocked": False,
                }
            ],
        },
        "/api/public/honeypot": {
            "generatedAt": _fmt(_now()),
            "available": True,
            "total": 40,
            "connections": 25,
            "logins": 15,
            "loginFails": 14,
            "sampled": 40,
            "topCredentials": ["root / 6 位·纯数字·弱口令"],
            "topSources": ["45.205.***.***"],
            "topClients": ["SSH-2.0-Go"],
            "timeline": [{"hour": "09:00", "count": 7}],
        },
    }


def _envelope(data):
    return {"code": 200, "message": "success", "data": data}


class _StubHandler(BaseHTTPRequestHandler):
    payloads = {}

    def do_GET(self):  # noqa: N802（BaseHTTPRequestHandler 的约定命名）
        path = self.path.split("?", 1)[0]
        body = self.payloads.get(path)
        if body is None:
            self.send_response(404)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"code": "STUB_NOT_FOUND", "path": path}, ensure_ascii=False).encode("utf-8"))
            return
        data = json.dumps(_envelope(body), ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):  # 静音，别把桩的请求日志混进冒烟输出
        return


def start_stub():
    _StubHandler.payloads = _stub_payloads()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


# ==================== stdio 客户端 ====================

class StdioClient:
    def __init__(self, command, env, timeout):
        self.timeout = timeout
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.queue = queue.Queue()
        self.stderr_lines = []
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()
        self._err_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._err_reader.start()

    def _read_stdout(self):
        for raw in self.proc.stdout:
            self.queue.put(raw)

    def _read_stderr(self):
        for raw in self.proc.stderr:
            self.stderr_lines.append(raw.decode("utf-8", "replace").rstrip())

    def send(self, message):
        data = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise RuntimeError("写 stdin 失败（server 是不是已经退出了？）：%s" % exc)

    def recv(self, expect_id):
        deadline = time.time() + self.timeout
        while True:
            remain = deadline - time.time()
            if remain <= 0:
                raise TimeoutError("等 id=%r 的回包超时（%.0fs）" % (expect_id, self.timeout))
            try:
                raw = self.queue.get(timeout=remain)
            except queue.Empty:
                raise TimeoutError("等 id=%r 的回包超时（%.0fs）" % (expect_id, self.timeout))
            text = raw.decode("utf-8", "replace").strip()
            if not text:
                continue
            try:
                message = json.loads(text)
            except json.JSONDecodeError:
                raise RuntimeError("server 输出了非 JSON 的一行（协议流被污染）：%r" % text[:300])
            if message.get("id") == expect_id:
                return message
            raise RuntimeError("收到了 id=%r 的不相关报文（期望 id=%r）：%r"
                               % (message.get("id"), expect_id, text[:300]))

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)


def die(message, client=None):
    print("\n[FAIL] " + message)
    if client is not None and client.stderr_lines:
        print("--- server stderr（最后 15 行）---")
        for line in client.stderr_lines[-15:]:
            print("  " + line)
    sys.exit(1)


def keys_of(payload, limit=40):
    keys = list(payload.keys())
    shown = keys[:limit]
    suffix = "" if len(keys) <= limit else " …(+%d)" % (len(keys) - limit)
    return ", ".join(shown) + suffix


def main(argv=None):
    parser = argparse.ArgumentParser(description="xk-lab MCP server 冒烟（stdio / JSON-RPC）")
    parser.add_argument("--jar", default=DEFAULT_JAR, help="MCP 可执行 jar 路径（默认 target/sec-agent-1.0-SNAPSHOT-mcp.jar）")
    parser.add_argument("--java", default="java", help="java 可执行文件（默认 java）")
    parser.add_argument("--base-url", default=os.environ.get("XK_MCP_BASE_URL", DEFAULT_BASE_URL),
                        help="平台只读端点（默认 http://127.0.0.1:9900）")
    parser.add_argument("--site-dir", default=os.environ.get("XK_MCP_SITE_DIR", SITE_DIR),
                        help="站点仓库根目录（xk_detections 用）")
    parser.add_argument("--timeout", type=float, default=25.0, help="单条报文超时秒数（默认 25）")
    parser.add_argument("--dry", action="store_true", help="只打印将发送的 JSON-RPC 报文，不起子进程")
    parser.add_argument("--stub-upstream", action="store_true",
                        help="在 127.0.0.1 随机端口起只读桩，用来验证 available:true 分支")
    ns = parser.parse_args(argv)

    if ns.dry:
        print("# 将要启动：%s -jar %s" % (ns.java, ns.jar))
        print("# XK_MCP_BASE_URL=%s" % ns.base_url)
        print("# XK_MCP_SITE_DIR=%s" % ns.site_dir)
        print("# 将发送 %d 条报文（stdin 一行一条，stdout 一行一条）：" % len(list(protocol_messages())))
        for message in protocol_messages():
            print(json.dumps(message, ensure_ascii=False))
        return 0

    if not os.path.isfile(ns.jar):
        die("找不到 jar：%s\n先构建：mvn -o -DskipTests package（产物 target/sec-agent-1.0-SNAPSHOT-mcp.jar）" % ns.jar)

    stub = None
    env = dict(os.environ)
    env["XK_MCP_BASE_URL"] = ns.base_url
    env["XK_MCP_SITE_DIR"] = ns.site_dir
    if ns.stub_upstream:
        stub, stub_url = start_stub()
        env["XK_MCP_BASE_URL"] = stub_url
        print("# 上游桩已启动：%s" % stub_url)

    client = StdioClient([ns.java, "-jar", ns.jar], env, ns.timeout)
    try:
        # 1) initialize
        init = None
        for message in protocol_messages():
            if message.get("method") == "initialize":
                client.send(message)
                init = client.recv(message["id"])
                break
        if init is None:
            die("没有发出 initialize（脚本自身 bug）", client)
        if "error" in init:
            die("initialize 失败：%s" % json.dumps(init["error"], ensure_ascii=False), client)
        result = init.get("result", {})
        server_info = result.get("serverInfo", {})
        print("initialize: ok  protocolVersion=%s  server=%s/%s"
              % (result.get("protocolVersion"), server_info.get("name"), server_info.get("version")))

        # 2) tools/list
        client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        listed = client.recv(2)
        if "error" in listed:
            die("tools/list 失败：%s" % json.dumps(listed["error"], ensure_ascii=False), client)
        tools = listed.get("result", {}).get("tools", [])
        print("tools/list: %d 个工具 → %s" % (len(tools), ", ".join(t.get("name", "?") for t in tools)))
        if len(tools) != len(TOOLS):
            die("工具数不对：期望 %d，实际 %d" % (len(TOOLS), len(tools)), client)

        # 3) 六个工具各一次
        print("")
        verdict = {}
        for index, (name, arguments) in enumerate(TOOLS, start=3):
            client.send({"jsonrpc": "2.0", "id": index, "method": "tools/call",
                         "params": {"name": name, "arguments": arguments}})
            reply = client.recv(index)
            if "error" in reply:
                die("%s 返回协议错误：%s" % (name, json.dumps(reply["error"], ensure_ascii=False)), client)
            call_result = reply.get("result", {})
            content = call_result.get("content") or []
            if not content or content[0].get("type") != "text":
                die("%s 没有 text content：%r" % (name, str(call_result)[:300]), client)
            text = content[0].get("text", "")
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                die("%s 的 content.text 不是 JSON：%r" % (name, text[:300]), client)
            if not isinstance(payload, dict):
                die("%s 的输出不是 JSON 对象：%r" % (name, str(payload)[:300]), client)
            if "available" not in payload:
                die("%s 的输出缺 available（红线：每个工具都必须带）" % name, client)

            available = payload.get("available") is True
            verdict[name] = available
            line = "%-20s available=%-5s  keys: %s" % (name, str(available), keys_of(payload))
            print(line)
            if not available:
                print("%-20s reason: %s" % ("", payload.get("reason")))
            if call_result.get("isError"):
                die("%s 被测出 isError=true" % name, client)

        print("")
        ok = sum(1 for v in verdict.values() if v)
        print("=== 汇总：%d/%d 个工具返回了合法 JSON；available=true %d 个，false %d 个 ==="
              % (len(verdict), len(TOOLS), ok, len(verdict) - ok))
        unavailable = [n for n, v in verdict.items() if not v]
        if unavailable:
            print("不可用（如实报告，不是失败）：%s" % ", ".join(unavailable))
            if not ns.stub_upstream:
                print("提示：平台 http://127.0.0.1:9900 没起时就是这样。要验证 available:true 分支请加 --stub-upstream。")
        print("冒烟通过：协议握手、工具清单、六个工具调用全部完成。")
        return 0
    except (RuntimeError, TimeoutError) as exc:
        die(str(exc), client)
        return 1
    finally:
        try:
            client.close()
        finally:
            if stub is not None:
                stub.shutdown()
                stub.server_close()


if __name__ == "__main__":
    sys.exit(main())
