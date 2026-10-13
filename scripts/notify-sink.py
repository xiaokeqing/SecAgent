#!/usr/bin/env python3
"""
通知中枢的本地 sink：把收到的每一个 POST 原样打印出来。

用途（RUNBOOK §19「如何本地验证」）：
    终端 1：  python3 scripts/notify-sink.py 18099
    终端 2：  跑 NotificationDemo（见 src/test/resources/demo/...）指向同一端口

为什么不用 `python3 -m http.server`：那是**静态文件**服务器，只处理 GET，
收到 POST 会回 501 —— 于是应用侧会（正确地）判定"发送失败"并重试，
看起来像"通知没通"，实际是 sink 选错了。这里用标准库的 http.server 显式实现 do_POST。

为什么不用 `nc -l`：nc 收到一个请求就退出，第二个请求（重试/聚合）就没人接了；
而且它不回响应，客户端会等到超时。这里显式回 200，把"对端正常接收"这一步也验证掉。

退出：Ctrl-C。
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COUNT = 0


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802  （标准库约定的命名）
        global COUNT
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        COUNT += 1
        print("=" * 72, flush=True)
        print(f"# {COUNT}  {self.command} {self.path}", flush=True)
        print(f"Content-Type: {self.headers.get('Content-Type')}", flush=True)
        # 尽量格式化一下，便于人眼核对模板渲染结果；不是合法 JSON 就原样打印
        try:
            print(json.dumps(json.loads(raw), ensure_ascii=False, indent=2), flush=True)
        except Exception:
            print(raw, flush=True)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        # 方便用浏览器/curl 确认 sink 活着
        body = f"notify-sink alive; received {COUNT} POST(s)\n".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # 关掉标准库自带的访问日志，避免刷屏
        pass


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18099
    server = ThreadingHTTPServer(("127.0.0.1", port), Sink)
    print(f"notify-sink 正在监听 http://127.0.0.1:{port}/（收到的 POST 会打印在这里）", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n收到 {COUNT} 个 POST，退出。", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
