#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecAgent 通知中继（应用/脚本 → 本机 → 飞书 + QQ 邮件）

为什么需要它（2026-10-13 事故教训）：
  应用的通知中枢只认一个"通用 webhook URL"。若把飞书的 JSON 报文模板直接写进 /opt/secagent/.env，
  docker compose 读 env_file 时会因为值里有 `{` 而报
  `unexpected character "{" in variable name` → 整个部署失败。
  所以：.env 只放一个简单 URL（本中继），JSON 形状、双通道、分级路由、冷却都放到这里。

接口：
  POST /notify   body: {"text": "..."}（也兼容飞书形状 {"msg_type":..,"content":{"text":..}}）
  返回：200 + {"feishu":"sent|skipped|failed","mail":"sent|skipped|failed","reason":"..."}
        两个通道都失败时返回 502（让应用侧的重试逻辑生效，不会被误判成成功）

路由与降噪：
  · 正文含 [严重]/[CRITICAL]/[紧急]/[高危]/[HIGH] → 飞书 + 邮件双发；其余 → 只飞书
  · 邮件单独冷却（默认 600s，按正文前 80 字做 key），防止刷爆邮箱
  · 飞书消息统一加 "SecAgent · " 前缀：适配自定义机器人"自定义关键词"安全设置

配置（全部从 /opt/secagent/.env 读；缺失即如实降级并在日志写明）：
  NOTIFY_WEBHOOK_URL    本中继自己的地址（应用指向它）
  FEISHU_WEBHOOK_URL    飞书群自定义机器人 Webhook
  NOTIFY_EMAIL_USER     QQ 邮箱地址（发件人，必须是授权码所属账号）
  NOTIFY_EMAIL_AUTHCODE QQ 邮箱 SMTP 授权码（不是登录密码）
  NOTIFY_EMAIL_TO       收件人（默认=发件人）
"""
import json
import os
import smtplib
import ssl
import sys
import time
import urllib.request
from email.header import Header
from email.mime.text import MIMEText
import socketserver
from http.server import BaseHTTPRequestHandler, HTTPServer

ENV_PATH = "/opt/secagent/.env"
LISTEN_HOST = os.environ.get("NOTIFY_RELAY_HOST", "127.0.0.1")  # 容器内访问需绑网桥网关
LISTEN_PORT = int(os.environ.get("NOTIFY_RELAY_PORT", "8899"))
MAIL_COOLDOWN = int(os.environ.get("NOTIFY_MAIL_COOLDOWN", "600"))
STATE = {"mail_last": {}, "count": 0}
HIGH_MARKERS = ("[严重]", "[CRITICAL]", "[紧急]", "[高危]", "[HIGH]")
# 邮件通道开关：站主 2026-10-13 明确「只要飞书，邮件一会有一下太麻烦」→ 默认关闭。
# 想重新启用：.env 写 NOTIFY_EMAIL_ENABLED=1，并补 NOTIFY_EMAIL_USER / NOTIFY_EMAIL_AUTHCODE / NOTIFY_EMAIL_TO。
EMAIL_ENABLED = (os.environ.get("NOTIFY_EMAIL_ENABLED", "0") == "1")


def log(msg):
    line = time.strftime("%Y-%m-%d %H:%M:%S") + " " + msg
    print(line, flush=True)
    try:
        with open("/var/log/secagent-notify.log", "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


def load_env():
    cfg = {}
    try:
        with open(ENV_PATH, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip('"').strip("'")
    except Exception as e:
        log("读取 %s 失败：%s" % (ENV_PATH, e))
    return cfg


def extract_text(payload):
    if isinstance(payload, dict):
        if "text" in payload and isinstance(payload["text"], str):
            return payload["text"]
        content = payload.get("content")
        if isinstance(content, dict) and isinstance(content.get("text"), str):
            return content["text"]
        if isinstance(content, str):
            return content
    if isinstance(payload, str):
        return payload
    return json.dumps(payload, ensure_ascii=False)[:2000]


def send_feishu(cfg, text):
    url = cfg.get("FEISHU_WEBHOOK_URL") or ""
    if not url:
        return "skipped", "未配置 FEISHU_WEBHOOK_URL"
    body = json.dumps({"msg_type": "text",
                       "content": {"text": "SecAgent · " + text}}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = resp.read().decode("utf-8", "replace")
        try:
            j = json.loads(raw)
        except Exception:
            j = {}
        if j.get("code") in (0, None) and j.get("StatusCode", 0) == 0:
            return "sent", ""
        return "failed", raw[:160]
    except Exception as e:
        return "failed", str(e)[:160]


def send_mail(cfg, text):
    if not EMAIL_ENABLED:
        return "skipped", "邮件通道已关闭（NOTIFY_EMAIL_ENABLED != 1）"
    user = cfg.get("NOTIFY_EMAIL_USER") or ""
    code = cfg.get("NOTIFY_EMAIL_AUTHCODE") or ""
    to = cfg.get("NOTIFY_EMAIL_TO") or user
    if not (user and code and to):
        return "skipped", "未配置邮件（NOTIFY_EMAIL_USER/AUTHCODE/TO）"
    key = text[:80]
    now = time.time()
    last = STATE["mail_last"].get(key, 0)
    if now - last < MAIL_COOLDOWN:
        return "skipped", "邮件冷却中（%ds 内已发过同类）" % MAIL_COOLDOWN
    msg = MIMEText(text, "plain", "utf-8")
    msg["Subject"] = Header("SecAgent 告警", "utf-8")
    msg["From"] = user
    msg["To"] = to
    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.qq.com", 465, context=ctx, timeout=15) as s:
            s.login(user, code)
            s.sendmail(user, [to], msg.as_string())
        STATE["mail_last"][key] = now
        return "sent", ""
    except Exception as e:
        return "failed", str(e)[:160]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        if self.path not in ("/notify", "/"):
            self.send_error(404)
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace")
            try:
                payload = json.loads(body)
            except Exception:
                payload = body
            text = extract_text(payload)
        except Exception as e:
            self._reply(400, {"error": "bad request: %s" % e})
            return

        cfg = load_env()
        STATE["count"] += 1
        is_high = any(m in text for m in HIGH_MARKERS)
        f_stat, f_reason = send_feishu(cfg, text)
        m_stat, m_reason = ("skipped", "非高危：只发飞书") if not is_high else send_mail(cfg, text)
        ok = (f_stat == "sent") or (m_stat == "sent")
        out = {"feishu": f_stat, "mail": m_stat, "high": is_high,
               "reason": "; ".join(x for x in (f_reason, m_reason) if x)[:200],
               "seq": STATE["count"]}
        log("notify seq=%d high=%s feishu=%s mail=%s %s" % (STATE["count"], is_high, f_stat, m_stat, out["reason"]))
        self._reply(200 if ok else 502, out)

    def do_GET(self):
        self._reply(200, {"service": "secagent-notify-relay", "seq": STATE["count"]})

    def _reply(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    log("中继启动：%s:%d（邮件冷却 %ds）" % (LISTEN_HOST, LISTEN_PORT, MAIL_COOLDOWN))
    # 【兼容性】srv1 是 Python 3.6，没有 ThreadingHTTPServer（3.7 才有），用 ThreadingMixIn 手搭
    class _ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True
        allow_reuse_address = True
    _ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler).serve_forever()
