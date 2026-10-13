#!/usr/bin/env bash
# ============================================================
# srv2：Dionaea 的**协议级**健康检查 + 自愈
# ------------------------------------------------------------
# 为什么不能只用"能连上 TCP"来判断：
#   2026-10-14 实测过它真的会卡死 —— 18:38:47 之后 MySQL 服务不再处理新连接，
#   但 **TCP 握手仍然成功**（内核 accept 队列照常回 SYN-ACK），
#   表现是：`exec 3<>/dev/tcp/127.0.0.1/3306` 成功、`docker ps` 看着 Up，
#   而它已经不再记任何 MySQL 事件了（等队列满之后才变成连接超时）。
#   也就是说"端口连得上"完全掩盖了"服务已经死了"。
#   所以这里必须**按协议要一个应答**：
#     3306 服务端先说话 -> 必须收到 MySQL 握手包（首 4 字节 len + 第 5 字节 0x0a）
#     1433 客户端先说话 -> 发 TDS prelogin，必须收到 0x04 响应
#     445  客户端先说话 -> 发 SMB2 NEGOTIATE，必须收到 \xfeSMB 响应
#   （SMB2 的 NetBIOS 头长度必须等于实际报文长度，且 NEGOTIATE 的固定部分要 36 字节 +
#     8 字节保留 + 2 字节 dialect —— 长度写错服务端会一直等剩下的字节，探针就会假失败。）
#
# 用法（srv2）：
#   bash srv2-dionaea-healthcheck.sh            # 只检查（0=健康，1=不健康）
#   sudo bash srv2-dionaea-healthcheck.sh --heal  # 不健康就重启容器（带冷却与日志）
# ============================================================
set -uo pipefail
HEAL=0
[ "${1:-}" = "--heal" ] && HEAL=1
APP=/opt/dionaea
STATE=/opt/secagent/state
LOG=/opt/secagent/logs/dionaea-health.log
mkdir -p "$STATE" "$(dirname "$LOG")"

python3 - <<'PYEOF'
import socket, struct, sys

def p3306():
    s = socket.create_connection(('127.0.0.1', 3306), 4); s.settimeout(4)
    d = s.recv(64); s.close()
    # MySQL 握手：3 字节长度 + 1 字节序号 + 1 字节协议版本 0x0a
    return (len(d) > 5 and d[4] == 0x0a), d[:16].hex(' ')

def p1433():
    s = socket.create_connection(('127.0.0.1', 1433), 4); s.settimeout(4)
    s.sendall(struct.pack('>BBHHBB', 0x12, 0x01, 0x0008, 0x0000, 0x01, 0x00) + bytes(8))
    try: d = s.recv(64)
    except Exception: d = b''
    s.close()
    return (len(d) > 0 and d[0] == 0x04), d[:16].hex(' ')

def p445():
    # 【实测】dionaea 0.11 的 SMB 只讲 **SMB1**：发 SMB2 NEGOTIATE 没有任何回应，
    #   发 SMB1 NEGOTIATE 才会回 89 字节（NetBIOS 头 + \xffSMB + 0x72）。
    #   所以健康探针必须用 SMB1，否则会把"活着"判成"死了"。
    #   （无论哪种，dionaea 都会把这次连接记成 smbd accept —— 所以攻击尝试仍然可告警。）
    smb1 = b'\xffSMB' + bytes([0x72]) + b'\x00\x00\x00\x00' + b'\x18\x53\xc8' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00'
    smb1 += b'\x00\x00' + b'\x00\x00\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00\x00\x00'
    smb1 += b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00' + b'\x00\x00' + b'\x00\x00'
    smb1 += b'\x00\x00\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00\x00\x00' + b'\x31\x00'
    pkt = b'\x00' + len(smb1).to_bytes(3, 'big') + smb1
    s = socket.create_connection(('127.0.0.1', 445), 4); s.settimeout(4)
    s.sendall(pkt)
    try: d = s.recv(128)
    except Exception: d = b''
    s.close()
    # 合法回应：NetBIOS 头(4) + \xffSMB + 命令 0x72(NEGOTIATE)
    return (len(d) > 8 and d[4:8] == b'\xffSMB' and d[8] == 0x72), d[:16].hex(' ')

bad = []
for name, fn in (('3306/MySQL', p3306), ('1433/MSSQL', p1433), ('445/SMB', p445)):
    try:
        ok, hx = fn()
    except Exception as e:
        ok, hx = False, '%s %s' % (type(e).__name__, e)
    print("  %-12s %s   %s" % (name, "OK" if ok else "FAIL", hx))
    if not ok:
        bad.append(name)
if bad:
    print("UNHEALTHY: %s" % ",".join(bad))
    sys.exit(1)
print("HEALTHY")
sys.exit(0)
PYEOF
rc=$?
echo "  健康检查退出码=$rc"

if [ "$rc" -ne 0 ] && [ "$HEAL" = "1" ]; then
  # 冷却：10 分钟内最多自愈一次，避免"重启风暴"
  stamp="$STATE/dionaea-heal.last"
  now=$(date +%s)
  last=0
  [ -f "$stamp" ] && last=$(cat "$stamp" 2>/dev/null || echo 0)
  if [ $((now - last)) -lt 600 ]; then
    echo "  冷却中（$((600 - (now - last)))s），这次不重启" | tee -a "$LOG"
  else
    echo "$(date '+%F %T') 不健康 -> 重启 dionaea" | tee -a "$LOG"
    ( cd "$APP" && docker compose restart ) >>"$LOG" 2>&1 || docker restart dionaea >>"$LOG" 2>&1
    echo "$now" > "$stamp"
    sleep 12
    echo "  重启后复检：" | tee -a "$LOG"
    # 复检结果同时决定日志、通知正文与【最终退出码】：
    #   自愈成功 => 退出 0（否则 cron 每次都当成失败，会淹掉真正的失败）
    if recheck=$(bash "$0" 2>&1); then
      echo "$recheck" | sed 's/^/    /' | tee -a "$LOG"
      [ -x /opt/secagent/scripts/notify.sh ] && \
        /opt/secagent/scripts/notify.sh HIGH "srv2 Dionaea 协议仿真卡死，已自动重启恢复" \
          "$(printf '%s\n%s\n' '健康检查曾失败，已重启并复检通过：' "$recheck")" >/dev/null 2>&1 || true
      rc=0
    else
      echo "$recheck" | sed 's/^/    /' | tee -a "$LOG"
      [ -x /opt/secagent/scripts/notify.sh ] && \
        /opt/secagent/scripts/notify.sh HIGH "srv2 Dionaea 协议仿真卡死，重启后仍不健康" \
          "$(printf '%s\n%s\n' '重启后复检仍然失败，需要人工介入：' "$recheck")" >/dev/null 2>&1 || true
      rc=1
    fi
  fi
fi
exit "$rc"
