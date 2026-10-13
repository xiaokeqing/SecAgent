#!/usr/bin/env bash
# ============================================================
# 蜜罐端口"谁在应答"指纹探针（在【另一台机器】上跑）
# ------------------------------------------------------------
# 解决的问题：光说"端口通"证明不了是谁在应答。
#   诱饵容器是 `nc -l` —— 接受连接后立刻关闭，**不回任何数据**（recv 得到 EOF）。
#   Dionaea 是真协议仿真 —— 会先回一个协议握手包
#     MySQL   : 服务器握手包（含版本串，如 5.5.5-... ）
#     MSSQL   : prelogin 响应（首字节 0x04）
#     SMB     : SMB2 negotiate 响应（首 4 字节 \x00\x00\x00\xfeSMB）
#   所以"回没回数据、回了什么"就能区分"诱饵的空壳"和"Dionaea 的真仿真"。
#
# 用法（任意有 bash+python3 的机器）：
#   bash srv2-honeypot-port-probe.sh <目标IP> [端口列表]
#   例：bash srv2-honeypot-port-probe.sh 43.143.114.79 "445 1433 3306 21 8080 27017"
# 默认端口列表 = 蜜罐对外暴露的 9 个。
# ============================================================
set -uo pipefail
TARGET=${1:-43.143.114.79}
PORTS=${2:-"445 1433 3306 21 23 6379 8080 8443 27017"}

echo "蜜罐端口指纹探针  目标=$TARGET  $(date '+%F %T')"
echo "端口   结果      应答首字节（hex / 可打印）"
echo "-----  --------  ----------------------------------------------"
for p in $PORTS; do
  python3 - "$TARGET" "$p" <<'PYEOF'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    s = socket.create_connection((host, port), 5)
except Exception as e:
    print("%-6s %-8s %s" % (port, "TIMEOUT" if "timed out" in str(e).lower() else "REFUSED", type(e).__name__))
    sys.exit(0)
s.settimeout(4)
try:
    data = s.recv(64)
except socket.timeout:
    data = b""
except Exception:
    data = b""
s.close()
if data:
    hexs = " ".join("%02x" % b for b in data[:16])
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:24])
    print("%-6s %-8s %s | %s" % (port, "OPEN", hexs, asc))
else:
    print("%-6s %-8s %s" % (port, "OPEN", "<连接建立后无数据（空壳诱饵的典型特征）>"))
PYEOF
done
echo
echo "判读："
echo "  OPEN + 有协议握手字节 = 真仿真（Dionaea）"
echo "  OPEN + 无任何数据      = 空壳诱饵（nc）"
echo "  TIMEOUT                = 云安全组未放行 或 主机防火墙 DROP"
echo "  REFUSED                = 包到了但没人监听"
