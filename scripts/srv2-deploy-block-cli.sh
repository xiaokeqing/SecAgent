#!/usr/bin/env bash
# ============================================================
# 在服务器 2 上部署【最小权限封禁入口】
# ------------------------------------------------------------
# 背景：Wazuh 的 Active Response 投递链路在这套环境里走不通
#   （配置全对、API 报成功，agent 就是不执行）。
#   脚本本身 100% 能封，差的只是"谁来扣这个扳机"。
#   所以改成：SecAgent 通过 SSH 直接触发封禁。
#
# 安全模型：一把钥匙只能做一个动作
#   authorized_keys 里用 command="..." 把密钥锁死，
#   即使密钥泄漏，攻击者也只能封/解封 IP，
#   开不了 shell、转不了端口、读不了任何文件。
#   这比 Wazuh AR 的权限小得多（AR 能跑整个 active-response 目录）。
#
# ------------------------------------------------------------
# 【最容易写错的一点】SSH_ORIGINAL_COMMAND
#
# 配了 command="..." 之后，客户端发的 `add 1.2.3.4` 不会作为参数传给脚本，
# 脚本是【无参数】被调用的，原始字符串放在环境变量 $SSH_ORIGINAL_COMMAND 里。
#   如果不解析它、而是去读 $1，结果就是"调用成功但什么都没做"——
#   又是一个"看起来成功、实际没生效"的故障。
#   这是 forced command 最常见的坑。
#
# ------------------------------------------------------------
# 【最关键的一点】命令注入防护
#
# 这个脚本以 root 运行。如果没有严格校验，客户端传
#     add 1.2.3.4; reboot
#     add $(whoami)
#     delete -j DROP
# 就是 root 级命令注入。
# 所以：
#   1) action 必须精确等于 add 或 delete，其它一律拒
#   2) IP 必须匹配严格的 IPv4/IPv6 格式，任何 shell 元字符直接拒
#   3) 拼接进 iptables 时用引号包裹、绝不 eval、绝不 sh -c 拼整串
#   4) 白名单在服务端【再兜一道】（纵深防御）
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\n\033[1;33m  [!] $*\033[0m"; }

log "1/6 安装 ipset（用它的 timeout 做天然 TTL 自动解封）"
if command -v ipset >/dev/null 2>&1; then
  ok "ipset 已安装"
else
  DEBIAN_FRONTEND=noninteractive apt-get install -y ipset 2>&1 | tail -3 | sed 's/^/  /'
fi
command -v ipset >/dev/null && ok "ipset: $(ipset --version 2>&1 | head -1)" || { echo "  [X] ipset 装不上"; exit 1; }

log "2/6 编写封禁入口脚本"
cat > /usr/local/sbin/secagent-block-cli <<'CLIEOF'
#!/usr/bin/env bash
# ============================================================
# SecAgent 封禁入口（只接受 add/delete + 单个 IP）
# 由 authorized_keys 的 forced command 调用，无参数，
# 实际指令从 $SSH_ORIGINAL_COMMAND 读取。
# ============================================================
set -uo pipefail

SETNAME=secagent_block
TTL=1800
AUDIT=/var/log/secagent-block.log

audit() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$AUDIT"; }
deny()  { audit "REJECT $*"; echo "REJECT: $*" >&2; exit 1; }

# ---- 取原始命令（forced command 的关键）----
RAW="${SSH_ORIGINAL_COMMAND:-}"
audit "收到: [$RAW]"

# 空指令 -> 拒（防止有人只是想连一下）
[ -n "$RAW" ] || deny "空指令"

# ---- 严格解析：只允许两个 token，多余的一个都不接受 ----
# 用 read 按空白切分，多余的 token 会因为第三个变量而暴露
read -r ACTION IP EXTRA <<< "$RAW"
[ -z "${EXTRA:-}" ] || deny "参数过多"

# ---- action 精确白名单 ----
case "$ACTION" in
  add|delete) ;;
  *) deny "非法 action: $ACTION" ;;
esac

# ---- IP 严格校验（这是防命令注入的核心）----
# 先挡掉所有 shell 元字符和危险前缀
case "$IP" in
  *[\;\|\&\$\`\(\)\<\>\"\'\\\ \	\n]*|-*|'') deny "IP 含非法字符: $IP" ;;
esac
[ ${#IP} -le 45 ] || deny "IP 过长"

# 用 Python 的 ipaddress 做权威校验（比自己写正则可靠）
VALID=$(python3 - "$IP" <<'PYEOF'
import sys
try:
    import ipaddress
    ipaddress.ip_address(sys.argv[1])
    print("OK")
except Exception:
    print("BAD")
PYEOF
)
[ "$VALID" = "OK" ] || deny "不是合法 IP: $IP"

# ---- 白名单（服务端纵深防御，不依赖 SecAgent 侧）----
# 即使 SecAgent 被绕过或出 bug，这里也必须挡住自家网络。
python3 - "$IP" <<'PYEOF' || deny "命中受保护网段，拒绝: $IP"
import sys, ipaddress
ip = ipaddress.ip_address(sys.argv[1])
protected = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::1/128", "fc00::/7", "fe80::/10",
]
for cidr in protected:
    net = ipaddress.ip_network(cidr)
    if ip.version == net.version and ip in net:
        print("命中 %s" % cidr)
        sys.exit(1)
sys.exit(0)
PYEOF

# ---- 执行（参数化，不 eval、不 sh -c 拼串）----
ipset create "$SETNAME" hash:net timeout "$TTL" -exist 2>/dev/null
# 确保 INPUT 引用这个集合（只加一次）
iptables -C INPUT -m set --match-set "$SETNAME" src -j DROP 2>/dev/null \
  || iptables -I INPUT 1 -m set --match-set "$SETNAME" src -j DROP

if [ "$ACTION" = "delete" ]; then
  ipset del "$SETNAME" "$IP" 2>/dev/null
  audit "UNBLOCK $IP (rc=$?)"
  echo "OK delete $IP"
else
  ipset add "$SETNAME" "$IP" timeout "$TTL" -exist 2>/dev/null
  audit "BLOCK $IP ttl=${TTL}s"
  echo "OK add $IP ttl=${TTL}s"
fi
exit 0
CLIEOF

chmod 700 /usr/local/sbin/secagent-block-cli
chown root:root /usr/local/sbin/secagent-block-cli
touch /var/log/secagent-block.log
chmod 640 /var/log/secagent-block.log
chown root:adm /var/log/secagent-block.log 2>/dev/null || true
ok "脚本已写入 /usr/local/sbin/secagent-block-cli"

log "3/6 【离线自测】先不经过 SSH，直接测脚本的校验逻辑"
echo "  --- 合法请求 ---"
for c in "add 203.0.113.55" "delete 203.0.113.55"; do
  printf "    SSH_ORIGINAL_COMMAND='%s' -> " "$c"
  SSH_ORIGINAL_COMMAND="$c" /usr/local/sbin/secagent-block-cli 2>&1 | head -1
done

echo
echo "  --- 【注入测试】这些必须全部被拒、且无副作用 ---"
for c in "add 1.2.3.4; reboot" 'add $(whoami)' "delete -j DROP" "add 1.2.3.4 && id" 'add `id`' "add 1.2.3.4|cat /etc/passwd" "rm -rf /" "add" "add 1.2.3.4 extra"; do
  printf "    '%-32s' -> " "$c"
  SSH_ORIGINAL_COMMAND="$c" /usr/local/sbin/secagent-block-cli 2>&1 | head -1
done

echo
echo "  --- 白名单测试（必须被拒）---"
for ip in 127.0.0.1 10.0.0.5 192.168.1.1 169.254.169.254 100.100.100.200 172.18.0.1; do
  printf "    add %-18s -> " "$ip"
  SSH_ORIGINAL_COMMAND="add $ip" /usr/local/sbin/secagent-block-cli 2>&1 | head -1
done

echo
echo "  --- 当前 ipset（应该只有 203.0.113.55 被加过又删了，所以为空）---"
ipset list "$SETNAME" 2>/dev/null | head -8 | sed 's/^/    /' || echo "    （集合还没创建，正常）"
echo "  审计日志:"
tail -6 /var/log/secagent-block.log 2>/dev/null | sed 's/^/    /'

log "4/6 生成 SecAgent 专用密钥（只在服务器 1 上存在私钥）"
KEYDIR=/opt/secagent-ssh
mkdir -p "$KEYDIR"
if [ -f "$KEYDIR/secagent_block_ed25519" ]; then
  echo "  密钥已存在，复用"
else
  ssh-keygen -t ed25519 -f "$KEYDIR/secagent_block_ed25519" -N "" -C "secagent-block-from-srv1" -q
  echo "  已生成"
fi
chmod 600 "$KEYDIR/secagent_block_ed25519"
chmod 644 "$KEYDIR/secagent_block_ed25519.pub"
echo "---BEGIN-PUBKEY---"
cat "$KEYDIR/secagent_block_ed25519.pub"
echo "---END-PUBKEY---"

log "5/6 把公钥装进 authorized_keys（用 forced command 锁死权限）"
AK=/root/.ssh/authorized_keys
MARK="secagent-block-from-srv1"
touch "$AK"; chmod 600 "$AK"
cp "$AK" "$AK.bak-block-$(date +%H%M%S)"
grep -v "$MARK" "$AK" > "$AK.tmp" 2>/dev/null || true
PUB=$(cat "$KEYDIR/secagent_block_ed25519.pub")
echo "command=\"/usr/local/sbin/secagent-block-cli\",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc $PUB" >> "$AK.tmp"
mv "$AK.tmp" "$AK"
chmod 600 "$AK"
chown root:root "$AK"
echo "  已写入（选项部分）:"
tail -1 "$AK" | cut -c1-140 | sed 's/^/    /'

log "6/6 自检"
for opt in 'command="/usr/local/sbin/secagent-block-cli"' no-port-forwarding no-pty no-user-rc; do
  tail -1 "$AK" | grep -qF "$opt" && echo "  ✅ 含 $opt" || echo "  ❌ 缺 $opt"
done
ls -la /usr/local/sbin/secagent-block-cli "$AK" | sed 's/^/  /'
echo
ok "服务器 2 侧就绪"
