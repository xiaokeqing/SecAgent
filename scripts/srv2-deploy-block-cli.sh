#!/usr/bin/env bash
# ============================================================
# 在服务器 2 上部署【最小权限封禁入口】v2
# ------------------------------------------------------------
# 背景：Wazuh 的 Active Response 投递链路在这套环境里走不通
#   （配置全对、API 报成功，agent 就是不执行）。
#   脚本本身 100% 能封，差的只是"谁来扣这个扳机"。
#   所以改成：SecAgent 通过 SSH 直接触发封禁。
#
# v2 变更：封禁从"逐条 iptables 规则"改成"ipset 集合"，
#   并新增 block <ip> <ttl> [reason] / flush / status 三个能力。
#   为什么用 ipset：集合匹配 O(1)、条目自带 timeout 到期自动消失。
#   没有 ipset 时脚本内部自动回退到逐条 -s 规则（带到期清理）；
#   回退放在服务端，是因为服务器 1 上的 SecAgent 看不到这里的 ipset，
#   而给它一条"能探测任意命令"的通道会毁掉 forced command 的最小权限。
#
# 安全模型：一把钥匙只能做一个动作
#   authorized_keys 里用 command="..." 把密钥锁死，
#   即使密钥泄漏，攻击者也只能封/解封 IP、清集合、看状态，
#   开不了 shell、转不了端口、读不了任何文件。
#   这比 Wazuh AR 的权限小得多（AR 能跑整个 active-response 目录）。
#
# ------------------------------------------------------------
# 【最容易写错的一点】SSH_ORIGINAL_COMMAND
#
# 配了 command="..." 之后，客户端发的 `block 1.2.3.4 600` 不会作为参数传给脚本，
# 脚本是【无参数】被调用的，原始字符串放在环境变量 $SSH_ORIGINAL_COMMAND 里。
#   如果不解析它、而是去读 $1，结果就是"调用成功但什么都没做"——
#   又是一个"看起来成功、实际没生效"的故障。
#   这是 forced command 最常见的坑。
#
# ------------------------------------------------------------
# 【最关键的一点】命令注入防护
#   1) action 必须精确等于 block/unblock/flush/status/add/delete，其它一律拒
#   2) IP 必须能被 python3 ipaddress 解析，任何 shell 元字符直接拒
#   3) TTL 必须是纯数字（否则 ipset 参数位就是注入面）
#   4) 拼接进 ipset/iptables 时用引号包裹、绝不 eval、绝不 sh -c 拼整串
#   5) 白名单在服务端【再兜一道】（纵深防御）
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\n\033[1;33m  [!] $*\033[0m"; }

log "1/6 安装 ipset（集合 + 原生 timeout）与 python3（IP 校验）"
if command -v ipset >/dev/null 2>&1; then
  ok "ipset 已安装"
else
  DEBIAN_FRONTEND=noninteractive apt-get install -y ipset 2>&1 | tail -3 | sed 's/^/  /'
fi
command -v ipset >/dev/null && ok "ipset: $(ipset --version 2>&1 | head -1)" || { echo "  [X] ipset 装不上"; exit 1; }

if command -v python3 >/dev/null 2>&1; then
  ok "python3 已安装"
else
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 2>&1 | tail -3 | sed 's/^/  /'
fi
command -v python3 >/dev/null || { echo "  [X] python3 装不上（IP 校验依赖它）"; exit 1; }

log "2/6 编写封禁入口脚本（v2：block/unblock/flush/status + 兼容 add/delete）"
cat > /usr/local/sbin/secagent-block-cli <<'CLIEOF'
#!/usr/bin/env bash
# ============================================================
# SecAgent 封禁入口 v2（服务器 2 上以 root 运行，经 SSH forced command 触发）
# ------------------------------------------------------------
# 协议（从 $SSH_ORIGINAL_COMMAND 读取，见文件末尾"forced command"说明）：
#   block <ip> <ttl 秒> [reason]   封禁，ttl 由 SecAgent 按攻击类型下发
#   unblock <ip>                   解封单个
#   flush                          清空两个集合（误封止血）
#   status                         查看后端与集合条目
#   add <ip> / delete <ip>         兼容旧协议（v1 客户端）
#
# 为什么用 ipset 而不是逐条 iptables -s：
#   1) 集合匹配是 O(1) 哈希查找，规则条数与包处理开销无关；
#      逐条 -s 规则是线性链，几十条之后每个包都要过一遍链。
#   2) ipset 条目自带 timeout，到期自动消失，解封不依赖"调度器还记得它"；
#      逐个 -s 规则没有 TTL，只能靠外部扫表，忘了就永久封死。
#
# 回退策略（为什么回退放在服务端而不是 SecAgent 侧）：
#   SecAgent 在服务器 1 上，看不到服务器 2 有没有 ipset。让它"探测"就得先建立
#   一条能执行任意命令的通道 —— 那等于把 forced command 的白名单拆了。
#   所以探测与回退都放在这个脚本里：有 ipset 就用集合，没有就退回逐条规则，
#   并用 /var/lib/secagent-block/active.db 记录到期时间，每次调用顺手清理过期项。
#   两种后端的回显都带 backend=ipset|iptables，SecAgent 只解析这个标记。
# ------------------------------------------------------------
# 安全模型（v1 的约束一条都没有放松）：
#   1) action 必须精确命中白名单，其它一律拒
#   2) IP 必须能被 python3 ipaddress 解析，且不含任何 shell 元字符
#   3) 拼接命令时全部加引号，绝不 eval、绝不 sh -c 拼整串
#   4) 白名单在服务端【再兜一道】（纵深防御，不依赖 SecAgent）
# ============================================================
set -euo pipefail

SET_V4=secagent_block
SET_V6=secagent_block6
DEFAULT_TTL=1800
MAX_TTL=31536000
AUDIT=/var/log/secagent-block.log
STATE_DIR=/var/lib/secagent-block
STATE_FILE="$STATE_DIR/active.db"

audit() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$AUDIT"; }
deny()  { audit "REJECT $*"; echo "REJECT: $*" >&2; exit 1; }

# ---- 为什么先记录原始命令：forced command 下脚本"无参数"，排查时唯一线索 ----
RAW="${SSH_ORIGINAL_COMMAND:-}"
audit "收到: [$RAW]"
[ -n "$RAW" ] || deny "空指令"

read -r ACTION A B C D <<< "$RAW"

# ---- action 精确白名单 ----
case "$ACTION" in
  block|unblock|flush|status|add|delete) ;;
  *) deny "非法 action: $ACTION" ;;
esac

# ---- 参数个数严格校验：多一个 token 都拒（v1 的注入面就是这么关掉的）----
need_ip()  { [ -n "${A:-}" ] || deny "缺少 IP"; }
no_extra() { [ -z "${B:-}" ] && [ -z "${C:-}" ] && [ -z "${D:-}" ] || deny "参数过多"; }

IP=""
TTL="$DEFAULT_TTL"
REASON=""
case "$ACTION" in
  block)
    need_ip
    [ -n "${B:-}" ] || deny "缺少 TTL"
    [ -z "${D:-}" ] || deny "参数过多"
    IP="$A"; TTL="$B"; REASON="${C:-}"
    # reason 只进审计日志，但仍按白名单校验：它是唯一一个"自由文本"入参，
    # 留一条不问内容的路，等于给未来的日志注入留口子
    if [ -n "$REASON" ]; then
      [[ "$REASON" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] || deny "reason 非法: $REASON"
    fi
    ;;
  add)      need_ip; no_extra; IP="$A" ;;
  unblock|delete) need_ip; no_extra; IP="$A" ;;
  flush|status)
    [ -z "${A:-}" ] && [ -z "${B:-}" ] && [ -z "${C:-}" ] && [ -z "${D:-}" ] || deny "参数过多"
    ;;
esac

# ---- IP 校验（防命令注入的核心）----
if [ -n "$IP" ]; then
  case "$IP" in
    *[\;\|\&\$\`\(\)\<\>\"\'\\\ \	\n]*|-*|'') deny "IP 含非法字符: $IP" ;;
  esac
  [ ${#IP} -le 45 ] || deny "IP 过长"
fi

# ---- TTL 校验：纯数字 + 1..1 年，避免把超大值写给 ipset ----
case "$TTL" in
  ''|*[!0-9]*) deny "TTL 必须是纯数字秒数: $TTL" ;;
esac
TTL=$((10#$TTL))
[ "$TTL" -ge 1 ] && [ "$TTL" -le "$MAX_TTL" ] || deny "TTL 超出范围 1..$MAX_TTL: $TTL"

# ---- IP 合法性 + 协议族（v4 与 v6 的集合必须分开：ipset 的 family 建好就不能改）----
VER=""
if [ -n "$IP" ]; then
  VER=$(python3 - "$IP" <<'PY' || true
import sys, ipaddress
try:
    a = ipaddress.ip_address(sys.argv[1])
except Exception:
    sys.exit(1)
print(a.version)
PY
)
  [ "$VER" = "4" ] || [ "$VER" = "6" ] || deny "不是合法 IP: $IP"
fi

# ---- 白名单（服务端纵深防御）----
# 注意：只对"封禁"生效。解封不查白名单 —— 白名单的意思是"不该被封"，
# 万一是历史误封，查白名单会让它永远解不掉。
if [ "$ACTION" = "block" ] || [ "$ACTION" = "add" ]; then
  python3 - "$IP" <<'PY' || deny "命中受保护网段，拒绝: $IP"
import sys, ipaddress
ip = ipaddress.ip_address(sys.argv[1])
protected = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::1/128", "::/128", "fc00::/7", "fe80::/10", "ff00::/8",
    "100::/64", "2001:db8::/32",
]
for cidr in protected:
    net = ipaddress.ip_network(cidr)
    if ip.version == net.version and ip in net:
        print("命中 %s" % cidr)
        sys.exit(1)
sys.exit(0)
PY
fi

# ---- 后端选择 ----
BACKEND=iptables
command -v ipset >/dev/null 2>&1 && BACKEND=ipset

SET=""
IFC=""
if [ "$VER" = "6" ]; then SET=$SET_V6; IFC=ip6tables; else SET=$SET_V4; IFC=iptables; fi

# ---- 无 ipset 时的回退：逐条 -s 规则 + 到期清理 ----
sweep_fallback() {
  [ -f "$STATE_FILE" ] || return 0
  local now tmp ver ip exp
  now=$(date +%s)
  tmp=$(mktemp)
  while IFS='|' read -r ver ip exp; do
    [ -n "$ip" ] || continue
    if [ "${exp:-0}" -le "$now" ] 2>/dev/null; then
      if [ "$ver" = "6" ]; then
        ip6tables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
      else
        iptables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
      fi
      audit "EXPIRE $ip"
    else
      echo "$ver|$ip|$exp" >> "$tmp"
    fi
  done < "$STATE_FILE"
  mv "$tmp" "$STATE_FILE"
}

if [ "$BACKEND" = "ipset" ]; then
  case "$ACTION" in
    block|add)
      ipset create "$SET" hash:net family "$([ "$VER" = "6" ] && echo inet6 || echo inet)" \
        timeout "$DEFAULT_TTL" -exist 2>/dev/null || true
      # INPUT 只挂一条集合匹配规则，条目怎么增删都不动防火墙链
      $IFC -C INPUT -m set --match-set "$SET" src -j DROP 2>/dev/null \
        || $IFC -I INPUT 1 -m set --match-set "$SET" src -j DROP
      # -exist：重复封同一 IP 不报错，同时刷新它的 timeout
      ipset add "$SET" "$IP" timeout "$TTL" -exist
      audit "BLOCK $IP ttl=${TTL}s set=$SET backend=ipset reason=${REASON:-auto}"
      echo "OK block $IP ttl=${TTL}s set=$SET backend=ipset"
      ;;
    unblock|delete)
      ipset del "$SET" "$IP" 2>/dev/null || true
      audit "UNBLOCK $IP set=$SET backend=ipset"
      echo "OK unblock $IP set=$SET backend=ipset"
      ;;
    flush)
      for s in "$SET_V4" "$SET_V6"; do
        ipset flush "$s" 2>/dev/null || true
      done
      audit "FLUSH backend=ipset"
      echo "OK flush backend=ipset sets=$SET_V4,$SET_V6"
      ;;
    status)
      echo "backend=ipset"
      for s in "$SET_V4" "$SET_V6"; do
        if ipset list "$s" >/dev/null 2>&1; then
          echo "set=$s entries=$(ipset list "$s" | grep -c '^[0-9a-fA-F:.]' || true)"
        else
          echo "set=$s 未创建"
        fi
      done
      ;;
  esac
else
  mkdir -p "$STATE_DIR"
  touch "$STATE_FILE"
  chmod 600 "$STATE_FILE" 2>/dev/null || true
  sweep_fallback
  case "$ACTION" in
    block|add)
      $IFC -C INPUT -s "$IP" -j DROP 2>/dev/null || $IFC -I INPUT 1 -s "$IP" -j DROP
      # 去掉旧记录再写新的（同一 IP 续封要更新到期时间）
      grep -vF "|$IP|" "$STATE_FILE" > "$STATE_FILE.tmp" || true
      mv "$STATE_FILE.tmp" "$STATE_FILE"
      echo "$VER|$IP|$(( $(date +%s) + TTL ))" >> "$STATE_FILE"
      audit "BLOCK $IP ttl=${TTL}s backend=iptables reason=${REASON:-auto}"
      echo "OK block $IP ttl=${TTL}s backend=iptables"
      ;;
    unblock|delete)
      $IFC -D INPUT -s "$IP" -j DROP 2>/dev/null || true
      grep -vF "|$IP|" "$STATE_FILE" > "$STATE_FILE.tmp" || true
      mv "$STATE_FILE.tmp" "$STATE_FILE"
      audit "UNBLOCK $IP backend=iptables"
      echo "OK unblock $IP backend=iptables"
      ;;
    flush)
      n=0
      while IFS='|' read -r ver ip exp; do
        [ -n "$ip" ] || continue
        if [ "$ver" = "6" ]; then ip6tables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
        else iptables -D INPUT -s "$ip" -j DROP 2>/dev/null || true; fi
        n=$((n + 1))
      done < "$STATE_FILE"
      : > "$STATE_FILE"
      audit "FLUSH backend=iptables removed=$n"
      echo "OK flush backend=iptables removed=$n"
      ;;
    status)
      echo "backend=iptables"
      echo "active=$(grep -c '|' "$STATE_FILE" 2>/dev/null || true)"
      ;;
  esac
fi
exit 0

# ------------------------------------------------------------
# forced command 备忘（v1 最大的坑，保持原样提醒）：
#   authorized_keys 里配了 command="..." 之后，客户端发的 "block 1.2.3.4 600"
#   不会作为参数传给脚本，脚本是【无参数】被调用的，原始字符串在
#   $SSH_ORIGINAL_COMMAND 里。去读 $1 的结果是"调用成功但什么都没做"。
# ------------------------------------------------------------
CLIEOF

chmod 700 /usr/local/sbin/secagent-block-cli
chown root:root /usr/local/sbin/secagent-block-cli
touch /var/log/secagent-block.log
chmod 640 /var/log/secagent-block.log
chown root:adm /var/log/secagent-block.log 2>/dev/null || true
ok "脚本已写入 /usr/local/sbin/secagent-block-cli"

log "3/6 【离线自测】先不经过 SSH，直接测脚本的校验逻辑与后端回显"
# 注意测试 IP 不能选 203.0.113.x / 198.51.100.x —— 那是 TEST-NET 文档网段，
# 服务端白名单里本来就有，用它们测"合法封禁"必然被拒（v1 自测就踩了这个坑）。
echo "  --- 合法请求（封 45.33.32.156 / 2001:470::1）---"
for c in "block 45.33.32.156 600 scan" "status" "block 2001:470::1 60 scan" \
         "unblock 45.33.32.156" "delete 2001:470::1" "flush"; do
  printf "    SSH_ORIGINAL_COMMAND='%s' -> " "$c"
  SSH_ORIGINAL_COMMAND="$c" /usr/local/sbin/secagent-block-cli 2>&1 | head -3 | tr '\n' ' '; echo
done

echo
echo "  --- 旧协议兼容（add / delete）---"
for c in "add 45.33.32.156" "delete 45.33.32.156"; do
  printf "    SSH_ORIGINAL_COMMAND='%s' -> " "$c"
  SSH_ORIGINAL_COMMAND="$c" /usr/local/sbin/secagent-block-cli 2>&1 | head -1
done

echo
echo "  --- 【注入测试】这些必须全部被拒、且无副作用 ---"
for c in "block 1.2.3.4 600; reboot" 'block $(whoami) 600' "block -j DROP 600" \
         "block 1.2.3.4 600 && id" 'block `id` 600' "block 1.2.3.4|cat /etc/passwd 600" \
         "block 1.2.3.4 600 extra1 extra2" "block 1.2.3.4 abc" "block 1.2.3.4 99999999999" \
         "rm -rf /" "block" "flush now" "unblock"; do
  printf "    '%-42s' -> " "$c"
  SSH_ORIGINAL_COMMAND="$c" /usr/local/sbin/secagent-block-cli 2>&1 | head -1
done

echo
echo "  --- 白名单测试（必须被拒）---"
for ip in 127.0.0.1 10.0.0.5 192.168.1.1 169.254.169.254 100.100.100.200 172.18.0.1 ::1; do
  printf "    block %-18s -> " "$ip"
  SSH_ORIGINAL_COMMAND="block $ip 600 scan" /usr/local/sbin/secagent-block-cli 2>&1 | head -1
done

echo
echo "  --- 当前集合状态 ---"
SSH_ORIGINAL_COMMAND="status" /usr/local/sbin/secagent-block-cli 2>&1 | sed 's/^/    /'
echo "  审计日志:"
tail -8 /var/log/secagent-block.log 2>/dev/null | sed 's/^/    /'

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
ok "服务器 2 侧就绪（v2：ipset 集合 + block/unblock/flush/status）"
