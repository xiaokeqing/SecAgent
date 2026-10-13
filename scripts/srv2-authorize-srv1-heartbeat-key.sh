#!/usr/bin/env bash
# ============================================================
# 步骤 2（在 srv2 上跑）：授权 srv1 的"反向探活"公钥
# ------------------------------------------------------------
# 与 srv1-authorize-heartbeat-key.sh 完全对称，只是方向相反。
# 写入 authorized_keys 的条目长这样：
#   restrict,command="/opt/secagent/scripts/srv2-heartbeat.sh" ssh-ed25519 AAAA… secagent-heartbeat-to-srv2
#
# 逐项说明（这是本脚本最重要的部分）：
#   restrict   —— 关掉一切：pty、agent 转发、X11、端口转发、~/.ssh/rc。
#                 用"白名单式"的起点，比逐条禁用更安全：SSH 以后新增功能默认仍是关的。
#   command=   —— 强制命令：无论客户端请求执行什么，sshd 都只跑这一句。
#                 于是这把钥匙的能力被钉死在"读一份只读的心跳 JSON"。
#   （可选）from= —— 限定来源 IP。默认【不加】：srv1 的出口 IP 万一变动，
#                 srv1 的 dead man switch 会静默失效 —— 一个"悄悄不报警的报警器"比没有更坏。
#                 要加就设 HEARTBEAT_FROM_IP=47.96.106.187 再跑。
#
# 改配置的铁律（本仓库的既有纪律）：备份 → 改 → 校验 → 失败回滚。
#   本脚本三步都做了，并且校验是【读回文件确认选项真的在】，
#   而不是"命令返回 0 就当成功"。
#
# 用法（srv2，root）：
#   bash srv2-authorize-srv1-heartbeat-key.sh /tmp/srv1-heartbeat.pub
#   HEARTBEAT_FROM_IP=47.96.106.187 bash srv2-authorize-srv1-heartbeat-key.sh /tmp/srv1-heartbeat.pub
#   撤销最后一条：bash srv2-authorize-srv1-heartbeat-key.sh --rollback
# ============================================================
set -uo pipefail

PUBKEY_FILE=${1:-/tmp/srv1-heartbeat.pub}
AK=/root/.ssh/authorized_keys
MARK="secagent-heartbeat-to-srv2"
STATUS_CMD=/opt/secagent/scripts/srv2-heartbeat.sh
FROM_IP=${HEARTBEAT_FROM_IP:-}

if [ "${1:-}" = "--rollback" ]; then
  echo "==> 回滚：从 $AK 移除含 $MARK 的条目"
  BAK=$(ls -1t "$AK".bak-heartbeat-* 2>/dev/null | head -1)
  if [ -n "$BAK" ]; then
    cp -p "$BAK" "$AK" && chmod 600 "$AK" && echo "  已从备份恢复：$BAK（当前 $(wc -l < "$AK") 行）"
    exit 0
  fi
  if grep -q "$MARK" "$AK" 2>/dev/null; then
    grep -v "$MARK" "$AK" > "$AK.tmp" && mv "$AK.tmp" "$AK" && chmod 600 "$AK"
    echo "  已移除条目（没有找到备份文件，只删了那一行；当前 $(wc -l < "$AK") 行）"
  else
    echo "  没有找到该条目，无需回滚"
  fi
  exit 0
fi

echo "==> 0/5 前置检查"
if [ ! -f "$PUBKEY_FILE" ]; then
  echo "  [X] 找不到公钥文件 $PUBKEY_FILE（先从 srv1 传过来）"
  exit 1
fi
if [ ! -f "$STATUS_CMD" ]; then
  echo "  [X] 找不到 $STATUS_CMD —— 强制命令指向的脚本不存在（先安装 scripts/srv2-heartbeat.sh）"
  exit 1
fi
PUB=$(tr -d '\n' < "$PUBKEY_FILE")
case "$PUB" in
  ssh-ed25519*|ssh-rsa*|ecdsa-*) : ;;
  *) echo "  [X] $PUBKEY_FILE 看起来不是公钥（应以 ssh-ed25519 / ssh-rsa 开头）"; exit 1 ;;
esac
echo "  待授权公钥：${PUB:0:60}…"
echo "  强制命令  ：$STATUS_CMD"
[ -n "$FROM_IP" ] && echo "  来源限制  ：from=$FROM_IP（注意：srv1 出口 IP 变了会导致探活失效）"

echo
echo "==> 1/5 备份 authorized_keys"
mkdir -p /root/.ssh && chmod 700 /root/.ssh
touch "$AK" && chmod 600 "$AK"
BAK="$AK.bak-heartbeat-$(date +%Y%m%d-%H%M%S)"
cp -p "$AK" "$BAK"
echo "  已备份到 $BAK（$(wc -l < "$BAK") 行）"

rollback() {
  echo "  [回滚] 用备份恢复 $AK"
  cp -p "$BAK" "$AK" && chmod 600 "$AK" && echo "  [回滚] 完成（authorized_keys 与改动前一致）"
}

echo
echo "==> 2/5 幂等清理旧条目"
if grep -q "$MARK" "$AK" 2>/dev/null; then
  grep -v "$MARK" "$AK" > "$AK.tmp" && mv "$AK.tmp" "$AK" && chmod 600 "$AK"
  echo "  已移除同名旧条目"
else
  echo "  没有旧条目"
fi

echo
echo "==> 3/5 写入带限制的新条目"
OPTS="restrict,command=\"$STATUS_CMD\""
[ -n "$FROM_IP" ] && OPTS="restrict,from=\"$FROM_IP\",command=\"$STATUS_CMD\""
printf '%s %s\n' "$OPTS" "$PUB" >> "$AK"
chmod 600 "$AK"

echo
echo "==> 4/5 校验（读回文件确认选项真的在）"
LAST=$(grep "$MARK" "$AK" | tail -1)
FAIL=0
for opt in restrict command; do
  printf '%s' "$LAST" | grep -q "$opt" || { echo "  [X] 缺 $opt"; FAIL=1; }
done
printf '%s' "$LAST" | grep -qF -- "$STATUS_CMD" || { echo "  [X] command= 指向的路径不对"; FAIL=1; }
[ -n "$FROM_IP" ] && { printf '%s' "$LAST" | grep -qF -- "$FROM_IP" || { echo "  [X] from= 没写进去"; FAIL=1; }; }
echo "  条目（截断显示）：$(printf '%s' "$LAST" | cut -c1-120)…"
echo "  当前 authorized_keys 行数：$(wc -l < "$AK")"

if [ "$FAIL" != "0" ]; then
  rollback
  exit 1
fi

# sshd 语法自检：配置本身坏了会让所有人都连不上，这一步必须做
if command -v sshd >/dev/null 2>&1; then
  if sshd -t 2>/dev/null; then echo "  sshd -t：配置语法 OK"
  else echo "  [X] sshd -t 失败"; rollback; exit 1; fi
fi

echo
echo "==> 5/5 完成。现在从 srv1 验证（应当【只能】拿到心跳 JSON）："
echo "  ssh -i /etc/secagent/heartbeat/srv2_ed25519 root@43.143.114.79 secagent-srv2-heartbeat"
echo "  反向验证（应当拿不到 uid，而是又一份心跳 JSON —— 证明强制命令生效）："
echo "  ssh -i /etc/secagent/heartbeat/srv2_ed25519 root@43.143.114.79 id"
echo
echo "  如需撤销：cp -p $BAK $AK && chmod 600 $AK"
