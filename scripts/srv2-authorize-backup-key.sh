#!/usr/bin/env bash
# ============================================================
# srv2：安装备份接收端 + 授权「状态备份」专用密钥（最小权限）
# ------------------------------------------------------------
# 这个脚本做四件事，顺序刻意如此（备份 → 改 → 校验 → 失败回滚）：
#   1) 装接收脚本：/usr/local/sbin/secagent-backup-receive（强制命令）
#                  /usr/local/sbin/secagent-backup-drill.sh（恢复抽测）
#      并建好 /opt/secagent-backup（700）与 /var/log/secagent-backup
#   2) 【备份】/root/.ssh/authorized_keys → authorized_keys.bak-<时间戳>
#   3) 【改】移除同名旧条目，再追加一条带强制命令 + restrict 的条目
#   4) 【校验】结构自检 + 接收端自检（必须对白名单外的命令返回 64）；
#      任何一项不过 → 自动【回滚】到刚做的备份，并把原因打出来
#
# 为什么用 restrict + command= 而不是给一把普通 SSH 钥匙：
#   restrict 是"白名单式起点"（关掉 tty / agent / X11 / 端口转发 / user-rc），
#   command= 再把 shell 也换掉 —— 于是这把钥匙的全部能力就是
#   "把一段 tar.gz 交给我，或者让我读一下我自己的备份清单"。
#   即使泄露，也写不出 /opt/secagent-backup 之外的一个字节。
#
# 用法（root@srv2）：
#   bash srv2-authorize-backup-key.sh /tmp/backup_pub.key
#   cat backup_pub.key | bash srv2-authorize-backup-key.sh
#   bash srv2-authorize-backup-key.sh --rollback     # 撤销：恢复最近一次备份
#   SRC_DIR=/tmp bash srv2-authorize-backup-key.sh /tmp/backup_pub.key
# ============================================================
set -uo pipefail

AK=/root/.ssh/authorized_keys
MARK="secagent-backup-from-srv1"
RECV=/usr/local/sbin/secagent-backup-receive
DRILL=/usr/local/sbin/secagent-backup-drill.sh
BASE=/opt/secagent-backup
LOGDIR=/var/log/secagent-backup
SRC_DIR=${SRC_DIR:-/tmp}
FORCED="command=\"$RECV\",restrict"

ok()   { echo -e "  \033[1;32m[OK]\033[0m $*"; }
bad()  { echo -e "  \033[1;31m[X]\033[0m $*"; }
info() { echo -e "\n\033[1;36m==> $*\033[0m"; }

# ------------------------------------------------------------
# --rollback：恢复最近一次 authorized_keys 备份
# ------------------------------------------------------------
if [ "${1:-}" = "--rollback" ]; then
  info "回滚 authorized_keys"
  LAST=$(ls -1t "$AK".bak-* 2>/dev/null | head -1)
  if [ -z "$LAST" ]; then
    bad "找不到任何 $AK.bak-* 备份，无法回滚"
    exit 1
  fi
  cp -a "$LAST" "$AK"
  chmod 600 "$AK"
  echo "  已恢复：$LAST → $AK"
  echo "  当前条目（只显示注释名）："
  awk '{print "    - " $NF}' "$AK" | sed 's/^/  /'
  exit 0
fi

# ------------------------------------------------------------
# 1) 装接收端脚本 + 目录
# ------------------------------------------------------------
info "1/5 安装接收端脚本与目录"
for f in srv2-backup-receive.sh srv2-backup-drill.sh; do
  if [ -f "$SRC_DIR/$f" ]; then
    :
  else
    bad "找不到 $SRC_DIR/$f —— 先把 scripts/$f 传到 srv2:$SRC_DIR/"
    exit 1
  fi
done
install -m 755 -o root -g root "$SRC_DIR/srv2-backup-receive.sh" "$RECV"
install -m 755 -o root -g root "$SRC_DIR/srv2-backup-drill.sh"   "$DRILL"
mkdir -p "$BASE" "$LOGDIR"
chmod 700 "$BASE"; chmod 700 "$LOGDIR"
ok "$RECV（$(stat -c '%A %U:%G' "$RECV")）"
ok "$DRILL（$(stat -c '%A %U:%G' "$DRILL")）"
ok "$BASE（$(stat -c '%A' "$BASE")）、$LOGDIR（$(stat -c '%A' "$LOGDIR")）"

info "1b/5 接收端自检：白名单外的命令必须被拒（期望退出码 64）"
OUT=$(SSH_ORIGINAL_COMMAND="rm -rf /" "$RECV" 2>&1); rc=$?
if [ $rc -eq 64 ]; then
  ok "非法命令被拒：exit=$rc，输出：$OUT"
else
  bad "接收端没有拒绝非法命令（exit=$rc）—— 授权中止"
  exit 1
fi
OUT=$(SSH_ORIGINAL_COMMAND="" "$RECV" 2>&1); rc=$?
[ $rc -eq 64 ] && ok "空命令被拒：exit=$rc" || { bad "空命令未被拒（exit=$rc）"; exit 1; }
OUT=$(SSH_ORIGINAL_COMMAND="list" "$RECV" 2>&1); rc=$?
[ $rc -eq 0 ] && ok "list 正常：$OUT" || { bad "list 异常（exit=$rc）：$OUT"; exit 1; }

# ------------------------------------------------------------
# 2) 取公钥
# ------------------------------------------------------------
info "2/5 读取待授权公钥"
PUB=""
if [ -n "${1:-}" ] && [ -f "${1:-}" ]; then
  PUB=$(tr -d '\n' < "$1")
else
  PUB=$(tr -d '\n')
fi
if ! printf '%s' "$PUB" | grep -qE '^(ssh-ed25519|ssh-rsa|ecdsa-)'; then
  bad "公钥格式不对（要 ssh-ed25519/ssh-rsa/ecdsa- 开头）：${PUB:0:40}"
  exit 1
fi
ok "公钥指纹：$(printf '%s\n' "$PUB" | ssh-keygen -lf - | awk '{print $2}')"
ok "格式与注释：${PUB:0:24}…（末尾：$(printf '%s' "$PUB" | awk '{print $NF}')）"

# ------------------------------------------------------------
# 3) 备份 authorized_keys
# ------------------------------------------------------------
info "3/5 备份 authorized_keys（改之前）"
mkdir -p /root/.ssh && chmod 700 /root/.ssh
touch "$AK" && chmod 600 "$AK"
BK="$AK.bak-$(date +%Y%m%d-%H%M%S)"
cp -a "$AK" "$BK"
ok "已备份 → $BK（$(wc -l < "$BK") 条）"

rollback() {
  bad "$1"
  echo "  → 自动回滚：$BK → $AK"
  cp -a "$BK" "$AK"; chmod 600 "$AK"
  echo "  回滚后条目数：$(grep -c . "$AK" 2>/dev/null || echo 0)"
  exit 1
}

# ------------------------------------------------------------
# 4) 写入受限条目
# ------------------------------------------------------------
info "4/5 写入带强制命令的条目"
if grep -q "$MARK" "$AK" 2>/dev/null; then
  grep -v "$MARK" "$AK" > "$AK.tmp" && mv "$AK.tmp" "$AK"
  chmod 600 "$AK"
  ok "已移除同名旧条目（保证幂等）"
else
  ok "没有同名旧条目"
fi
printf '%s %s\n' "$FORCED" "$PUB" >> "$AK"
chmod 600 "$AK"
ok "写入完成，当前 $(( $(grep -c . "$AK") )) 条"
echo "  本条（只显示选项部分）："
tail -1 "$AK" | cut -c1-120 | sed 's/^/    /'

# ------------------------------------------------------------
# 5) 校验（不过就回滚）
# ------------------------------------------------------------
info "5/5 校验"
LAST=$(tail -1 "$AK")
for opt in "command=" "restrict"; do
  printf '%s' "$LAST" | grep -q -- "$opt" || rollback "缺少必须的选项：$opt"
  ok "含 $opt"
done
printf '%s' "$LAST" | grep -q "$MARK" || rollback "最后一条不是本次写入的条目（marker 缺失）"
ok "含标记 $MARK（便于将来幂等替换/审计）"

[ "$(stat -c %a "$AK")" = "600" ] || rollback "authorized_keys 权限不是 600（是 $(stat -c %a "$AK")）"
ok "authorized_keys 权限 600"
[ "$(stat -c %a /root/.ssh)" = "700" ] || rollback "/root/.ssh 权限不是 700"
ok "/root/.ssh 权限 700"
for f in "$RECV" "$DRILL"; do
  [ -x "$f" ] || rollback "$f 不可执行"
done
ok "接收端脚本可执行"

echo
echo "  当前 authorized_keys 全部条目用途："
awk '{print "    - " $NF}' "$AK" | sed 's/^/  /'
echo
echo -e "  \033[1;32m授权完成。\033[0m下一步在 srv1 上跑：bash /opt/secagent/scripts/srv1-data-backup.sh"
echo "  —— 那一次真实推送就是这条通道的功能验证；若失败，在 srv2 上执行："
echo "     bash $0 --rollback"
