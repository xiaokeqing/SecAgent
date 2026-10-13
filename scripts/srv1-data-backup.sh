#!/usr/bin/env bash
# ============================================================
# srv1：把 /opt/secagent/data 打包 + 校验 + 推到 srv2（异地备份）
# ------------------------------------------------------------
# 为什么这件事是 P0：
#   /opt/secagent/data/ 里的 blocked-ips.json、response-audit.json、
#   三池额度文件是【唯一状态】—— 没有数据库、没有第二份副本，全在 srv1
#   的 bind-mount 目录里。磁盘坏 / 误删 / 误 mount 覆盖 → 处置审计链直接断掉，
#   而且是不可重建的（审计记录没法"重新生成"，封禁名单也回不来）。
#
# 为什么推到 srv2 而不是留在 srv1 本机：
#   本机副本挡不住"这台机器/这块盘没了"。srv2 是另一家云的独立机器
#   （腾讯云上海 vs 阿里云杭州），且已经在跑检测/蜜罐，属于既有的信任边界内。
#
# 上传通道（重要，与最初的设想不同）：
#   项目里【已有的】srv1→srv2 SSH 通道是一把隧道密钥，它在 srv2 侧被限制成
#   restrict,port-forwarding,permitopen="127.0.0.1:55000" —— 连 shell 都开不了，
#   更不可能传文件。所以这里用【另开一把专用密钥 + srv2 侧强制命令】的方式：
#     密钥只能执行 /usr/local/sbin/secagent-backup-receive，
#     只能做 push / drill / list 三件事，拿不到 shell、tty、端口转发。
#   即"为备份新开一条最小权限通道"，而不是把隧道密钥放宽成万能钥匙。
#
# 为什么先快照再打包（而不是直接 tar 正在被写的目录）：
#   data/ 里的文件是活文件（容器一直在写）。直接 tar 可能把一个文件读到一半，
#   产出一份"能解开、但内容自相矛盾"的备份 —— 那比没有备份更危险，
#   因为它看起来是成功的。这里先 cp 到暂存目录，再对每个文件复核 sha256，
#   对不上就重拷（最多 3 次）；仍对不上就【失败退出、不推】，绝不推一份可能坏的。
#
# 用法（root@srv1）：
#   bash srv1-data-backup.sh               # 备份 + 推送 + srv2 侧恢复抽测
#   bash srv1-data-backup.sh --dry-run     # 只做快照+打包，不联系 srv2（演练）
#   bash srv1-data-backup.sh --status      # 看本地归档 + srv2 现有备份清单
#   bash srv1-data-backup.sh --drill       # 让 srv2 对最新备份再做一次恢复抽测
#   bash srv1-data-backup.sh --drill <stamp>
# ============================================================
set -uo pipefail

SRC=/opt/secagent/data
STAGE_ROOT=/var/backups/secagent-data
ARCH_DIR=$STAGE_ROOT/archives
LOG=/var/log/secagent-backup/backup.log
KEY=/root/.ssh/backup_srv2_ed25519
SRV2=43.143.114.79
KEEP_LOCAL=3          # 本地只留最近 3 份（异地才是主副本，本地只为快速回滚）

MODE=backup
DRILL_STAMP=""
case "${1:-}" in
  --dry-run)  MODE=dry ;;
  --status)   MODE=status ;;
  --drill)    MODE=drill; DRILL_STAMP=${2:-} ;;
  --help|-h)  sed -n '1,40p' "$0"; exit 0 ;;
  "")         ;;
  *)          echo "未知参数：$1（--dry-run / --status / --drill [stamp]）"; exit 64 ;;
esac

mkdir -p "$ARCH_DIR" "$(dirname "$LOG")" || { echo "无法创建 $ARCH_DIR / $(dirname "$LOG")"; exit 70; }
umask 077

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG"; }
die() { log "失败：$*"; exit 1; }

SSH_OPTS=(-T -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new
          -o UserKnownHostsFile=/root/.ssh/known_hosts
          -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)

remote() {  # remote <命令串> [stdin文件]
  local cmd=$1; shift
  if [ $# -gt 0 ]; then
    ssh "${SSH_OPTS[@]}" "root@$SRV2" "$cmd" < "$1"
  else
    ssh "${SSH_OPTS[@]}" "root@$SRV2" "$cmd"
  fi
}

latest_local() { ls -1 "$ARCH_DIR"/data-*.tar.gz 2>/dev/null | sort | tail -1; }

# ------------------------------------------------------------
# --status / --drill：不产生新备份，只查询
# ------------------------------------------------------------
if [ "$MODE" = status ]; then
  log "== srv1 本地归档（$ARCH_DIR，保留最近 $KEEP_LOCAL 份）=="
  ls -la "$ARCH_DIR" 2>/dev/null | sed 's/^/  /'
  log "== srv2 备份清单 =="
  remote "list" || die "连不上 srv2 或命令被拒（见上面输出）"
  exit 0
fi

if [ "$MODE" = drill ]; then
  log "== 请求 srv2 做恢复抽测 ${DRILL_STAMP:-（最新一份）} =="
  if [ -n "$DRILL_STAMP" ]; then remote "drill $DRILL_STAMP"; else remote "drill"; fi
  rc=$?
  [ $rc -eq 0 ] && log "抽测通过" || log "抽测失败（退出码 $rc）"
  exit $rc
fi

# ------------------------------------------------------------
# 备份主流程
# ------------------------------------------------------------
[ -d "$SRC" ] || die "找不到状态目录 $SRC"
command -v tar >/dev/null || die "缺 tar"
command -v sha256sum >/dev/null || die "缺 sha256sum"

STAMP=$(date '+%Y%m%d-%H%M%S')
SNAP=$STAGE_ROOT/staging.$STAMP

log "== SecAgent 状态异地备份 开始（stamp=$STAMP）=="
log "源目录：$SRC（$(find "$SRC" -maxdepth 1 -type f | wc -l) 个顶层文件）"

# ---------- 1. 一致性快照 ----------
rm -rf -- "$SNAP"
mkdir -p "$SNAP/data" || die "无法创建暂存目录"
cp -a "$SRC"/. "$SNAP/data"/ || die "拷贝 $SRC 失败"

FILES=$(cd "$SRC" && find . -type f | sed 's|^\./||' | sort)
log "开始逐文件复核 sha256（快照 vs 源，最多重拷 3 次）：$(printf '%s\n' "$FILES" | grep -c .) 个文件"
BAD=0
while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  if [ ! -f "$SRC/$rel" ]; then
    log "  注意：$rel 在快照期间消失，本次快照不含它"
    rm -f -- "$SNAP/data/$rel"
    continue
  fi
  ok=0
  for try in 1 2 3; do
    a=$(sha256sum "$SRC/$rel" | awk '{print $1}')
    b=$(sha256sum "$SNAP/data/$rel" 2>/dev/null | awk '{print $1}')
    if [ -n "$a" ] && [ "$a" = "$b" ]; then ok=1; break; fi
    sleep 1
    mkdir -p -- "$(dirname "$SNAP/data/$rel")"
    cp -a -- "$SRC/$rel" "$SNAP/data/$rel"
  done
  if [ "$ok" -ne 1 ]; then
    log "  [X] $rel 复核 3 次仍不一致（写入方在备份窗口内一直在改它）"
    BAD=1
  fi
done <<< "$FILES"

if [ "$BAD" -ne 0 ]; then
  rm -rf -- "$SNAP"
  die "源目录在被持续写入，快照不自洽 —— 本次不生成、不推送备份（fail-closed）。请择机重跑。"
fi

# ---------- 2. manifest + meta ----------
( cd "$SNAP" && find data -type f | sort | while IFS= read -r f; do sha256sum "$f"; done ) > "$SNAP/manifest.sha256"
{
  echo "stamp=$STAMP"
  echo "host=$(hostname)"
  echo "source=$SRC"
  echo "created=$(date -Is)"
  echo "files=$(wc -l < "$SNAP/manifest.sha256" | tr -d ' ')"
  echo "bytes=$(du -sb "$SNAP/data" | cut -f1)"
} > "$SNAP/meta.txt"
NF=$(wc -l < "$SNAP/manifest.sha256" | tr -d ' ')
NB=$(du -sh "$SNAP/data" | cut -f1)
log "快照完成：$NF 个文件 / $NB（逐文件 sha256 全部复核通过）"

# ---------- 3. 打包 + 外层 sha256 ----------
ARCH=$ARCH_DIR/data-$STAMP.tar.gz
tar -czf "$ARCH" -C "$SNAP" data manifest.sha256 meta.txt || die "打包失败"
chmod 600 "$ARCH"
( cd "$ARCH_DIR" && sha256sum "data-$STAMP.tar.gz" > "data-$STAMP.tar.gz.sha256" )
chmod 600 "$ARCH_DIR/data-$STAMP.tar.gz.sha256"
SHA=$(awk '{print $1}' "$ARCH_DIR/data-$STAMP.tar.gz.sha256")
log "归档：$ARCH（$(stat -c %s "$ARCH") 字节）sha256=$SHA"
rm -rf -- "$SNAP"

if [ "$MODE" = dry ]; then
  log "== --dry-run：到此为止，未联系 srv2 =="
  log "（正式执行会把同样的归档推给 srv2 并触发恢复抽测）"
  exit 0
fi

# ---------- 4. 推送到 srv2（强制命令通道） ----------
[ -f "$KEY" ] || die "找不到备份专用密钥 $KEY（先跑 scripts/srv1-gen-backup-key.sh 并在 srv2 授权）"
log "推送到 srv2（root@$SRV2，强制命令 push）…"
PUSH_OUT=$(mktemp)
remote "push $STAMP $SHA" "$ARCH" > "$PUSH_OUT" 2>&1
rc=$?
sed 's/^/  /' "$PUSH_OUT"
if [ $rc -ne 0 ]; then
  log "推送失败（退出码 $rc）。归档仍保留在 $ARCH，未删除。"
  log "排查：① 密钥是否已授权 ② srv2 磁盘是否满 ③ srv2 侧 journalctl -u ssh -n 30"
  log "回滚授权（若怀疑是授权改动导致的）：在 srv2 上跑 scripts/srv2-authorize-backup-key.sh --rollback"
  rm -f "$PUSH_OUT"
  exit $rc
fi
rm -f "$PUSH_OUT"

# ---------- 5. 本地归档保留策略 ----------
i=0
for a in $(ls -1 "$ARCH_DIR"/data-*.tar.gz 2>/dev/null | sort -r); do
  i=$((i + 1))
  [ "$i" -le "$KEEP_LOCAL" ] && continue
  log "本地保留策略：删除旧归档 $(basename "$a")"
  rm -f -- "$a" "$a.sha256"
done

log "== 备份完成（stamp=$STAMP，已落 srv2 并通过恢复抽测）=="
