#!/usr/bin/env bash
# ============================================================
# srv1：把 /opt/secagent/data 打包 + 加密 + 校验 + 推到 srv2（异地备份）
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
# 【2026-10-13 改动 1】排除可再生的观测数据（access.jsonl*）：
#   以前整个 data/ 一起打包，把 data/access.jsonl（每天最多 64MB×7）也塞进去。
#   它是【可再生的观测数据】，而备份的价值在于"封禁表 / 处置审计 / 额度"这些
#   不可再生的东西；把几十上百 MB 的日志混进去，既撑大异地存储，又会在
#   恢复时把真正重要的文件淹掉。现在打包前排除 access.jsonl*，
#   并把"排除了哪些、多大"如实写进 meta.txt 与日志 —— 排除必须是可见的。
#
# 【2026-10-13 改动 2】对称加密（不引入任何新依赖）：
#   以前推给 srv2 的是【明文 tar.gz】，里面有封禁名单、处置审计和真实 IP。
#   srv2 是蜜罐机、暴露面更大：拿到 srv2 的磁盘就等于拿到全部审计内容。
#   现在用系统自带的 openssl 做 AES-256-CBC + PBKDF2。
#   密钥：/opt/secagent-backup.key（权限 600，root）。
#     · srv1 与 srv2 各一份，内容相同；【不进仓库】
#     · 丢了密钥 = 所有备份都解不开（见 RUNBOOK 的后果说明）
#   为什么不是 gpg：这台机器上 openssl 一定有（openssl 1.1.1k），
#     gpg 要先确认存在；任务要求"零新增依赖"，所以选 openssl。
#
# 上传通道（重要，与最初的设想不同）：
#   项目里【已有的】srv1→srv2 SSH 通道是一把隧道密钥，它在 srv2 侧被限制成
#   restrict,port-forwarding,permitopen="127.0.0.1:55000" —— 连 shell 都开不了，
#   更不可能传文件。所以这里用【另开一把专用密钥 + srv2 侧强制命令】的方式：
#     密钥只能执行 /usr/local/sbin/secagent-backup-receive，
#     只能做 push / drill / list 三件事，拿不到 shell、tty、端口转发。
#   即"为备份新开一条最小权限通道"，而不是把隧道密钥放宽成万能钥匙。
#   协议带了格式参数：push <stamp> <sha256> enc（旧的无第三参 = plain，向后兼容）。
#
# 为什么先快照再打包（而不是直接 tar 正在被写的目录）：
#   data/ 里的文件是活文件（容器一直在写）。直接 tar 可能把一个文件读到一半，
#   产出一份"能解开、但内容自相矛盾"的备份 —— 那比没有备份更危险，
#   因为它看起来是成功的。这里先 cp 到暂存目录，再对每个文件复核 sha256，
#   对不上就重拷（最多 3 次）；仍对不上就【失败退出、不推】，绝不推一份可能坏的。
#
# 用法（root@srv1）：
#   bash srv1-data-backup.sh               # 备份 + 加密 + 推送 + srv2 侧恢复抽测
#   bash srv1-data-backup.sh --dry-run     # 只做快照+加密，不联系 srv2（演练）
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

# 对称加密密钥（600）。srv2 侧同一份；不进仓库。
BACKUP_KEY=${BACKUP_KEY:-/opt/secagent-backup.key}
# 打包前排除的文件（bash 通配，按文件名匹配，顶层/嵌套都认）
EXCLUDE_GLOBS=("access.jsonl*")

MODE=backup
DRILL_STAMP=""
case "${1:-}" in
  --dry-run)  MODE=dry ;;
  --status)   MODE=status ;;
  --drill)    MODE=drill; DRILL_STAMP=${2:-} ;;
  --help|-h)  sed -n '1,60p' "$0"; exit 0 ;;
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

# 归档现在一律是 .enc（加密）；旧的 .tar.gz 仍会被 --status 列出来便于过渡期查看
latest_local() { ls -1 "$ARCH_DIR"/data-*.tar.gz.enc 2>/dev/null | sort | tail -1; }

is_excluded() {  # 1=相对路径（用 basename 匹配，顶层/嵌套都认）
  local b=${1##*/} g
  for g in "${EXCLUDE_GLOBS[@]}"; do
    # shellcheck disable=SC2254
    case "$b" in $g) return 0 ;; esac
  done
  return 1
}

# ------------------------------------------------------------
# --status / --drill：不产生新备份，只查询
# ------------------------------------------------------------
if [ "$MODE" = status ]; then
  log "== srv1 本地归档（$ARCH_DIR，保留最近 $KEEP_LOCAL 份；*.tar.gz.enc = 加密归档）=="
  ls -la "$ARCH_DIR" 2>/dev/null | sed 's/^/  /'
  if [ -f "$BACKUP_KEY" ]; then
    log "== 加密密钥 ==  存在：$BACKUP_KEY（$(stat -c %A "$BACKUP_KEY")，$(stat -c %s "$BACKUP_KEY") 字节）"
  else
    log "== 加密密钥 ==  [X] 缺失：$BACKUP_KEY —— 备份会失败（fail-closed，不会退化成明文）"
  fi
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
command -v openssl >/dev/null || die "缺 openssl（加密要靠它；本脚本刻意不引第三方依赖）"
# fail-closed：宁可这次不备份，也绝不"悄悄退回明文"
[ -f "$BACKUP_KEY" ] || die "找不到加密密钥 $BACKUP_KEY（600，root）。
  生成：openssl rand -hex 32 > $BACKUP_KEY && chmod 600 $BACKUP_KEY
  并把它放到 srv2 的同一路径（内容必须一致）——见 RUNBOOK 对应小节"

STAMP=$(date '+%Y%m%d-%H%M%S')
SNAP=$STAGE_ROOT/staging.$STAMP

log "== SecAgent 状态异地备份 开始（stamp=$STAMP）=="
log "源目录：$SRC（$(find "$SRC" -maxdepth 1 -type f | wc -l) 个顶层文件）"
log "加密：openssl aes-256-cbc + pbkdf2(-iter 200000)，密钥 $BACKUP_KEY"

# ---------- 1. 一致性快照 ----------
rm -rf -- "$SNAP"
mkdir -p "$SNAP/data" || die "无法创建暂存目录"
cp -a "$SRC"/. "$SNAP/data"/ || die "拷贝 $SRC 失败"

# 排除清单：先算出来（后面 FILES 与快照都要按它保持一致），
# 并把"排除了什么、多大"记下来 —— 排除必须是可见的，不能静默少文件。
EXCLUDED_INFO=""; EXCLUDED_N=0
for g in "${EXCLUDE_GLOBS[@]}"; do
  for f in "$SRC"/$g; do
    [ -e "$f" ] || continue
    EXCLUDED_INFO="$EXCLUDED_INFO $(basename "$f"):$(stat -c %s "$f")B"
    EXCLUDED_N=$((EXCLUDED_N + 1))
  done
done
if [ "$EXCLUDED_N" -gt 0 ]; then
  log "排除（可再生观测数据，$EXCLUDED_N 个）：$EXCLUDED_INFO"
else
  log "排除（可再生观测数据）：本轮到打包时 $SRC 下没有匹配 ${EXCLUDE_GLOBS[*]} 的文件"
fi

FILES=$(cd "$SRC" && find . -type f | sed 's|^\./||' | sort | while IFS= read -r f; do is_excluded "$f" || printf '%s\n' "$f"; done)

# 让快照与 FILES 严格一致：把被排除的（以及期间新冒出来的）从快照里删掉，
# 保证"manifest 里有什么 = 归档里有什么"，不给恢复留歧义。
if [ "$EXCLUDED_N" -gt 0 ]; then
  ( cd "$SNAP/data" && find . -type f | sed 's|^\./||' ) | while IFS= read -r srel; do
    if printf '%s\n' "$FILES" | grep -qxF -- "$srel"; then :; else rm -f -- "$SNAP/data/$srel"; fi
  done
fi

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
  echo "excluded_count=$EXCLUDED_N"
  echo "excluded=$EXCLUDED_INFO"
  echo "encryption=openssl-aes-256-cbc-pbkdf2-iter200000"
} > "$SNAP/meta.txt"
NF=$(wc -l < "$SNAP/manifest.sha256" | tr -d ' ')
NB=$(du -sh "$SNAP/data" | cut -f1)
log "快照完成：$NF 个文件 / $NB（逐文件 sha256 全部复核通过；已排除 $EXCLUDED_N 个观测日志）"

# ---------- 3. 打包 + 加密 + 外层 sha256 ----------
PLAIN=$ARCH_DIR/.data-$STAMP.tar.gz.plain
ARCH=$ARCH_DIR/data-$STAMP.tar.gz.enc
tar -czf "$PLAIN" -C "$SNAP" data manifest.sha256 meta.txt || { rm -f -- "$PLAIN"; die "打包失败"; }
chmod 600 "$PLAIN"
PLAIN_SZ=$(stat -c %s "$PLAIN")

if ! openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
       -in "$PLAIN" -out "$ARCH" -pass file:"$BACKUP_KEY" 2>/dev/null; then
  rm -f -- "$PLAIN" "$ARCH"; die "加密失败（openssl 报错；密钥文件是否可读？）"
fi
# 明文只在加密期间短暂存在，立刻删除 —— 服务器上不留明文副本
rm -f -- "$PLAIN"
chmod 600 "$ARCH"

( cd "$ARCH_DIR" && sha256sum "data-$STAMP.tar.gz.enc" > "data-$STAMP.tar.gz.enc.sha256" )
chmod 600 "$ARCH_DIR/data-$STAMP.tar.gz.enc.sha256"
SHA=$(awk '{print $1}' "$ARCH_DIR/data-$STAMP.tar.gz.enc.sha256")
# 自证加密过：密文前两个字节不该是 gzip 魔数 1f 8b
MAGIC=$(head -c 2 "$ARCH" | od -An -tx1 | tr -d ' \n')
log "归档：$ARCH（明文 $PLAIN_SZ 字节 → 密文 $(stat -c %s "$ARCH") 字节）sha256=$SHA"
log "格式自证：密文头 2 字节 = $MAGIC（gzip 魔数应为 1f8b；不同即说明确实被加密了）"
rm -rf -- "$SNAP"

if [ "$MODE" = dry ]; then
  log "== --dry-run：到此为止，未联系 srv2 =="
  log "（正式执行会把同样的加密归档推给 srv2 并触发恢复抽测）"
  log "本地自查：openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in $ARCH -pass file:$BACKUP_KEY | tar -tzf - | head"
  exit 0
fi

# ---------- 4. 推送到 srv2（强制命令通道；第三个参数 = 格式 enc） ----------
[ -f "$KEY" ] || die "找不到备份专用密钥 $KEY（先跑 scripts/srv1-gen-backup-key.sh 并在 srv2 授权）"
log "推送到 srv2（root@$SRV2，强制命令 push … enc）…"
PUSH_OUT=$(mktemp)
remote "push $STAMP $SHA enc" "$ARCH" > "$PUSH_OUT" 2>&1
rc=$?
sed 's/^/  /' "$PUSH_OUT"
if [ $rc -ne 0 ]; then
  log "推送失败（退出码 $rc）。归档仍保留在 $ARCH，未删除。"
  log "排查：① 密钥是否已授权 ② srv2 是否有 /opt/secagent-backup.key 且与 srv1 一致"
  log "      ③ srv2 磁盘是否满 ④ srv2 侧 journalctl -u ssh -n 30"
  log "回滚授权（若怀疑是授权改动导致的）：在 srv2 上跑 scripts/srv2-authorize-backup-key.sh --rollback"
  rm -f "$PUSH_OUT"
  exit $rc
fi
rm -f "$PUSH_OUT"

# ---------- 5. 本地归档保留策略 ----------
i=0
for a in $(ls -1 "$ARCH_DIR"/data-*.tar.gz.enc 2>/dev/null | sort -r); do
  i=$((i + 1))
  [ "$i" -le "$KEEP_LOCAL" ] && continue
  log "本地保留策略：删除旧归档 $(basename "$a")"
  rm -f -- "$a" "$a.sha256"
done

log "== 备份完成（stamp=$STAMP，已加密落 srv2 并通过恢复抽测）=="
