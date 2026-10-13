#!/usr/bin/env bash
# ============================================================
# srv2：接收 srv1 推来的状态备份（SSH 强制命令 / forced command）
# ------------------------------------------------------------
# 安装位置：/usr/local/sbin/secagent-backup-receive（755，root:root）
# 触发方式：srv1 用专用密钥登录 root@srv2，authorized_keys 里写
#           command="/usr/local/sbin/secagent-backup-receive",restrict,...
#           —— 于是这个脚本【代替 shell】执行，客户端发来的命令串落在
#           SSH_ORIGINAL_COMMAND 里，stdin 就是 tar.gz 数据流。
#
# 为什么必须是"强制命令 + 白名单参数"而不是"给一把能 scp 的密钥"：
#   项目里已有的隧道密钥是 restrict,port-forwarding,permitopen=127.0.0.1:55000
#   —— 它连 shell 都开不了，更传不了文件。
#   如果为了备份再开一把"完整 SSH 权限"的钥匙，等于用最小的便利换一把
#   能登录 srv2 root 的万能钥匙。这里的做法是：钥匙只能做下面三件事，
#   命令串不在白名单里一律拒绝，且【写不出去的东西】只有 tar 流一个入口。
#
# 协议（三个动词，其余一律拒绝，exit 64）：
#   push <stamp> <sha256> [enc|plain]   stdin 读归档；先校验 sha256，
#                          加密格式先解出明文体再做结构校验（密文没法 tar -t），
#                          再落盘（600，加密归档【以密文形式落盘】）→ 立刻做恢复抽测
#                          → 抽测不过就删掉（fail-closed：宁可不留，也不留一份救不回来的备份）
#                          第三参缺省 = plain（兼容旧版 srv1 脚本）
#   drill [<stamp>]         对某份（默认最新）备份做恢复抽测，打印 N/N 一致
#   list                    列出已保存的备份（时间、大小、sha256、文件数、格式）
#
# 【2026-10-13 同步更新】加密格式（*.tar.gz.enc）：
#   · 落盘一律保存密文；解密只发生在抽测的临时目录里，明文不留痕
#   · srv2 上必须有同一把密钥 /opt/secagent-backup.key（600）；
#     没有就【拒收】—— 收下一份自己解不开的备份等于没备份
#   · 密钥不一致会在解密那一步暴露（拒绝落盘），不会静默存下一份废数据
#
# 落盘布局：/opt/secagent-backup/<YYYYMMDD-HHMMSS>/
#             data-<stamp>.tar.gz.enc     600（加密归档；过渡期可能是 .tar.gz）
#             data-<stamp>.tar.gz.enc.sha256  600
#             RECEIVED.txt                600（来源、大小、格式、抽测结论）
#             DRILL.log                   600（抽测原始输出）
#           目录 700；保留最近 14 份，更旧的按时间删（14 这个数来自
#           "磁盘坏掉/误删后要能找回最近两周"的诉求，5MB 一份，成本可忽略）
# ============================================================
set -uo pipefail

BASE=/opt/secagent-backup
LOGDIR=/var/log/secagent-backup
LOG=$LOGDIR/receive.log
DRILL=/usr/local/sbin/secagent-backup-drill.sh
KEEP=14
BACKUP_KEY=${BACKUP_KEY:-/opt/secagent-backup.key}
OPENSSL_ITER=${OPENSSL_ITER:-200000}
umask 077

# 所有输出同时进日志（srv2 本地）和 stdout（回给 srv1，最终落在
# srv1 的 journald 里）—— 两边都能查到"这次到底存了什么、抽测结果是什么"。
log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG" >&2; }
say() { printf '%s\n' "$*" | tee -a "$LOG"; }
die() { local rc=$1; shift; say "错误：$*"; exit "$rc"; }

mkdir -p "$BASE" "$LOGDIR" "$BASE/.incoming" || die 70 "无法创建 $BASE / $LOGDIR"
chmod 700 "$BASE" "$BASE/.incoming" "$LOGDIR"

# 命令串来自客户端，这里【一个字符都不执行】，只做白名单匹配。
read -r -a ARGV <<< "${SSH_ORIGINAL_COMMAND:-}"
VERB=${ARGV[0]:-}

# ---------- 恢复抽测（复用同一个脚本，保证"抽测"只有一份实现） ----------
run_drill() {
  local dir=$1
  if [ ! -x "$DRILL" ]; then
    say "错误：找不到抽测脚本 $DRILL"
    return 127
  fi
  "$DRILL" "$dir" 2>&1 | tee -a "$LOG"
  return "${PIPESTATUS[0]}"
}

# ---------- 清理 12 小时前残留的半截上传 ----------
find "$BASE/.incoming" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.tar.gz.enc' -o -name '*.plain' \) -mmin +720 -delete 2>/dev/null || true

# ---------- 保留策略：只留最近 KEEP 份 ----------
prune() {
  local i=0 d
  while IFS= read -r d; do
    i=$((i + 1))
    [ "$i" -le "$KEEP" ] && continue
    # 双保险：名字必须严格是 <8位日期>-<6位时间>，否则绝不 rm -rf
    case "$d" in
      [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;
      *) say "跳过不合规目录名（不删）：$d"; continue ;;
    esac
    say "保留策略：删除旧备份 $d"
    rm -rf -- "$BASE/$d"
  done < <(ls -1 "$BASE" 2>/dev/null | grep -E '^[0-9]{8}-[0-9]{6}$' | sort -r)
}

# 在目录里定位归档（优先加密格式；兼容过渡期明文）
archive_in() {
  local d=$1
  if [ -f "$BASE/$d/data-$d.tar.gz.enc" ]; then printf '%s' "$BASE/$d/data-$d.tar.gz.enc"; return 0; fi
  if [ -f "$BASE/$d/data-$d.tar.gz" ]; then printf '%s' "$BASE/$d/data-$d.tar.gz"; return 0; fi
  return 1
}

# ---------- push ----------
do_push() {
  local stamp=${ARGV[1]:-} want=${ARGV[2]:-} fmt=${ARGV[3]:-plain}
  local tmp dest got ext chk plain=""
  [[ $stamp =~ ^[0-9]{8}-[0-9]{6}$ ]] || die 64 "stamp 格式非法（要 YYYYMMDD-HHMMSS）：$stamp"
  [[ $want =~ ^[0-9a-f]{64}$ ]] || die 64 "sha256 格式非法"
  case "$fmt" in
    enc)   ext=".tar.gz.enc" ;;
    plain) ext=".tar.gz" ;;
    *)     die 64 "格式不在白名单内：$fmt（只接受 enc / plain）" ;;
  esac
  if [ "$fmt" = "enc" ] && [ ! -f "$BACKUP_KEY" ]; then
    die 70 "收到加密备份，但本机没有密钥 $BACKUP_KEY —— 拒收（收下一份自己解不开的备份等于没备份）"
  fi

  dest=$BASE/$stamp
  if [ -e "$dest" ]; then
    die 3 "该时间点的备份已存在，拒绝覆盖：$dest"
  fi

  tmp=$BASE/.incoming/$stamp$ext
  say "接收中：$stamp ← srv1（格式 $fmt，sha256 期望 $want）"
  if ! cat > "$tmp"; then
    rm -f "$tmp"
    die 5 "读取 stdin 失败"
  fi
  chmod 600 "$tmp"

  got=$(sha256sum "$tmp" | awk '{print $1}')
  if [ "$got" != "$want" ]; then
    local sz; sz=$(stat -c %s "$tmp")
    rm -f "$tmp"
    die 6 "sha256 不匹配（收到 $(printf %s "$got" | cut -c1-16)… 期望 $(printf %s "$want" | cut -c1-16)…，$sz 字节）——已丢弃，未落盘"
  fi
  say "sha256 校验通过：$got（$(stat -c %s "$tmp") 字节）"

  # 结构白名单：只接受 data/ 与两个元文件，且拒绝绝对路径与 ..
  # 为什么：这份归档将来会被【解压】，一个带 ../ 或符号链接的成员
  # 就是一个任意写原语。宁可拒收，也不要存一份能写出 /opt 之外的备份。
  # 加密格式：密文不能直接 tar -t，先解出明文体再校验（明文只存在于 .incoming，随后删除）。
  chk="$tmp"
  if [ "$fmt" = "enc" ]; then
    plain=$BASE/.incoming/$stamp.tar.gz.plain
    if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter "$OPENSSL_ITER" \
           -in "$tmp" -out "$plain" -pass file:"$BACKUP_KEY" 2>/dev/null; then
      rm -f "$tmp" "$plain"
      die 7 "解密失败（srv1 与 srv2 的 $BACKUP_KEY 不一致？密文损坏？）—— 已丢弃，未落盘"
    fi
    say "解密成功（明文 $(stat -c %s "$plain") 字节）；按明文做归档结构校验，落盘仍存密文"
    chk="$plain"
  fi

  local members bad
  members=$(tar -tzf "$chk") || { rm -f "$tmp" "$plain"; die 7 "不是合法的 tar.gz"; }
  if printf '%s\n' "$members" | grep -qE '^/|(^|/)\.\.(/|$)'; then
    rm -f "$tmp" "$plain"
    die 7 "归档含绝对路径或 .. 成员，拒收"
  fi
  bad=$(printf '%s\n' "$members" | grep -vE '^(data/|manifest\.sha256$|meta\.txt$)' | head -5)
  if [ -n "$bad" ]; then
    rm -f "$tmp" "$plain"
    die 7 "归档含白名单外的成员，拒收：$(printf '%s' "$bad" | tr '\n' ' ')"
  fi
  say "归档结构校验通过：$(printf '%s\n' "$members" | wc -l) 个成员"
  [ -n "$plain" ] && rm -f "$plain"     # 明文绝不留痕

  mkdir -m 700 "$dest" || { rm -f "$tmp"; die 70 "无法创建 $dest"; }
  mv "$tmp" "$dest/data-$stamp$ext"
  chmod 600 "$dest/data-$stamp$ext"
  ( cd "$dest" && sha256sum "data-$stamp$ext" > "data-$stamp$ext.sha256" )
  chmod 600 "$dest/data-$stamp$ext.sha256"

  say "落盘完成：$dest/data-$stamp$ext（权限 600；$([ "$fmt" = enc ] && echo '以密文形式存储' || echo '明文存储（旧格式）'))"
  say "== 恢复抽测（解到临时目录逐文件比对）=="
  if run_drill "$dest" > "$dest/DRILL.log" 2>&1; then
    cat "$dest/DRILL.log" | tee -a "$LOG"
    local verdict; verdict=$(tail -1 "$dest/DRILL.log")
  else
    cat "$dest/DRILL.log" | tee -a "$LOG"
    rm -rf "$dest"
    die 4 "恢复抽测不通过 —— 已删除这份备份（fail-closed），请检查 srv1 侧 /opt/secagent/data 是否正在被写坏 / 密钥是否一致"
  fi
  chmod 600 "$dest/DRILL.log"

  {
    echo "stamp      = $stamp"
    echo "received   = $(date -Is)"
    echo "from       = srv1（强制命令通道 secagent-backup-receive）"
    echo "format     = $fmt"
    echo "at_rest    = $([ "$fmt" = enc ] && echo 'encrypted (aes-256-cbc/pbkdf2)' || echo plain)"
    echo "bytes      = $(stat -c %s "$dest/data-$stamp$ext")"
    echo "sha256     = $got"
    echo "drill      = $verdict"
  } > "$dest/RECEIVED.txt"
  chmod 600 "$dest/RECEIVED.txt"

  prune
  say "== srv2 现有备份 =="
  do_list
}

# ---------- list ----------
do_list() {
  local d n=0 f
  for d in $(ls -1 "$BASE" 2>/dev/null | grep -E '^[0-9]{8}-[0-9]{6}$' | sort -r); do
    n=$((n + 1))
    if ! f=$(archive_in "$d"); then continue; fi
    say "$(printf '%2d' "$n"). $d  $(stat -c %s "$f") 字节  $(stat -c '%A' "$f")  $([ "${f##*.}" = enc ] && echo enc || echo plain)  $(cut -d' ' -f1 "$f.sha256" 2>/dev/null)  $( [ -f "$BASE/$d/DRILL.log" ] && tail -1 "$BASE/$d/DRILL.log" || echo '')"
  done
  [ "$n" -gt 0 ] || say "（srv2 上还没有任何备份）"
  if [ -f "$BACKUP_KEY" ]; then
    say "解密密钥：$BACKUP_KEY 存在（$(stat -c %A "$BACKUP_KEY")）"
  else
    say "解密密钥：[X] 缺失 $BACKUP_KEY —— 加密备份现在解不开"
  fi
}

# ---------- drill ----------
do_drill() {
  local stamp=${ARGV[1]:-} dir
  if [ -n "$stamp" ]; then
    [[ $stamp =~ ^[0-9]{8}-[0-9]{6}$ ]] || die 64 "stamp 格式非法：$stamp"
    dir=$BASE/$stamp
  else
    stamp=$(ls -1 "$BASE" 2>/dev/null | grep -E '^[0-9]{8}-[0-9]{6}$' | sort -r | head -1)
    [ -n "$stamp" ] || die 66 "srv2 上没有任何备份可抽测"
    dir=$BASE/$stamp
  fi
  [ -d "$dir" ] || die 66 "找不到备份目录：$dir"
  say "对 $stamp 做恢复抽测（只读，不改动已保存的备份）"
  run_drill "$dir"
  return $?
}

case "$VERB" in
  push)  do_push ;;
  list)  say "== srv2 备份清单（$BASE）=="; do_list ;;
  drill) do_drill ;;
  "")    die 64 "缺少命令（本密钥只接受 push / drill / list）" ;;
  *)     die 64 "命令不在白名单内：$VERB（只接受 push / drill / list）" ;;
esac
