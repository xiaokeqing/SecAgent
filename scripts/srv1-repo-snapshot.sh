#!/usr/bin/env bash
# ============================================================
# srv1-repo-snapshot.sh —— 维护「权威仓库的只读快照」
# ------------------------------------------------------------
# 为什么需要快照（真事）：srv1 现在【连不上 GitHub】（实测：到 github.com:443 超时、
#   到 ssh.github.com:443 能建 TCP 但 Permission denied (publickey)，且 /root/.ssh
#   下没有任何 GitHub 凭据），所以 `git fetch origin main` 这条"首选基准"在 srv1 上
#   根本走不通。漂移巡检必须有一个【不依赖网络】的权威来源，
#   否则它只能退回"拿服务器自己那份旧仓库当基准"—— 那正是会造成"差点丢落地物"的循环论证。
#   所以：发布侧（Windows，权威仓库所在机器）把权威提交的文件树 + 哈希清单打成一份
#   只读快照推过来，srv1 只读消费；快照过期 → 漂移巡检直接失败（fail-closed）。
#
# 快照目录布局（/opt/secagent/.repo-snapshot）：
#   SNAPSHOT-INFO      KEY=VALUE：SNAP_COMMIT / SNAP_TIME_EPOCH / SNAP_HASHMODE / SNAP_FILES / SNAP_SOURCE
#   MANIFEST.sha256    "<sha256>  <path>"，哈希口径=文件内容去掉全部 CR（HASHMODE 里写明）
#   tree/<path>        与权威提交逐字节相同的文件（只含 scripts/ deploy/，与巡检范围一致）
#
# 用法（srv1，root）：
#   bash srv1-repo-snapshot.sh --install <tgz>      # 安装发布侧生成的快照（推荐路径；原子替换+校验+置只读）
#   bash srv1-repo-snapshot.sh --from-git [ref]     # 本机 git 已有该 ref 时直接生成（ref 默认 origin/main）
#   bash srv1-repo-snapshot.sh --status             # 看当前快照的信息与年龄
#   bash srv1-repo-snapshot.sh --verify             # 只做完整性 + 新鲜度校验（巡检用的是同一套判据）
#
# 退出码：0=成功；1=校验不过；2=用法/环境错误
# ============================================================
set -uo pipefail

REPO=${DRIFT_REPO:-/opt/secagent}
SNAPSHOT=${DRIFT_SNAPSHOT:-/opt/secagent/.repo-snapshot}
DIRS=${DRIFT_DIRS:-"scripts deploy"}
SNAP_MAX_AGE_DAYS=${DRIFT_SNAPSHOT_MAX_AGE_DAYS:-7}
SNAP_HASHMODE_EXPECT=sha256-cr-stripped
HASHMODE=$SNAP_HASHMODE_EXPECT

nz_file() { tr -d '\r' < "$1" | sha256sum | awk '{print $1}'; }
die() { echo "snapshot: [X] $*" >&2; exit "${2:-1}"; }
say() { echo "snapshot: $*"; }

# 校验并读取一份 stage 树（stage 里应有 SNAPSHOT-INFO / MANIFEST.sha256 / tree/）
verify_tree() { # 1=stage 目录；成功=0
  local stage=$1 info="$1/SNAPSHOT-INFO" mani="$1/MANIFEST.sha256" tree="$1/tree"
  [ -f "$info" ] || { echo "snapshot: [!] 缺 SNAPSHOT-INFO"; return 1; }
  [ -f "$mani" ] || { echo "snapshot: [!] 缺 MANIFEST.sha256"; return 1; }
  [ -d "$tree" ] || { echo "snapshot: [!] 缺 tree/"; return 1; }
  local SNAP_COMMIT="" SNAP_TIME_EPOCH="" SNAP_HASHMODE=""
  # shellcheck disable=SC1090
  . "$info" || { echo "snapshot: [!] SNAPSHOT-INFO 不可读"; return 1; }
  [ -n "${SNAP_COMMIT:-}" ] || { echo "snapshot: [!] 缺 SNAP_COMMIT"; return 1; }
  case "${SNAP_TIME_EPOCH:-}" in ''|*[!0-9]*) echo "snapshot: [!] SNAP_TIME_EPOCH 不是整数"; return 1;; esac
  [ "${SNAP_HASHMODE:-}" = "$SNAP_HASHMODE_EXPECT" ] || { echo "snapshot: [!] 哈希口径不认：${SNAP_HASHMODE:-}"; return 1; }
  local bad=0 n=0 line h p got
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    h=$(printf '%s' "$line" | awk '{print $1}'); p=$(printf '%s' "$line" | awk '{print $2}')
    [ -n "$h" ] && [ -n "$p" ] || continue
    n=$((n + 1))
    if [ ! -f "$tree/$p" ]; then bad=$((bad + 1)); [ "$bad" -le 5 ] && echo "snapshot: [!] tree 里缺 $p"; continue; fi
    got=$(nz_file "$tree/$p")
    [ "$got" = "$h" ] || { bad=$((bad + 1)); [ "$bad" -le 5 ] && echo "snapshot: [!] 哈希对不上 $p"; }
  done < "$mani"
  [ "$n" -gt 0 ] || { echo "snapshot: [!] 清单为空"; return 1; }
  [ "$bad" -eq 0 ] || { echo "snapshot: [!] $bad/$n 个文件校验失败"; return 1; }
  echo "snapshot: 校验通过（$n 个文件，commit=$(printf '%s' "$SNAP_COMMIT" | cut -c1-12)）"
  return 0
}

# 原子替换：旧目录改名保留（便于回滚），新目录上位并置只读
install_tree() { # 1=stage 目录
  local stage=$1 ts old
  ts=$(date +%Y%m%d-%H%M%S)
  old="$SNAPSHOT.old-$ts"
  if [ -d "$SNAPSHOT" ]; then
    chmod -R u+w "$SNAPSHOT" 2>/dev/null || true
    mv "$SNAPSHOT" "$old" || die "旧快照挪不动：$SNAPSHOT → $old" 1
    say "旧快照已保留为 $old（确认无误后可删）"
  fi
  if ! mv "$stage" "$SNAPSHOT"; then
    [ -d "$old" ] && mv "$old" "$SNAPSHOT" && say "安装失败，已回滚旧快照"
    die "快照安装失败" 1
  fi
  chmod -R a-w "$SNAPSHOT" 2>/dev/null || true
  find "$SNAPSHOT" -type d -exec chmod 555 {} + 2>/dev/null || true
  say "快照已安装并置为只读：$SNAPSHOT"
}

read_info() { # 打印 INFO 关键字段
  local info="$SNAPSHOT/SNAPSHOT-INFO"
  [ -f "$info" ] || die "没有快照：$info 不存在（先 --install 或 --from-git）" 2
  local SNAP_COMMIT="" SNAP_TIME_EPOCH="" SNAP_HASHMODE="" SNAP_SOURCE="" SNAP_FILES=""
  # shellcheck disable=SC1090
  . "$info"
  local now age
  now=$(date +%s); age=$(( now - ${SNAP_TIME_EPOCH:-0} ))
  echo "快照目录  : $SNAPSHOT"
  echo "权威提交  : ${SNAP_COMMIT:-?}"
  echo "生成时间  : ${SNAP_TIME_EPOCH:-?}（$(date -d "@${SNAP_TIME_EPOCH:-0}" '+%F %T' 2>/dev/null || echo '?')）"
  echo "年龄      : $(( age / 86400 )) 天（阈值 ${SNAP_MAX_AGE_DAYS} 天）"
  echo "哈希口径  : ${SNAP_HASHMODE:-?}"
  echo "文件数    : ${SNAP_FILES:-?}"
  echo "来源      : ${SNAP_SOURCE:-?}"
  if [ "$age" -gt $(( SNAP_MAX_AGE_DAYS * 86400 )) ]; then
    echo "新鲜度    : [X] 已过期 —— 漂移巡检会 fail-closed（退出 2）"
  else
    echo "新鲜度    : OK"
  fi
}

MODE=""; ARG1=""; ARG2=""
case "${1:-}" in
  --install) MODE=install; ARG1=${2:-} ;;
  --from-git) MODE=fromgit; ARG1=${2:-origin/main} ;;
  --status)  MODE=status ;;
  --verify)  MODE=verify ;;
  --help|-h) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "未知参数：${1:-}（--install <tgz> / --from-git [ref] / --status / --verify）" >&2; exit 2 ;;
esac

case "$MODE" in
  status) read_info; exit 0 ;;
  verify)
    read_info
    verify_tree "$SNAPSHOT" || exit 1
    exit 0 ;;
  install)
    [ -n "$ARG1" ] || die "--install 需要给出 tgz 路径" 2
    [ -f "$ARG1" ] || die "找不到 $ARG1" 2
    command -v tar >/dev/null || die "缺 tar" 2
    STAGE=$(mktemp -d "${TMPDIR:-/tmp}/repo-snapshot.XXXXXX") || die "mktemp 失败" 2
    # 安全检查：不允许多余的绝对路径/上跳路径成员
    if tar -tzf "$ARG1" 2>/dev/null | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
      rm -rf "$STAGE"; die "tgz 里有绝对路径或 .. —— 拒绝解包" 2
    fi
    tar -xzf "$ARG1" -C "$STAGE" || { rm -rf "$STAGE"; die "解包失败" 2; }
    # 兼容"顶层套一层目录"的打包方式
    if [ ! -f "$STAGE/SNAPSHOT-INFO" ]; then
      inner=$(find "$STAGE" -maxdepth 2 -name SNAPSHOT-INFO -printf '%h\n' 2>/dev/null | head -1)
      [ -n "$inner" ] && STAGE=$inner
    fi
    verify_tree "$STAGE" || { rm -rf "$STAGE"; die "快照内容校验不过，拒绝安装" 1; }
    install_tree "$STAGE" ; rc=$?
    [ $rc -eq 0 ] && read_info
    exit $rc ;;
  fromgit)
    REF=$ARG1
    command -v git >/dev/null || die "缺 git" 2
    git -C "$REPO" rev-parse --verify --quiet "$REF^{commit}" >/dev/null || \
      die "$REPO 里没有 ref：$REF（先 git fetch origin main）" 2
    COMMIT=$(git -C "$REPO" rev-parse "$REF")
    STAGE=$(mktemp -d "${TMPDIR:-/tmp}/repo-snapshot.XXXXXX") || die "mktemp 失败" 2
    mkdir -p "$STAGE/tree" || die "建目录失败" 2
    : > "$STAGE/MANIFEST.sha256"
    n=0; skipped=0
    while IFS= read -r p; do
      [ -n "$p" ] || continue
      if printf '%s' "$p" | grep -qE '[[:space:]]'; then
        skipped=$((skipped + 1)); continue            # 路径里有空格/制表符就不冒险（本仓库没有这种路径）
      fi
      mkdir -p "$STAGE/tree/$(dirname "$p")" || { rm -rf "$STAGE"; die "建目录失败：$p" 2; }
      git -C "$REPO" show "$REF:$p" > "$STAGE/tree/$p" || { rm -rf "$STAGE"; die "取文件失败：$p" 2; }
      printf '%s  %s\n' "$(nz_file "$STAGE/tree/$p")" "$p" >> "$STAGE/MANIFEST.sha256"
      n=$((n + 1))
    done < <(git -C "$REPO" ls-tree -r --name-only "$REF" -- $DIRS | sort)
    [ "$n" -gt 0 ] || { rm -rf "$STAGE"; die "ref $REF 下 $DIRS 里没有任何文件" 2; }
    {
      echo "SNAP_COMMIT=$COMMIT"
      echo "SNAP_TIME_EPOCH=$(date +%s)"
      echo "SNAP_HASHMODE=$HASHMODE"
      echo "SNAP_FILES=$n"
      echo "SNAP_SOURCE=from-git:$REPO@$REF"
    } > "$STAGE/SNAPSHOT-INFO"
    say "已从 $REF 生成快照内容：$n 个文件（跳过 $skipped 个含空格的路径）"
    verify_tree "$STAGE" || { rm -rf "$STAGE"; die "生成的内容自校验不过" 1; }
    install_tree "$STAGE"; rc=$?
    [ $rc -eq 0 ] && read_info
    exit $rc ;;
esac
