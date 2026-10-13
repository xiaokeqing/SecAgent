#!/usr/bin/env bash
# ============================================================
# srv1-drift-check.sh —— 「权威仓库 ↔ 服务器」漂移巡检
# ------------------------------------------------------------
# 为什么需要它（真事）：srv1 的 /opt/secagent 一度【不是 git 仓库】，
#   落地物只存在于服务器磁盘上 —— RUNBOOK §21 与 20 个落地文件
#   曾差点丢掉，是靠手工捞回来的。这类损失不会被任何"健康检查"发现：
#   服务器一切正常，只是"这台机器就是唯一副本"。
#   本脚本每天把服务器上的落地文件与【权威来源】逐文件比一次，把
#   "只存在服务器"和"和权威来源不一致"的点名报出来。
#
# 【2026-10-13 重大修正：比对基准必须是"权威来源"，不是服务器自己那份仓库】
#   旧版基准 = `git -C /opt/secagent show HEAD:<path>`，也就是【服务器自己的 HEAD】。
#   这是循环论证：服务器上的文件本来就来自这份工作树，
#   一旦服务器仓库自己落后/分叉（实测就是这样：srv1 的 HEAD 停在 2999371，
#   而 GitHub main 早已前进 8 个提交），巡检会拿"旧仓库"去证明"服务器没错"，
#   结论不可信，真实漂移被静默吞掉。
#   现在基准只有两个，按顺序尝试（DRIFT_SOURCE=auto）：
#     ① origin/main —— 先 `git fetch` 再 `git show origin/main:<path>`（首选，权威）
#     ② 只读快照   —— /opt/secagent/.repo-snapshot/（发布侧生成的文件树 + 清单）
#   ② 是【fail-closed】的：
#        · 快照缺失 / 清单缺失 / 树缺失 / 哈希对不上 / 格式版本不认 → 退出 2
#        · 快照年龄 > DRIFT_SNAPSHOT_MAX_AGE_DAYS（默认 7 天）→ 退出 2
#      绝不"静默拿一份旧快照当权威"。宁可当天的自检报"检查自身失败"。
#
# 比对方式：
#   服务器侧：sha256( /opt/secagent/<path> )
#   权威侧  ：sha256( git show origin/main:<path> )  或  快照清单里的哈希
#   —— 用内容哈希而不是 mtime/大小；两边都先 tr -d '\r'，
#      因此 CRLF↔LF 不算漂移（实测：仓库 .gitattributes 对 *.ps1 是 eol=crlf，
#      Linux 检出后工作树是 LF，旧版按原始字节比会恒定误报 9 个 .ps1；
#      这类"假失败"会让检查天天红、很快没人看）。
#
# 三个计数（有【未被登记】的差异即失败，进每日自检的失败项）：
#   diff            = 两边都有、内容不一致
#   missing_in_repo = 服务器有、权威来源里没有   ← "落地物只存在服务器"
#   missing_on_server = 权威来源里有、服务器上没有
#
# 关于「登记表」（accepted）—— 为什么必须有：
#   仓库与服务器本来就不会字节级同步（临时探针、运维现场新增的探测脚本等）。
#   不加区分，这个检查从第一天起就永远红 —— 一个永远红的检查等于没有检查。
#   所以这里用一份【显式登记表】把"已知且已接受"的偏差记在书面上：
#     /opt/secagent/deploy/srv1-drift-accepted.txt
#     每行： <sha256>  <path>   # 原因（可选）
#   · 登记过的偏差算 accepted，不计入失败，但【仍然原样打印在报告里】——
#     可见的债，不是藏起来的债
#   · 登记是"内容哈希"级别的：被登记的文件只要再改一个字节，立刻重新变成 diff
#   · 新增/改动文件不在登记表里 → 立即失败（这正是我们要抓的）
#   · --accept 把当前状态重新登记；RUNBOOK 里写明"登记表应当越缩越短，
#     目标是把每一项都变成仓库里的提交"
#
# 输出：末尾一行机读汇总 + 明细写 /opt/secagent/logs/drift-report.txt
#   drift: diff=<n> missing_in_repo=<n> missing_on_server=<n> accepted=<m> baseline=<origin/main@sha|snapshot@sha age=..d>
#
# 退出码：0=无未登记差异；1=有未登记差异；2=配置/依赖/基准错误（含快照过期，fail-closed）
#
# 用法（srv1，root）：
#   bash srv1-drift-check.sh              # 正常巡检（每日自检调用）
#   bash srv1-drift-check.sh --status     # 同上，但把完整报告打到 stdout
#   bash srv1-drift-check.sh --baseline   # 只解析并打印"这次会拿什么当权威"，然后退出
#   bash srv1-drift-check.sh --accept     # 把当前状态登记为"已接受"（会改登记表，带备份）
#   bash srv1-drift-check.sh --no-report  # 不写报告文件，只算（自测用）
# 环境变量：
#   DRIFT_SOURCE=auto|origin|snapshot     （默认 auto）
#   DRIFT_SNAPSHOT=/opt/secagent/.repo-snapshot
#   DRIFT_SNAPSHOT_MAX_AGE_DAYS=7
#   DRIFT_FETCH_TIMEOUT=25                （git fetch 超时秒数）
#   DRIFT_REMOTE=origin  DRIFT_BRANCH=main
# 临时关闭：把每日自检里的第 5 项注释掉，或设 DRIFT_CHECK_DISABLED=1
# ============================================================
set -uo pipefail

SERVER_ROOT=${DRIFT_SERVER_ROOT:-/opt/secagent}
REPO=${DRIFT_REPO:-/opt/secagent}
DIRS=${DRIFT_DIRS:-"scripts deploy"}
ACCEPTED=${DRIFT_ACCEPTED_FILE:-$SERVER_ROOT/deploy/srv1-drift-accepted.txt}
REPORT=${DRIFT_REPORT:-$SERVER_ROOT/logs/drift-report.txt}
SOURCE_MODE=${DRIFT_SOURCE:-auto}
SNAPSHOT=${DRIFT_SNAPSHOT:-/opt/secagent/.repo-snapshot}
SNAP_MAX_AGE_DAYS=${DRIFT_SNAPSHOT_MAX_AGE_DAYS:-7}
FETCH_TIMEOUT=${DRIFT_FETCH_TIMEOUT:-25}
REMOTE=${DRIFT_REMOTE:-origin}
BRANCH=${DRIFT_BRANCH:-main}
BASELINE_REF=${DRIFT_BASELINE_REF:-$REMOTE/$BRANCH}
SNAP_HASHMODE_EXPECT=sha256-cr-stripped

MODE=check
for a in "$@"; do
  case "$a" in
    --status)    MODE=status ;;
    --accept)    MODE=accept ;;
    --baseline)  MODE=baseline ;;
    --no-report) NO_REPORT=1 ;;
    --help|-h)   sed -n '2,100p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数：$a" >&2; exit 2 ;;
  esac
done
NO_REPORT=${NO_REPORT:-0}

if [ "${DRIFT_CHECK_DISABLED:-0}" = "1" ]; then
  echo "drift: 已按 DRIFT_CHECK_DISABLED=1 关闭（skip）"
  exit 0
fi

# ---------- 统一换行：比对前两边都去掉全部 CR ----------
# 详情见文件头：.gitattributes 里 *.ps1 是 eol=crlf，Linux 检出后是 LF，
# 按原始字节比会恒定误报。二进制文件不在这两个目录里，去掉 \r 是安全的。
nz_sum() { tr -d '\r' | sha256sum | awk '{print $1}'; }
nz_file() { tr -d '\r' < "$1" | sha256sum | awk '{print $1}'; }

command -v git >/dev/null 2>&1 || { echo "drift: [X] 缺 git —— 无法比对仓库" >&2; exit 2; }

# ---------- 解析权威基准（fail-closed） ----------
BASE_KIND=""; BASE_DESC=""; BASE_SHA=""; SNAP_AGE_DAYS=""

try_origin() { # 成功=0，并把 BASE_* 填好
  local t=()
  command -v timeout >/dev/null 2>&1 && t=(timeout "$FETCH_TIMEOUT")
  # 【可移植写法】空数组在 set -u 下直接 "$ {t[@]}" 展开，
  # 在 bash 4.3 及更老会报 unbound variable；${t[@]+"${t[@]}"} 在任何版本都安全。
  "${t[@]+"${t[@]}"}" git -C "$REPO" fetch --quiet --prune "$REMOTE" "$BRANCH" >/dev/null 2>&1 || return 1
  git -C "$REPO" rev-parse --verify --quiet "${BASELINE_REF}^{commit}" >/dev/null 2>&1 || return 1
  BASE_KIND=origin
  BASE_SHA=$(git -C "$REPO" rev-parse --short "$BASELINE_REF")
  BASE_DESC="$BASELINE_REF@$BASE_SHA"
  return 0
}

snapshot_error() { echo "drift: [X] $*（fail-closed：拒绝在'看不见权威来源'的情况下出结论）" >&2; exit 2; }

load_snapshot() {
  local info="$SNAPSHOT/SNAPSHOT-INFO" mani="$SNAPSHOT/MANIFEST.sha256" tree="$SNAPSHOT/tree"
  [ -d "$SNAPSHOT" ] || snapshot_error "只读快照目录不存在：$SNAPSHOT（跑 scripts/srv1-repo-snapshot.sh --install <tgz>，或让发布侧 scripts/publish-drift-snapshot.ps1 推一份）"
  [ -f "$info" ]     || snapshot_error "快照缺少 SNAPSHOT-INFO：$info"
  [ -f "$mani" ]     || snapshot_error "快照缺少 MANIFEST.sha256：$mani"
  [ -d "$tree" ]     || snapshot_error "快照缺少文件树：$tree"
  # shellcheck disable=SC1090
  local SNAP_COMMIT="" SNAP_TIME_EPOCH="" SNAP_HASHMODE="" SNAP_FILES=""
  . "$info" || snapshot_error "SNAPSHOT-INFO 不可读：$info"
  [ -n "${SNAP_COMMIT:-}" ] || snapshot_error "SNAPSHOT-INFO 缺 SNAP_COMMIT"
  [ -n "${SNAP_TIME_EPOCH:-}" ] || snapshot_error "SNAPSHOT-INFO 缺 SNAP_TIME_EPOCH"
  [ "${SNAP_HASHMODE:-}" = "$SNAP_HASHMODE_EXPECT" ] || \
    snapshot_error "快照哈希口径不认：SNAP_HASHMODE='${SNAP_HASHMODE:-}'（期望 $SNAP_HASHMODE_EXPECT）—— 口径不同的清单不能用来下结论"
  case "${SNAP_TIME_EPOCH:-}" in ''|*[!0-9]*) snapshot_error "SNAP_TIME_EPOCH 不是整数：${SNAP_TIME_EPOCH:-}";; esac
  local now age
  now=$(date +%s); age=$(( now - SNAP_TIME_EPOCH ))
  [ "$age" -ge -86400 ] || snapshot_error "快照时间戳在未来（$(( 0 - age )) 秒），时钟或文件有问题"
  SNAP_AGE_DAYS=$(( age / 86400 ))
  local max=$(( SNAP_MAX_AGE_DAYS * 86400 ))
  if [ "$age" -gt "$max" ]; then
    snapshot_error "只读快照已过期：${SNAP_AGE_DAYS} 天 > 阈值 ${SNAP_MAX_AGE_DAYS} 天（SNAPSHOT-INFO 时间 $(date -d "@$SNAP_TIME_EPOCH" '+%F %T' 2>/dev/null || echo "epoch $SNAP_TIME_EPOCH")）—— 请重新发布快照（scripts/publish-drift-snapshot.ps1）"
  fi
  # 完整性：清单里每个文件都必须在树里、且哈希对得上
  local bad=0 line h p got n=0
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    h=$(printf '%s' "$line" | awk '{print $1}')
    p=$(printf '%s' "$line" | awk '{print $2}')
    [ -n "$h" ] && [ -n "$p" ] || continue
    n=$((n + 1))
    if [ ! -f "$tree/$p" ]; then bad=$((bad + 1)); [ "$bad" -le 5 ] && echo "drift: [!] 快照缺文件：$p" >&2; continue; fi
    got=$(nz_file "$tree/$p")
    if [ "$got" != "$h" ]; then bad=$((bad + 1)); [ "$bad" -le 5 ] && echo "drift: [!] 快照哈希对不上：$p" >&2; fi
  done < "$mani"
  [ "$n" -gt 0 ] || snapshot_error "快照清单是空的：$mani"
  [ "$bad" -eq 0 ] || snapshot_error "只读快照损坏：$bad/$n 个文件与 MANIFEST.sha256 不一致"
  BASE_KIND=snapshot
  BASE_SHA=$(printf '%s' "$SNAP_COMMIT" | cut -c1-12)
  BASE_DESC="snapshot@$BASE_SHA age=${SNAP_AGE_DAYS}d files=$n"
  echo "[drift] origin/main 不可用 → 退化到只读快照 $SNAPSHOT（$BASE_DESC，阈值 ${SNAP_MAX_AGE_DAYS} 天）" >&2
}

case "$SOURCE_MODE" in
  origin)   try_origin || snapshot_error "DRIFT_SOURCE=origin 但 fetch/解析 $BASELINE_REF 失败（网络/凭据/host key？）";;
  snapshot) load_snapshot;;
  auto)     try_origin || load_snapshot;;
  *)        echo "drift: [X] DRIFT_SOURCE 只接受 auto|origin|snapshot，收到：$SOURCE_MODE" >&2; exit 2;;
esac

HEAD_SHA=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo "no-git")

if [ "$MODE" = "baseline" ]; then
  echo "drift: baseline=$BASE_DESC kind=$BASE_KIND server=$SERVER_ROOT dirs=[$DIRS] local_head=$HEAD_SHA"
  exit 0
fi

# ---------- 排除"本来就不该比"的东西（假失败的来源） ----------
EXCLUDE_RE='(^|/)(__pycache__|\.git)(/|$)|\.pyc$|~$|\.(bak|orig|rej|swp|swo|tmp)$|\.bak-[0-9]'
keep() { printf '%s' "$1" | grep -Eq "$EXCLUDE_RE" && return 1 || return 0; }

# 【自引用】登记表自己就住在 deploy/ 里，必须排除 ——
#   否则"登记表不在权威来源里"会被报成 missing_in_repo=1，永远消不掉。
#   （登记表现在也进了权威仓库，这条仍然保留：它不该参与比对。）
ACCEPTED_REL=""
case "$ACCEPTED" in
  "$SERVER_ROOT"/*) ACCEPTED_REL=${ACCEPTED#"$SERVER_ROOT"/} ;;
esac
in_scope() {
  [ -n "$ACCEPTED_REL" ] && [ "$1" = "$ACCEPTED_REL" ] && return 1
  keep "$1"
}

# ---------- 服务器侧清单 ----------
mapfile -t SERVER_FILES < <(
  cd "$SERVER_ROOT" || exit 2
  for d in $DIRS; do [ -d "$d" ] && find "$d" -type f -print; done | sort
)
if [ "${#SERVER_FILES[@]}" -eq 0 ]; then
  echo "drift: [X] $SERVER_ROOT/{$DIRS} 下没找到任何文件" >&2; exit 2
fi

# ---------- 权威侧清单 ----------
# 【fail-closed 的关键一步】如果清单这次没给出任何文件（不是"权威里确实没有"，
#   而是 git 偶发失败/清单读废了），绝不能当成"权威是空的"继续往下跑：
#   那样所有文件都会被算成 missing_in_repo，而登记表又会把它们全部"接受"掉，
#   于是真实的漂移被静默掩盖。所以：探两次仍然为空 → 直接退出 2。
list_baseline() {
  if [ "$BASE_KIND" = origin ]; then
    git -C "$REPO" ls-tree -r --name-only "$BASELINE_REF" -- $DIRS 2>/dev/null
  else
    awk '!/^#/ && NF>=2 {print $2}' "$SNAPSHOT/MANIFEST.sha256" 2>/dev/null
  fi
}
mapfile -t REPO_FILES < <(list_baseline | sort)
if [ "${#REPO_FILES[@]}" -eq 0 ]; then
  sleep 1
  mapfile -t REPO_FILES < <(list_baseline | sort)
fi
if [ "${#REPO_FILES[@]}" -eq 0 ]; then
  echo "drift: [X] 权威来源（$BASE_DESC）下没给出任何文件 —— 拒绝在'看不见权威'的情况下出结论（fail-closed）" >&2
  exit 2
fi

declare -A REPO_SET=()
for _p in "${REPO_FILES[@]}"; do REPO_SET["$_p"]=1; done
repo_has() { [ -n "${REPO_SET[$1]:-}" ]; }

# 权威侧内容哈希
declare -A SNAP_HASH=()
if [ "$BASE_KIND" = snapshot ]; then
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    h=$(printf '%s' "$line" | awk '{print $1}'); p=$(printf '%s' "$line" | awk '{print $2}')
    [ -n "$h" ] && [ -n "$p" ] && SNAP_HASH["$p"]=$h
  done < "$SNAPSHOT/MANIFEST.sha256"
  repo_sha256() { printf '%s' "${SNAP_HASH[$1]:-}"; }
else
  repo_sha256() { git -C "$REPO" show "$BASELINE_REF:$1" 2>/dev/null | nz_sum; }
fi
SERVER_ROOT_SAFE=$SERVER_ROOT
server_sha256() { nz_file "$SERVER_ROOT_SAFE/$1"; }

# ---------- 登记表 ----------
declare -A ACC=()
if [ -f "$ACCEPTED" ]; then
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    line=${line%%#*}                                   # 去掉行尾原因
    h=$(printf '%s' "$line" | awk '{print $1}')
    p=$(printf '%s' "$line" | awk '{print $2}')
    [ -n "$h" ] && [ -n "$p" ] && ACC["$p"]="$h"
  done < "$ACCEPTED"
fi

# ---------- 逐文件比对 ----------
DIFF=0; MIR=0; MOS=0; ACC_N=0; NSCOPE=0
REPORT_LINES=(); ROW_DIFF=(); ROW_MIR=(); ROW_MOS=(); ROW_ACC=()

for rel in "${SERVER_FILES[@]}"; do
  in_scope "$rel" || continue
  NSCOPE=$((NSCOPE + 1))
  sh=$(server_sha256 "$rel")
  if repo_has "$rel"; then
    rh=$(repo_sha256 "$rel")
    if [ "$sh" = "$rh" ]; then
      continue                                        # 完全一致
    fi
    if [ "${ACC[$rel]:-}" = "$sh" ]; then
      ACC_N=$((ACC_N + 1)); ROW_ACC+=("  [accepted] $rel（已登记；权威内容不同）")
    else
      DIFF=$((DIFF + 1))
      ROW_DIFF+=("  [diff] $rel  server=${sh:0:16}…  baseline=${rh:0:16}…$([ -n "${ACC[$rel]:-}" ] && echo '  ← 登记表里的哈希已过期（文件被改过）')")
    fi
  else
    if [ "${ACC[$rel]:-}" = "$sh" ]; then
      ACC_N=$((ACC_N + 1)); ROW_ACC+=("  [accepted] $rel（已登记；权威来源里没有）")
    else
      MIR=$((MIR + 1))
      ROW_MIR+=("  [missing_in_repo] $rel  server=${sh:0:16}…$([ -n "${ACC[$rel]:-}" ] && echo '  ← 登记表里的哈希已过期（文件被改过）')")
    fi
  fi
done

for rel in "${REPO_FILES[@]}"; do
  in_scope "$rel" || continue
  [ -f "$SERVER_ROOT_SAFE/$rel" ] && continue
  MOS=$((MOS + 1)); ROW_MOS+=("  [missing_on_server] $rel（权威来源里有、服务器上没有）")
done

# ---------- 汇总行（机读） ----------
SUMMARY="drift: diff=$DIFF missing_in_repo=$MIR missing_on_server=$MOS accepted=$ACC_N"
SUMMARY="$SUMMARY  baseline=$BASE_DESC  local_head=$HEAD_SHA  files=$NSCOPE  baseline_files=${#REPO_FILES[@]}  time=$(date '+%F %T')"

# ---------- 报告落盘 ----------
if [ "$NO_REPORT" != "1" ]; then
  mkdir -p "$(dirname "$REPORT")" 2>/dev/null || true
  {
    echo "SecAgent 权威仓库 ↔ 服务器 漂移报告"
    echo "时间      : $(date '+%F %T')"
    echo "服务器侧  : $SERVER_ROOT/{$(printf '%s' "$DIRS" | tr ' ' ',')}"
    echo "权威侧    : $BASE_DESC（kind=$BASE_KIND；origin 模式=fetch 后的 git show，snapshot 模式=只读快照）"
    echo "本机 HEAD : $HEAD_SHA（仅供参考；比对【不用】它，避免拿旧仓库自证）"
    echo "登记表    : $ACCEPTED（$( [ ${#ACC[@]} -gt 0 ] && echo ${#ACC[@]} || echo 0 ) 条已接受）"
    echo "汇总      : $SUMMARY"
    echo ""
    echo "== 需要处理（未登记的偏差） =="
    if [ "$DIFF" = 0 ] && [ "$MIR" = 0 ] && [ "$MOS" = 0 ]; then
      echo "  （无）"
    else
      [ "$MIR" -gt 0 ] && { echo "-- 服务器有、权威来源没有（$MIR）—— 这些文件【只存在于服务器】，丢了就没了："; printf '%s\n' "${ROW_MIR[@]}"; }
      [ "$DIFF" -gt 0 ] && { echo "-- 两边内容不一致（$DIFF）："; printf '%s\n' "${ROW_DIFF[@]}"; }
      [ "$MOS" -gt 0 ] && { echo "-- 权威来源有、服务器没有（$MOS）："; printf '%s\n' "${ROW_MOS[@]}"; }
    fi
    echo ""
    echo "== 已登记的技术债（$ACC_N 项，不计入失败，但目标是把它们清零） =="
    if [ "$ACC_N" = 0 ]; then echo "  （无）"; else printf '%s\n' "${ROW_ACC[@]}"; fi
    echo ""
    echo "处理办法：把该入库的文件提交进权威仓库（F:\\7AAA\\AI\\SecAgent\\sec-agent → GitHub main）；"
    echo "         确实只需要留在服务器的，跑 bash $0 --accept 重新登记（并在 RUNBOOK 里记一笔原因）。"
  } > "$REPORT" 2>/dev/null || echo "drift: [!] 报告写不进去：$REPORT" >&2
fi

# ---------- --accept ----------
# 【顺序很重要】--accept 放在所有"话多"的输出【之前】：
#   否则 `bash srv1-drift-check.sh --accept | grep -m1 drift` 这种用法里，
#   下游 grep 一命中就退出，本脚本再往管道写就会收到 SIGPIPE 被打断 ——
#   于是"登记表看起来重写了、其实那一行都没写"（实测栽过一次：
#   摘要行打出来了，登记表却还是旧的，检查继续红）。
if [ "$MODE" = "accept" ]; then
  mkdir -p "$(dirname "$ACCEPTED")" 2>/dev/null || true
  if [ -f "$ACCEPTED" ]; then
    BAK="$ACCEPTED.bak-$(date +%Y%m%d-%H%M%S)"
    cp -p "$ACCEPTED" "$BAK" && echo "已备份登记表：$BAK"
  fi
  {
    echo "# SecAgent 漂移登记表（srv1-drift-check.sh 读）"
    echo "# 每行：<sha256>  <path>  # 原因"
    echo '# 这里登记的是【已知且已接受】的"服务器 ≠ 权威来源"偏差 —— 是技术债，不是正确状态。'
    echo "# 哈希口径：内容去掉全部 CR 后的 sha256（所以 CRLF↔LF 不会被登记）。"
    echo "# 登记是内容哈希级的：被登记的文件只要再改一个字节，立刻重新变成 diff 并告警。"
    echo "# 生成时间：$(date '+%F %T')  权威基准=$BASE_DESC"
    for rel in "${SERVER_FILES[@]}"; do
      in_scope "$rel" || continue
      sh=$(server_sha256 "$rel")
      if repo_has "$rel"; then rh=$(repo_sha256 "$rel"); else rh=""; fi
      [ "$sh" = "$rh" ] && continue
      if [ -n "$rh" ]; then
        printf '%s  %s  # 内容与权威来源不同（已接受）\n' "$sh" "$rel"
      else
        printf '%s  %s  # 服务器有、权威来源无（已接受）\n' "$sh" "$rel"
      fi
    done
  } > "$ACCEPTED.tmp.$$" && mv "$ACCEPTED.tmp.$$" "$ACCEPTED" || { rm -f "$ACCEPTED.tmp.$$"; echo "drift: [X] 登记表写不进去" >&2; exit 2; }
  echo "登记表已重写：$ACCEPTED（$(grep -vc '^#' "$ACCEPTED" 2>/dev/null || echo 0) 条）"
  exit 0
fi

# ---------- 控制台输出 ----------
if [ "$MODE" = "status" ]; then
  cat "$REPORT" 2>/dev/null || echo "$SUMMARY"
else
  echo "$SUMMARY"
  [ "$DIFF" -gt 0 ] && printf '%s\n' "${ROW_DIFF[@]}"
  [ "$MIR" -gt 0 ] && printf '%s\n' "${ROW_MIR[@]}"
  [ "$MOS" -gt 0 ] && printf '%s\n' "${ROW_MOS[@]}"
fi

if [ "$DIFF" = 0 ] && [ "$MIR" = 0 ] && [ "$MOS" = 0 ]; then
  exit 0
fi
exit 1
