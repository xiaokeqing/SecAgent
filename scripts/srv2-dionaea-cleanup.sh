#!/usr/bin/env bash
# ============================================================
# srv2：Dionaea 的磁盘上限维护
# ------------------------------------------------------------
# 为什么需要：
#   Dionaea 会把每条 TCP 连接的原始字节流 dump 到
#     /opt/dionaea/var/lib/dionaea/bistreams/<日期>/
#   （实测每连一次就多一个文件，文件名带会话 id），
#   而它【没有内建清理】。日志有 logrotate 管，bistreams 没有。
#   磁盘 19GB 可用，被慢慢吃掉是迟早的事。
#
# 口径：
#   · bistreams   : 先按天数删（默认 2 天），再按总量兜底（默认 1GB，从最旧的删起）
#   · binaries    : 【不自动删】—— 那是攻击者投递的样本，是蜜罐最有价值的产物。
#                   只做用量报表；超过阈值（默认 2GB）时打印醒目告警交给站主决定。
#   · sip/rtp     : SIP 的 RTP dump，同样按天数清理（默认 2 天）
#
# 用法（srv2）：
#   bash srv2-dionaea-cleanup.sh            # 只报表（默认，不改任何东西）
#   sudo bash srv2-dionaea-cleanup.sh --apply   # 真的清理
# 环境变量：BISTREAM_DAYS(2) BISTREAM_MAX_MB(1024) BINARIES_WARN_MB(2048)
# ============================================================
set -uo pipefail
APP=/opt/dionaea
BASE="$APP/var/lib/dionaea"
BISTREAM_DAYS=${BISTREAM_DAYS:-2}
BISTREAM_MAX_MB=${BISTREAM_MAX_MB:-1024}
BINARIES_WARN_MB=${BINARIES_WARN_MB:-2048}
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_CY='\033[1;36m'; C_0='\033[0m'
log()  { printf "${C_CY}==> %s${C_0}\n" "$*"; }
info() { printf "    %s\n" "$*"; }

size_mb() { du -sm "$1" 2>/dev/null | awk '{print $1+0}'; }

echo "Dionaea 磁盘维护  $(date '+%F %T')  模式=$([ "$APPLY" = 1 ] && echo 应用 || echo 报表)"

log "1. 现状"
for d in bistreams binaries sip ftp tftp upnp printer http; do
  [ -d "$BASE/$d" ] && info "$(printf '%-10s %6s MB  %7s 个文件' "$d" "$(size_mb "$BASE/$d")" "$(find "$BASE/$d" -type f 2>/dev/null | wc -l)")"
done
info "根分区: $(df -h / | awk 'NR==2{print $4" 可用 ("$5" 已用)"}')"

log "2. bistreams：按天数删除（> ${BISTREAM_DAYS} 天）"
old=$(find "$BASE/bistreams" -type f -mtime +"$BISTREAM_DAYS" 2>/dev/null | wc -l)
oldmb=$(find "$BASE/bistreams" -type f -mtime +"$BISTREAM_DAYS" -printf '%s\n' 2>/dev/null | awk '{s+=$1}END{print int(s/1048576)}')
info "命中 $old 个文件，约 ${oldmb:-0} MB"
if [ "$APPLY" = 1 ] && [ "$old" -gt 0 ]; then
  find "$BASE/bistreams" -type f -mtime +"$BISTREAM_DAYS" -delete 2>/dev/null
  find "$BASE/bistreams" -mindepth 1 -type d -empty -delete 2>/dev/null
  info "已删除"
fi

log "3. bistreams：总量兜底（上限 ${BISTREAM_MAX_MB} MB，从最旧删起）"
cur=$(size_mb "$BASE/bistreams")
info "当前 ${cur} MB"
if [ "$cur" -gt "$BISTREAM_MAX_MB" ]; then
  need=$((cur - BISTREAM_MAX_MB))
  info "超出 ${need} MB，开始从最旧的删"
  if [ "$APPLY" = 1 ]; then
    # 按 mtime 从旧到新删，直到降到上限以下
    while [ "$(size_mb "$BASE/bistreams")" -gt "$BISTREAM_MAX_MB" ]; do
      f=$(find "$BASE/bistreams" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | head -1 | cut -d' ' -f2-)
      [ -n "$f" ] || break
      rm -f "$f"
    done
    info "清理后 $(size_mb "$BASE/bistreams") MB"
  else
    info "（报表模式，未删）"
  fi
else
  info "未超上限"
fi

log "4. SIP RTP dump（> ${BISTREAM_DAYS} 天）"
if [ -d "$BASE/sip/rtp" ]; then
  n=$(find "$BASE/sip/rtp" -type f -mtime +"$BISTREAM_DAYS" 2>/dev/null | wc -l)
  info "命中 $n 个文件"
  [ "$APPLY" = 1 ] && [ "$n" -gt 0 ] && find "$BASE/sip/rtp" -type f -mtime +"$BISTREAM_DAYS" -delete 2>/dev/null && info "已删除"
else
  info "无此目录"
fi

log "5. binaries（下载到的样本）—— 只报表，不自动删"
bmb=$(size_mb "$BASE/binaries")
info "占用 ${bmb} MB（告警阈值 ${BINARIES_WARN_MB} MB）"
if [ "$bmb" -gt "$BINARIES_WARN_MB" ]; then
  printf "    ${C_WARN}[!]${C_0} 样本目录超过阈值 —— 请人工决定是留档（拉到别处）还是清理\n"
  find "$BASE/binaries" -type f -printf '      %TY-%Tm-%Td %10s  %f\n' 2>/dev/null | sort | tail -10
fi

log "6. 结果"
info "bistreams 现在 $(size_mb "$BASE/bistreams") MB / 上限 ${BISTREAM_MAX_MB} MB"
info "根分区: $(df -h / | awk 'NR==2{print $4" 可用 ("$5" 已用)"}')"
[ "$APPLY" = 1 ] && echo "  清理完成" || echo "  报表模式：加 --apply 才会真的删"
