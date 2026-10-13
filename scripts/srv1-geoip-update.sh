#!/usr/bin/env bash
# ============================================================
# srv1 离线地理库月度更新（DB-IP Lite City + DB-IP Lite ASN，CC BY 4.0）
# ------------------------------------------------------------
# 这条脚本解决的是一件事：**让「地图是拿哪一版库画的」这件事可复现、可回滚、失败了不会更糟**。
#
# 形状（月更）：
#   下载新版 → 逐项校验（gzip 完整 / 体积在预期区间 / 首末行形状 / 行数 / 有 v6 段）
#     ├── 任一项不过 → **保留旧库不动**，写日志 + notify.sh HIGH，退出 1
#     └── 全过 → 原子替换（临时目录 → 同目录 rename）+ 稳定符号链接翻转 + 权限 600/700
#                → 保留 current 与 prev 两份 → 打印"需要重建容器"的命令（不自己重启）
#
# 为什么不"直接覆盖当前文件"：
#   覆盖到一半（磁盘满 / 进程被杀 / 网络断）会留下半个库。应用加载半个库的后果不是报错，
#   而是**地图上少掉一些国家**（判据见 GeoIpDatabase：坏行超 1% 才判整库不可用）。
#   所以必须先落到临时文件、校验通过后再 rename —— rename 在同一文件系统上是原子的。
#
# 为什么不自己重启容器：
#   本项目的部署链有硬规矩（见 CLAUDE.md）：**不能用 docker compose up 手工重建**，
#   否则会丢 digest 引用（"镜像是新的、代码是旧的"就是这么来的）。
#   所以脚本只打印命令，由发布链 srv1-redeploy.sh 去重建。
#
# 用法：
#   bash srv1-geoip-update.sh                 # 更新到当前月（当月未发布则回退到上月）
#   bash srv1-geoip-update.sh --month 2026-10 # 指定月份（补票/复现用）
#   bash srv1-geoip-update.sh --from-dir DIR  # ★不下载：用 DIR 里已就绪的两个 gz（校验+落地照旧）
#   bash srv1-geoip-update.sh --dry-run       # 只下载与校验，绝不改动现有库
#   bash srv1-geoip-update.sh --verify        # 只校验当前在用的库，不下载
#   bash srv1-geoip-update.sh --rollback      # 把稳定链接指回上一份（并打印重建命令）
#   bash srv1-geoip-update.sh --self-test     # 不需要网络/root：跑纯函数自测
# 退出码：0 = 成功或无需变更；1 = 失败（旧库保持原样）；
#
# 【为什么要有 --from-dir】实测：srv1（阿里云杭州）直连 download.db-ip.com 只有
#   30–200 KB/s，86MB 的 city 库要 7–45 分钟，而且会中途掉速 —— 本脚本原先只支持"自己下载"，
#   在这种链路上月度更新很可能一直失败。所以把两件事拆开：
#     · **下载可以在任何地方做**（本机/CI/别的机器，只要能拿到文件）；
#     · **校验与落地必须在 srv1 上做**（同一套判据、同一条原子替换路径，不许绕过）。
#   推荐链路：先把两个 gz 传到 srv1 的临时目录，再 --from-dir 落地。
set -uo pipefail

APP=${GEOIP_APP_DIR:-/opt/secagent}
GEO_DIR=${GEOIP_DIR:-$APP/geoip}
LOG=${GEOIP_LOG:-$APP/logs/geoip-update.log}
BASE=${GEOIP_BASE_URL:-https://download.db-ip.com/free}
NOTIFY=${GEOIP_NOTIFY:-$APP/scripts/notify.sh}
# 容器以 uid 999 运行（实测 docker exec secagent id → uid=999(secagent)）；
# 库目录 700 + 文件 600 + 属主 999:999 ⇒ 容器读得到，宿主机上其它用户读不到。
GEO_UID=${GEOIP_UID:-999}
GEO_GID=${GEOIP_GID:-999}
# 体积预期（gzip 包）：2026-10 实测 city 85.8MB / asn 7.0MB。
# 区间给得宽（数据源逐年变大），但足以拦住"下到一个 HTML 错误页"。
CITY_MIN_MB=${GEOIP_CITY_MIN_MB:-50}
CITY_MAX_MB=${GEOIP_CITY_MAX_MB:-200}
ASN_MIN_MB=${GEOIP_ASN_MIN_MB:-2}
ASN_MAX_MB=${GEOIP_ASN_MAX_MB:-40}
CITY_MIN_ROWS=${GEOIP_CITY_MIN_ROWS:-1000000}

CITY_LINK=dbip-city-lite.csv.gz
ASN_LINK=dbip-asn-lite.csv.gz

DRY=0; VERIFY_ONLY=0; ROLLBACK=0; MONTH=""; SRC_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --verify) VERIFY_ONLY=1 ;;
    --rollback) ROLLBACK=1 ;;
    --from-dir) SRC_DIR="${2:-}"; shift ;;
    --month) MONTH="${2:-}"; shift ;;
    --self-test) SELF_TEST=1 ;;
    *) echo "未知参数：$1"; exit 1 ;;
  esac
  shift
done
SELF_TEST=${SELF_TEST:-0}

mkdir -p "$(dirname "$LOG")" 2>/dev/null || true
ts() { date '+%Y-%m-%d %H:%M:%S'; }
say() { echo "[$(ts)] $*" | tee -a "$LOG" 2>/dev/null || echo "[$(ts)] $*"; }

notify() { # notify <level> <title> <body>
  local lvl="$1" title="$2" body="$3"
  if [ "$DRY" = "1" ]; then say "（dry-run）本应通知：[$lvl] $title — $body"; return 0; fi
  if [ -x "$NOTIFY" ]; then
    bash "$NOTIFY" "$lvl" "$title" "$body" >/dev/null 2>&1
    say "已尝试通知（notify.sh 退出码=$?）"
  else
    say "!! 找不到 $NOTIFY —— 只能写日志（这本身就是个问题）"
  fi
}

# ============================================================
# 纯函数部分（--self-test 直接跑这些，不需要网络与 root）
# ============================================================

# 从文件名解析月份：dbip-city-lite-2026-10.csv.gz → 2026-10
month_of() { printf '%s' "$1" | sed -n 's/.*\([0-9]\{4\}-[0-9]\{2\}\).*/\1/p'; }

# 上一个月：prev_month 2026-01 → 2025-12（纯算术，不依赖 date 的跨平台差异）
prev_month() {
  local y m
  y=${1%%-*}; m=${1##*-}
  m=$((10#$m - 1))
  if [ "$m" -lt 1 ]; then m=12; y=$((y - 1)); fi
  printf '%04d-%02d' "$y" "$m"
}

# 体积是否在预期区间：in_range <字节> <最小MB> <最大MB>
in_range() {
  local b="$1" min="$2" max="$3"
  local mb=$(( (b + 1048575) / 1048576 ))
  [ "$mb" -ge "$min" ] && [ "$mb" -le "$max" ]
}

# 首行是否像 DB-IP city CSV：以 IPv4 区间开头，且至少 6 个逗号（8 列左右）。
#
# ⚠️ 这里【刻意不写】带引号逗号的 case 模式（例如 *","*","*",*）：那在 srv1 的 bash 上
#    会报 `syntax error near unexpected token`（实测：整脚本 bash -n rc=2，
#    报错行还指向了下面 20 行的另一句，看起来完全不像这个模式的问题）。
#    用 tr 数逗号既没有这个坑，也更容易看懂。
looks_like_city_header() {
  case "$1" in
    0.0.0.0,0.255.255.255,*|1.0.0.0,*) return 0 ;;
  esac
  # 同前：关掉 pipefail 再做"提前退出的管道"（grep -q 命中即退，printf 可能收到 SIGPIPE）
  ( set +o pipefail; printf '%s' "$1" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3},' ) || return 1
  [ "$(printf '%s' "$1" | tr -cd ',' | wc -c)" -ge 6 ] || return 1
  return 0
}

if [ "$SELF_TEST" = "1" ]; then
  rc=0
  [ "$(month_of dbip-city-lite-2026-10.csv.gz)" = "2026-10" ] || { echo "month_of 失败"; rc=1; }
  [ "$(prev_month 2026-10)" = "2026-09" ] || { echo "prev_month 2026-10 失败"; rc=1; }
  [ "$(prev_month 2026-01)" = "2025-12" ] || { echo "prev_month 跨年失败"; rc=1; }
  [ "$(prev_month 2026-03)" = "2026-02" ] || { echo "prev_month 2026-03 失败"; rc=1; }
  in_range 85827400 50 200 || { echo "in_range 正例失败"; rc=1; }
  in_range 1000 50 200 && { echo "in_range 反例失败（1KB 不该算合格）"; rc=1; }
  looks_like_city_header "0.0.0.0,0.255.255.255,ZZ,ZZ,,,0,0" || { echo "header 正例失败"; rc=1; }
  looks_like_city_header "<html><body>404" && { echo "header 反例失败（HTML 不该算合格）"; rc=1; }
  [ "$rc" = "0" ] && echo "self-test: OK（month_of / prev_month / in_range / looks_like_city_header）"
  exit $rc
fi

[ "$(id -u)" = "0" ] || { say "必须以 root 运行（要改 /opt/secagent/geoip 的属主与权限）"; exit 1; }

# ============================================================
# --rollback：把稳定链接指回上一份
# ============================================================
if [ "$ROLLBACK" = "1" ]; then
  if [ ! -L "$GEO_DIR/$CITY_LINK" ]; then say "当前没有稳定链接，无法回滚：$GEO_DIR/$CITY_LINK"; exit 1; fi
  CUR=$(basename "$(readlink -f "$GEO_DIR/$CITY_LINK")")
  CUR_MONTH=$(month_of "$CUR")
  PREV_MONTH=$(prev_month "$CUR_MONTH")
  PREV_FILE="$GEO_DIR/dbip-city-lite-$PREV_MONTH.csv.gz"
  if [ ! -s "$PREV_FILE" ]; then
    say "找不到上一份库文件 $PREV_FILE（保留策略只留 current+prev）—— 只能重新下载：--month $PREV_MONTH"
    exit 1
  fi
  say "回滚：$CUR → $(basename "$PREV_FILE")"
  if [ "$DRY" = "1" ]; then say "（dry-run）不做实际替换"; exit 0; fi
  ln -sfn "$(basename "$PREV_FILE")" "$GEO_DIR/.$CITY_LINK.tmp"
  mv -T "$GEO_DIR/.$CITY_LINK.tmp" "$GEO_DIR/$CITY_LINK"
  say "已回滚。**需要重建容器**才能生效：bash $APP/scripts/srv1-redeploy.sh --force"
  exit 0
fi

# ============================================================
# 校验一个已落地的 gz（--verify 与"下载后校验"共用同一套判据）
# 校验 <路径> <类型 city|asn>
# ============================================================
validate_gz() {
  local f="$1" kind="$2" size
  [ -s "$f" ] || { say "校验失败：文件不存在或为空 $f"; return 1; }
  size=$(stat -c %s "$f")
  gzip -t "$f" 2>/dev/null || { say "校验失败：不是完整的 gzip（被截断/HTML 错误页）$f"; return 1; }
  if [ "$kind" = "city" ]; then
    in_range "$size" "$CITY_MIN_MB" "$CITY_MAX_MB" \
      || { say "校验失败：city 体积 $((size/1048576))MB 不在预期 ${CITY_MIN_MB}-${CITY_MAX_MB}MB"; return 1; }
  else
    in_range "$size" "$ASN_MIN_MB" "$ASN_MAX_MB" \
      || { say "校验失败：asn 体积 $((size/1048576))MB 不在预期 ${ASN_MIN_MB}-${ASN_MAX_MB}MB"; return 1; }
  fi
  local head1
  head1=$(zcat "$f" 2>/dev/null | head -n 1)
  [ -n "$head1" ] || { say "校验失败：解压后没有内容 $f"; return 1; }
  if [ "$kind" = "city" ]; then
    looks_like_city_header "$head1" || { say "校验失败：首行不像 DB-IP city CSV：$head1"; return 1; }
    local rows
    rows=$(zcat "$f" | wc -l)
    [ "$rows" -ge "$CITY_MIN_ROWS" ] \
      || { say "校验失败：city 行数 $rows < $CITY_MIN_ROWS（疑似被裁剪/替换）"; return 1; }
    # ⚠️ 必须在【关掉 pipefail】的子壳里跑：grep -q -m1 命中后立刻退出，
    #    上游 zcat 收到 SIGPIPE（退出码 141）；在 set -o pipefail 下整条管道被判为失败 ——
    #    于是"库确实有 IPv6 段"被读成"缺少 IPv6 段"（实测踩到过：真库被拒，日志写"缺少 IPv6 段"）。
    ( set +o pipefail; zcat "$f" | grep -q -m1 '^::,' ) \
      || { say "校验失败：city 库缺少 IPv6 段（首行应为 ::,…）"; return 1; }
    say "校验通过：city 行数=$rows 体积=$((size/1048576))MB"
  else
    # 至少 3 个逗号（4 列）；同样避开带引号逗号的 case 模式（见 looks_like_city_header 的注释）
    [ "$(printf '%s' "$head1" | tr -cd ',' | wc -c)" -ge 3 ] \
      || { say "校验失败：asn 首行不是 4 列形状：$head1"; return 1; }
    say "校验通过：asn 体积=$((size/1048576))MB"
  fi
  return 0
}

if [ "$VERIFY_ONLY" = "1" ]; then
  ok=1
  for f in "$GEO_DIR/$CITY_LINK" "$GEO_DIR/$ASN_LINK"; do
    [ -e "$f" ] || { say "缺失：$f"; ok=0; continue; }
    if [ "$(basename "$f")" = "$CITY_LINK" ]; then validate_gz "$(readlink -f "$f")" city || ok=0
    else validate_gz "$(readlink -f "$f")" asn || ok=0; fi
  done
  [ "$ok" = "1" ] && { say "当前在用的库校验全部通过"; exit 0; } || { say "当前在用的库校验失败"; exit 1; }
fi

# ============================================================
# 下载
# ============================================================
CUR_MONTH=${MONTH:-$(date '+%Y-%m')}
[ -n "$MONTH" ] || : # 指定月份时不做回退探测
TMP=$(mktemp -d "$GEO_DIR/.tmp-XXXXXX" 2>/dev/null) || { mkdir -p "$GEO_DIR"; TMP=$(mktemp -d "$GEO_DIR/.tmp-XXXXXX"); }
cleanup() { [ -n "${TMP:-}" ] && rm -rf "$TMP"; }
trap cleanup EXIT

fetch() { # fetch <月份> → 成功打印落地的文件名
  # ⚠️ 必须分成两条 local：`local m="$1" c="...$m..."` 里的 $m 取的是【外层】的 m，
  #    在 set -u 下会直接 `m: unbound variable` 退出 —— 而且报错行号指向函数里更靠后的行，
  #    看起来完全不像这一行的问题（实测踩到过：脚本"瞬间失败"，日志里连"开始下载"都没打印）。
  local m="$1"
  local c="$TMP/dbip-city-lite-$m.csv.gz"
  local a="$TMP/dbip-asn-lite-$m.csv.gz"
  say "下载 DB-IP Lite $m：$BASE/dbip-city-lite-$m.csv.gz"
  if ! curl -fsS --retry 3 --retry-delay 5 --connect-timeout 20 --max-time 1800 \
        -o "$c" "$BASE/dbip-city-lite-$m.csv.gz"; then
    say "下载 city 失败（月份 $m）"; return 1
  fi
  say "下载 DB-IP Lite $m：$BASE/dbip-asn-lite-$m.csv.gz"
  if ! curl -fsS --retry 3 --retry-delay 5 --connect-timeout 20 --max-time 900 \
        -o "$a" "$BASE/dbip-asn-lite-$m.csv.gz"; then
    say "下载 asn 失败（月份 $m）"; return 1
  fi
  printf '%s\n%s\n%s\n' "$m" "$c" "$a"
  return 0
}

TARGET=$CUR_MONTH
if [ -n "$SRC_DIR" ]; then
  # ===== 不下载：用调用方已经准备好的文件（下载慢/被墙的链路上推荐走这条）=====
  [ -d "$SRC_DIR" ] || { say "--from-dir 目录不存在：$SRC_DIR"; exit 1; }
  if [ -n "$MONTH" ]; then
    TARGET=$MONTH
    CITY_SRC="$SRC_DIR/dbip-city-lite-$TARGET.csv.gz"
  else
    CITY_SRC=$(ls -1 "$SRC_DIR"/dbip-city-lite-*.csv.gz 2>/dev/null | LC_ALL=C sort | tail -1)
    [ -n "$CITY_SRC" ] || { say "--from-dir 目录里没有 dbip-city-lite-*.csv.gz：$SRC_DIR"; exit 1; }
    TARGET=$(month_of "$(basename "$CITY_SRC")")
  fi
  ASN_SRC="$SRC_DIR/dbip-asn-lite-$TARGET.csv.gz"
  for f in "$CITY_SRC" "$ASN_SRC"; do
    [ -s "$f" ] || { say "缺少输入文件（--from-dir 模式下必须两个都有）：$f"; exit 1; }
  done
  say "使用已有文件（不下载）：TARGET=$TARGET  CITY=$CITY_SRC  ASN=$ASN_SRC"
else
DL=$(fetch "$TARGET" 2>&1 | tee -a "$LOG")
if ! printf '%s\n' "$DL" | grep -q "^$TARGET$"; then
  if [ -n "$MONTH" ]; then
    say "指定月份 $MONTH 下载失败，中止（不自动换月）"
    notify HIGH "GeoIP 月度更新失败（指定月份）" "月份：$MONTH
原因：下载失败。旧库保持不变，地图仍按旧版本绘制。时间：$(ts)"
    exit 1
  fi
  FALLBACK=$(prev_month "$CUR_MONTH")
  say "当月（$CUR_MONTH）尚未发布，回退到上月 $FALLBACK"
  DL=$(fetch "$FALLBACK" 2>&1 | tee -a "$LOG")
  if ! printf '%s\n' "$DL" | grep -q "^$FALLBACK$"; then
    say "上月 $FALLBACK 也下载失败，中止"
    notify HIGH "GeoIP 月度更新失败" "当月（$CUR_MONTH）与上月（$FALLBACK）都下载失败。
旧库保持不变。时间：$(ts)（详见 $LOG）"
    exit 1
  fi
  TARGET=$FALLBACK
fi

CITY_SRC="$TMP/dbip-city-lite-$TARGET.csv.gz"
ASN_SRC="$TMP/dbip-asn-lite-$TARGET.csv.gz"
fi

say "开始校验（gzip 完整性 / 体积区间 / 首行形状 / 行数 / v6 段）"
if ! validate_gz "$CITY_SRC" city || ! validate_gz "$ASN_SRC" asn; then
  say "校验未通过 —— **旧库保持不变**（绝不用半个库覆盖好库）"
  notify HIGH "GeoIP 月度更新校验失败" "月份：$TARGET
校验未通过，旧库保持原样（地图仍按旧版本绘制，不是坏图）。
详见 $LOG"
  exit 1
fi

if [ "$DRY" = "1" ]; then
  say "（dry-run）校验全部通过，不做替换。本应落地："
  say "  $GEO_DIR/dbip-city-lite-$TARGET.csv.gz"
  say "  $GEO_DIR/dbip-asn-lite-$TARGET.csv.gz"
  exit 0
fi

# ============================================================
# 原子替换：临时文件 → 同目录 rename；稳定链接用 mv -T 原子翻转
# ============================================================
say "落地：$GEO_DIR（目录 700，文件 600，属主 $GEO_UID:$GEO_GID）"
install -o "$GEO_UID" -g "$GEO_GID" -m 600 "$CITY_SRC" "$GEO_DIR/dbip-city-lite-$TARGET.csv.gz" \
  || { say "install city 失败"; notify HIGH "GeoIP 落地失败" "install city 失败，旧库未动。时间：$(ts)"; exit 1; }
install -o "$GEO_UID" -g "$GEO_GID" -m 600 "$ASN_SRC" "$GEO_DIR/dbip-asn-lite-$TARGET.csv.gz" \
  || { say "install asn 失败"; notify HIGH "GeoIP 落地失败" "install asn 失败（city 已落地，链接尚未翻转，旧库仍在生效）。时间：$(ts)"; exit 1; }

OLD_CITY_MONTH=""
[ -L "$GEO_DIR/$CITY_LINK" ] && OLD_CITY_MONTH=$(month_of "$(basename "$(readlink -f "$GEO_DIR/$CITY_LINK")")")

ln -sfn "dbip-city-lite-$TARGET.csv.gz" "$GEO_DIR/.$CITY_LINK.tmp"
mv -T "$GEO_DIR/.$CITY_LINK.tmp" "$GEO_DIR/$CITY_LINK"
ln -sfn "dbip-asn-lite-$TARGET.csv.gz" "$GEO_DIR/.$ASN_LINK.tmp"
mv -T "$GEO_DIR/.$ASN_LINK.tmp" "$GEO_DIR/$ASN_LINK"
# ⚠️ 目录必须 **chown 到容器用户**，不能只 chmod 700：
#    容器以 uid 999 运行，700 的 root:root 目录它连 traverse 都不行 ——
#    文件权限 600 设得再对，容器一样读不到（实测：AccessDeniedException on /opt/geoip/…），
#    而失败形态是"应用如实报 GEO_DB_UNUSABLE"，不会静默变空图，但地图就是没有。
#    chown 999:999 + chmod 700 ⇒ 容器能读；宿主机上其它非 root 用户仍读不到。
chown "$GEO_UID:$GEO_GID" "$GEO_DIR" 2>/dev/null || say "!! chown 目录失败（$GEO_DIR）—— 容器可能读不到库"
chmod 700 "$GEO_DIR"

# 可读性自检：按**数字**核对"容器用户（uid $GEO_UID）能不能读"。
#
# 为什么不用 `runuser -u 999`：util-linux 的 runuser 只认**用户名**，`-u 999` 会报
#   "user 999 does not exist"；而 uid 999 在每台机器上的名字还不一样
#   （srv1 上叫 systemd-coredump，容器里叫 secagent）——按名字判会随宿主机变化（§22.4 同一条纪律）。
# 所以这里直接核对内核真正用的两件事：目录属主有 x 位、文件属主有 r 位。
container_can_read() { # <稳定链接路径>
  local f="$1" dir perm
  f=$(readlink -f "$f" 2>/dev/null) || return 1
  [ -n "$f" ] || return 1
  dir=$(dirname "$f")
  [ "$(stat -c '%u' "$dir")" = "$GEO_UID" ] || return 1
  perm=$(( 8#$(stat -c '%a' "$dir") )); [ $((perm & 0100)) -ne 0 ] || return 1
  [ "$(stat -c '%u' "$f")" = "$GEO_UID" ] || return 1
  perm=$(( 8#$(stat -c '%a' "$f") )); [ $((perm & 0400)) -ne 0 ] || return 1
  return 0
}
if container_can_read "$GEO_DIR/$CITY_LINK" && container_can_read "$GEO_DIR/$ASN_LINK"; then
  say "可读性自检：目录属主=$GEO_UID 且 u+x、文件属主=$GEO_UID 且 u+r —— 容器（uid $GEO_UID）可读 ✓"
else
  say "!! 可读性自检失败：容器（uid $GEO_UID）读不到库（应用会报 GEO_DB_UNUSABLE）—— 检查目录属主与权限"
fi

# 保留策略：current + prev 两份，更早的删掉（一份 city 库约 86MB，2GB 内存/40GB 盘的机器不该囤）
for f in "$GEO_DIR"/dbip-city-lite-*.csv.gz "$GEO_DIR"/dbip-asn-lite-*.csv.gz; do
  [ -e "$f" ] || continue
  case "$(month_of "$(basename "$f")")" in
    "$TARGET"|"$OLD_CITY_MONTH") : ;;
    *) say "删除更早的库：$(basename "$f")"; rm -f "$f" ;;
  esac
done

say "更新完成：$TARGET（上一版：${OLD_CITY_MONTH:-无}）"
say "当前：$(ls -l "$GEO_DIR" | tr '\n' ' | ')"
say "★ 库文件是启动时装载的 —— 需要重建容器才会生效："
say "    bash $APP/scripts/srv1-redeploy.sh --force"
say "  或（演练/临时）先验证配置能读到：curl -s localhost:9900/api/public/geo | head -c 300"
notify INFO "GeoIP 库已更新到 $TARGET" "DB-IP Lite City/ASN $TARGET 已落地（600/700，属主 $GEO_UID:$GEO_GID）。
署名：IP 地理位置数据由 DB-IP (https://db-ip.com) 提供，CC BY 4.0
生效条件：需重建容器（bash scripts/srv1-redeploy.sh --force）
回滚：bash scripts/srv1-geoip-update.sh --rollback"
exit 0
