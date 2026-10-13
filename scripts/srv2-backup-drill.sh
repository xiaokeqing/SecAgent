#!/usr/bin/env bash
# ============================================================
# srv2：状态备份的「恢复抽测」（把备份真的还原一次，再逐文件比对）
# ------------------------------------------------------------
# 安装位置：/usr/local/sbin/secagent-backup-drill.sh（755，root:root）
# 用法：secagent-backup-drill.sh <备份目录>
#       备份目录里应有 data-<stamp>.tar.gz 与同名 .sha256
# 退出码：0 = 抽测通过；非 0 = 不通过（调用方据此决定是否留这份备份）
#
# 为什么"备份成功"必须用抽测而不是用 tar 的退出码来证明：
#   tar 只保证"写进去了"，不保证"能读回来"。而这份备份的唯一用途
#   就是灾难时读回来。所以每收一份就真的解一次、逐个文件算 sha256 ——
#   这正是"结论必须有运行态证据"那条铁律在备份链上的用法。
#
# 比对四个量（任一不符即失败）：
#   ① 外层：.sha256 与 tar.gz 本身是否对得上（传输/磁盘层面没坏）
#   ② 数量：manifest 里的行数 == 解出来的文件数（没漏、没多）
#   ③ 集合：文件路径集合逐一对应（不是"数量对但换了个文件"）
#   ④ 内容：sha256sum -c manifest 全部 OK（每个字节都对）
# ============================================================
set -uo pipefail

DIR=${1:-}
[ -n "$DIR" ] || { echo "用法：$0 <备份目录>"; exit 64; }
[ -d "$DIR" ] || { echo "错误：不是目录：$DIR"; exit 66; }

ARCH=$(find "$DIR" -maxdepth 1 -type f -name 'data-*.tar.gz' | sort | head -1)
[ -n "$ARCH" ] || { echo "错误：$DIR 下找不到 data-*.tar.gz"; exit 66; }
STAMP=$(basename "$ARCH" .tar.gz); STAMP=${STAMP#data-}
SHAF="$ARCH.sha256"

echo "--- 恢复抽测 $STAMP ---"
echo "归档：$ARCH（$(stat -c %s "$ARCH") 字节，权限 $(stat -c %A "$ARCH")）"

# ---------- ① 外层完整性 ----------
if [ -f "$SHAF" ]; then
  if ! ( cd "$(dirname "$ARCH")" && sha256sum -c "$(basename "$SHAF")" ); then
    echo "抽测失败：归档自身 sha256 不匹配（备份文件已损坏）"
    exit 1
  fi
else
  echo "抽测失败：缺少校验文件 $SHAF"
  exit 1
fi

TMP=$(mktemp -d /tmp/secagent-drill.XXXXXX) || { echo "抽测失败：无法创建临时目录"; exit 70; }
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

if ! tar -xzf "$ARCH" -C "$TMP" --no-same-owner; then
  echo "抽测失败：解压失败"
  exit 1
fi

[ -f "$TMP/manifest.sha256" ] || { echo "抽测失败：归档里没有 manifest.sha256"; exit 1; }
[ -d "$TMP/data" ] || { echo "抽测失败：归档里没有 data/ 目录"; exit 1; }

# ---------- ② 数量 ----------
WANT=$(wc -l < "$TMP/manifest.sha256" | tr -d ' ')
HAVE=$(find "$TMP/data" -type f | wc -l | tr -d ' ')
echo "文件数：manifest=$WANT  实际解出=$HAVE"
if [ "$WANT" != "$HAVE" ]; then
  echo "抽测失败：文件数不一致（manifest 说 $WANT，实际 $HAVE）"
  exit 1
fi
if [ "$WANT" = "0" ]; then
  echo "抽测失败：备份里一个文件都没有（空的备份等于没有备份）"
  exit 1
fi

# ---------- ③ 集合 ----------
# 用 sed 取文件名而不是 awk '{print $2}'：coreutils 在文本模式写 "hash  file"，
# 在二进制模式写 "hash *file"（Git Bash for Windows 就是后者）。两种都要认，
# 否则"在开发机上做抽测"会误报清单不一致。
LIST=$(mktemp)
sed 's/^[0-9a-f]\{64\} [ *]//' "$TMP/manifest.sha256" | sort > "$LIST"
if ! diff -u "$LIST" <(cd "$TMP" && find data -type f | sort) > "$LIST.diff"; then
  echo "抽测失败：文件清单不一致（manifest 与实际解出的路径集合不同）"
  sed -n '1,20p' "$LIST.diff"
  rm -f "$LIST" "$LIST.diff"
  exit 1
fi
rm -f "$LIST" "$LIST.diff"

# ---------- ④ 内容 ----------
CHECK=$TMP/.sha256-check.txt
if ! ( cd "$TMP" && sha256sum -c manifest.sha256 > "$CHECK" 2>&1 ); then
  echo "抽测失败：有文件内容对不上："
  grep -v ': OK$' "$CHECK" | sed -n '1,20p'
  exit 1
fi
OKN=$(grep -c ': OK$' "$CHECK" | tr -d ' ')

echo "逐文件 sha256 比对：全部 OK"
echo "恢复抽测 $STAMP：$OKN/$WANT 一致（文件数 $HAVE 个，内容与归档时逐字节相同）"
exit 0
