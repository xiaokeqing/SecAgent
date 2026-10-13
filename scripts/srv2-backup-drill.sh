#!/usr/bin/env bash
# ============================================================
# srv2：状态备份的「恢复抽测」（把备份真的还原一次，再逐文件比对）
# ------------------------------------------------------------
# 安装位置：/usr/local/sbin/secagent-backup-drill.sh（755，root:root）
# 用法：secagent-backup-drill.sh <备份目录>
#       备份目录里应有 data-<stamp>.tar.gz.enc（或过渡期的 data-<stamp>.tar.gz）与同名 .sha256
# 退出码：0 = 抽测通过；非 0 = 不通过（调用方据此决定是否留这份备份）
#
# 为什么"备份成功"必须用抽测而不是用 tar 的退出码来证明：
#   tar 只保证"写进去了"，不保证"能读回来"。而这份备份的唯一用途
#   就是灾难时读回来。所以每收一份就真的解一次、逐个文件算 sha256 ——
#   这正是"结论必须有运行态证据"那条铁律在备份链上的用法。
#
# 【2026-10-13 同步更新】备份改成 AES-256-CBC 加密（*.tar.gz.enc）之后，
#   抽测必须跟着改：先解密再解压，否则抽测会在"tar: 不是 gzip 格式"上失败，
#   或者更糟 —— 被误判成"备份坏了"。密钥位置 /opt/secagent-backup.key（600）。
#   这一步同时也是"密钥到底对不对"的唯一运行态证明：
#   解密成功 + 逐文件 sha256 全中 ⇒ 密钥可用、密文完整。
#
# 比对四个量（任一不符即失败）：
#   ① 外层：.sha256 与归档文件本身是否对得上（传输/磁盘层面没坏）
#   ①b 解密：*.enc 能用本机密钥解开（密钥可用性的运行态证据）
#   ② 数量：manifest 里的行数 == 解出来的文件数（没漏、没多）
#   ③ 集合：文件路径集合逐一对应（不是"数量对但换了个文件"）
#   ④ 内容：sha256sum -c manifest 全部 OK（每个字节都对）
# ============================================================
set -uo pipefail

DIR=${1:-}
[ -n "$DIR" ] || { echo "用法：$0 <备份目录>"; exit 64; }
[ -d "$DIR" ] || { echo "错误：不是目录：$DIR"; exit 66; }

BACKUP_KEY=${BACKUP_KEY:-/opt/secagent-backup.key}
OPENSSL_ITER=${OPENSSL_ITER:-200000}

# 归档定位：优先加密格式（现在的默认），兼容过渡期的明文 *.tar.gz
ARCH=$(find "$DIR" -maxdepth 1 -type f -name 'data-*.tar.gz.enc' | sort | head -1)
ENC=1
if [ -z "$ARCH" ]; then
  ARCH=$(find "$DIR" -maxdepth 1 -type f -name 'data-*.tar.gz' | sort | head -1)
  ENC=0
fi
[ -n "$ARCH" ] || { echo "错误：$DIR 下找不到 data-*.tar.gz.enc 或 data-*.tar.gz"; exit 66; }

BASE=$(basename "$ARCH")
case "$BASE" in
  *.tar.gz.enc) STAMP=${BASE%.tar.gz.enc} ;;
  *)            STAMP=${BASE%.tar.gz} ;;
esac
STAMP=${STAMP#data-}
SHAF="$ARCH.sha256"

echo "--- 恢复抽测 $STAMP ---"
echo "归档：$ARCH（$(stat -c %s "$ARCH") 字节，权限 $(stat -c %A "$ARCH")）"
echo "格式：$([ "$ENC" = 1 ] && echo 'enc（AES-256-CBC + PBKDF2，加密存储）' || echo 'plain（旧格式，明文）')"

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

# ---------- ①b 解密（加密格式才有） ----------
EXTRACT="$ARCH"
if [ "$ENC" = "1" ]; then
  if [ ! -f "$BACKUP_KEY" ]; then
    echo "抽测失败：备份是加密的，但找不到解密密钥 $BACKUP_KEY —— 这份备份当前【解不开】"
    exit 1
  fi
  # 【踩坑】密文的前两字节不是 gzip 魔数 —— 打印出来当"确实加密了"的证据，
  # 而不是只相信文件名后缀。
  echo "密文头 2 字节：$(head -c 2 "$ARCH" | od -An -tx1 | tr -d ' \n')（gzip 魔数应为 1f8b）"
  EXTRACT="$TMP/.archive.tar.gz.plain"
  if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter "$OPENSSL_ITER" \
         -in "$ARCH" -out "$EXTRACT" -pass file:"$BACKUP_KEY" 2>/dev/null; then
    echo "抽测失败：解密失败（密钥不对？密文被截断/损坏？）"
    exit 1
  fi
  echo "解密成功：明文 $(stat -c %s "$EXTRACT") 字节（gzip 头 $(head -c 2 "$EXTRACT" | od -An -tx1 | tr -d ' \n')）"
fi

if ! tar -xzf "$EXTRACT" -C "$TMP" --no-same-owner; then
  echo "抽测失败：解压失败"
  exit 1
fi
rm -f "$EXTRACT" 2>/dev/null || true

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
echo "排除项（如是加密归档，meta.txt 里会记 access.jsonl* 被排除；这不是损坏）："
grep -E '^excluded' "$TMP/meta.txt" 2>/dev/null | sed 's/^/  /' || echo "  （没有 meta.txt 或没有 excluded 行）"
echo "恢复抽测 $STAMP：$OKN/$WANT 一致（文件数 $HAVE 个，内容与归档时逐字节相同）"
exit 0
