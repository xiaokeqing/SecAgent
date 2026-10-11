#!/usr/bin/env bash
# ============================================================
# SecAgent 数据备份 / 恢复验证
# ------------------------------------------------------------
# 用法：
#   bash backup.sh              创建一份备份
#   bash backup.sh --verify     取出最新备份解到临时目录，逐项校验
#   bash backup.sh --list       列出所有备份
#
# 为什么这个脚本必须存在：
#   这台是阿里云「到期不续」的试用机，/opt/secagent/data 下是向量库、
#   事件、评测记录、审计、工单 —— 全部只有内存 + 单份 JSON 文件。
#   机器一到期、或者一次误操作 rm，这些东西就永久没了。
#   而且它属于「不可逆」那一类风险：代码丢了可以从 GitHub 拉回来，
#   数据丢了没有任何地方能找回。
#
# 备份内容：
#   /opt/secagent/data/          业务数据（向量库、事件、审计、评测…）
#   /opt/secagent/docker-compose.yml  编排配置
#   /opt/secagent/.env           凭据（⚠️ 含密钥，备份包属于敏感文件）
#
# 注意：.env 里有 API Key 和口令，所以备份包【本身就是敏感文件】，
#      不要丢进 git 仓库、不要发给别人。脚本会把这一点打在输出里。
# ============================================================
set -euo pipefail

APP_DIR=/opt/secagent
BACKUP_DIR=/opt/secagent-backups
KEEP=14

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请用 root 运行"
[[ -d $APP_DIR ]] || die "找不到 $APP_DIR"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# ------------------------------------------------------------
# --list
# ------------------------------------------------------------
if [[ "${1:-}" == "--list" ]]; then
  log "已有备份"
  if ls -1 "$BACKUP_DIR"/*.tar.gz >/dev/null 2>&1; then
    ls -lht "$BACKUP_DIR"/*.tar.gz | awk '{printf "  %-46s %6.1f MB  %s %s %s\n", $9, $5/1048576, $6, $7, $8}'
    echo
    echo "  合计 $(du -sh "$BACKUP_DIR" | cut -f1)"
  else
    warn "还没有任何备份"
  fi
  exit 0
fi

# ------------------------------------------------------------
# --verify：真的解出来校验，而不是只看文件在不在
# ------------------------------------------------------------
if [[ "${1:-}" == "--verify" ]]; then
  LATEST=$(ls -1t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | head -1 || true)
  [[ -n $LATEST ]] || die "没有可校验的备份"
  log "校验备份：$(basename "$LATEST")"

  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT

  echo "  1) 解包"
  tar -xzf "$LATEST" -C "$TMP" || die "解包失败 —— 备份包已损坏"
  ok "解包成功"

  echo
  echo "  2) 逐项校验内容"
  FAIL=0
  for f in $(find "$TMP" -type f | sort); do
    rel=${f#$TMP/}
    size=$(stat -c %s "$f")
    if [[ $size -eq 0 ]]; then
      echo "     [空文件] $rel"
      FAIL=1
      continue
    fi
    # .json 文件必须能被解析，否则恢复出来也没用
    if [[ $rel == *.json ]]; then
      if command -v python3 >/dev/null 2>&1; then
        if python3 -c "import json,sys; json.load(open(sys.argv[1], encoding='utf-8'))" "$f" 2>/dev/null; then
          echo "     [JSON OK] $rel  ${size} bytes"
        else
          echo "     [JSON 解析失败] $rel"
          FAIL=1
        fi
      else
        # 没有 python3 就退化为结构检查
        head -c1 "$f" | grep -qE '[\[{]' && echo "     [结构 OK] $rel  ${size} bytes" || { echo "     [结构可疑] $rel"; FAIL=1; }
      fi
    else
      echo "     [文件 OK] $rel  ${size} bytes"
    fi
  done

  echo
  echo "  3) 与当前线上数据比对大小"
  for name in vector-store.json security-events.json; do
    CUR="$APP_DIR/data/$name"
    BAK=$(find "$TMP" -name "$name" | head -1)
    if [[ -f $CUR && -n $BAK ]]; then
      cs=$(stat -c %s "$CUR"); bs=$(stat -c %s "$BAK")
      printf "     %-26s 线上 %8s bytes  备份 %8s bytes\n" "$name" "$cs" "$bs"
    fi
  done

  echo
  if [[ $FAIL -eq 0 ]]; then
    ok "校验通过 —— 这份备份是【真的能恢复】的，不只是文件存在"
  else
    die "校验发现问题，这份备份不可信"
  fi
  exit 0
fi

# ------------------------------------------------------------
# 默认：创建备份
# ------------------------------------------------------------
TS=$(date +%Y%m%d-%H%M%S)
NAME="secagent-$TS.tar.gz"
OUT="$BACKUP_DIR/$NAME"

log "1/4 打包"
INCLUDE=("data" "docker-compose.yml" ".env")
for item in "${INCLUDE[@]}"; do
  [[ -e "$APP_DIR/$item" ]] || die "缺少 $APP_DIR/$item，拒绝生成不完整的备份"
done
tar -czf "$OUT" -C "$APP_DIR" "${INCLUDE[@]}"
ok "已生成 $NAME  ($(du -h "$OUT" | cut -f1))"

log "2/4 校验包完整性"
# 只验证能不能列出内容，不解包（解包留给 --verify）
if ! tar -tzf "$OUT" >/dev/null 2>&1; then
  rm -f "$OUT"
  die "生成的包无法读取，已删除"
fi
ok "包结构可读"

log "3/4 计算校验和"
sha256sum "$OUT" | awk '{print "    "$1}' > "$OUT.sha256"
ok "校验和已存 $(basename "$OUT.sha256")"

log "4/4 清理旧备份（保留最近 $KEEP 份）"
COUNT=$(ls -1 "$BACKUP_DIR"/*.tar.gz 2>/dev/null | wc -l)
if [[ $COUNT -gt $KEEP ]]; then
  ls -1t "$BACKUP_DIR"/*.tar.gz | tail -n +$((KEEP + 1)) | while read -r old; do
    rm -f "$old" "$old.sha256"
    echo "    已删除旧备份 $(basename "$old")"
  done
else
  echo "    当前 $COUNT 份，未超过上限"
fi

echo
echo "============================================================"
echo " 备份完成：$OUT"
echo " 大小：$(du -h "$OUT" | cut -f1)"
echo "============================================================"
echo
warn "这个包里【含 .env】，也就是 API Key 与口令，属于敏感文件。"
warn "不要放进 git 仓库、不要发给别人、不要上传到公开网盘。"
echo
echo " 下一步建议："
echo "   · 校验这份备份是否真能恢复：bash backup.sh --verify"
echo "   · 拉一份到本地：在开发机上执行"
echo "       scp root@<服务器>:$OUT ./"
echo
echo " ⚠️ 只留在服务器上的备份不算备份 —— 机器到期时它一起没。"
