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
#
#   业务数据（能恢复服务）
#     /opt/secagent/data/               向量库、事件、审计、评测、工单
#     /opt/secagent/docker-compose.yml  编排配置
#     /opt/secagent/.env                凭据（⚠️ 含密钥，备份包属于敏感文件）
#
#   主机配置（能换机）—— 放在 host/ 子目录，与业务数据分开
#     host/crontab.txt                  定时任务
#     host/cloudflared*                 隧道凭据与 systemd 单元
#     host/security/                    fail2ban / firewalld / sshd 配置
#     host/scripts/                     /root 下的运维脚本
#     host/system-info.txt              系统快照
#
# 【为什么要把主机配置也收进来】
#   一开始只备份业务数据。但「能恢复数据」不等于「能换机」——
#   crontab 丢了，备份任务本身就不再执行（而且不会报错，是静默失效）；
#   cloudflared token 丢了，要重建隧道；安全配置丢了，要凭记忆重配。
#   换机这种事一辈子做不了几次，做完一次就忘，所以必须让备份自己带全。
#   换机步骤见 docs/迁移手册.md。
#
# 注意：.env 与 cloudflared-token 里有密钥，所以备份包【本身就是敏感文件】，
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
  # 「能恢复业务数据」不等于「能换机」。换机还依赖主机配置，逐项点名检查，
  # 缺了就明确报出缺哪个 —— 而不是给一个笼统的「校验通过」。
  echo "  4) 换机必备项检查"
  while IFS=: read -r path desc; do
    if [[ -f "$TMP/$path" ]]; then
      printf "     \033[1;32m[有]\033[0m %-30s %s\n" "$path" "$desc"
    else
      printf "     \033[1;31m[缺]\033[0m %-30s %s\n" "$path" "$desc"
      FAIL=1
    fi
  done <<'ITEMS'
host/crontab.txt:定时任务（备份任务本身在里面，丢了会静默失效）
host/cloudflared-token:隧道凭据（丢了要重建隧道，或从 API 重新取）
host/cloudflared.service:隧道 systemd 单元
host/system-info.txt:系统快照（换机时对照发行版差异）
docker-compose.yml:编排配置
.env:凭据与配置
ITEMS

  echo
  if [[ $FAIL -eq 0 ]]; then
    ok "校验通过 —— 业务数据能恢复，换机必备项也齐全"
    echo "       换机步骤见 docs/迁移手册.md"
  else
    die "校验发现问题，这份备份不可信（或不足以换机）"
  fi
  exit 0
fi

# ------------------------------------------------------------
# 默认：创建备份
# ------------------------------------------------------------
TS=$(date +%Y%m%d-%H%M%S)
NAME="secagent-$TS.tar.gz"
OUT="$BACKUP_DIR/$NAME"

log "1/4 打包业务数据"
INCLUDE=("data" "docker-compose.yml" ".env")
for item in "${INCLUDE[@]}"; do
  [[ -e "$APP_DIR/$item" ]] || die "缺少 $APP_DIR/$item，拒绝生成不完整的备份"
done

# ------------------------------------------------------------
# 主机配置：光有业务数据是不足以「换机」的。
# 这台机器上还有一堆东西是业务数据之外的，丢了就得凭记忆重建：
#   · crontab（备份任务本身就在里面，丢了就再也不备份了 —— 会静默失效）
#   · cloudflared 的 systemd 单元与 tunnel token（丢了要重建隧道）
#   · fail2ban / firewalld / sshd 的安全配置
#   · /root 下的运维脚本
# 所以一并收进来，放在 host/ 子目录里与业务数据分开。
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/host/security" "$STAGE/host/scripts"

crontab -l > "$STAGE/host/crontab.txt" 2>/dev/null || echo "# crontab 为空" > "$STAGE/host/crontab.txt"

for u in cloudflared.service cloudflared-update.service secagent-tunnel.service; do
  [[ -f "/etc/systemd/system/$u" ]] && cp "/etc/systemd/system/$u" "$STAGE/host/"
done
[[ -f /etc/cloudflared/token ]] && cp /etc/cloudflared/token "$STAGE/host/cloudflared-token"

cp /etc/fail2ban/jail.local "$STAGE/host/security/" 2>/dev/null || true
cp -r /etc/fail2ban/jail.d/. "$STAGE/host/security/" 2>/dev/null || true
cp /etc/firewalld/zones/public.xml "$STAGE/host/security/" 2>/dev/null || true
cp /etc/ssh/sshd_config.d/*.conf "$STAGE/host/security/" 2>/dev/null || true
cp /root/*.sh "$STAGE/host/scripts/" 2>/dev/null || true

# 系统信息快照：换机时用来对照发行版差异（RHEL 系与 Debian 系的坑不一样）
{
  echo "=== 采集时间 ==="; date -Is
  echo; echo "=== 内核 ==="; uname -a
  echo; echo "=== 发行版 ==="; cat /etc/os-release 2>/dev/null
  echo; echo "=== systemd 版本 ==="; systemctl --version 2>/dev/null | head -1
  echo; echo "=== 内存 / Swap ==="; free -m
  echo; echo "=== 磁盘 ==="; df -h /
  echo; echo "=== 监听端口 ==="; ss -tlnp 2>/dev/null
  echo; echo "=== 已启用的服务 ==="; systemctl list-unit-files --state=enabled --no-legend 2>/dev/null
  echo; echo "=== 镜像 ==="; docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' 2>/dev/null
} > "$STAGE/host/system-info.txt" 2>&1

tar -czf "$OUT" -C "$APP_DIR" "${INCLUDE[@]}" -C "$STAGE" host
ok "已生成 $NAME  ($(du -h "$OUT" | cut -f1))"
echo "       业务数据: ${INCLUDE[*]}"
echo "       主机配置: host/（crontab / systemd / 隧道 token / 安全配置 / 运维脚本 / 系统快照）"

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
