#!/usr/bin/env bash
# ============================================================
# 把临时隧道换成 Cloudflare 命名隧道
# ------------------------------------------------------------
# 用法：bash setup-named-tunnel.sh
# 前置：/root/tunnel-token.txt 里放着命名隧道的 Token（权限 600）
#
# 为什么换：
#   原来的快速隧道（quick tunnel）地址是随机分配的，
#   每次重启都会换一个新的 —— 简历上的链接根本没法用。
#   命名隧道把地址固定成 demo.xiaokeqing.cn，而且因为 DNS 指向的是
#   Cloudflare 而不是服务器本身，以后换机器地址也不用改。
#
# 安全要点：Token 从文件读，不从命令行参数读 ——
#   命令行参数会出现在 ps 输出里，同机器其他用户能看到。
# ============================================================
set -euo pipefail

TOKEN_FILE=/root/tunnel-token.txt
OLD_SERVICE=secagent-tunnel

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请用 root 运行"
command -v cloudflared >/dev/null || die "cloudflared 未安装"

log "1/4 读取 Token"
[[ -f $TOKEN_FILE ]] || die "找不到 $TOKEN_FILE"
TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE")
[[ -n $TOKEN ]] || die "Token 为空"
ok "Token 已读取（长度 ${#TOKEN}，不回显内容）"

log "2/4 停用旧的快速隧道"
# 判断方式用「文件是否存在」而不是 grep systemctl list-unit-files 的输出。
# 原来写的是 grep -q "^${OLD_SERVICE}.service"，实测没匹配上 ——
# list-unit-files 的输出是定宽对齐的，而且不同版本/语言环境下的表头与
# 分隔符都不一样，靠解析它的文本很脆。直接看单元文件在不在最可靠。
if [[ -f "/etc/systemd/system/${OLD_SERVICE}.service" ]]; then
  systemctl disable --now "$OLD_SERVICE" 2>/dev/null || true
  ok "已停用 $OLD_SERVICE"
else
  warn "$OLD_SERVICE 单元不存在，跳过"
fi
# 顺手把之前手工跑的 cloudflared 进程也清掉，避免两套同时在跑
pkill -f 'cloudflared tunnel' 2>/dev/null || true
sleep 2

log "3/4 安装命名隧道服务"
# cloudflared service install 会自己生成 systemd 单元并把 Token 写进去
cloudflared service install "$TOKEN"
sleep 3
systemctl enable cloudflared >/dev/null 2>&1 || true
systemctl restart cloudflared
ok "cloudflared 服务已安装并启动"

log "4/4 等待连接建立"
for i in $(seq 1 20); do
  sleep 3
  st=$(systemctl is-active cloudflared 2>/dev/null || echo unknown)
  # 日志里出现 Registered tunnel connection 就说明连上了
  if journalctl -u cloudflared --since "2 minutes ago" 2>/dev/null | grep -q 'Registered tunnel connection'; then
    ok "隧道已注册（第 ${i} 次检查，服务状态 $st）"
    break
  fi
  echo "    [$i] 服务=$st，等待注册…"
done

echo
echo "  --- 服务状态 ---"
printf "    %-20s %s\n" "cloudflared" "$(systemctl is-active cloudflared 2>/dev/null || echo unknown)"
printf "    %-20s %s\n" "$OLD_SERVICE" "$(systemctl is-active $OLD_SERVICE 2>/dev/null || echo 已停用)"

echo
echo "  --- 最近日志 ---"
journalctl -u cloudflared --since "3 minutes ago" --no-pager 2>/dev/null | grep -iE 'registered|location=|error|failed' | tail -5 | sed 's/^/    /' || true

echo
echo "  --- 本机自测（隧道走 Cloudflare 回来）---"
curl -s -o /dev/null -w '    demo.xiaokeqing.cn  HTTP %{http_code}  ttfb=%{time_starttransfer}s\n' \
  --max-time 30 https://demo.xiaokeqing.cn/api/health 2>/dev/null || echo "    （解析可能还没生效，稍等再试）"

echo
echo "  完成后：https://demo.xiaokeqing.cn"
echo "  这个地址不会再变 —— 以后换服务器只需要在新机器上重装隧道。"
