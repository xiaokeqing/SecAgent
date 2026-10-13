#!/usr/bin/env bash
# ============================================================
# srv1：把 ACR 拉取凭据从"主账号"切换为只读子账号（srv1-puller）
# ------------------------------------------------------------
# 背景（2026-10-13 实测）：srv1 上 /root/.docker/config.json 与 /etc/secagent/docker/config.json
#   仍以【主账号 aliyun4512567175】登录 ACR —— 主账号凭据权限过大且已多次出现在记录里。
#   目标：换成 RAM 子账号 srv1-puller（仅 cr:GetAuthorizationToken + cr:PullRepository）。
#
# 本脚本做四件事（每一步都可复核）：
#   ① 用新凭据登录两个 ACR 域名（VPC 内网 + 公网）
#   ② 把凭据同步到服务用的独立目录 /etc/secagent/docker（systemd 单元用 DOCKER_CONFIG 指向它）
#   ③ 正向验证：docker pull stable 必须成功
#   ④ 负向验证：docker push 一个测试 tag 必须【失败】（证明它只有拉取权限）—— 这是最小权限的关键边界
#
# 用法（srv1，root）：
#   # 方式一：交互输入（推荐，不落历史）
#   bash srv1-switch-acr-credential.sh
#   # 方式二：从环境变量读（适合你自己用一次性 shell）
#   ACR_USER='srv1-puller@xxx.onaliyun.com' ACR_PASS='***' bash srv1-switch-acr-credential.sh
#   # 只做检查不改动：
#   bash srv1-switch-acr-credential.sh --check
# 退出码：0=切换成功且负向验证通过；1=有问题（脚本会把原凭据恢复）
# ============================================================
set -uo pipefail

VPC=crpi-bhyvm4rwtqasz9y3-vpc.cn-hangzhou.personal.cr.aliyuncs.com
PUB=crpi-bhyvm4rwtqasz9y3.cn-hangzhou.personal.cr.aliyuncs.com
REPO_PATH=xiaokeqing/secagent
NEW_CFG_DIR=/etc/secagent/docker
ROOT_CFG=/root/.docker/config.json
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

ok()   { printf '  \033[1;32m[OK]\033[0m %s\n' "$*"; }
bad()  { printf '  \033[1;31m[X]\033[0m  %s\n' "$*"; }
info() { printf '      %s\n' "$*"; }

show_current_user() {
  python3 - "$1" <<'PY'
import json,base64,sys
try:
    d=json.load(open(sys.argv[1]))
except Exception:
    print("      （读不到 %s）" % sys.argv[1]); raise SystemExit
for k,v in (d.get('auths') or {}).items():
    try: u=base64.b64decode(v.get('auth','')).decode().split(':')[0]
    except Exception: u='?'
    print("      %s → %s" % (k,u))
PY
}

echo "== 当前凭据身份 =="
info "root: $ROOT_CFG"; show_current_user "$ROOT_CFG"
info "服务: $NEW_CFG_DIR/config.json"; show_current_user "$NEW_CFG_DIR/config.json"
[ "$CHECK_ONLY" = "1" ] && { echo; echo "（--check：只查看，不改动）"; exit 0; }

# ---------- 取新凭据 ----------
if [ -z "${ACR_USER:-}" ] || [ -z "${ACR_PASS:-}" ]; then
  printf '  ACR 只读子账号用户名（srv1-puller 的登录名或 AccessKeyId）: '; read -r ACR_USER
  printf '  密码 / AccessKeySecret（输入不回显）: '; read -rs ACR_PASS; echo
fi
[ -n "$ACR_USER" ] && [ -n "$ACR_PASS" ] || { bad "凭据为空，退出"; exit 1; }

# ---------- 备份原凭据（失败可回滚） ----------
TS=$(date +%Y%m%d-%H%M%S)
BAK=/etc/secagent/backup/docker-config-$TS.json
mkdir -p /etc/secagent/backup
[ -f "$NEW_CFG_DIR/config.json" ] && cp -a "$NEW_CFG_DIR/config.json" "$BAK" && info "已备份原凭据 → $BAK"

echo "== ① 登录两个 ACR 域名 =="
FAILED=0
for H in "$VPC" "$PUB"; do
  if printf '%s' "$ACR_PASS" | docker login "$H" -u "$ACR_USER" --password-stdin >/dev/null 2>&1; then
    ok "登录成功：$H"
  else
    bad "登录失败：$H"; FAILED=1
  fi
done
[ "$FAILED" = "1" ] && { bad "有域名登录失败 —— 不改动服务凭据，退出（原凭据未动）"; exit 1; }

echo "== ② 同步到服务用的独立目录（systemd 单元通过 DOCKER_CONFIG 使用它） =="
mkdir -p "$NEW_CFG_DIR"
cp -a "$ROOT_CFG" "$NEW_CFG_DIR/config.json"
chmod 700 "$NEW_CFG_DIR"; chmod 600 "$NEW_CFG_DIR/config.json"
chown -R root:root "$NEW_CFG_DIR"
ok "已写入 $NEW_CFG_DIR/config.json（700/600）"
show_current_user "$NEW_CFG_DIR/config.json"

echo "== ③ 正向验证：拉取必须成功 =="
if docker pull -q "$VPC/$REPO_PATH:stable" >/dev/null 2>&1; then
  REV=$(docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$VPC/$REPO_PATH:stable" 2>/dev/null | head -c 7)
  ok "拉取成功（stable revision=${REV:-?}）"
else
  bad "拉取失败 —— 回滚原凭据"
  [ -f "$BAK" ] && cp -a "$BAK" "$NEW_CFG_DIR/config.json" && info "已回滚"
  exit 1
fi

echo "== ④ 负向验证：推送必须【失败】（证明只有拉取权限） =="
TAG="$VPC/$REPO_PATH:verify-pull-only-$TS"
docker tag "$VPC/$REPO_PATH:stable" "$TAG" >/dev/null 2>&1
if docker push "$TAG" >/dev/null 2>&1; then
  bad "推送竟然成功了 —— 这个凭据权限过大（不是只读子账号）！"
  info "请检查 RAM 策略：srv1-puller 只应有 cr:GetAuthorizationToken + cr:PullRepository"
  docker rmi "$TAG" >/dev/null 2>&1 || true
  exit 1
else
  ok "推送被拒绝（符合预期：只读子账号推不了镜像）"
  docker rmi "$TAG" >/dev/null 2>&1 || true
fi

echo "== ⑤ 触发一次真实发布，确认整链仍正常 =="
systemctl start secagent-redeploy.service
sleep 3
echo "  发布服务结果：$(systemctl show secagent-redeploy.service -p Result --value)"
bash /opt/secagent/scripts/deploy-chain-check.sh 2>&1 | tail -n 6 | sed 's/^/  /'

echo
ok "切换完成：srv1 现在以【只读子账号】拉取镜像；主账号凭据可轮换"
info "备份（若要回滚）：$BAK"
