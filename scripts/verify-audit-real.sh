#!/usr/bin/env bash
# ============================================================
# 正确版审计持久化测试
# ------------------------------------------------------------
# 上一次测试失败的原因：直接去看审计文件在不在，然后重启再看。
# 但文件【从来没被创建过】—— 因为生产实例上从没执行过被审计的动作。
# "文件不见了"和"文件没被创建过"是两件完全不同的事，
# 我上一版把它们混为一谈了。
#
# 正确的测法：
#   1) 做一个会被审计的动作
#   2) 确认审计文件真的出现了
#   3) 重启容器
#   4) 确认文件还在、内容还在
#
# 安全性说明：
#   在 MOCK 模式下，封 IP 只是往 blocked-ips.json 写一条记录，
#   不会调用 iptables / Wazuh，对真实网络零影响。
#   而且用的是一个无关的测试 IP，60 分钟后自动过期。
#
# 顺便测护栏：故意封一个白名单里的地址（TEST-NET），
#   期望被拒绝 —— 而且【拒绝也要留痕】。
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

APP=/opt/secagent
BASE=http://127.0.0.1:9900

log "0/7 登录拿 Token"
U=$(grep '^SECAGENT_USERNAME=' "$APP/.env" | cut -d= -f2)
P=$(grep '^SECAGENT_PASSWORD=' "$APP/.env" | cut -d= -f2)
TOKEN=$(curl -s -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$U\",\"password\":\"$P\"}" 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["token"])' 2>/dev/null)
[ -n "$TOKEN" ] || die "登录失败"
ok "登录成功"

AUTH="Authorization: Bearer $TOKEN"

log "1/7 测试前：审计文件状态"
for f in response-audit.json tool-call-audit.json blocked-ips.json; do
  if [ -f "$APP/data/$f" ]; then
    printf "    %-24s 存在  %s bytes\n" "$f" "$(stat -c %s "$APP/data/$f")"
  else
    printf "    %-24s 【不存在】\n" "$f"
  fi
done

log "2/7 动作 A：故意封一个【白名单里的】地址（期望被护栏拒绝，且拒绝要留痕）"
echo "    目标: 203.0.113.45（TEST-NET-3，已在保护白名单里）"
R1=$(curl -s -X POST "$BASE/api/response/block" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"ip":"203.0.113.45","durationMinutes":10,"reason":"审计持久化测试-白名单拒绝场景"}' 2>/dev/null)
echo "    返回: $(echo "$R1" | head -c 300)"

log "3/7 动作 B：封一个普通公网地址（MOCK 模式，只写记录）"
echo "    目标: 45.83.91.12（一个无关的公网地址）"
R2=$(curl -s -X POST "$BASE/api/response/block" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"ip":"45.83.91.12","durationMinutes":10,"reason":"审计持久化测试"}' 2>/dev/null)
echo "    返回: $(echo "$R2" | head -c 300)"

log "4/7 审计文件出现了吗（这一步才是上一版漏掉的）"
FOUND=0
for f in response-audit.json tool-call-audit.json blocked-ips.json; do
  if [ -f "$APP/data/$f" ]; then
    printf "    ✅ %-24s %s bytes\n" "$f" "$(stat -c %s "$APP/data/$f")"
    echo "       sha256: $(sha256sum "$APP/data/$f" | cut -c1-24)"
    FOUND=$((FOUND+1))
  else
    printf "    ❌ %-24s 【仍然不存在】\n" "$f"
  fi
done
[ "$FOUND" -gt 0 ] || warn "一个审计文件都没生成 —— 审计功能可能没工作"

echo
echo "    --- 审计内容（确认真的记了刚才两个动作）---"
if [ -f "$APP/data/response-audit.json" ]; then
  python3 -c "
import json
d = json.load(open('$APP/data/response-audit.json', encoding='utf-8'))
recs = d if isinstance(d, list) else d.get('records', [])
print('      审计条数:', len(recs))
for r in recs[-4:]:
    print('      -', r.get('action'), '|', r.get('target'), '|', r.get('result'), '|', (r.get('reason') or '')[:30])
" 2>/dev/null || head -c 400 "$APP/data/response-audit.json" | sed 's/^/      /'
fi

if [ -f "$APP/data/blocked-ips.json" ]; then
  echo "    --- 封禁记录 ---"
  python3 -c "
import json
d = json.load(open('$APP/data/blocked-ips.json', encoding='utf-8'))
recs = d if isinstance(d, list) else d.get('records', [])
print('      封禁条数:', len(recs))
for r in recs[-3:]:
    print('      -', r.get('ip'), '| 到期', r.get('expiresAt') or r.get('expireAt'))
" 2>/dev/null || head -c 300 "$APP/data/blocked-ips.json" | sed 's/^/      /'
fi

log "5/7 重启容器"
docker restart secagent >/dev/null 2>&1
for i in $(seq 1 40); do
  sleep 5
  ST=$(docker inspect --format '{{.State.Health.Status}}' secagent 2>/dev/null || echo unknown)
  [ "$ST" = "healthy" ] && { echo "    第 $((i*5)) 秒: healthy"; break; }
done

log "6/7 重启后：审计文件还在吗、内容还对得上吗（关键比对）"
for f in response-audit.json tool-call-audit.json blocked-ips.json; do
  if [ -f "$APP/data/$f" ]; then
    printf "    ✅ %-24s %s bytes  sha256 %s\n" "$f" "$(stat -c %s "$APP/data/$f")" "$(sha256sum "$APP/data/$f" | cut -c1-24)"
  else
    printf "    ❌ %-24s 【重启后丢了】\n" "$f"
  fi
done

echo
echo "    --- 容器内能读到吗（新容器实例）---"
docker exec secagent sh -c 'ls -la /app/data/ 2>/dev/null' | sed 's/^/      /'

log "7/7 结论"
echo "    ① 审计功能是否真的工作  -> 看第 4 步有没有生成文件"
echo "    ② 审计是否真的持久化    -> 对比第 4 步和第 6 步的 sha256"
echo "       · 一致 -> 落在 bind mount 上，容器重建不丢 ✅"
echo "       · 不一致/丢失 -> '全部动作留痕' 是假的，必须改存储方式"
echo "    ③ 护栏是否留痕          -> 看审计里有没有那个被拒绝的 203.0.113.45"
echo
echo "    清理：测试封禁 10 分钟后自动过期。如需立刻解封："
echo "      curl -X POST $BASE/api/response/unblock -H '$AUTH' -d '{\"ip\":\"45.83.91.12\"}'"
