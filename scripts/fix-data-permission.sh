#!/usr/bin/env bash
# ============================================================
# 修两个真问题
# ------------------------------------------------------------
# 问题① 部署漂移：服务器 1 跑的是 11:05 构建的旧镜像，
#   缺 P0 修复（BCrypt 口令 / 13 条白名单 / 边界转义）。
#   -> 需要重新部署最新镜像（本脚本先修权限，镜像在本地重建后传）
#
# 问题② 数据目录写不进去，但 API 返回成功：
#   宿主机 /opt/secagent/data 是 root:root 755，
#   而容器以 secagent(uid=999) 运行 -> 写不进去。
#   AuditService / BlockRecordStore 只在日志里报错，API 照样返回 success。
#
#   这条比①更隐蔽：功能"看起来正常"，但审计和封禁记录全是空的。
#   对安全项目来说这是致命的 —— "全部动作留痕"这句话是假的。
#
# 修法：
#   a) 把宿主机 data 目录的属主改成容器用户（999:999）
#   b) 【更重要】部署脚本里固化这个 chown，否则下次重建卷又复发
#   c) 让这类失败能被看见（改代码，见后续提交）
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }

APP=/opt/secagent

log "1/4 查清楚容器用户的 uid/gid"
CID=$(docker inspect secagent --format '{{.Id}}' 2>/dev/null)
UID_GID=$(docker exec secagent id -u 2>/dev/null):$(docker exec secagent id -g 2>/dev/null)
echo "    容器内用户: $(docker exec secagent sh -c 'id' 2>/dev/null)"
echo "    uid:gid = $UID_GID"

log "2/4 修宿主机 data 与 uploads 目录属主"
echo "    修改前:"
ls -ld "$APP/data" "$APP/uploads" 2>/dev/null | sed 's/^/      /'
chown -R "$UID_GID" "$APP/data" "$APP/uploads" 2>/dev/null
chmod 750 "$APP/data" "$APP/uploads" 2>/dev/null
echo "    修改后:"
ls -ld "$APP/data" "$APP/uploads" 2>/dev/null | sed 's/^/      /'

log "3/4 验证容器内现在能写了"
docker restart secagent >/dev/null 2>&1
for i in $(seq 1 40); do
  sleep 5
  ST=$(docker inspect --format '{{.State.Health.Status}}' secagent 2>/dev/null || echo unknown)
  [ "$ST" = "healthy" ] && { echo "    容器 healthy（第 $((i*5)) 秒）"; break; }
done

docker exec secagent sh -c 'touch /app/data/.write-test 2>&1 && echo "  ✅ 可写了" && rm -f /app/data/.write-test || echo "  ❌ 仍然不可写"' | sed 's/^/    /'

log "4/4 再做一个动作，验证审计真的落盘"
U=$(grep '^SECAGENT_USERNAME=' "$APP/.env" | cut -d= -f2)
P=$(grep '^SECAGENT_PASSWORD=' "$APP/.env" | cut -d= -f2)
T=$(curl -s -X POST http://127.0.0.1:9900/api/auth/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"$U\",\"password\":\"$P\"}" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["token"])' 2>/dev/null)

if [ -z "$T" ]; then
  warn "登录失败，跳过动作测试"
else
  echo "    封一个普通公网 IP（MOCK，只写记录）"
  curl -s -X POST http://127.0.0.1:9900/api/response/block -H "Authorization: Bearer $T" \
    -H 'Content-Type: application/json' \
    -d '{"ip":"198.18.0.9","durationMinutes":5,"reason":"权限修复后的落盘验证"}' 2>/dev/null | head -c 200 | sed 's/^/      /'
  echo
  echo "    审计文件现在出现了吗:"
  for f in response-audit.json blocked-ips.json; do
    if [ -f "$APP/data/$f" ]; then
      printf "      ✅ %-24s %s bytes\n" "$f" "$(stat -c %s "$APP/data/$f")"
    else
      printf "      ❌ %-24s 仍然不存在\n" "$f"
    fi
  done
  echo
  echo "    最近的审计记录:"
  [ -f "$APP/data/response-audit.json" ] && python3 -c "
import json
d=json.load(open('$APP/data/response-audit.json',encoding='utf-8'))
r=d if isinstance(d,list) else d.get('records',[])
print('      共',len(r),'条')
for x in r[-3:]: print('      -',x.get('action'),'|',x.get('target'),'|',x.get('result'),'|',(x.get('reason') or '')[:26])
" 2>/dev/null | sed 's/^/    /'
fi

echo
echo "    最近的写回失败日志（应该是空的）:"
docker logs secagent 2>&1 | grep -c '写回失败' | sed 's/^/      写回失败次数: /'
docker logs secagent 2>&1 | grep '写回失败' | tail -2 | sed 's/^/      /'
