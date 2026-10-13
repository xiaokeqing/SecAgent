#!/usr/bin/env bash
# 查两个严重问题的根因
echo "########## 问题①：护栏为什么没拦住白名单地址 ##########"
echo
echo "=== 1. 服务器 1 跑的镜像是哪个（是改了白名单之后构建的吗）==="
docker inspect secagent --format '  镜像: {{.Config.Image}}
  镜像ID: {{.Image}}
  容器创建: {{.Created}}' 2>/dev/null
echo
echo "  镜像构建时间:"
docker image inspect secagent:local --format '    {{.Created}}' 2>/dev/null
echo
echo "  镜像里的 jar 时间戳:"
docker exec secagent sh -c 'ls -la /app/*.jar 2>/dev/null' | sed 's/^/    /'

echo
echo "=== 2. 关键：镜像里的白名单是新的还是旧的 ==="
echo "  期望（新代码）应包含 203.0.113.0/24 和 100.64.0.0/10"
echo "  实际镜像内的 application.yml:"
docker exec secagent sh -c 'find /app -name "application*.yml" 2>/dev/null | head -3' | sed 's/^/    /'
docker exec secagent sh -c 'for f in $(find /app -name "application.yml" 2>/dev/null | head -1); do grep -A2 "response:" "$f" | head -6; done' | sed 's/^/    /'

echo
echo "=== 3. 容器启动日志里的白名单条数（这是关键证据）==="
docker logs secagent 2>&1 | grep -E '处置护栏初始化|白名单' | tail -3 | sed 's/^/    /'

echo
echo "=== 4. 直接问它：封一个白名单地址，看守卫的判定 ==="
U=$(grep '^SECAGENT_USERNAME=' /opt/secagent/.env | cut -d= -f2)
P=$(grep '^SECAGENT_PASSWORD=' /opt/secagent/.env | cut -d= -f2)
T=$(curl -s -X POST http://127.0.0.1:9900/api/auth/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"$U\",\"password\":\"$P\"}" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["token"])' 2>/dev/null)

echo "  封 127.0.0.1（所有版本的白名单里都有）:"
curl -s -X POST http://127.0.0.1:9900/api/response/block -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d '{"ip":"127.0.0.1","durationMinutes":5,"reason":"测试"}' 2>/dev/null | head -c 250 | sed 's/^/    /'
echo
echo "  封 100.100.100.200（阿里云元数据，只有新代码才拦）:"
curl -s -X POST http://127.0.0.1:9900/api/response/block -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d '{"ip":"100.100.100.200","durationMinutes":5,"reason":"测试"}' 2>/dev/null | head -c 250 | sed 's/^/    /'
echo

echo
echo "########## 问题②：审计为什么没落盘 ##########"
echo
echo "=== 1. 容器里全盘找 response-audit.json ==="
docker exec secagent sh -c 'find / -name "response-audit.json" -o -name "blocked-ips.json" -o -name "tool-call-audit.json" 2>/dev/null' | sed 's/^/    /'
echo "  (空 = 根本没写出来)"

echo
echo "=== 2. 容器的实际工作目录 ==="
docker inspect secagent --format '  WorkingDir: {{.Config.WorkingDir}}' 2>/dev/null

echo
echo "=== 3. 启动日志里 AuditService 说了什么 ==="
docker logs secagent 2>&1 | grep -iE 'audit|审计' | tail -8 | sed 's/^/    /'

echo
echo "=== 4. 刚才那两个动作在日志里留下了什么 ==="
docker logs secagent 2>&1 | grep -iE '封IP|block|203.0.113.45|45.83.91.12|AUD-' | tail -10 | sed 's/^/    /'

echo
echo "=== 5. data 目录权限（可能是写不进去）==="
docker exec secagent sh -c 'id; ls -ld /app/data; touch /app/data/.write-test 2>&1 && echo "  可写 ✅" && rm -f /app/data/.write-test || echo "  不可写 ❌"' | sed 's/^/    /'
