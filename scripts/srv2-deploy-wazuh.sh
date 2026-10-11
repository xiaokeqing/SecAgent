#!/usr/bin/env bash
# ============================================================
# 部署 Wazuh 单节点 4.9.2（按 v4.9.2 的真实 compose 结构）
# ------------------------------------------------------------
# 第一版脚本读错了 compose 版本（读的是 main 分支的 5.1.0），
# 导致两个错误假设：
#   · 以为证书在 config/root-ca/certs/  —— 实际在 config/wazuh_indexer_ssl_certs/
#   · 以为有 healthcheck                —— v4.9.2 的 compose 里根本没有
# 教训：仓库的 main 分支不等于你要用的版本。clone 时必须带 -b <tag>，
#       而且读文件时要确认读的就是那个 tag 的内容。
#
# 改了四处：
#   1) indexer 堆 1g -> 512m（4GB 机器，还要留地方给别的组件）
#   2) 所有端口绑 127.0.0.1（对外走隧道，不直接开公网）
#   3) 用 override 补 healthcheck + mem_limit（不改上游文件）
#   4) 分批启动，便于定位
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }
die()  { echo -e "\033[1;31m  [X] $*\033[0m" >&2; exit 1; }

WORK=/opt/wazuh
cd "$WORK" || die "找不到 $WORK"

log "0/6 改造编排"
# 先停掉并清理上一轮可能残留的容器
docker compose down --remove-orphans >/dev/null 2>&1 || true

cp -n docker-compose.yml docker-compose.yml.orig 2>/dev/null || true

# 重跑时从 .orig 恢复，保证每次都在【上游原文件】上做同样的修改。
# 否则第二次运行时 sed 找不到 -Xms1g 就静默不改，而 grep 检查又会通过 ——
# 看起来"改过了"，其实用的是上一轮的残留状态。这类问题最难查。
if [ -f docker-compose.yml.orig ]; then
  cp docker-compose.yml.orig docker-compose.yml
  ok "已从 docker-compose.yml.orig 恢复上游原文件（保证重跑确定性）"
fi

sed -i 's/-Xms1g -Xmx1g/-Xms512m -Xmx512m -XX:MaxDirectMemorySize=512m/' docker-compose.yml
grep -q 'Xms512m' docker-compose.yml || die "堆没改成功"
ok "indexer 堆 -> 512m"

# ⚠️ 这里踩过一个坑，记下来。
# 只压堆是不够的：第一次只改了 -Xms/-Xmx，结果 indexer 反复重启 14 次。
# 日志里的根因是：
#   java.lang.OutOfMemoryError: Cannot reserve 291650519 bytes of
#   direct buffer memory (allocated: 1, limit: 268435456)
# OpenSearch 的安全插件启动时要给插件 jar 算 SHA-256，一次性申请 278MB 的
# direct buffer，而 OpenSearch 默认把 -XX:MaxDirectMemorySize 设成 256MB。
# 所以除了堆，还必须把这个上限一起提上去。
# 【教训】压内存不能只压 -Xmx —— JVM 除堆之外还有 direct memory、metaspace、
# 线程栈、code cache。只看堆会得出"内存够用"的错误结论。
grep -q 'MaxDirectMemorySize' docker-compose.yml || die "MaxDirectMemorySize 没加上"
ok "direct memory 上限 -> 512m"

sed -i 's|- "1514:1514"|- "127.0.0.1:1514:1514"|' docker-compose.yml
sed -i 's|- "1515:1515"|- "127.0.0.1:1515:1515"|' docker-compose.yml
sed -i 's|- "514:514/udp"|- "127.0.0.1:514:514/udp"|' docker-compose.yml
sed -i 's|- "55000:55000"|- "127.0.0.1:55000:55000"|' docker-compose.yml
sed -i 's|- "9200:9200"|- "127.0.0.1:9200:9200"|' docker-compose.yml
sed -i 's|      - 443:5601|      - "127.0.0.1:443:5601"|' docker-compose.yml
ok "端口 -> 127.0.0.1"
grep -nE '127\.0\.0\.1:' docker-compose.yml | sed 's/^/      /'

log "1/6 检查证书"
CERTS=config/wazuh_indexer_ssl_certs
if [ -f "$CERTS/root-ca.pem" ]; then
  ok "证书已就位"
  ls -1 "$CERTS" | sed 's/^/      /'
else
  warn "证书缺失，重新生成"
  docker compose -f generate-indexer-certs.yml run --rm generator 2>&1 | tail -3 | sed 's/^/      /'
  [ -f "$CERTS/root-ca.pem" ] || die "仍找不到 $CERTS/root-ca.pem"
  ok "证书生成完成"
fi

log "2/6 写 override（healthcheck + mem_limit）"
cat > docker-compose.override.yml <<'EOF'
# 本项目维护的覆盖文件。不要改上游的 docker-compose.yml —— 
# 上游更新时能直接换，自己改的都在这里。
services:
  wazuh.manager:
    container_name: wazuh.manager
    # 4GB 机器上必须设上限：某个组件失控时让它自己被 OOM kill 并重启，
    # 而不是把整台机器拖死（那会连累一起跑的 Cowrie 和其他组件）
    mem_limit: 900m

  wazuh.indexer:
    container_name: wazuh.indexer
    # 1500m 的构成：堆 512 + direct 512 + metaspace/线程栈/code cache 约 300-400
    # 校验方式：启动后看 docker stats 的实际值，而不是只看堆设置。
    mem_limit: 1500m
    # 官方 v4.9.2 的 compose 没写 healthcheck，但分批启动需要一个就绪判据。
    # 这里补一个，不改上游文件。
    healthcheck:
      test: ["CMD-SHELL", "curl -sk -u admin:SecretPassword https://localhost:9200/_cluster/health | grep -qE '\"status\":\"(green|yellow)\"'"]
      interval: 20s
      timeout: 10s
      retries: 10
      start_period: 90s

  wazuh.dashboard:
    container_name: wazuh.dashboard
    mem_limit: 700m
EOF
ok "override 已写入"

log "3/6 启动 indexer"
docker compose up -d wazuh.indexer 2>&1 | tail -3 | sed 's/^/      /'
echo "      轮询 /_cluster/health（最多 6 分钟）..."
IDX_OK=0
for i in $(seq 1 72); do
  sleep 5
  R=$(curl -sk -u admin:SecretPassword --max-time 8 https://127.0.0.1:9200/_cluster/health 2>/dev/null)
  if echo "$R" | grep -qE '"status":"(green|yellow)"'; then
    IDX_OK=1; echo "      第 $((i*5)) 秒: $(echo "$R" | head -c 130)"; break
  fi
  if [ $((i % 6)) -eq 0 ]; then
    echo "      第 $((i*5)) 秒: 未就绪  内存 $(docker stats --no-stream --format '{{.MemUsage}}' wazuh.indexer 2>/dev/null)"
  fi
done
if [ "$IDX_OK" -eq 0 ]; then
  warn "indexer 未就绪，日志尾部："
  docker logs --tail 30 wazuh.indexer 2>&1 | sed 's/^/        /'
  die "indexer 起不来，先解决它"
fi
ok "indexer 就绪，内存 $(docker stats --no-stream --format '{{.MemUsage}}' wazuh.indexer 2>/dev/null)"

log "4/6 启动 manager"
docker compose up -d wazuh.manager 2>&1 | tail -3 | sed 's/^/      /'
MGR_OK=0
for i in $(seq 1 48); do
  sleep 5
  C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1:55000/ 2>/dev/null)
  if [ "$C" = "401" ] || [ "$C" = "200" ]; then
    MGR_OK=1; echo "      第 $((i*5)) 秒: API HTTP $C（401=活着但要认证）"; break
  fi
done
if [ "$MGR_OK" -eq 0 ]; then
  warn "manager API 未响应，日志尾部："
  docker logs --tail 30 wazuh.manager 2>&1 | sed 's/^/        /'
else
  ok "manager 就绪，内存 $(docker stats --no-stream --format '{{.MemUsage}}' wazuh.manager 2>/dev/null)"
fi

log "5/6 启动 dashboard"
docker compose up -d wazuh.dashboard 2>&1 | tail -3 | sed 's/^/      /'
DSH_OK=0
for i in $(seq 1 48); do
  sleep 5
  C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1:443/app/login 2>/dev/null)
  if [ "$C" = "200" ]; then DSH_OK=1; echo "      第 $((i*5)) 秒: HTTP 200"; break; fi
done
if [ "$DSH_OK" -eq 0 ]; then
  warn "dashboard 未就绪，日志尾部："
  docker logs --tail 25 wazuh.dashboard 2>&1 | sed 's/^/        /'
else
  ok "dashboard 就绪，内存 $(docker stats --no-stream --format '{{.MemUsage}}' wazuh.dashboard 2>/dev/null)"
fi

log "6/6 总账"
echo "    --- 容器 ---"
docker ps --format '      {{.Names}}  {{.Status}}' 2>/dev/null
echo
echo "    --- 内存（4GB 机器上的关键指标）---"
free -m | sed 's/^/      /'
echo
docker stats --no-stream --format '      {{.Name}}  内存 {{.MemUsage}}  {{.MemPerc}}' 2>/dev/null
echo
echo "    --- 端口（应全部在 127.0.0.1）---"
ss -tlnp 2>/dev/null | grep -E '9200|55000|:443|1514|1515' | sed 's/^/      /'
echo
echo "    --- 连通性 ---"
printf "      indexer   : "; curl -sk -u admin:SecretPassword https://127.0.0.1:9200/_cluster/health 2>/dev/null | head -c 110; echo
printf "      manager   : HTTP "; curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:55000/ 2>/dev/null
printf "      dashboard : HTTP "; curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:443/app/login 2>/dev/null

echo
ok "Wazuh 部署流程结束"
echo
warn "⚠️ 当前仍是 Wazuh 官方默认口令（SecretPassword / MyS3cr37P450r.*- / kibanaserver）"
warn "   这些在官方文档里公开可查 —— 必须在【暴露之前】改掉。"
warn "   下一步就是改口令，改完才考虑开隧道。"
