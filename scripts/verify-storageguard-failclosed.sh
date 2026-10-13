#!/usr/bin/env bash
# 反向验证 StorageGuard 真的会 fail-closed
# 上一次做这个测试时只等了 30 秒 —— Spring 应用启动要 30~40 秒，
# StorageGuard 是 @PostConstruct，那时候还没跑到。
# "容器还在启动"被我误判成"通过了"。这次给足 90 秒。
set -uo pipefail

echo "===== 准备：把 data 目录改成 root 属主（模拟权限配置错误）====="
chown -R root:root /opt/secagent/data
chmod 750 /opt/secagent/data
ls -ld /opt/secagent/data | sed 's/^/  /'

echo
echo "===== 重启容器，等 90 秒（Spring 启动需要时间）====="
docker restart secagent >/dev/null 2>&1
for i in $(seq 1 18); do
  sleep 5
  ST=$(docker inspect --format '{{.State.Status}}' secagent 2>/dev/null || echo unknown)
  H=$(docker inspect --format '{{.State.Health.Status}}' secagent 2>/dev/null || echo none)
  printf "  %3ds  状态=%s  健康=%s\n" "$((i*5))" "$ST" "$H"
  # 出现 failed/退出就提前结束
  if [ "$ST" = "exited" ] || [ "$ST" = "restarting" ] || [ "$ST" = "created" ]; then
    echo "  → 容器已停止（符合 fail-closed 预期）"
    break
  fi
done

echo
echo "===== 关键证据：日志里有没有拒绝启动 ====="
docker logs secagent 2>&1 | grep -iE '存储目录不可写|IllegalStateException|Application run failed|全部留痕' | head -8 | sed 's/^/  /'
echo
echo "  最近 15 行日志:"
docker logs secagent 2>&1 | tail -15 | sed 's/^/    /'

echo
echo "===== 恢复正确属主，让服务重新可用 ====="
chown -R 999:999 /opt/secagent/data
chmod 750 /opt/secagent/data
docker restart secagent >/dev/null 2>&1
for i in $(seq 1 24); do
  sleep 5
  H=$(docker inspect --format '{{.State.Health.Status}}' secagent 2>/dev/null || echo none)
  if [ "$H" = "healthy" ]; then echo "  恢复成功：healthy（第 $((i*5)) 秒）"; break; fi
done

echo
echo "===== 最终状态 ====="
docker ps --format '  {{.Names}}  {{.Status}}' | grep secagent
docker logs secagent 2>&1 | grep '存储可写性' | tail -1 | sed 's/^/  /'
curl -s -o /dev/null -w '  线上: HTTP %{http_code}  ttfb=%{time_starttransfer}s\n' --max-time 25 https://demo.xiaokeqing.cn/api/health

echo
echo "===== 结论 ====="
echo "  预期：改回 root 后应用【拒绝启动】并在日志里说明原因"
echo "        （这正是把『静默失效』变成『起不来』的意义）"
