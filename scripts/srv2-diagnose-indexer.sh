#!/usr/bin/env bash
# indexer 崩溃诊断
echo "=== 1. 容器状态（重启了几次）==="
docker inspect wazuh.indexer --format '  Status: {{.State.Status}}
  ExitCode: {{.State.ExitCode}}
  OOMKilled: {{.State.OOMKilled}}
  RestartCount: {{.RestartCount}}
  StartedAt: {{.State.StartedAt}}
  FinishedAt: {{.State.FinishedAt}}' 2>/dev/null

echo
echo "=== 2. 找异常的第一行（堆栈上面那句才是根因）==="
docker logs wazuh.indexer 2>&1 | grep -nE 'Exception|Error|error|failed|FATAL|cannot|No such' | head -20 | sed 's/^/  /'

echo
echo "=== 3. 完整堆栈的前 40 行（含被截断的那部分）==="
docker logs wazuh.indexer 2>&1 | grep -B5 -A40 'OpenSearchSecurityPlugin' | head -60 | sed 's/^/  /'

echo
echo "=== 4. 容器内的 opensearch 日志 ==="
docker exec wazuh.indexer bash -c 'ls -la /var/log/wazuh-indexer/ 2>/dev/null; echo ---; tail -40 /var/log/wazuh-indexer/opensearch.log 2>/dev/null' 2>&1 | sed 's/^/  /'

echo
echo "=== 5. 宿主内存实况 ==="
free -m | sed 's/^/  /'
echo
docker stats --no-stream --format '  {{.Name}}  {{.MemUsage}}  {{.MemPerc}}' 2>/dev/null

echo
echo "=== 6. cgroup 限制实际是多少 ==="
docker inspect wazuh.indexer --format '  HostConfig.Memory: {{.HostConfig.Memory}}' 2>/dev/null
CG=$(docker inspect wazuh.indexer --format '{{.Id}}' 2>/dev/null)
if [ -n "$CG" ]; then
  echo "  cgroup memory.max: $(cat /sys/fs/cgroup/system.slice/docker-$CG.scope/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/docker/$CG/memory.limit_in_bytes 2>/dev/null || echo '读不到')"
fi

echo
echo "=== 7. 证书文件是否可读（可能只是权限/路径问题）==="
ls -la /opt/wazuh/config/wazuh_indexer_ssl_certs/ | sed 's/^/  /'

echo
echo "=== 8. 是否真的是 OOM（宿主 dmesg）==="
dmesg 2>/dev/null | grep -iE 'oom|killed process' | tail -5 | sed 's/^/  /' || echo "  dmesg 读不到或没有 OOM 记录"
