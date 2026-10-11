#!/usr/bin/env bash
# ============================================================
# 准备 Wazuh 部署材料
# ------------------------------------------------------------
# 目标：拉齐三个镜像 + 拿到官方编排与证书生成工具
#
# 关于内存的取舍说明：
#   Wazuh 官方 single-node 编排默认给 indexer 1GB JVM 堆，
#   在 4GB 机器上跑不动（还要留地方给 manager / dashboard / Cowrie / Suricata）。
#   所以后面会把 indexer 堆压到 512MB（OpenSearch 的下限）。
#   这台机器的可用内存约 3180MB，预算分配：
#     indexer   ~1200MB (512M 堆)
#     manager   ~700MB
#     dashboard ~400MB
#     小计      ~2300MB  -> 还剩约 880MB 给 Cowrie
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }

WAZUH_VER=4.9.2
WORK=/opt/wazuh

log "1/4 拉取三个镜像"
for img in "wazuh/wazuh-indexer:${WAZUH_VER}" "wazuh/wazuh-dashboard:${WAZUH_VER}"; do
  name=$(echo "$img" | cut -d/ -f2 | cut -d: -f1)
  if docker image inspect "$img" >/dev/null 2>&1; then
    ok "$name 已存在，跳过"
    continue
  fi
  printf "    拉取 %-40s " "$img"
  T0=$(date +%s)
  if timeout 900 docker pull "$img" >/dev/null 2>&1; then
    T1=$(date +%s)
    SIZE=$(docker image inspect "$img" --format '{{.Size}}' 2>/dev/null)
    printf "OK  %ss  %.0fMB\n" "$((T1-T0))" "$(awk -v s="$SIZE" 'BEGIN{print s/1048576}')"
  else
    printf "失败/超时\n"
  fi
done
echo
echo "    当前镜像清单:"
docker images --format '      {{.Repository}}:{{.Tag}}  {{.Size}}' | sort

log "2/4 取官方编排仓库"
mkdir -p "$WORK"
cd "$WORK"
if [ -d wazuh-docker ]; then
  ok "wazuh-docker 已存在"
else
  # github.com 在预检里是通的（200），但 clone 可能慢，给足超时
  printf "    clone 中... "
  if timeout 300 git clone --depth 1 https://github.com/wazuh/wazuh-docker.git >/dev/null 2>&1; then
    echo "OK"
    ok "已克隆"
  else
    echo "失败/超时"
    warn "clone 失败 —— 后面可能需要手写编排文件（也不难，就三个服务）"
  fi
fi

if [ -d "$WORK/wazuh-docker/single-node" ]; then
  echo "    single-node 目录内容:"
  ls -1 "$WORK/wazuh-docker/single-node" | sed 's/^/      /'
fi

log "3/4 检查官方编排的资源要求（要改哪些）"
if [ -f "$WORK/wazuh-docker/single-node/docker-compose.yml" ]; then
  echo "    --- indexer 的堆设置 ---"
  grep -nE 'OPENSEARCH_JAVA_OPTS|mem_limit|Xms|Xmx' "$WORK/wazuh-docker/single-node/docker-compose.yml" | sed 's/^/      /'
  echo
  echo "    --- 服务清单 ---"
  grep -nE '^  [a-z-]+:$' "$WORK/wazuh-docker/single-node/docker-compose.yml" | sed 's/^/      /'
fi

log "4/4 资源现状"
free -m | sed 's/^/    /'
echo
df -h / | tail -1 | sed 's/^/    /'
echo
docker system df 2>/dev/null | sed 's/^/    /'
