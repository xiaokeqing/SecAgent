#!/usr/bin/env bash
# ============================================================
# 关键配置快照 + 清单校验（配置版本化 / 恢复演练用）
# ------------------------------------------------------------
# 为什么需要：本项目的"资产"不只是代码，还有一堆散在服务器上的关键配置——
#   ipset/iptables（处置封禁的落点）、开机恢复单元、cron、
#   Wazuh manager 的 ossec.conf、Suricata 规则、docker compose、ISM 保留策略…
# 这些东西一旦丢/被改坏，没有任何版本可回退。本脚本把它们打成带 sha256 清单的快照包。
#
# 用法：
#   config-snapshot.sh [输出目录]         # 默认 /var/backups/secagent-config
#   config-snapshot.sh --drill <包路径>   # 恢复演练：解包到临时目录并逐文件校验 sha256（不碰线上配置）
# ============================================================
set -uo pipefail

OUT_DEFAULT=/var/backups/secagent-config

if [ "${1:-}" = "--drill" ]; then
  PKG="${2:?用法: config-snapshot.sh --drill <包路径>}"
  TMP="$(mktemp -d)"
  echo "== 恢复演练：解包到 $TMP（不触碰线上配置）=="
  tar -xzf "$PKG" -C "$TMP" || { echo "  [X] 解包失败"; exit 1; }
  MAN="$(find "$TMP" -name manifest.sha256 | head -n 1)"
  [ -n "$MAN" ] || { echo "  [X] 包里没有清单"; exit 1; }
  # 清单条目是相对 <快照目录>/files 生成的，校验必须 cd 到那一层
  # （踩过：cd 到上一层的 $DIR，于是所有文件都"FAILED open or read"——是演练脚本错，不是快照坏）
  BASE="$(dirname "$MAN")"
  [ -d "$BASE/files" ] && BASE="$BASE/files"
  cd "$BASE"
  # 清单文件本身在上一层（$DIR），校验时的工作目录必须在 files/ ——
  # 所以引用清单要用绝对路径 $MAN，不能写相对名（踩过：wd 里没有 manifest.sha256）
  echo "  清单条目: $(wc -l < "$MAN")"
  if sha256sum -c "$MAN" --quiet 2>/dev/null; then
    echo "  [OK] 全部文件校验通过 —— 该快照可用于恢复"
    rc=0
  else
    echo "  [X] 存在校验失败的文件："
    sha256sum -c "$MAN" 2>/dev/null | grep -v ': OK$' | head -n 5
    rc=1
  fi
  rm -rf "$TMP"
  exit $rc
fi

OUT="${1:-$OUT_DEFAULT}"
STAMP="$(date +%Y%m%d-%H%M%S)"
HOST="$(hostname -s)"
DIR="$OUT/$HOST-$STAMP"
mkdir -p "$DIR/files"

echo "== 快照 $HOST @ $STAMP → $DIR =="

copy() {
  local p="$1" label="${2:-}"
  [ -z "$label" ] && label="$(echo "$p" | sed 's|^/||')"
  if [ -e "$p" ]; then
    mkdir -p "$DIR/files/$(dirname "$label")"
    cp -a "$p" "$DIR/files/$label" 2>/dev/null && echo "  收 $p"
  fi
}

dcopy() {
  local c="$1" p="$2" label="$3"
  if docker exec "$c" sh -c "test -e '$p'" >/dev/null 2>&1; then
    mkdir -p "$DIR/files/$(dirname "$label")"
    docker cp "$c:$p" "$DIR/files/$label" >/dev/null 2>&1 && echo "  收 $c:$p"
  fi
}

# --- 主机侧：网络与调度（处置能力的落点）---
copy /etc/ipset.conf
copy /etc/iptables/rules.v4
copy /etc/iptables/rules.v6
copy /etc/systemd/system/secagent-firewall-restore.service
copy /etc/cron.d

# --- 主机侧：SecAgent 自身（若本机是 srv1）---
copy /opt/secagent/docker-compose.yml
copy /opt/secagent/Dockerfile.runtime
copy /opt/secagent/.env.template
copy /etc/cron.d/secagent-eval
copy /opt/secagent/DEPLOY-FINGERPRINTS.txt

# --- 主机侧：Wazuh manager ---
copy /var/ossec/etc/ossec.conf
copy /var/ossec/etc/local_internal_options.conf
copy /var/ossec/etc/decoders/local_decoder.xml
copy /var/ossec/etc/rules/local_rules.xml
copy /var/ossec/etc/lists

# --- 自动探测 compose 文件 ---
for d in /root /opt /srv /home; do
  f="$(find "$d" -maxdepth 3 -name 'docker-compose.yml' -o -maxdepth 3 -name 'compose.yml' 2>/dev/null | head -n 2)"
  [ -n "$f" ] && echo "$f" | while read -r x; do copy "$x" "compose/$(echo "$x" | sed 's|^/||; s|/|_|g')"; done
done

# --- 容器内：Suricata 规则与配置 ---
dcopy suricata /etc/suricata/suricata.yaml        suricata/suricata.yaml
dcopy suricata /etc/suricata/rules                suricata/rules
dcopy suricata /var/lib/suricata/rules            suricata/var-lib-rules
# --- 容器内：Cowrie 配置 ---
dcopy cowrie /etc/cowrie/cowrie.cfg               cowrie/cowrie.cfg
dcopy cowrie /etc/cowrie/userdb.txt               cowrie/userdb.txt

# --- 索引保留策略（ISM）---
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q '^secagent$'; then
  docker exec secagent sh -c 'curl -sk -m 20 -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" "https://wazuh-tunnel:9200/_plugins/_ism/policies"' \
    > "$DIR/files/ism-policies.json" 2>/dev/null && echo "  收 ISM 策略清单"
fi

# --- 清单 + 打包 ---
cd "$DIR/files"
find . -type f ! -name manifest.sha256 -exec sha256sum {} \; > "$DIR/manifest.sha256" 2>/dev/null
CNT=$(wc -l < "$DIR/manifest.sha256")
PKG="$OUT/$HOST-$STAMP.tar.gz"
tar -czf "$PKG" -C "$OUT" "$HOST-$STAMP"
echo "== 完成：$CNT 个文件 → $PKG ($(du -h "$PKG" | cut -f1)) =="

# --- 保留最近 10 份 ---
ls -1t "$OUT"/*.tar.gz 2>/dev/null | tail -n +11 | while read -r old; do rm -f "$old"; echo "  清理旧快照 $(basename "$old")"; done
