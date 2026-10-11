#!/usr/bin/env bash
# 更新服务器 1 的 .env，写入 Wazuh 对接配置。
# 口令由调用方替换 __WAZUH_PASS__ 占位符传入 ——
# 这样脚本本身可以安全地保存在仓库里（不含任何凭据），
# 也不必在 PowerShell 里拼字符串（那个引号地狱已经踩过太多次）。
set -e

ENV=/opt/secagent/.env

if [ ! -f "$ENV" ]; then
  echo "  [X] 找不到 $ENV"
  exit 1
fi

cp "$ENV" "$ENV.bak-$(date +%Y%m%d-%H%M%S)"
echo "  已备份"

# 幂等：先删掉所有旧的 WAZUH_ 行，再追加
grep -v '^WAZUH_' "$ENV" > "$ENV.tmp" || true
cat >> "$ENV.tmp" <<'ENVEOF'
# ===== Wazuh 对接（通过本机 SSH 隧道，见 secagent-wazuh-tunnel.service）=====
# 用 host.docker.internal 而不是写死网关 IP：网桥网关在网络重建后会变，
# 写死的话某天会静默失效 —— 而连不上 Wazuh 会【自动降级 MOCK】，
# 页面照常显示，只是数据变成假的了。
WAZUH_URL=https://host.docker.internal:55000
WAZUH_USER=wazuh-wui
WAZUH_PASS=__WAZUH_PASS__
ENVEOF
mv "$ENV.tmp" "$ENV"
chmod 600 "$ENV"

echo "  更新后的 WAZUH_ 配置（口令隐藏）:"
grep '^WAZUH_' "$ENV" | sed 's/^WAZUH_PASS=.*/WAZUH_PASS=***（已隐藏）/' | sed 's/^/    /'
