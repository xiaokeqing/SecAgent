#!/usr/bin/env bash
# ============================================================
# srv2：Suricata 扫描检测调优（补 P3 演练的两个真实发现）
# ------------------------------------------------------------
# 演练发现（2026-10-12）：
#   ① 【漏报】8 端口 × 单次 × 600ms 的低速扫描，Suricata 一条告警都没出
#      （现有 ET SCAN 规则偏 SSH 高频场景，覆盖不到通用低速扫描）
#   ② 【误报】运营者自己的正常批量运维 SSH（60 秒内 6 次登录）触发了
#      ET SCAN Potential SSH Scan（sid 2001219）→ 日常运维会持续刷告警
#
# 本脚本做两件事：
#   · 新增本机规则 local-scan.rules：20 秒内 >=6 个 SYN（by_src）即告警 → 补低速扫描检测
#   · 新增 threshold.conf：给 sid 2001219 设 threshold（10 秒内 >=3 次才报）→ 压误报、保留真扫
#
# 为什么写成脚本而不是手改：
#   这份 suricata.yaml 是【单文件 bind mount】，`sed -i`（临时文件+rename）会失败；
#   而上次我手工插行还破坏了 YAML 块结构、导致 Suricata 崩溃重启（conf-yaml-loader line 10）。
#   所以这里统一：python3+yaml 结构化改 → `suricata -T` 以【退出码】放行 → 失败立刻回滚。
#
# 用法（在 srv2 上，root）：
#   bash apply-suricata-scan-tuning.sh            # 应用
#   bash apply-suricata-scan-tuning.sh --check     # 只校验当前配置，不改动
#   bash apply-suricata-scan-tuning.sh --rollback  # 回滚到最近一次备份
# ============================================================
set -euo pipefail

APP_HOST=/opt/suricata                 # 宿主机上的 suricata 配置目录
YAML_HOST="$APP_HOST/etc/suricata.yaml"        # 被单文件 bind mount 到容器 /etc/suricata/suricata.yaml
RULES_HOST="$APP_HOST/rules"                   # 被挂载到容器 /var/lib/suricata/rules
CT=suricata
CONF_IN_CT=/etc/suricata/suricata.yaml
TH_IN_CT=/etc/suricata/threshold.conf
RULE_NAME=local-scan.rules
SID_FP=2001219

ok()   { printf '\033[1;32m  [OK] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  [!] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  [X] %s\033[0m\n' "$*"; exit "${2:-1}"; }

need_root() { [ "$(id -u)" = "0" ] || die "请用 root 运行（sudo bash $0）"; }
need_ct()   { docker ps --format '{{.Names}}' | grep -qx "$CT" || die "容器 $CT 未运行"; }

# 以【退出码】判定配置是否有效 —— 这是上次踩坑的地方（把 exit=0 误判为失败）
validate_conf() {
  local rc
  set +e
  docker exec "$CT" sh -c "suricata -T -c $CONF_IN_CT > /tmp/su-validate.log 2>&1"
  rc=$?
  set -e
  if [ "$rc" != "0" ]; then
    warn "suricata -T 校验失败（exit=$rc），最后 8 行："
    docker exec "$CT" sh -c "tail -n 8 /tmp/su-validate.log" 2>/dev/null | sed 's/^/      /' || true
    return 1
  fi
  ok "suricata -T 校验通过（exit=0）"
  return 0
}

reload_rules() {
  if docker exec "$CT" sh -c 'ls /var/run/suricata/*.socket >/dev/null 2>&1'; then
    docker exec "$CT" suricatasc -c reload-rules 2>&1 | tail -n 2 | sed 's/^/      /'
    ok "已热加载规则（suricatasc reload-rules）"
  else
    warn "容器内没有 suricatasc socket → 重启容器以加载规则（检测空窗约 5–10 秒）"
    docker restart "$CT" >/dev/null
    sleep 25
    ok "容器已重启"
  fi
}

loaded_rule_count() {
  docker logs --tail 400 "$CT" 2>&1 | grep -iE 'rules successfully loaded' | tail -n 1 | sed 's/^/      /' || true
}

case "${1:-}" in
  --check)
    need_root; need_ct
    validate_conf || exit 1
    loaded_rule_count
    echo "  当前 rule-files："; docker exec "$CT" sh -c "grep -A3 '^rule-files' $CONF_IN_CT | sed 's/^/      /'"
    exit 0
    ;;
  --rollback)
    need_root; need_ct
    BK=$(ls -1t "$APP_HOST"/etc/suricata.yaml.bak-* 2>/dev/null | head -n1 || true)
    [ -n "$BK" ] || die "没有可回滚的备份"
    cat "$BK" > "$YAML_HOST"
    ok "已回滚 suricata.yaml ← $(basename "$BK")"
    validate_conf || die "回滚后校验仍失败 —— 需要人工介入" 2
    reload_rules
    exit 0
    ;;
esac

need_root; need_ct
command -v python3 >/dev/null || die "srv2 需要 python3"
python3 -c 'import yaml' 2>/dev/null || die "srv2 的 python3 缺少 PyYAML（pip3 install pyyaml 后再来）；本次不改动任何配置"

echo "==> 1/6 备份"
TS=$(date +%Y%m%d-%H%M%S)
BK="$APP_HOST/etc/suricata.yaml.bak-$TS"
cp -a "$YAML_HOST" "$BK"
ok "备份 → $BK"

echo "==> 2/6 写本机规则 $RULE_NAME（低速多端口扫描）"
mkdir -p "$RULES_HOST"
cat > "$RULES_HOST/$RULE_NAME" <<'EOF'
# 本机补充规则（2026-10-12，P3 演练驱动）：现有 ET SCAN 偏 SSH 高频场景，
# 8 端口 × 单次 × 600ms 这类低速扫描会漏 → 用阈值规则补上。by_src 计数，阈值内只报一次。
alert tcp any any -> $HOME_NET any (msg:"LOCAL 低速率多端口扫描 (by_src)"; flags:S; threshold: type both, track by_src, count 6, seconds 20; classtype:attempted-recon; sid:1000001; rev:1;)
EOF
ok "规则文件已写入（宿主机 $RULES_HOST/$RULE_NAME）"

echo "==> 3/6 写阈值文件（压 sid $SID_FP 的误报）"
docker exec "$CT" sh -c "cat > $TH_IN_CT" <<EOF
# 2026-10-12：修 P3 演练发现的误报 —— 运营者正常批量 SSH 登录会触发 ET SCAN Potential SSH Scan
# 用 threshold 限速：同一来源 10 秒内累计 3 次以上才告警（保留真实快速扫描的检出能力）
threshold gen_id 1, sig_id $SID_FP, type threshold, track by_src, count 3, seconds 10
EOF
ok "阈值文件已写入容器 $TH_IN_CT"

echo "==> 4/6 结构化修改 suricata.yaml（python3+yaml，就地覆盖写）"
python3 - "$YAML_HOST" "$RULE_NAME" "$TH_IN_CT" <<'PY'
import sys, io, yaml
path, rule_name, th_path = sys.argv[1], sys.argv[2], sys.argv[3]
with io.open(path, 'r', encoding='utf-8') as f:
    cfg = yaml.safe_load(f)
if not isinstance(cfg, dict):
    sys.exit("yaml 根节点不是映射，拒绝改动")
rf = cfg.get('rule-files')
if rf is None:
    rf = []
if not isinstance(rf, list):
    sys.exit("rule-files 不是列表，拒绝改动")
if rule_name not in rf:
    rf.append(rule_name)
cfg['rule-files'] = rf
cfg['threshold-file'] = th_path
with io.open(path, 'w', encoding='utf-8') as f:
    yaml.safe_dump(cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
print("      rule-files =", rf)
print("      threshold-file =", cfg['threshold-file'])
PY
ok "配置已就地写回"

echo "==> 5/6 校验（不合格立即回滚）"
if ! validate_conf; then
  cat "$BK" > "$YAML_HOST"
  docker exec "$CT" sh -c "rm -f $TH_IN_CT"
  rm -f "$RULES_HOST/$RULE_NAME"
  die "已回滚到备份（$BK）并清理新增文件 —— 线上配置保持原样" 3
fi

echo "==> 6/6 加载规则并确认"
reload_rules
sleep 3
loaded_rule_count
echo
ok "完成。验证方法（P3 复测口径）："
echo "      1) 从 srv1 对 srv2 做 8 端口单次扫描（间隔 600ms）→ 应出现 sid 1000001 告警"
echo "      2) 从本机做 6 次快速 SSH 登录 → 不应出现 sid $SID_FP 告警"
echo "      3) 若要撤销：bash $0 --rollback"
