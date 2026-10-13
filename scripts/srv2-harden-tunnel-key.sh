#!/usr/bin/env bash
# ============================================================
# B3 步骤 5：修正隧道密钥的权限限制
# ------------------------------------------------------------
# 上一版我写的是：
#   restrict,port-forwarding,permitopen="127.0.0.1:55000"
#
# 我以为 restrict 就等于"什么都干不了"，实测发现【不是】：
#   ssh -i tunnel_key root@srv2 'echo 拿到shell了'
#   -> 命令真的执行了
#
# 查 man sshd 里 restrict 的定义：
#   它会禁用 port / agent / X11 转发、PTY 分配、~/.ssh/rc 执行，
#   并且"以后新增的限制项也会默认加上"。
#   【但它不禁止命令执行】—— 也就是仍然可以跑任意命令、读任意文件。
#
# 所以必须显式加 command="/bin/false"：
#   任何试图执行命令的会话都会被替换成 /bin/false（直接失败）。
#   而隧道用的是 ssh -N（不请求 session、不执行命令），
#   所以端口转发【不受影响】。
#
# 【这条漏洞是我自己跑测试才发现的】
# 如果只是"看着那行配置觉得对"，它会一直留着 ——
# 名称看起来很严格的选项，实际语义可能窄得多。
# 凡是安全相关的配置，都要用"实际尝试违规操作"来验证，
# 而不是靠对选项名的直觉。
# ============================================================
set -uo pipefail

MARK="secagent-tunnel-to-srv2"
AK=/root/.ssh/authorized_keys

echo "==> 1/4 备份 authorized_keys"
cp "$AK" "$AK.bak-$(date +%Y%m%d-%H%M%S)"
echo "  已备份"

echo
echo "==> 2/4 取出现有的公钥部分（保留密钥本身，换掉选项）"
PUB=$(grep "$MARK" "$AK" | sed 's/^.*\(ssh-ed25519\)/\1/')
if [ -z "$PUB" ]; then
  echo "  [X] 找不到隧道密钥条目"
  exit 1
fi
echo "  公钥前缀: ${PUB:0:50}..."

echo
echo "==> 3/4 用强化后的选项重写该条目"
# 逐项说明：
#   command="/bin/false"  禁止执行任何命令（本次修正的关键）
#   restrict              关掉其余一切（转发/agent/X11/PTY/rc）
#   port-forwarding       单独开回端口转发（restrict 会关掉它）
#   permitopen=...        且只允许转发到 Wazuh API 这一个目标
grep -v "$MARK" "$AK" > "$AK.tmp"
echo "command=\"/bin/false\",restrict,port-forwarding,permitopen=\"127.0.0.1:55000\" $PUB" >> "$AK.tmp"
mv "$AK.tmp" "$AK"
chmod 600 "$AK"
echo "  写好的选项部分:"
tail -1 "$AK" | cut -c1-100 | sed 's/^/    /'

echo
echo "==> 4/4 自检"
LAST=$(tail -1 "$AK")
for opt in 'command="/bin/false"' restrict port-forwarding permitopen; do
  if echo "$LAST" | grep -qF "$opt"; then
    echo "  ✅ 含 $opt"
  else
    echo "  ❌ 缺 $opt"
  fi
done
echo
echo "  条目总数: $(wc -l < "$AK")"
