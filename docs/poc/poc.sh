#!/usr/bin/env bash
# SecAgent 安全 PoC（Git Bash / Linux / macOS）
# 用法：先启动应用（默认 http://localhost:9900），再运行本脚本
set -u
BASE="${BASE:-http://localhost:9900}"
CURL="curl -s"

echo "[0] 健康检查"
$CURL "$BASE/api/health"; echo; echo

echo "[1] 正常上传（期望 200 成功）"
$CURL -X POST "$BASE/api/upload" -F "file=@security-docs/01-OWASP-Top10-安全概览.md"; echo; echo

echo "[2] 路径穿越文件名（修复后期望 400 非法文件名）"
$CURL -X POST "$BASE/api/upload" \
  -F "file=@security-docs/01-OWASP-Top10-安全概览.md;filename=../../../../../../tmp/poc.txt"; echo; echo

echo "[3] URL 编码分隔符穿越（修复后期望 400）"
$CURL -X POST "$BASE/api/upload" \
  -F "file=@security-docs/01-OWASP-Top10-安全概览.md;filename=..%2f..%2fpoc.txt"; echo; echo

echo "[4] 非法扩展名（期望 400）"
$CURL -X POST "$BASE/api/upload" \
  -F "file=@security-docs/01-OWASP-Top10-安全概览.md;filename=shell.jsp"; echo; echo

echo "[5] 文档含密钥（期望 422 被 DLP 拦截）"
tmp=$(mktemp --suffix=.md 2>/dev/null || echo /tmp/secret-demo.md)
echo "LTAI5t7abcdefghijklmnop" > "$tmp"
$CURL -X POST "$BASE/api/upload" -F "file=@$tmp;filename=secret-demo.md"; echo
rm -f "$tmp"; echo

echo "[6] 鉴权（当 app.auth.enabled=true 时）"
echo "  无 Token 访问受保护接口期望 401："
echo "  $CURL -X POST '$BASE/api/upload' -F 'file=@x.md'"
echo "  正确 Token：  -H 'X-API-Token: secagent-demo-token'"
echo
echo "完成。"
