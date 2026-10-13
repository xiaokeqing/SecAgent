#!/usr/bin/env bash
# ============================================================
# 验证两件「看着有、实际可能是空的」的事
# ------------------------------------------------------------
# 评审提的两条，我认为是整个项目最该验的：
#   1) 审计"留痕"是不是真的持久化
#      tool-call-audit.json 如果写在容器层，容器一重建审计就没了 ——
#      那"全部动作留痕"这句话就是假的。
#      验证方式：记录当前状态 -> 重启容器 -> 再看还在不在。
#   2) PDF 导出是不是真能出中文
#      Docker 里最经典的翻车是字体缺失，导出全是方块。
#      验证方式：真的生成一个 PDF 并检查内容。
#
# 注意：会重启容器（约 40 秒不可用）。
# ============================================================
set -uo pipefail

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m  [OK] $*\033[0m"; }
warn() { echo -e "\033[1;33m  [!] $*\033[0m"; }

APP=/opt/secagent

log "1/6 重启前：记录审计文件的现状"
echo "  --- data/ 目录 ---"
ls -la "$APP/data/" 2>/dev/null | sed 's/^/    /'
echo
echo "  --- 审计类文件的哈希（重启后要一致）---"
for f in response-audit.json tool-call-audit.json blocked-ips.json security-events.json; do
  p="$APP/data/$f"
  if [ -f "$p" ]; then
    printf "    %-26s sha256=%s  %s bytes\n" "$f" "$(sha256sum "$p" | cut -c1-16)" "$(stat -c %s "$p")"
  else
    printf "    %-26s 【不存在】\n" "$f"
  fi
done

echo
echo "  --- 容器内的对应路径（判断是不是挂在卷上）---"
docker exec secagent sh -c 'ls -la /app/data/ 2>/dev/null' | sed 's/^/    /' || warn "读不到容器内目录"

echo
echo "  --- 挂载点确认 ---"
docker inspect secagent --format '{{range .Mounts}}    {{.Source}} -> {{.Destination}} ({{.Type}}){{"\n"}}{{end}}' 2>/dev/null

log "2/6 重启容器（模拟容器重建）"
docker restart secagent >/dev/null 2>&1
echo "    已发起重启，等待健康..."

for i in $(seq 1 40); do
  sleep 5
  ST=$(docker inspect --format '{{.State.Health.Status}}' secagent 2>/dev/null || echo unknown)
  if [ "$ST" = "healthy" ]; then echo "    第 $((i*5)) 秒: healthy"; break; fi
done
docker ps --format '    {{.Names}}  {{.Status}}' | grep secagent

log "3/6 重启后：审计文件还在吗（这是关键）"
for f in response-audit.json tool-call-audit.json blocked-ips.json security-events.json; do
  p="$APP/data/$f"
  if [ -f "$p" ]; then
    printf "    %-26s sha256=%s  %s bytes\n" "$f" "$(sha256sum "$p" | cut -c1-16)" "$(stat -c %s "$p")"
  else
    printf "    %-26s 【重启后不见了！】\n" "$f"
  fi
done

log "4/6 容器内的审计数据（重启后新容器能读到吗）"
docker exec secagent sh -c 'ls -la /app/data/ 2>/dev/null; echo "---"; echo "向量条数: $(grep -o "\"records\"" /app/data/vector-store.json 2>/dev/null | wc -l)"' | sed 's/^/    /'

log "5/6 PDF 导出实测"
# 先登录拿 token
U=$(grep '^SECAGENT_USERNAME=' "$APP/.env" | cut -d= -f2)
P=$(grep '^SECAGENT_PASSWORD=' "$APP/.env" | cut -d= -f2)
TOKEN=$(curl -s -X POST http://127.0.0.1:9900/api/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$U\",\"password\":\"$P\"}" 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["token"])' 2>/dev/null)

if [ -z "$TOKEN" ]; then
  warn "登录拿不到 token，跳过 PDF 测试"
else
  ok "登录成功"

  # 找一条事件
  EID=$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9900/api/events 2>/dev/null \
    | python3 -c '
import json,sys
d=json.load(sys.stdin)
data=d.get("data",d)
items=data if isinstance(data,list) else data.get("items",[]) or data.get("records",[])
print(items[0].get("id","") if items else "")' 2>/dev/null)

  if [ -z "$EID" ]; then
    warn "没有事件可导出（先看 /api/events 返回结构）"
    curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9900/api/events 2>/dev/null | head -c 300 | sed 's/^/      /'
  else
    echo "    用事件 id=$EID 导出 PDF"
    OUT=/tmp/test-export.pdf
    curl -s -o "$OUT" -w '    HTTP %{http_code}  大小 %{size_download} 字节  类型 %{content_type}\n' \
      -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9900/api/events/$EID/pdf"

    if [ -f "$OUT" ] && [ "$(stat -c %s "$OUT")" -gt 500 ]; then
      ok "拿到了 PDF（$(stat -c %s "$OUT") 字节）"
      echo "    文件类型: $(file -b "$OUT" 2>/dev/null || echo 未知)"
      echo
      echo "    --- 中文能不能正常渲染（关键）---"
      # 用 pdftotext 抽取文字；没有就退化为检查字体嵌入
      if command -v pdftotext >/dev/null 2>&1; then
        echo "    抽取出的文本（前 200 字）:"
        pdftotext "$OUT" - 2>/dev/null | head -c 200 | sed 's/^/      /'
      else
        echo "    (没有 pdftotext，改为检查字体嵌入)"
        strings "$OUT" 2>/dev/null | grep -iE 'FontFile|NotoSans|BaseFont' | head -6 | sed 's/^/      /'
      fi
      echo
      echo "    --- 有没有内嵌中文字体 ---"
      if strings "$OUT" 2>/dev/null | grep -qiE 'NotoSansCJK|Noto.*CJK'; then
        ok "PDF 里内嵌了 CJK 字体 —— 中文应该能正常显示"
      else
        warn "没找到 CJK 字体嵌入 —— 中文可能是方块或空白"
      fi
    else
      warn "PDF 导出失败或文件过小"
      head -c 300 "$OUT" 2>/dev/null | sed 's/^/      /'
    fi
  fi
fi

log "6/6 结论"
echo "    审计持久化: 对比第 1 步和第 3 步的哈希"
echo "      · 哈希一致 -> 审计真的落在挂载卷上，容器重建不丢 ✅"
echo "      · 文件不见了 -> '全部动作留痕' 是假的，必须挂卷或外置"
echo
echo "    PDF 中文:   看第 5 步的字体嵌入结论"
