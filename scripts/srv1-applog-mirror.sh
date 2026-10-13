#!/usr/bin/env bash
# ============================================================
# SecAgent 应用容器日志镜像（srv1 主机侧）
# ------------------------------------------------------------
# 由 deploy/secagent-applog-mirror.service 调用，职责只有一个：
#   把应用容器的 stdout 变成宿主上一个【路径稳定】的纯文本文件
#     docker logs -f secagent  ->  /var/log/secagent/app.log
#
# 为什么需要它（而不是让检测直接读 docker 的 json 日志）：
#   docker 的 json 日志路径是
#     /var/lib/docker/containers/<容器ID>/<容器ID>-json.log
#   其中 <容器ID> 每次 CI 重建（ACR stable digest 变了就重建）都会变。
#   把 fail2ban / wazuh 指向那个路径 = 每次部署之后检测【静默失效】，
#   而面板上看起来一切正常。镜像文件路径固定，重建容器后自动跟随。
#
# 为什么外面套一层 while 循环（实测踩到）：
#   `docker logs -f <name>` 在容器【非 running】（重启中/已停止）时
#   会把已有日志刷完就正常退出（exit 0）。只靠 systemd 的 Restart=always
#   会得到"服务反复 Succeeded"的抖动状态，fail2ban 的 logpath 时有时无。
#   循环里显式重试才是稳的；每次重连写一行标记，缺口可见、不装作连续。
#
# 为什么这一段要放进独立脚本，而不是写在 unit 的 ExecStart 里（实测踩到）：
#   systemd 会对 unit 里的 % 做 specifier 展开 —— 我原来用
#   printf "... %s ..." "$(date -Is)" 结果 %s 被展开成了 /bin/sh，
#   日志文件里写进去的是 "=== ... (re)connect /bin/sh ==="，
#   而真正的应用日志一行都没落盘。unit 里要写字面 % 得写 %%。
#   把循环搬到脚本里，这类展开陷阱就彻底没有了。
#
# 已知边界（如实记录）：
#   · 容器重建的瞬间流会断，重连间隔 3 秒 —— 这 3 秒的应用日志会丢。
#   · `--tail 0`：只跟新日志，不重放历史，避免重连后重复告警。
# ============================================================
set -u
LOG=/var/log/secagent/app.log
mkdir -p "$(dirname "$LOG")"
[ -e "$LOG" ] || : > "$LOG"

while :; do
  printf '=== secagent-applog-mirror (re)connect %s ===\n' "$(date -Is)" >> "$LOG"
  docker logs -f --tail 0 secagent >> "$LOG" 2>&1
  printf '=== secagent-applog-mirror stream ended %s, retry in 3s ===\n' "$(date -Is)" >> "$LOG"
  sleep 3
done
