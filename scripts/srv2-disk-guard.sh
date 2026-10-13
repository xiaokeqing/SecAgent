#!/bin/bash
# 磁盘水位守护（本机 40G 盘曾因 Wazuh 漏洞检测模块临时文件堆到 100% 而停写告警）
# 策略：>=85% 清理可安全清理的缓存并写 WARN；>=70% 写 NOTICE；否则每小时写一条 OK
LOG=/var/log/disk-guard.log
USE=${TEST_USE:-$(df --output=pcent / | tail -1 | tr -dc "0-9")}
TS=$(date '+%F %T')
MIN=$(date '+%M')
if [ "$USE" -ge 85 ]; then
  echo "$TS WARN disk_usage=${USE}% action=clean" >> "$LOG"
  rm -rf /var/lib/docker/volumes/wazuh_wazuh_queue/_data/vd_updater/tmp/* 2>/dev/null || true
  apt-get clean 2>/dev/null || true
  journalctl --vacuum-size=100M >/dev/null 2>&1 || true
  echo "$TS INFO disk_usage_after=$(df --output=pcent / | tail -1 | tr -dc '0-9')%" >> "$LOG"
elif [ "$USE" -ge 70 ]; then
  echo "$TS NOTICE disk_usage=${USE}%" >> "$LOG"
elif [ "$MIN" -lt 15 ]; then
  echo "$TS OK disk_usage=${USE}%" >> "$LOG"
fi
exit 0
