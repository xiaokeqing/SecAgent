#!/usr/bin/env node
/**
 * 引用溯源逐条定性 —— 【已合并，仅保留兼容入口】。
 *
 * 背景（为什么要合并）：同一个指标此前有三套口径 ——
 *   · eval-papers.py（服务器 cron 实际在跑的那份）：没有引用指标；
 *   · eval-papers.mjs 内联的 citationCheck()：另一套实现，只吐数字；
 *   · 本文件（旧版）：第三套实现，词表也不同（exact / prefix-only / not-found）。
 * 结果是"指标说 92%、工具说 30%"时无法判定谁对 —— 两把尺子量同一件东西。
 *
 * 现在实现统一到 `scripts/citation_audit.py`：
 *   · `eval-papers.py` 直接 import 它计算指标（同一实现、同一份证据块）；
 *   · 本脚本只是转发，保证历史文档/肌肉记忆里的命令仍然可用。
 *
 * 用法（与旧版一致）：node scripts/analyze-citations.mjs <结果文件.json> [...]
 */
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const tool = path.join(here, 'citation_audit.py');

console.error('[analyze-citations] 已合并到 scripts/citation_audit.py（同一实现），本入口仅转发。');
const r = spawnSync('python3', [tool, ...process.argv.slice(2)], { stdio: 'inherit' });
if (r.error) {
  console.error(`[analyze-citations] 转发失败：${r.error.message}（需要 python3）`);
  process.exit(2);
}
process.exit(r.status === null ? 2 : r.status);
