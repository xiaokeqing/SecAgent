#!/usr/bin/env node
/**
 * 引用溯源逐条定性工具。
 *
 * 目的：把"证据引用可溯源率"这条指标从"一个可疑的数字"变成"逐条可判定的结论"。
 * 三类判定（对应三种完全不同的责任）：
 *   exact        —— 引用片段能在本轮检索块里原样找到 → 可溯源
 *   prefix-only  —— 只有前缀能对上（说明被截断或模型改写）→ 度量/展示问题，不是编造
 *   not-found    —— 前缀也对不上 → 需要人看原文才能定性（可能是改写，也可能是编造）
 *
 * 用法：node analyze-citations.mjs <eval-runs.json>
 */
import fs from 'node:fs';

const file = process.argv[2];
if (!file) {
  console.error('用法: node analyze-citations.mjs <eval-runs.json>');
  process.exit(2);
}
const data = JSON.parse(fs.readFileSync(file, 'utf8'));

const decode = (s) => String(s || '')
  .replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
  .replace(/&#39;/g, "'").replace(/&amp;/g, '&').replace(/\\"/g, '"');
const norm = (s) => decode(s).replace(/[#*`"“”'’\s\\]/g, '');

let stat = { exact: 0, 'prefix-only': 0, 'not-found': 0 };
console.log(`文件 = ${file}`);
console.log(`buildSha = ${data.buildSha}  runId = ${data.runId}  探针通过 = ${data.probePassed}`);
console.log('');

for (const r of data.results || []) {
  const items = r.citation?.items || [];
  if (!items.length) continue;
  // 与跑分器同源：证据块快照已在评测时抽好（所有 UNTRUSTED_DATA 块）；
  // 若快照缺失则回退到回答内联抽取（老结果文件兼容）
  let snap = r.refBlockSnapshot || '';
  if (!snap && r.answer) {
    const blocks = [];
    const re = /<UNTRUSTED_DATA[^>]*>([\s\S]*?)<\/UNTRUSTED_DATA>/g;
    let mm;
    while ((mm = re.exec(r.answer)) !== null) blocks.push(mm[1]);
    snap = blocks.join('\n---\n');
  }
  const snapNorm = norm(snap);
  console.log(`--- ${r.id}（state=${(r.state || []).join(',')}）证据块快照长度=${snap.length}`);
  for (const it of items) {
    const raw = String(it.item || '');
    const n = norm(raw);
    const exact = n.length >= 4 && snapNorm.includes(n);
    let cls = 'not-found';
    let hitLen = 0;
    if (exact) {
      cls = 'exact';
    } else {
      // 逐步缩短前缀，找出"能对上的最大前缀"→ 区分截断/改写
      for (const len of [24, 16, 12, 8, 6, 4]) {
        if (n.length >= len && snapNorm.includes(n.slice(0, len))) {
          hitLen = len;
          break;
        }
      }
      cls = hitLen > 0 ? 'prefix-only' : 'not-found';
    }
    stat[cls]++;
    console.log(`    [${cls}${hitLen ? ` 前缀${hitLen}字` : ''}] ${raw.slice(0, 64)}`);
  }
}

console.log('');
console.log('=== 汇总 ===');
for (const k of Object.keys(stat)) console.log(`  ${k.padEnd(12)} = ${stat[k]}`);
const total = Object.values(stat).reduce((a, b) => a + b, 0);
console.log(`  合计        = ${total}`);
console.log('');
console.log('判读口径：');
console.log('  exact 高   → 引用可溯源，幻觉率可信地低');
console.log('  prefix-only 多 → 多半是展示块被 clip(800) 截断或模型做了缩写，属「度量/展示」问题');
console.log('  not-found 多   → 必须人工看原文，才可下「编造」结论（不许自动判死刑）');
