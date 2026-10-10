/* 红队回归评测视图：运行 / KPI 看板 / 逐例表 / 图表 / 历史 run / 对比 */
(function () {
    'use strict';

    var state = { latest: null, runs: [], compareA: null, compareB: null, compareResult: null };

    function pct(v) { return (v == null ? 0 : v) + '%'; }
    function ms(v) { return (v == null ? 0 : v) + ' ms'; }

    function statusTag(s) {
        if (s === 'BLOCKED') return '<span class="sa-tag sa-tag-ok">已拦截</span>';
        if (s === 'BYPASSED') return '<span class="sa-tag sa-tag-critical">被绕过</span>';
        if (s === 'MISBLOCKED') return '<span class="sa-tag sa-tag-critical">误拦</span>';
        if (s === 'ALLOWED') return '<span class="sa-tag sa-tag-low">正常放行</span>';
        if (s === 'SKIPPED') return '<span class="sa-tag sa-tag-info">跳过</span>';
        return '<span class="sa-tag sa-tag-info">' + SecUI.escapeHtml(s || '-') + '</span>';
    }

    function renderKpi(summary) {
        var k = document.getElementById('evKpi');
        if (!k) return;
        if (!summary) { k.innerHTML = '<div class="sa-muted" style="padding:20px;">尚未运行评测，点右上角“运行评测”开始。</div>'; return; }
        var fpr = summary.falsePositiveRate || 0;
        var fpTone = fpr > 0 ? 'crit' : 'ok';
        k.innerHTML =
            kpiCard('攻击成功率', pct(summary.attackSuccessRate), summary.bypassed + ' / ' + summary.executed + ' 例被绕过', 'crit')
            + kpiCard('绕过率', pct(summary.bypassRate), '期望拦截用例中未拦住的比例', 'warn')
            + kpiCard('误报率', pct(fpr), (summary.normalMisblocked || 0) + ' / ' + (summary.normalExecuted || 0) + ' 正常用例被误拦', fpTone)
            + kpiCard('平均耗时', ms(summary.avgLatencyMs), '共执行 ' + summary.executed + ' 例（跳过 ' + summary.skipped + '）', 'info')
            + kpiCard('Token 成本', (summary.totalTokenCost || 0) + '', '离线用例为 0；模型用例据实统计', 'ok');
    }

    function kpiCard(label, value, sub, tone) {
        return '<div class="sa-card ev-kpi">'
            + '<div class="ev-kpi-label">' + label + '</div>'
            + '<div class="ev-kpi-value ev-tone-' + tone + '">' + SecUI.escapeHtml(value) + '</div>'
            + '<div class="ev-kpi-sub sa-muted">' + SecUI.escapeHtml(sub) + '</div>'
            + '</div>';
    }

    function renderDetails(run) {
        var t = document.getElementById('evDetailBody');
        if (!t) return;
        if (!run || !run.details) { t.innerHTML = '<tr><td colspan="6" class="ev-empty">暂无明细</td></tr>'; return; }
        var html = '';
        run.details.forEach(function (d) {
            var snippet = (d.payload || '');
            if (snippet.length > 42) snippet = snippet.substring(0, 42) + '…';
            html += '<tr>'
                + '<td>' + SecUI.escapeHtml(d.category || '-') + '</td>'
                + '<td class="ev-payload" title="' + SecUI.escapeHtml(d.payload || '') + '">' + SecUI.escapeHtml(snippet) + '</td>'
                + '<td>' + statusTag(d.status) + '</td>'
                + '<td class="sa-muted">' + (d.latencyMs || 0) + ' ms</td>'
                + '<td class="sa-muted">' + (d.tokenCost || 0) + '</td>'
                + '<td class="sa-muted ev-detail">' + SecUI.escapeHtml(d.detail || '') + '</td>'
                + '</tr>';
        });
        t.innerHTML = html;
    }

    function renderChart(run) {
        var wrap = document.getElementById('evChartWrap');
        if (!wrap) return;
        SecUI.charts.forEach(function (c) { try { c.destroy(); } catch (e) {} });
        SecUI.charts = [];
        if (!run || !run.summary || !run.summary.byCategory) {
            wrap.innerHTML = '<div class="sa-muted" style="padding:16px;">运行后展示各分类拦截情况。</div>';
            return;
        }
        wrap.innerHTML = '<canvas id="evChart"></canvas>';
        var cats = Object.keys(run.summary.byCategory);
        var blocked = cats.map(function (c) { return run.summary.byCategory[c].blocked; });
        var bypassed = cats.map(function (c) { return run.summary.byCategory[c].bypassed; });
        var allowed = cats.map(function (c) { return run.summary.byCategory[c].allowed || 0; });
        var skipped = cats.map(function (c) { return run.summary.byCategory[c].skipped; });
        var ctx = document.getElementById('evChart').getContext('2d');
        var chart = new window.Chart(ctx, {
            type: 'bar',
            data: {
                labels: cats,
                datasets: [
                    { label: '已拦截', data: blocked, backgroundColor: '#12b76a' },
                    { label: '被绕过', data: bypassed, backgroundColor: '#d92d20' },
                    { label: '放行(良性)', data: allowed, backgroundColor: '#2e90fa' },
                    { label: '已跳过', data: skipped, backgroundColor: '#c3ccd4' }
                ]
            },
            options: { responsive: true, scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } } }
        });
        SecUI.charts.push(chart);
    }

    function renderRuns() {
        var box = document.getElementById('evRunList');
        if (!box) return;
        if (!state.runs.length) { box.innerHTML = '<div class="sa-muted" style="padding:14px;">暂无历史运行。</div>'; return; }
        var html = '';
        state.runs.forEach(function (r) {
            var s = r.summary || {};
            var checkedA = state.compareA === r.runId ? 'checked' : '';
            var checkedB = state.compareB === r.runId ? 'checked' : '';
            html += '<div class="ev-run">'
                + '<div class="ev-run-main">'
                + '<div class="ev-run-id">' + SecUI.escapeHtml(r.runId)
                + ' <span class="sa-tag sa-tag-info">' + SecUI.escapeHtml(r.model || '') + '</span></div>'
                + '<div class="sa-muted" style="font-size:12px;">' + SecUI.escapeHtml(r.startedAt || '')
                + ' · 成功率 ' + pct(s.attackSuccessRate) + ' · 绕过 ' + (s.bypassed || 0)
                + ' · 误报 ' + pct(s.falsePositiveRate || 0) + '（' + (s.normalMisblocked || 0) + '/' + (s.normalExecuted || 0) + '）'
                + ' · 跳过 ' + (s.skipped || 0) + '</div>'
                + '</div>'
                + '<div class="ev-run-ops">'
                + '<label class="ev-cmp"><input type="checkbox" data-cmp="A" data-id="' + SecUI.escapeHtml(r.runId) + '" ' + checkedA + '> A</label>'
                + '<label class="ev-cmp"><input type="checkbox" data-cmp="B" data-id="' + SecUI.escapeHtml(r.runId) + '" ' + checkedB + '> B</label>'
                + '<button class="sa-btn" data-detail="' + SecUI.escapeHtml(r.runId) + '">查看</button>'
                + '</div></div>';
        });
        box.innerHTML = html;
    }

    function renderCompare() {
        var box = document.getElementById('evCompareBox');
        if (!box) return;
        if (!state.compareResult) { box.innerHTML = ''; return; }
        var r = state.compareResult;
        if (!r.found) { box.innerHTML = '<div class="sa-muted" style="padding:12px;">' + SecUI.escapeHtml(r.message || '无法对比') + '</div>'; return; }
        var html = '<div class="sa-card-head" style="padding:10px 14px;border-bottom:1px solid var(--sa-border);">'
            + '<span class="sa-card-title">对比：' + SecUI.escapeHtml(r.runA) + ' − ' + SecUI.escapeHtml(r.runB) + '</span></div>'
            + '<table class="sa-table"><thead><tr><th>指标</th><th>A</th><th>B</th><th>差值(A−B)</th></tr></thead><tbody>';
        (r.diffs || []).forEach(function (d) {
            var dCls = d.delta > 0 ? 'ev-up' : (d.delta < 0 ? 'ev-down' : '');
            html += '<tr><td>' + SecUI.escapeHtml(d.metric) + '</td>'
                + '<td>' + SecUI.escapeHtml(d.runA) + '</td>'
                + '<td>' + SecUI.escapeHtml(d.runB) + '</td>'
                + '<td class="' + dCls + '">' + (d.delta > 0 ? '+' : '') + SecUI.escapeHtml(d.delta) + '</td></tr>';
        });
        html += '</tbody></table>';
        box.innerHTML = html;
    }

    function refreshRuns() {
        return SecUI.get('/eval/runs').then(function (res) {
            state.runs = res.data || [];
            renderRuns();
        }).catch(function (err) { SecUI.toast(err.message, 'error'); });
    }

    function showRun(run) {
        state.latest = run;
        renderKpi(run.summary);
        renderDetails(run);
        renderChart(run);
    }

    function runEval(model) {
        var btn = document.getElementById('evRunBtn');
        if (btn) btn.disabled = true;
        SecUI.post('/eval/run' + (model ? '?model=' + encodeURIComponent(model) : ''), {})
            .then(function (res) {
                SecUI.toast('评测完成', 'success');
                showRun(res.data);
                refreshRuns();
            })
            .catch(function (err) { SecUI.toast(err.message, 'error'); })
            .finally(function () { if (btn) btn.disabled = false; });
    }

    function mount(root) {
        root.innerHTML =
            '<div class="sa-page">'
            + '<div class="sa-card">'
            + '<div class="sa-card-head">'
            + '<span class="sa-card-title">红队回归评测</span>'
            + '<div style="display:flex;gap:8px;align-items:center;">'
            + '<select class="sa-select" id="evModel" style="max-width:200px;">'
            + '<option value="">离线护栏套件（默认）</option>'
            + '<option value="qwen-plus">qwen-plus</option>'
            + '<option value="qwen-max">qwen-max</option>'
            + '</select>'
            + '<button class="sa-btn sa-btn-primary" id="evRunBtn">运行评测</button>'
            + '</div></div>'
            + '<div class="sa-card-body">'
            + '<div class="ev-kpi-grid" id="evKpi"></div>'
            + '</div></div>'

            + '<div class="sa-card" style="margin-top:14px;">'
            + '<div class="sa-card-head"><span class="sa-card-title">逐例结果</span></div>'
            + '<div class="sa-card-body" style="overflow:auto;">'
            + '<table class="sa-table"><thead><tr><th>类别</th><th>载荷片段</th><th>状态</th>'
            + '<th>耗时</th><th>Token</th><th>判定说明</th></tr></thead>'
            + '<tbody id="evDetailBody"></tbody></table>'
            + '</div></div>'

            + '<div class="sa-grid" style="grid-template-columns:1fr 1fr;margin-top:14px;">'
            + '<div class="sa-card"><div class="sa-card-head"><span class="sa-card-title">各分类拦截情况</span></div>'
            + '<div class="sa-card-body" id="evChartWrap"></div></div>'
            + '<div class="sa-card"><div class="sa-card-head"><span class="sa-card-title">历史运行（勾选两个做对比）</span></div>'
            + '<div class="sa-card-body" id="evRunList"></div></div>'
            + '</div>'

            + '<div class="sa-card" style="margin-top:14px;" id="evCompareBox"></div>'
            + '</div>';

        renderKpi(null);
        renderDetails(null);
        renderChart(null);

        root.querySelector('#evRunBtn').onclick = function () {
            var m = root.querySelector('#evModel').value;
            runEval(m || null);
        };

        root.querySelector('#evRunList').addEventListener('click', function (e) {
            var cb = e.target.closest('input[type=checkbox][data-cmp]');
            if (cb) {
                var id = cb.getAttribute('data-id');
                var side = cb.getAttribute('data-cmp');
                if (side === 'A') state.compareA = cb.checked ? id : null;
                else state.compareB = cb.checked ? id : null;
                if (state.compareA && state.compareB) {
                    SecUI.post('/eval/compare?a=' + encodeURIComponent(state.compareA)
                        + '&b=' + encodeURIComponent(state.compareB), {})
                        .then(function (res) { state.compareResult = res.data; renderCompare(); })
                        .catch(function (err) { SecUI.toast(err.message, 'error'); });
                } else { state.compareResult = null; renderCompare(); }
                return;
            }
            var det = e.target.closest('button[data-detail]');
            if (det) {
                var rid = det.getAttribute('data-detail');
                SecUI.get('/eval/runs/' + rid).then(function (res) { showRun(res.data); })
                    .catch(function (err) { SecUI.toast(err.message, 'error'); });
            }
        });
    }

    window.SecUI.registerView('evals', mount, function () {
        renderKpi(state.latest ? state.latest.summary : null);
        renderDetails(state.latest);
        renderChart(state.latest);
        refreshRuns();
    });
})();
