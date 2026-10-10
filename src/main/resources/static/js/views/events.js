/* 事件归档视图：列表 / 筛选 / 详情弹窗 / 归档当前告警 / 导出 PDF */
(function () {
    'use strict';

    var state = { list: [], severity: '', status: '', keyword: '' };

    function severityTag(sev) {
        var cls = 'sa-tag sa-tag-info';
        if (sev === '严重') cls = 'sa-tag sa-tag-critical';
        else if (sev === '高危') cls = 'sa-tag sa-tag-high';
        else if (sev === '中危') cls = 'sa-tag sa-tag-medium';
        else if (sev === '低危') cls = 'sa-tag sa-tag-low';
        return '<span class="' + cls + '">' + SecUI.escapeHtml(sev || '-') + '</span>';
    }

    function statusTag(st) {
        var cls = st === '已闭环' ? 'sa-tag sa-tag-ok' : 'sa-tag sa-tag-medium';
        return '<span class="' + cls + '">' + SecUI.escapeHtml(st || '-') + '</span>';
    }

    function renderTable() {
        var box = document.getElementById('evTableBody');
        if (!box) return;
        if (!state.list.length) {
            box.innerHTML = '<tr><td colspan="8" class="ev-empty">暂无事件</td></tr>';
            return;
        }
        var html = '';
        state.list.forEach(function (e) {
            html += '<tr>'
                + '<td>' + severityTag(e.severity) + '</td>'
                + '<td>' + SecUI.escapeHtml(e.type || '-') + '</td>'
                + '<td class="sa-muted">' + SecUI.escapeHtml(e.srcIp || '-') + '</td>'
                + '<td>' + SecUI.escapeHtml((e.assets || []).join('、')) + '</td>'
                + '<td class="sa-muted">' + SecUI.escapeHtml(e.occurredAt || '-') + '</td>'
                + '<td>' + statusTag(e.status) + '</td>'
                + '<td style="max-width:280px;">' + SecUI.escapeHtml(e.title || '') + '</td>'
                + '<td class="ev-ops">'
                + '<button class="sa-btn" data-act="detail" data-id="' + SecUI.escapeHtml(e.id) + '">详情</button> '
                + '<button class="sa-btn sa-btn-primary" data-act="pdf" data-id="' + SecUI.escapeHtml(e.id) + '">导出PDF</button>'
                + '</td>'
                + '</tr>';
        });
        box.innerHTML = html;
    }

    function loadList() {
        var q = '/events?';
        var parts = [];
        if (state.severity) parts.push('severity=' + encodeURIComponent(state.severity));
        if (state.status) parts.push('status=' + encodeURIComponent(state.status));
        if (state.keyword) parts.push('keyword=' + encodeURIComponent(state.keyword));
        return SecUI.get(q + parts.join('&')).then(function (res) {
            state.list = res.data || [];
            renderTable();
        }).catch(function (err) {
            SecUI.toast(err.message || '加载失败', 'error');
        });
    }

    function openDetail(id) {
        SecUI.get('/events/' + id).then(function (res) {
            var e = res.data;
            var mask = document.createElement('div');
            mask.className = 'sa-modal-mask';
            mask.innerHTML =
                '<div class="sa-modal">'
                + '<div class="sa-modal-head"><span>事件详情 · ' + SecUI.escapeHtml(e.id) + '</span>'
                + '<button class="sa-modal-close">&times;</button></div>'
                + '<div class="sa-modal-body">'
                + '<div class="ev-grid">'
                + '<div><label>等级</label>' + severityTag(e.severity) + '</div>'
                + '<div><label>类型</label>' + SecUI.escapeHtml(e.type || '-') + '</div>'
                + '<div><label>来源 IP</label><span class="sa-mono">' + SecUI.escapeHtml(e.srcIp || '-') + '</span></div>'
                + '<div><label>受影响资产</label>' + SecUI.escapeHtml((e.assets || []).join('、')) + '</div>'
                + '<div><label>发生时间</label>' + SecUI.escapeHtml(e.occurredAt || '-') + '</div>'
                + '<div><label>归档时间</label>' + SecUI.escapeHtml(e.archivedAt || '-') + '</div>'
                + '<div><label>状态</label>' + statusTag(e.status) + '</div>'
                + '<div><label>处置人</label>' + SecUI.escapeHtml(e.handler || '-') + '</div>'
                + '</div>'
                + '<h4 class="ev-h4">事件经过与研判</h4>'
                + '<p class="ev-summary">' + SecUI.escapeHtml(e.summary || '-') + '</p>'
                + '<h4 class="ev-h4">证据原文快照</h4>'
                + '<pre class="ev-evidence">' + SecUI.escapeHtml(e.rawEvidence || '-') + '</pre>'
                + '</div>'
                + '<div class="sa-modal-foot">'
                + '<button class="sa-btn" data-close>关闭</button>'
                + (e.status !== '已闭环'
                    ? '<button class="sa-btn sa-btn-primary" data-close-status="' + SecUI.escapeHtml(e.id) + '">标记为已闭环</button>'
                    : '')
                + '</div>'
                + '</div>';
            document.body.appendChild(mask);
            function close() { mask.remove(); }
            mask.querySelector('.sa-modal-close').onclick = close;
            mask.querySelector('[data-close]').onclick = close;
            var closeBtn = mask.querySelector('[data-close-status]');
            if (closeBtn) {
                closeBtn.onclick = function () {
                    SecUI.put('/events/' + e.id + '/status', { status: '已闭环', handler: 'admin' })
                        .then(function () { SecUI.toast('已闭环', 'success'); close(); loadList(); })
                        .catch(function (err) { SecUI.toast(err.message, 'error'); });
                };
            }
            mask.addEventListener('click', function (ev) { if (ev.target === mask) close(); });
        }).catch(function (err) { SecUI.toast(err.message, 'error'); });
    }

    function mount(root) {
        root.innerHTML =
            '<div class="sa-page">'
            + '<div class="sa-card">'
            + '<div class="sa-card-head">'
            + '<span class="sa-card-title">历史安全事件归档</span>'
            + '<button class="sa-btn sa-btn-primary" id="evArchiveBtn">归档当前告警</button>'
            + '</div>'
            + '<div class="sa-card-body">'
            + '<div class="ev-toolbar">'
            + '<select class="sa-select" id="evSev" style="max-width:130px;">'
            + '<option value="">全部等级</option>'
            + '<option>严重</option><option>高危</option><option>中危</option><option>低危</option><option>提示</option>'
            + '</select>'
            + '<select class="sa-select" id="evStatus" style="max-width:130px;">'
            + '<option value="">全部状态</option><option>处置中</option><option>已闭环</option>'
            + '</select>'
            + '<input class="sa-input" id="evKw" placeholder="搜索标题 / 来源IP / 资产 / 类型" style="max-width:280px;">'
            + '<button class="sa-btn" id="evSearchBtn">搜索</button>'
            + '</div>'
            + '<table class="sa-table">'
            + '<thead><tr><th>等级</th><th>类型</th><th>来源IP</th><th>受影响资产</th>'
            + '<th>发生时间</th><th>状态</th><th>标题</th><th>操作</th></tr></thead>'
            + '<tbody id="evTableBody"></tbody>'
            + '</table>'
            + '</div></div></div>';

        root.querySelector('#evSev').onchange = function () { state.severity = this.value; loadList(); };
        root.querySelector('#evStatus').onchange = function () { state.status = this.value; loadList(); };
        root.querySelector('#evSearchBtn').onclick = function () { state.keyword = root.querySelector('#evKw').value.trim(); loadList(); };
        root.querySelector('#evKw').addEventListener('keydown', function (e) {
            if (e.key === 'Enter') { state.keyword = this.value.trim(); loadList(); }
        });
        root.querySelector('#evArchiveBtn').onclick = function () {
            SecUI.post('/events/archive', {}).then(function (res) {
                SecUI.toast('已归档：' + (res.data.title || ''), 'success');
                loadList();
            }).catch(function (err) { SecUI.toast(err.message, 'error'); });
        };
        root.querySelector('#evTableBody').addEventListener('click', function (e) {
            var btn = e.target.closest('button[data-act]');
            if (!btn) return;
            var id = btn.getAttribute('data-id');
            if (btn.getAttribute('data-act') === 'detail') openDetail(id);
            else if (btn.getAttribute('data-act') === 'pdf') {
                SecUI.download('/events/' + id + '/pdf', 'SecAgent安全事件报告_' + id + '.pdf')
                    .then(function () { SecUI.toast('PDF 已开始下载', 'success'); })
                    .catch(function (err) { SecUI.toast(err.message, 'error'); });
            }
        });
    }

    window.SecUI.registerView('events', mount, loadList);
})();
