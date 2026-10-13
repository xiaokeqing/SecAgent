/**
 * SecAgent 知识库视图（验收项7）：
 *  - 5 大类别卡片（含分片计数徽标）+ 类别筛选
 *  - 检索框：标题 / 片段 / 来源 / 相似度 / 类别标签
 *  - 提交知识表单：写入前先过服务端注入检测，被拦截时明确显示原因
 *  - 管理员可见"待审核"区：通过 / 驳回；分析员隐藏（后端也会拒）
 *  - 已通过列表
 * XSS：所有动态文本一律经 SecUI.escapeHtml 转义后再插入。
 */
(function () {
    'use strict';

    var state = {
        mounted: false,
        categories: [],      // [{name,count,files}]
        currentCategory: '全部',
        lastQuery: ''
    };

    function fmtTime(ts) {
        if (!ts) return '';
        try {
            var d = new Date(ts);
            function p(n) { return (n < 10 ? '0' : '') + n; }
            return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate())
                + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
        } catch (e) { return ''; }
    }

    // 分数语义（2026-10-13 混合检索改造后）：后端返回的不再是余弦相似度，
    // 而是【最终检索分】（两路召回 RRF + 轻量重排信号）。它是一个排序分，
    // 绝对值不可解释（RRF 分数量级约 0.01~0.05），所以这里不显示绝对分数，
    // 而是显示"相对本次结果里最高分"的百分比 —— 至少它说的是一件真实的事：
    // 这条结果相对于第一条有多接近。
    function scoreRel(s, best) {
        if (s === null || s === undefined || isNaN(s)) return '-';
        if (!best || isNaN(best) || best <= 0) return '-';
        return Math.round(100 * s / best) + '%';
    }

    function mount(root) {
        root.innerHTML =
            '<div class="kb-page">' +
            '  <div class="kb-cat-row" id="kbCatRow"></div>' +
            '  <div class="kb-layout">' +
            '    <div class="kb-main">' +
            '      <div class="sa-card">' +
            '        <div class="sa-card-head"><span class="sa-card-title">知识检索</span>' +
            '          <span class="sa-muted" id="kbSearchHint"></span></div>' +
            '        <div class="sa-card-body kb-search-bar">' +
            '          <input class="sa-input kb-search-input" id="kbSearchInput" placeholder="搜漏洞原理、应急处置、设备加固……" />' +
            '          <select class="sa-select kb-search-cat" id="kbSearchCat"></select>' +
            '          <button class="sa-btn sa-btn-primary" id="kbSearchBtn">搜索</button>' +
            '        </div>' +
            '        <div class="sa-card-body kb-results" id="kbResults"></div>' +
            '      </div>' +
            '    </div>' +
            '    <div class="kb-side">' +
            '      <div class="sa-card">' +
            '        <div class="sa-card-head"><span class="sa-card-title">提交知识</span>' +
            '          <span class="sa-tag sa-tag-info">人工提交</span></div>' +
            '        <div class="sa-card-body">' +
            '          <textarea class="sa-textarea" id="kbSubmitContent" placeholder="粘贴一条经验 / 漏洞处置笔记……（提交后管理员审核通过才会入库）"></textarea>' +
            '          <div class="kb-form-row">' +
            '            <select class="sa-select" id="kbSubmitCat"></select>' +
            '            <button class="sa-btn sa-btn-primary" id="kbSubmitBtn">提交审核</button>' +
            '          </div>' +
            '          <div class="kb-alert kb-alert-block" id="kbSubmitAlert" style="display:none;"></div>' +
            '        </div>' +
            '      </div>' +
            '      <div class="sa-card kb-admin-only" id="kbPendingCard" style="display:none;">' +
            '        <div class="sa-card-head"><span class="sa-card-title">待审核</span>' +
            '          <span class="sa-tag sa-tag-high" id="kbPendingCount">0</span></div>' +
            '        <div class="sa-card-body kb-pending" id="kbPendingList"></div>' +
            '      </div>' +
            '      <div class="sa-card">' +
            '        <div class="sa-card-head"><span class="sa-card-title">已通过</span>' +
            '          <span class="sa-muted">人工/自动写入审核通过的知识</span></div>' +
            '        <div class="sa-card-body kb-approved" id="kbApprovedList"></div>' +
            '      </div>' +
            '    </div>' +
            '  </div>' +
            '</div>';

        // 类别卡片点击 = 筛选
        root.querySelector('#kbCatRow').addEventListener('click', function (e) {
            var card = e.target.closest('.kb-cat-card');
            if (!card) return;
            state.currentCategory = card.getAttribute('data-cat');
            refreshCatActive();
            var sel = root.querySelector('#kbSearchCat');
            if (sel) sel.value = state.currentCategory;
            doSearch();
        });

        root.querySelector('#kbSearchBtn').addEventListener('click', doSearch);
        root.querySelector('#kbSearchInput').addEventListener('keydown', function (e) {
            if (e.key === 'Enter') doSearch();
        });
        root.querySelector('#kbSearchCat').addEventListener('change', function (e) {
            state.currentCategory = e.target.value;
            refreshCatActive();
            doSearch();
        });

        root.querySelector('#kbSubmitBtn').addEventListener('click', doSubmit);

        state.mounted = true;
    }

    function refreshCatActive() {
        var row = document.getElementById('kbCatRow');
        if (!row) return;
        row.querySelectorAll('.kb-cat-card').forEach(function (c) {
            c.classList.toggle('active', c.getAttribute('data-cat') === state.currentCategory);
        });
    }

    function renderCategories(data) {
        state.categories = (data && data.categories) || [];
        var row = document.getElementById('kbCatRow');
        if (!row) return;

        var html = '<div class="kb-cat-card' + (state.currentCategory === '全部' ? ' active' : '') + '" data-cat="全部">' +
            '<div class="kb-cat-name">全部知识</div>' +
            '<div class="kb-cat-sub">不按类别筛选</div></div>';
        var total = 0;
        state.categories.forEach(function (c) {
            total += c.count || 0;
            html += '<div class="kb-cat-card' + (state.currentCategory === c.name ? ' active' : '') + '" data-cat="' + SecUI.escapeHtml(c.name) + '">' +
                '<div class="kb-cat-name">' + SecUI.escapeHtml(c.name) + '</div>' +
                '<div class="kb-cat-sub">内置分片 <b>' + (c.count || 0) + '</b> 条</div>' +
                '</div>';
        });
        row.innerHTML = html;

        // 同步两个下拉框
        var cats = ['全部'].concat(state.categories.map(function (c) { return c.name; }));
        [['#kbSearchCat', state.currentCategory], ['#kbSubmitCat', null]].forEach(function (pair) {
            var sel = document.querySelector(pair[0]);
            if (!sel) return;
            sel.innerHTML = cats.map(function (n) {
                return '<option value="' + SecUI.escapeHtml(n) + '"' +
                    (pair[1] === n ? ' selected' : '') + '>' + SecUI.escapeHtml(n) + '</option>';
            }).join('');
        });
        var hint = document.getElementById('kbSearchHint');
        if (hint) hint.textContent = '内置 ' + total + ' 条预计算向量 + 已通过人工知识';
    }

    function doSearch() {
        var input = document.getElementById('kbSearchInput');
        var query = input ? input.value.trim() : '';
        state.lastQuery = query;
        var box = document.getElementById('kbResults');
        if (!box) return;
        if (!query) {
            box.innerHTML = '<div class="kb-empty">输入关键词开始检索；点击上方类别卡片可按类别浏览。</div>';
            return;
        }
        box.innerHTML = '<div class="kb-empty">检索中…</div>';
        SecUI.get('/kb/search?query=' + encodeURIComponent(query) +
            '&category=' + encodeURIComponent(state.currentCategory === '全部' ? '' : state.currentCategory))
            .then(function (res) { renderResults(res.data || []); })
            .catch(function (err) {
                box.innerHTML = '<div class="kb-empty kb-err">检索失败：' + SecUI.escapeHtml(err.message) + '</div>';
            });
    }

    function renderResults(list) {
        var box = document.getElementById('kbResults');
        if (!box) return;
        if (!list.length) {
            box.innerHTML = '<div class="kb-empty">没有命中知识。换个关键词，或在右侧提交一条新知识。</div>';
            return;
        }
        var html = '';
        var bestScore = 0;
        list.forEach(function (r) {
            if (typeof r.score === 'number' && r.score > bestScore) bestScore = r.score;
        });
        list.forEach(function (r) {
            html += '<div class="kb-result">' +
                '<div class="kb-result-head">' +
                '  <span class="kb-result-title">' + SecUI.escapeHtml(r.title || '(无标题)') + '</span>' +
                '  <span class="kb-tag-cat">' + SecUI.escapeHtml(r.category || '') + '</span>' +
                '</div>' +
                '<div class="kb-result-snippet">' + SecUI.escapeHtml(r.snippet || '') + '</div>' +
                '<div class="kb-result-meta">' +
                '  <span>来源：' + SecUI.escapeHtml(r.source || '-') + '</span>' +
                '  <span class="kb-origin">' + SecUI.escapeHtml(r.origin || '') + '</span>' +
                '  <span title="两路召回(稠密+BM25)融合后的排序分，相对于本次第一条">相关度：' +
                SecUI.escapeHtml(scoreRel(r.score, bestScore)) + '</span>' +
                '</div></div>';
        });
        box.innerHTML = html;
    }

    function doSubmit() {
        var cInput = document.getElementById('kbSubmitContent');
        var catSel = document.getElementById('kbSubmitCat');
        var alertBox = document.getElementById('kbSubmitAlert');
        var content = cInput.value.trim();
        var category = catSel.value;
        alertBox.style.display = 'none';
        if (!content) {
            alertBox.textContent = '请填写知识内容。';
            alertBox.className = 'kb-alert kb-alert-warn';
            alertBox.style.display = '';
            return;
        }
        SecUI.post('/kb/submit', { content: content, category: category })
            .then(function (res) {
                SecUI.toast(res.message || '已提交', 'success');
                cInput.value = '';
                loadPending();
                loadApproved();
            })
            .catch(function (err) {
                // 注入拦截等拒绝原因在这里明确展示
                alertBox.textContent = err.message || '提交失败';
                alertBox.className = 'kb-alert kb-alert-block';
                alertBox.style.display = '';
            });
    }

    function loadPending() {
        var card = document.getElementById('kbPendingCard');
        var list = document.getElementById('kbPendingList');
        var badge = document.getElementById('kbPendingCount');
        if (!card || !list) return;
        if (!SecUI.isAdmin()) {           // 分析员直接隐藏（后端同时强制 403）
            card.style.display = 'none';
            return;
        }
        card.style.display = '';
        SecUI.get('/kb/pending')
            .then(function (res) {
                var arr = res.data || [];
                badge.textContent = arr.length;
                if (!arr.length) {
                    list.innerHTML = '<div class="kb-empty">暂无待审核知识。</div>';
                    return;
                }
                var html = '';
                arr.forEach(function (e) {
                    html += '<div class="kb-pend-item">' +
                        '<div class="kb-pend-content">' + SecUI.escapeHtml(e.content) + '</div>' +
                        '<div class="kb-pend-meta">' +
                        '  <span class="kb-tag-cat">' + SecUI.escapeHtml(e.category || '') + '</span>' +
                        '  <span>来源：' + SecUI.escapeHtml(e.source || '') + '</span>' +
                        '  <span>提交人：' + SecUI.escapeHtml(e.actor || '') + '</span>' +
                        '  <span>' + SecUI.escapeHtml(fmtTime(e.createdAt)) + '</span>' +
                        '</div>' +
                        '<div class="kb-pend-actions">' +
                        '  <button class="sa-btn sa-btn-primary kb-approve" data-id="' + SecUI.escapeHtml(e.id) + '">通过入库</button>' +
                        '  <button class="sa-btn sa-btn-danger kb-reject" data-id="' + SecUI.escapeHtml(e.id) + '">驳回</button>' +
                        '</div></div>';
                });
                list.innerHTML = html;
                list.querySelectorAll('.kb-approve').forEach(function (btn) {
                    btn.addEventListener('click', function () { actOnPending(btn.getAttribute('data-id'), 'approve'); });
                });
                list.querySelectorAll('.kb-reject').forEach(function (btn) {
                    btn.addEventListener('click', function () { actOnPending(btn.getAttribute('data-id'), 'reject'); });
                });
            })
            .catch(function (err) {
                list.innerHTML = '<div class="kb-empty kb-err">加载失败：' + SecUI.escapeHtml(err.message) + '</div>';
            });
    }

    function actOnPending(id, action) {
        SecUI.post('/kb/' + action + '/' + encodeURIComponent(id), {})
            .then(function (res) {
                SecUI.toast(res.message || '完成', 'success');
                loadPending();
                loadApproved();
                doSearch();
            })
            .catch(function (err) { SecUI.toast(err.message || '操作失败', 'error'); });
    }

    function loadApproved() {
        var list = document.getElementById('kbApprovedList');
        if (!list) return;
        SecUI.get('/kb/approved')
            .then(function (res) {
                var arr = res.data || [];
                if (!arr.length) {
                    list.innerHTML = '<div class="kb-empty">暂无人工知识。提交并审核通过后会出现在这里。</div>';
                    return;
                }
                var html = '';
                arr.slice().reverse().forEach(function (e) {
                    html += '<div class="kb-appr-item">' +
                        '<div class="kb-pend-content">' + SecUI.escapeHtml(e.content) + '</div>' +
                        '<div class="kb-pend-meta">' +
                        '  <span class="kb-tag-cat">' + SecUI.escapeHtml(e.category || '') + '</span>' +
                        '  <span class="sa-tag sa-tag-info">待向量化</span>' +
                        '  <span>' + SecUI.escapeHtml(e.source || '') + '</span>' +
                        '  <span>' + SecUI.escapeHtml(fmtTime(e.approvedAt)) + '</span>' +
                        '</div></div>';
                });
                list.innerHTML = html;
            })
            .catch(function (err) {
                list.innerHTML = '<div class="kb-empty kb-err">加载失败：' + SecUI.escapeHtml(err.message) + '</div>';
            });
    }

    function refresh() {
        SecUI.get('/kb/categories').then(function (res) {
            renderCategories(res.data || {});
        }).catch(function () {});
        loadPending();
        loadApproved();
        if (state.lastQuery) doSearch();
        else {
            var box = document.getElementById('kbResults');
            if (box) box.innerHTML = '<div class="kb-empty">输入关键词开始检索；点击上方类别卡片可按类别浏览。</div>';
        }
    }

    SecUI.registerView('knowledge', mount, refresh);
})();
