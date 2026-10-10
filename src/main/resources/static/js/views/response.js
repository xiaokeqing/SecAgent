/**
 * 处置中心（人在回路分级自动响应）。
 * 功能：自动策略开关、处置建议、待审批队列、封IP对话框、审计留痕表。
 * 安全：所有后端文本一律 textContent 写入，禁止未转义 innerHTML。
 */
(function () {
    'use strict';
    var UI = window.SecUI;

    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text !== undefined && text !== null) e.textContent = text;
        return e;
    }

    function tagFor(risk) {
        var t = el('span', 'tag ' + (risk === 'HIGH' ? 'tag-high' : 'tag-low'), risk === 'HIGH' ? '高危' : '低危');
        return t;
    }

    function emptyBox(where, text) {
        where.textContent = '';
        where.appendChild(el('div', 'empty-tip', text));
    }

    UI.registerView('response', function (container) {
        container.textContent = '';
        var root = el('div');
        container.appendChild(root);

        // 头部
        var header = el('div', 'resp-header');
        var h2 = el('h2', null, '处置中心');
        var modeBadge = el('span', 'resp-mode', '模式加载中…');
        header.appendChild(h2);
        header.appendChild(modeBadge);
        root.appendChild(header);

        var grid = el('div', 'resp-grid');
        root.appendChild(grid);

        // 左列：策略面板 + 审计表
        var left = el('div');
        grid.appendChild(left);

        var policyCard = el('div', 'resp-card');
        policyCard.appendChild(el('h3', null, '自动处置策略'));
        var policyBody = el('div');
        policyCard.appendChild(policyBody);
        left.appendChild(policyCard);

        // 右列：建议 + 待审批
        var right = el('div');
        grid.appendChild(right);

        var sugCard = el('div', 'resp-card');
        sugCard.appendChild(el('h3', null, '处置建议（来自当前告警）'));
        var sugBody = el('div', 'resp-list');
        sugCard.appendChild(sugBody);
        right.appendChild(sugCard);

        var apprCard = el('div', 'resp-card');
        apprCard.appendChild(el('h3', null, '待人工审批（高危动作）'));
        var apprBody = el('div', 'resp-list');
        apprCard.appendChild(apprBody);
        right.appendChild(apprCard);

        // 封禁中（含到期自动解封）
        var blocksCard = el('div', 'resp-card');
        blocksCard.appendChild(el('h3', null, '封禁中（到期自动解封）'));
        var blocksBody = el('div', 'resp-list');
        blocksCard.appendChild(blocksBody);
        right.appendChild(blocksCard);

        // 审计卡片（放左列）
        var auditCard = el('div', 'resp-card');
        auditCard.appendChild(el('h3', null, '处置审计留痕'));
        var filterBar = el('div', 'resp-filter');
        var actSel = document.createElement('select');
        actSel.appendChild(new Option('全部动作', ''));
        ['block-ip', 'unblock-ip', 'lock-account', 'kill-process', 'approve', 'reject', 'policy-update'].forEach(function (a) {
            actSel.appendChild(new Option(a, a));
        });
        var succSel = document.createElement('select');
        succSel.appendChild(new Option('全部结果', ''));
        succSel.appendChild(new Option('成功', 'true'));
        succSel.appendChild(new Option('失败/拦截', 'false'));
        var refreshBtn = el('button', 'resp-btn ghost', '刷新');
        filterBar.appendChild(actSel);
        filterBar.appendChild(succSel);
        filterBar.appendChild(refreshBtn);
        auditCard.appendChild(filterBar);

        var auditWrap = el('div');
        auditCard.appendChild(auditWrap);
        // 审计表占整行宽度，避免窄列挤压长文本
        root.appendChild(auditCard);

        // ---- 策略面板 ----
        var policyState = {};
        function buildPolicyRow(label, hint, key) {
            var row = el('div', 'policy-row');
            var leftDiv = el('div');
            leftDiv.appendChild(el('div', 'pl-label', label));
            if (hint) leftDiv.appendChild(el('div', 'pl-hint', hint));
            var sw = el('label', 'switch');
            var input = document.createElement('input');
            input.type = 'checkbox';
            input.addEventListener('change', function () {
                var body = {};
                body[key] = input.checked;
                UI.put('/response/policy', body).then(function () {
                    UI.toast('策略已更新：' + label + (input.checked ? ' 开启' : ' 关闭'), 'success');
                }).catch(function (e) { UI.toast(e.message, 'error'); input.checked = !input.checked; });
            });
            var slider = el('span', 'slider');
            sw.appendChild(input);
            sw.appendChild(slider);
            row.appendChild(leftDiv);
            row.appendChild(sw);
            policyBody.appendChild(row);
            return input;
        }
        var iBlock = buildPolicyRow('封 IP', '默认开启；白名单/私网/环回由护栏保护', 'autoBlockEnabled');
        var iLock = buildPolicyRow('锁账号', '高危，默认关闭，需人工确认', 'autoLockAccount');
        var iKill = buildPolicyRow('杀进程', '高危，默认关闭，需人工确认', 'autoKillProcess');
        var iApproval = buildPolicyRow('高危强制人工确认门', '开启后高危动作必须审批才执行', 'highRiskRequireApproval');

        // ---- 封 IP 弹窗 ----
        function openBlockDialog(suggestedIp) {
            var mask = el('div', 'resp-modal-mask');
            var modal = el('div', 'resp-modal');
            modal.appendChild(el('h3', null, '封禁来源 IP'));
            var warn = el('div', 'm-warn', '封 IP 前会经过护栏校验：环回/私网/白名单/非法地址将被自动拦截。');
            modal.appendChild(warn);

            var ipField = el('div', 'm-field');
            ipField.appendChild(el('label', null, '来源 IP'));
            var ipInput = document.createElement('input');
            ipInput.placeholder = '如 203.0.113.24';
            if (suggestedIp) ipInput.value = suggestedIp;
            ipField.appendChild(ipInput);

            var durField = el('div', 'm-field');
            durField.appendChild(el('label', null, '封禁时长（分钟，>120 视为高危需审批）'));
            var durInput = document.createElement('input');
            durInput.type = 'number';
            durInput.value = '60';
            durField.appendChild(durInput);

            var reasonField = el('div', 'm-field');
            reasonField.appendChild(el('label', null, '处置原因'));
            var reasonInput = document.createElement('input');
            reasonInput.placeholder = '如 SSH 暴力破解';
            reasonField.appendChild(reasonInput);

            modal.appendChild(ipField);
            modal.appendChild(durField);
            modal.appendChild(reasonField);

            var actions = el('div', 'm-actions');
            var cancel = el('button', 'resp-btn ghost', '取消');
            var okBtn = el('button', 'resp-btn ok', '执行封禁');
            actions.appendChild(cancel);
            actions.appendChild(okBtn);
            modal.appendChild(actions);
            mask.appendChild(modal);
            document.body.appendChild(mask);

            function close() { mask.remove(); }
            cancel.addEventListener('click', close);
            mask.addEventListener('click', function (e) { if (e.target === mask) close(); });

            okBtn.addEventListener('click', function () {
                var body = { ip: ipInput.value.trim(), durationMinutes: parseInt(durInput.value, 10), reason: reasonInput.value.trim() };
                UI.post('/response/block', body).then(function (resp) {
                    var d = resp.data || {};
                    var r = d.result;
                    if (d.needApproval) {
                        UI.toast('该封禁为高危，已转入待审批队列', 'info');
                    } else if (r && r.mode === 'BLOCKED') {
                        UI.toast('护栏拦截：' + r.message, 'error');
                    } else if (r && r.success) {
                        UI.toast('已封禁：' + r.message, 'success');
                    } else {
                        UI.toast('执行失败：' + (r ? r.message : ''), 'error');
                    }
                    close();
                    refreshAll();
                }).catch(function (e) { UI.toast(e.message, 'error'); });
            });
        }

        function openConfirmDialog(title, text, onOk, okText) {
            var mask = el('div', 'resp-modal-mask');
            var modal = el('div', 'resp-modal');
            modal.appendChild(el('h3', null, title));
            modal.appendChild(el('div', 'm-warn', text));
            var actions = el('div', 'm-actions');
            var cancel = el('button', 'resp-btn ghost', '取消');
            var ok = el('button', 'resp-btn danger', okText || '确认');
            actions.appendChild(cancel);
            actions.appendChild(ok);
            modal.appendChild(actions);
            mask.appendChild(modal);
            document.body.appendChild(mask);
            function close() { mask.remove(); }
            cancel.addEventListener('click', close);
            mask.addEventListener('click', function (e) { if (e.target === mask) close(); });
            ok.addEventListener('click', function () { close(); onOk(); });
        }

        // ---- 建议列表 ----
        function renderSuggestions(data) {
            sugBody.textContent = '';
            var items = (data && data.items) || [];
            modeBadge.textContent = '执行模式：' + (data && data.mode === 'REAL' ? 'REAL 已连 Wazuh' : 'MOCK 模拟');
            if (!items.length) { emptyBox(sugBody, '暂无告警建议'); return; }
            items.forEach(function (s) {
                var row = el('div', 'resp-item');
                row.appendChild(tagFor(s.riskLevel));
                var main = el('div', 'ri-main');
                main.appendChild(el('div', 'ri-title', (s.ruleName || '') + ' · ' + (s.target || '')));
                main.appendChild(el('div', 'ri-sub', s.reason || ''));
                row.appendChild(main);

                var btn = el('button', 'resp-btn', '处置');
                btn.addEventListener('click', function () {
                    if (s.recommendAction === 'block-ip') {
                        openBlockDialog(s.target);
                    } else if (s.recommendAction === 'lock-account') {
                        openConfirmDialog('锁定账号', '即将锁定账号 ' + s.target + '（高危动作，需人工确认），确认？', function () {
                            UI.post('/response/lock', { account: s.target, reason: s.reason }).then(function (resp) {
                                var d = resp.data || {};
                                if (d.needApproval) UI.toast('已转待审批', 'info');
                                else if (d.result && !d.result.success) UI.toast('被拦截：' + d.result.message, 'error');
                                else UI.toast('已执行：' + (d.result && d.result.message), 'success');
                                refreshAll();
                            }).catch(function (e) { UI.toast(e.message, 'error'); });
                        }, '提交审批');
                    } else if (s.recommendAction === 'kill-process') {
                        openConfirmDialog('结束进程', '即将结束进程 ' + s.target + '（高危动作，需人工确认），确认？', function () {
                            UI.post('/response/kill', { pid: /^\d+$/.test(s.target) ? s.target : '', process: /^\d+$/.test(s.target) ? '' : s.target, reason: s.reason }).then(function (resp) {
                                var d = resp.data || {};
                                if (d.needApproval) UI.toast('已转待审批', 'info');
                                else if (d.result && !d.result.success) UI.toast('被拦截：' + d.result.message, 'error');
                                else UI.toast('已执行：' + (d.result && d.result.message), 'success');
                                refreshAll();
                            }).catch(function (e) { UI.toast(e.message, 'error'); });
                        }, '提交审批');
                    }
                });
                row.appendChild(btn);
                sugBody.appendChild(row);
            });
        }

        // ---- 待审批 ----
        function renderApprovals(list) {
            apprBody.textContent = '';
            if (!list || !list.length) { emptyBox(apprBody, '暂无待审批的高危动作'); return; }
            list.forEach(function (o) {
                var row = el('div', 'resp-item');
                row.appendChild(tagFor(o.riskLevel));
                var main = el('div', 'ri-main');
                main.appendChild(el('div', 'ri-title', o.action + ' → ' + (o.target || '')));
                main.appendChild(el('div', 'ri-sub', (o.reason || '') + '  ·  提交人 ' + (o.requestedBy || '') + '  ·  ' + (o.createdAt || '')));
                row.appendChild(main);
                var ok = el('button', 'resp-btn ok', '批准');
                ok.addEventListener('click', function () {
                    openConfirmDialog('批准处置', '批准后将真正执行：' + o.action + ' → ' + o.target, function () {
                        UI.post('/response/approve/' + o.id, {}).then(function (resp) {
                            var d = resp.data || {};
                            if (d.success) UI.toast('已批准并执行', 'success');
                            else UI.toast(d.message || '处理失败', 'error');
                            refreshAll();
                        }).catch(function (e) { UI.toast(e.message, 'error'); });
                    }, '批准并执行');
                });
                var rej = el('button', 'resp-btn danger', '驳回');
                rej.addEventListener('click', function () {
                    openConfirmDialog('驳回处置', '驳回后不执行：' + o.action + ' → ' + o.target, function () {
                        UI.post('/response/reject/' + o.id, {}).then(function (resp) {
                            var d = resp.data || {};
                            UI.toast(d.success ? '已驳回' : (d.message || '处理失败'), d.success ? 'info' : 'error');
                            refreshAll();
                        }).catch(function (e) { UI.toast(e.message, 'error'); });
                    }, '确认驳回');
                });
                row.appendChild(ok);
                row.appendChild(rej);
                apprBody.appendChild(row);
            });
        }

        // ---- 封禁中（到期自动解封） ----
        function renderBlocks(data) {
            blocksBody.textContent = '';
            var items = (data && data.items) || [];
            if (!items.length) { emptyBox(blocksBody, '暂无生效中的封禁记录'); return; }
            items.forEach(function (b) {
                var row = el('div', 'resp-item');
                var active = !b.unblocked;
                row.appendChild(el('span', 'tag ' + (active ? 'tag-high' : 'tag-low'), active ? '封禁中' : '已解封'));
                var main = el('div', 'ri-main');
                main.appendChild(el('div', 'ri-title', (b.ip || '') + '  ·  ' + (b.durationMinutes == null ? '' : b.durationMinutes) + ' 分钟'));
                var sub = '到期 ' + (b.expiresAt || '-') + '  ·  来源 ' + (b.source || '-') + '  ·  操作人 ' + (b.actor || '-');
                main.appendChild(el('div', 'ri-sub', sub));
                row.appendChild(main);
                if (active) {
                    var left = Number(b.remainingMinutes);
                    row.appendChild(el('span', 'block-cd', (isNaN(left) || left <= 0) ? '已到期待解封' : '距到期 ' + left + ' 分钟'));
                } else {
                    row.appendChild(el('span', 'block-unblocked-at', '解封 ' + (b.unblockedAt || '-')));
                }
                blocksBody.appendChild(row);
            });
        }

        // ---- 审计表 ----
        function renderAudit(list) {
            auditWrap.textContent = '';
            if (!list || !list.length) { emptyBox(auditWrap, '暂无审计记录'); return; }
            var table = el('table', 'resp-table');
            var thead = document.createElement('thead');
            var htr = document.createElement('tr');
            ['时间', '动作', '目标', '操作人', '风险', '模式', '结果', '原因/明细'].forEach(function (h) {
                var th = el('th', null, h);
                htr.appendChild(th);
            });
            thead.appendChild(htr);
            table.appendChild(thead);
            var tbody = document.createElement('tbody');
            list.forEach(function (r) {
                var tr = document.createElement('tr');
                [r.time, r.action, r.target, r.actor, r.riskLevel, r.mode,
                    (r.success ? '成功' : (r.mode === 'BLOCKED' ? '拦截/驳回' : '失败')),
                    (r.reason || '') + (r.detail ? '｜' + r.detail : '')].forEach(function (v, idx) {
                    var td = el('td', idx === 2 || idx === 0 ? 'mono' : null, v == null ? '' : String(v));
                    tr.appendChild(td);
                });
                tbody.appendChild(tr);
            });
            table.appendChild(tbody);
            auditWrap.appendChild(table);
        }

        // ---- 刷新 ----
        function refreshPolicy() {
            UI.get('/response/policy').then(function (resp) {
                var p = resp.data || {};
                policyState = p;
                iBlock.checked = !!p.autoBlockEnabled;
                iLock.checked = !!p.autoLockAccount;
                iKill.checked = !!p.autoKillProcess;
                iApproval.checked = !!p.highRiskRequireApproval;
            }).catch(function () {});
        }
        function refreshSuggestions() { UI.get('/response/suggestions').then(function (r) { renderSuggestions(r.data); }).catch(function () {}); }
        function refreshApprovals() { UI.get('/response/approvals').then(function (r) { renderApprovals(r.data); }).catch(function () {}); }
        function refreshBlocks() { UI.get('/response/blocks').then(function (r) { renderBlocks(r.data); }).catch(function () {}); }
        function refreshAudit() {
            var q = '/response/audit?action=' + encodeURIComponent(actSel.value) + '&success=' + encodeURIComponent(succSel.value);
            UI.get(q).then(function (r) { renderAudit(r.data); }).catch(function () {});
        }
        function refreshAll() { refreshPolicy(); refreshSuggestions(); refreshApprovals(); refreshBlocks(); refreshAudit(); }

        actSel.addEventListener('change', refreshAudit);
        succSel.addEventListener('change', refreshAudit);
        refreshBtn.addEventListener('click', refreshAudit);

        refreshAll();
    });
})();
