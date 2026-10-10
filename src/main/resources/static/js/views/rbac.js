/**
 * 用户权限（RBAC 可视化与管理，仅管理员）。
 * 列用户、新增用户、展示权限矩阵。后端 RBAC 已由 RbacInterceptor 真实生效，本页用于可视化与管理。
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

    UI.registerView('rbac', function (container) {
        container.textContent = '';
        var root = el('div');
        container.appendChild(root);

        var header = el('div', 'rbac-header');
        header.appendChild(el('h2', null, '用户权限管理'));
        root.appendChild(header);

        var grid = el('div', 'rbac-grid');
        root.appendChild(grid);

        // 左列：新增用户
        var left = el('div');
        grid.appendChild(left);
        var addCard = el('div', 'rbac-card');
        addCard.appendChild(el('h3', null, '新增用户'));
        var userField = el('div', 'rbac-field');
        userField.appendChild(el('label', null, '用户名'));
        var userInput = document.createElement('input');
        userInput.placeholder = '如 soc-analyst-01';
        userField.appendChild(userInput);
        var passField = el('div', 'rbac-field');
        passField.appendChild(el('label', null, '密码（至少 8 位）'));
        var passInput = document.createElement('input');
        passInput.type = 'password';
        passInput.placeholder = '至少 8 位';
        passField.appendChild(passInput);
        var roleField = el('div', 'rbac-field');
        roleField.appendChild(el('label', null, '角色'));
        var roleSel = document.createElement('select');
        roleSel.appendChild(new Option('分析员 ANALYST（仅查看/研判/提交知识）', 'ANALYST'));
        roleSel.appendChild(new Option('管理员 ADMIN（可处置/审核/用户管理）', 'ADMIN'));
        roleField.appendChild(roleSel);
        addCard.appendChild(userField);
        addCard.appendChild(passField);
        addCard.appendChild(roleField);
        var addBtn = el('button', 'rbac-btn', '创建用户');
        addCard.appendChild(addBtn);
        left.appendChild(addCard);

        // 用户列表
        var listCard = el('div', 'rbac-card');
        listCard.appendChild(el('h3', null, '用户列表'));
        var listWrap = el('div');
        listCard.appendChild(listWrap);
        left.appendChild(listCard);

        // 右列：权限矩阵
        var right = el('div');
        grid.appendChild(right);
        var matrixCard = el('div', 'rbac-card');
        matrixCard.appendChild(el('h3', null, '权限矩阵'));
        var matrixWrap = el('div');
        matrixCard.appendChild(matrixWrap);
        matrixCard.appendChild(el('div', 'rbac-note', '后端 RbacInterceptor 已强制：执行处置、审核知识、用户管理仅管理员；分析员请求这些接口会返回 403。'));
        right.appendChild(matrixCard);

        function renderUsers(list) {
            listWrap.textContent = '';
            if (!list || !list.length) { listWrap.appendChild(el('div', null, '暂无用户')); return; }
            var table = el('table', 'rbac-table');
            var thead = document.createElement('thead');
            var htr = document.createElement('tr');
            ['用户名', '角色'].forEach(function (h) { htr.appendChild(el('th', null, h)); });
            thead.appendChild(htr);
            table.appendChild(thead);
            var tbody = document.createElement('tbody');
            list.forEach(function (u) {
                var tr = document.createElement('tr');
                tr.appendChild(el('td', null, u.username));
                var td = document.createElement('td');
                var badge = el('span', 'role-badge ' + (u.role === 'ADMIN' ? 'role-admin' : 'role-analyst'),
                        u.roleLabel || u.role);
                td.appendChild(badge);
                tr.appendChild(td);
                tbody.appendChild(tr);
            });
            table.appendChild(tbody);
            listWrap.appendChild(table);
        }

        function renderMatrix() {
            matrixWrap.textContent = '';
            var rows = [
                ['查看告警 / 日志 / 事件', true, true],
                ['对话研判', true, true],
                ['提交知识（候选）', true, true],
                ['执行处置（封IP/锁账号/杀进程）', false, true],
                ['审批高危处置 / 审核知识', false, true],
                ['用户管理', false, true]
            ];
            var table = el('table', 'rbac-table');
            var thead = document.createElement('thead');
            var htr = document.createElement('tr');
            ['功能权限', '分析员 ANALYST', '管理员 ADMIN'].forEach(function (h) { htr.appendChild(el('th', null, h)); });
            thead.appendChild(htr);
            table.appendChild(thead);
            var tbody = document.createElement('tbody');
            rows.forEach(function (r) {
                var tr = document.createElement('tr');
                tr.appendChild(el('td', null, r[0]));
                [r[1], r[2]].forEach(function (yes) {
                    var td = document.createElement('td');
                    td.appendChild(el('span', yes ? 'perm-yes' : 'perm-no', yes ? '✓ 允许' : '✕ 禁止'));
                    tr.appendChild(td);
                });
                tbody.appendChild(tr);
            });
            table.appendChild(tbody);
            matrixWrap.appendChild(table);
        }

        function refresh() {
            UI.get('/auth/users').then(function (r) { renderUsers(r.data); }).catch(function (e) { UI.toast(e.message, 'error'); });
            renderMatrix();
        }

        addBtn.addEventListener('click', function () {
            var body = { username: userInput.value.trim(), password: passInput.value, role: roleSel.value };
            if (!body.username || !body.password) { UI.toast('用户名和密码不能为空', 'error'); return; }
            UI.post('/auth/users', body).then(function () {
                UI.toast('用户创建成功', 'success');
                userInput.value = ''; passInput.value = '';
                refresh();
            }).catch(function (e) { UI.toast(e.message, 'error'); });
        });

        refresh();
    });
})();
