/**
 * SecAgent 前端公共层（无框架原生 JS）。
 * 职责：统一 API 调用（自动带登录 Token）、顶部导航路由、角色菜单可见性、各功能视图注册、通用提示。
 * 各功能页面（告警大屏/处置中心/知识库/事件归档/红队评测/用户权限）通过 SecUI.registerView 注册，
 * 只在自己的容器里渲染，互不干扰。
 */
(function () {
    'use strict';

    // 随当前页面来源，便于在不同端口起服务做并行实测；默认本地 9900
    var API_BASE = ((typeof window !== 'undefined' && window.location && window.location.origin)
        ? window.location.origin : 'http://localhost:9900') + '/api';

    var SecUI = {
        token: localStorage.getItem('secagent_token'),
        username: null,
        role: null,          // 'ADMIN' / 'ANALYST'
        booted: false,
        currentView: 'chat',
        _views: {},          // name -> { mount: fn, mounted: bool, refresh: fn }
        charts: []           // 已创建的 Chart 实例，切换时可销毁
    };

    // ---------- 通用工具 ----------

    SecUI.escapeHtml = function (s) {
        if (s === null || s === undefined) return '';
        return String(s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    };

    SecUI.toast = function (msg, type) {
        var box = document.getElementById('toastBox');
        if (!box) {
            box = document.createElement('div');
            box.id = 'toastBox';
            box.className = 'toast-box';
            document.body.appendChild(box);
        }
        var t = document.createElement('div');
        t.className = 'toast-item toast-' + (type || 'info');
        t.textContent = msg;
        box.appendChild(t);
        setTimeout(function () {
            t.classList.add('toast-fade');
            setTimeout(function () { t.remove(); }, 300);
        }, 2600);
    };

    SecUI.headers = function (extra) {
        var h = Object.assign({ 'Content-Type': 'application/json' }, extra || {});
        if (SecUI.token) h['Authorization'] = 'Bearer ' + SecUI.token;
        return h;
    };

    /**
     * 统一请求。返回解析后的 JSON；HTTP 非 2xx 或业务 code 非 200 时抛 Error(后端 message)。
     */
    SecUI.request = function (method, path, body) {
        var opt = { method: method, headers: SecUI.headers() };
        if (body !== undefined && body !== null) opt.body = JSON.stringify(body);
        return fetch(API_BASE + path, opt).then(function (res) {
            if (res.status === 401) { SecUI.handleLogout(); throw new Error('登录已失效，请重新登录'); }
            return res.json().then(function (json) {
                if (res.status >= 400 || (json.code !== undefined && json.code !== 200)) {
                    var msg = json.message || ('请求失败(' + res.status + ')');
                    var err = new Error(msg);
                    err.status = res.status;
                    throw err;
                }
                return json;
            });
        });
    };

    SecUI.get = function (path) { return SecUI.request('GET', path); };
    SecUI.post = function (path, body) { return SecUI.request('POST', path, body || {}); };
    SecUI.put = function (path, body) { return SecUI.request('PUT', path, body || {}); };

    /** 直接下载（用于导出 PDF），携带登录 Token */
    SecUI.download = function (path, filename) {
        return fetch(API_BASE + path, { headers: { 'Authorization': 'Bearer ' + SecUI.token } })
            .then(function (res) {
                if (!res.ok) throw new Error('导出失败(' + res.status + ')');
                return res.blob();
            }).then(function (blob) {
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                a.remove();
                setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
            });
    };

    SecUI.isAdmin = function () { return SecUI.role === 'ADMIN'; };

    // ---------- 视图注册与路由 ----------

    /**
     * 注册一个功能视图。
     * @param name 视图名（与导航 data-view、容器 id 对应）
     * @param mountFn 首次打开时调用，参数为容器元素，可在此构建 DOM、绑定事件、启动轮询
     * @param refreshFn 可选，每次切换到该视图时刷新数据
     */
    SecUI.registerView = function (name, mountFn, refreshFn) {
        SecUI._views[name] = { mount: mountFn, mounted: false, refresh: refreshFn };
    };

    SecUI.showView = function (name) {
        // 切换前销毁其它视图的 Chart，避免画布叠加
        SecUI.charts.forEach(function (c) { try { c.destroy(); } catch (e) {} });
        SecUI.charts = [];

        document.querySelectorAll('.topnav-item').forEach(function (b) {
            b.classList.toggle('active', b.getAttribute('data-view') === name);
        });
        document.querySelectorAll('.view').forEach(function (v) {
            v.classList.toggle('active', v.id === 'view-' + name);
        });
        SecUI.currentView = name;

        var v = SecUI._views[name];
        if (v) {
            if (!v.mounted) { v.mounted = true; v.mount(document.getElementById('view-' + name)); }
            if (typeof v.refresh === 'function') { v.refresh(); }
        }
    };

    // ---------- 登录态衔接 ----------

    SecUI.handleLogout = function () {
        try { localStorage.removeItem('secagent_token'); } catch (e) {}
        location.reload();
    };

    function applyRole() {
        // 管理员专属菜单
        document.querySelectorAll('.topnav-item[data-role="ADMIN"]').forEach(function (b) {
            b.style.display = SecUI.isAdmin() ? '' : 'none';
        });
        var u = document.getElementById('topnavUser');
        if (u) u.textContent = (SecUI.username || '') + '（' +
            (SecUI.role === 'ADMIN' ? '管理员' : '分析员') + '）';
    }

    function bootstrap() {
        if (SecUI.booted) { applyRole(); return; }
        SecUI.token = localStorage.getItem('secagent_token');
        if (!SecUI.token) return;
        fetch(API_BASE + '/auth/check', { headers: { 'Authorization': 'Bearer ' + SecUI.token } })
            .then(function (res) { return res.ok ? res.json() : null; })
            .then(function (json) {
                if (json && json.data) {
                    SecUI.booted = true;
                    SecUI.username = json.data.username;
                    SecUI.role = json.data.role;
                    applyRole();
                }
            })
            .catch(function () {});
    }

    document.addEventListener('DOMContentLoaded', function () {
        // 导航点击
        document.querySelectorAll('.topnav-item').forEach(function (b) {
            b.addEventListener('click', function () {
                var need = b.getAttribute('data-role');
                if (need === 'ADMIN' && !SecUI.isAdmin()) {
                    SecUI.toast('该功能仅管理员可用', 'error');
                    return;
                }
                SecUI.showView(b.getAttribute('data-view'));
            });
        });

        var logoutBtn = document.getElementById('topnavLogout');
        if (logoutBtn) logoutBtn.addEventListener('click', function () {
            fetch(API_BASE + '/auth/logout', { method: 'POST', headers: SecUI.headers() }).catch(function () {});
            SecUI.handleLogout();
        });

        // 观察封面：app.js 登录成功后会给 cover 加 cover-hidden
        var cover = document.getElementById('cover');
        if (cover) {
            var obs = new MutationObserver(function () {
                if (cover.classList.contains('cover-hidden') || cover.style.display === 'none') {
                    bootstrap();
                }
            });
            obs.observe(cover, { attributes: true, attributeFilter: ['class', 'style'] });
            // 已登录自动进入的情况
            if (cover.classList.contains('cover-hidden') || cover.style.display === 'none') bootstrap();
        }
        bootstrap();
    });

    window.SecUI = SecUI;
})();
