/**
 * 告警大屏视图（验收项8）。
 * 顶部 KPI 卡片 + 四张 Chart.js 图表（等级环图/类型柱图/来源占比/时间趋势折线）
 * + 告警滚动列表 + 点行弹详情弹窗（日志原文/取证日志）。
 *
 * 安全红线：所有来自后端/攻击者的文本一律通过 textContent 写入，绝不 innerHTML 拼用户数据。
 * 每 5 秒轮询一次；图表实例推入 SecUI.charts，切视图时由 common.js 统一销毁。
 */
(function () {
    'use strict';

    // 等级配色（与后端 AlertSeverity 枚举一一对应）
    var SEV_COLORS = {
        CRITICAL: '#ff4d4f',
        HIGH: '#fa8c16',
        MEDIUM: '#1677ff',
        LOW: '#52c41a',
        INFO: '#8c8c8c'
    };
    var SRC_COLORS = {
        WAZUH: '#1677ff',
        SURICATA: '#52c41a',
        BUILTIN: '#8c8c8c'
    };

    var charts = {};      // canvasId -> Chart 实例
    var timer = null;

    // ---------- 小工具：安全地创建 DOM ----------
    function el(tag, className, text) {
        var n = document.createElement(tag);
        if (className) n.className = className;
        if (text !== undefined && text !== null) n.textContent = String(text);
        return n;
    }

    function splitKey(k) {
        // 后端 key 形如 "CRITICAL|严重"
        var i = k.indexOf('|');
        return i < 0 ? { code: k, label: k } : { code: k.substring(0, i), label: k.substring(i + 1) };
    }

    // ---------- 首次挂载：搭静态骨架 ----------
    function mount(container) {
        container.innerHTML = '';

        // 顶部标题 + 数据源状态
        var header = el('div', 'alerts-header');
        var titleBox = el('div', 'alerts-title-box');
        titleBox.appendChild(el('h2', 'alerts-title', '安全告警大屏'));
        var modeBox = el('div', 'alerts-modes');
        modeBox.appendChild(buildModeBadge('wazuhModeBadge', 'Wazuh'));
        modeBox.appendChild(buildModeBadge('suricataModeBadge', 'Suricata'));
        titleBox.appendChild(modeBox);
        header.appendChild(titleBox);

        var refreshInfo = el('div', 'alerts-refresh', '每 5 秒自动刷新中…');
        refreshInfo.id = 'alertsRefreshInfo';
        header.appendChild(refreshInfo);
        container.appendChild(header);

        // KPI 卡片
        var kpis = el('div', 'alerts-kpis');
        kpis.appendChild(buildKpi('kpiTotal', '告警总数', '--', 'kpi-total'));
        kpis.appendChild(buildKpi('kpiCritical', '严重', '--', 'kpi-critical'));
        kpis.appendChild(buildKpi('kpiHigh', '高危', '--', 'kpi-high'));
        kpis.appendChild(buildKpi('kpiActive', '活跃告警', '--', 'kpi-active'));
        kpis.appendChild(buildKpi('kpiAggregated', '聚合告警', '--', 'kpi-agg'));
        container.appendChild(kpis);

        // 图表区
        var grid = el('div', 'alerts-charts-grid');
        grid.appendChild(buildChartCard('等级分布', 'chartSeverity'));
        grid.appendChild(buildChartCard('攻击类型分布', 'chartType'));
        grid.appendChild(buildChartCard('来源占比', 'chartSource'));
        grid.appendChild(buildChartCard('最近24小时趋势', 'chartTrend'));
        container.appendChild(grid);

        // 告警列表
        var listCard = el('div', 'alerts-list-card');
        var listHead = el('div', 'alerts-list-head');
        listHead.appendChild(el('h3', 'alerts-list-title', '实时告警列表（点击行查看详情）'));
        listHead.appendChild(el('span', 'alerts-list-count', ''));
        listHead.lastChild.id = 'alertsListCount';
        listCard.appendChild(listHead);

        var wrap = el('div', 'alerts-table-wrap');
        var table = document.createElement('table');
        table.className = 'alerts-table';
        var thead = document.createElement('thead');
        var trh = document.createElement('tr');
        ['等级', '规则/标题', '来源IP', '受影响资产', '发生时间', '来源'].forEach(function (h) {
            trh.appendChild(el('th', '', h));
        });
        thead.appendChild(trh);
        table.appendChild(thead);
        var tbody = document.createElement('tbody');
        tbody.id = 'alertsTbody';
        table.appendChild(tbody);
        wrap.appendChild(table);
        listCard.appendChild(wrap);
        container.appendChild(listCard);

        // 详情弹窗
        container.appendChild(buildModal());
        // 聚合下钻弹窗
        container.appendChild(buildDrillModal());

        // 启动轮询
        load();
        if (timer) clearInterval(timer);
        timer = setInterval(load, 5000);
    }

    function buildModeBadge(id, name) {
        var b = el('span', 'mode-badge mode-unknown', name + '：--');
        b.id = id;
        return b;
    }

    function buildKpi(id, label, value, extraClass) {
        var card = el('div', 'kpi-card ' + extraClass);
        card.appendChild(el('div', 'kpi-label', label));
        var v = el('div', 'kpi-value', value);
        v.id = id;
        card.appendChild(v);
        return card;
    }

    function buildChartCard(title, canvasId) {
        var card = el('div', 'chart-card');
        card.appendChild(el('h3', 'chart-card-title', title));
        var box = el('div', 'chart-box');
        var cv = document.createElement('canvas');
        cv.id = canvasId;
        box.appendChild(cv);
        card.appendChild(box);
        return card;
    }

    function buildModal() {
        var mask = el('div', 'alerts-modal-mask');
        mask.id = 'alertsModalMask';
        mask.style.display = 'none';

        var dialog = el('div', 'alerts-modal');
        var head = el('div', 'alerts-modal-head');
        var title = el('h3', 'alerts-modal-title', '告警详情');
        title.id = 'alertsModalTitle';
        var close = el('button', 'alerts-modal-close', '×');
        close.addEventListener('click', function () { mask.style.display = 'none'; });
        head.appendChild(title);
        head.appendChild(close);
        dialog.appendChild(head);

        var meta = el('div', 'alerts-modal-meta');
        meta.id = 'alertsModalMeta';
        dialog.appendChild(meta);

        dialog.appendChild(el('div', 'alerts-modal-section-title', '日志原文'));
        var raw = el('pre', 'alerts-raw');
        raw.id = 'alertsModalRaw';
        dialog.appendChild(raw);

        dialog.appendChild(el('div', 'alerts-modal-section-title', '关联取证日志'));
        var forensic = el('div', 'alerts-forensic');
        forensic.id = 'alertsModalForensic';
        dialog.appendChild(forensic);

        mask.appendChild(dialog);
        mask.addEventListener('click', function (e) {
            if (e.target === mask) mask.style.display = 'none';
        });
        return mask;
    }

    // ---------- 拉数据 ----------
    function load() {
        SecUI.get('/alerts/stats').then(function (json) {
            if (json && json.data) renderStats(json.data);
            return SecUI.get('/alerts/list?limit=80');
        }).then(function (json) {
            if (json && json.data) renderList(json.data);
            var info = document.getElementById('alertsRefreshInfo');
            if (info) info.textContent = '已刷新 ' + new Date().toLocaleTimeString();
        }).catch(function (err) {
            var info = document.getElementById('alertsRefreshInfo');
            if (info) info.textContent = '刷新失败：' + err.message;
        });
    }

    // ---------- 渲染 KPI + 图表 ----------
    function renderStats(d) {
        setText('kpiTotal', d.total);
        setText('kpiCritical', d.critical);
        setText('kpiHigh', d.high);
        setText('kpiActive', d.active);

        setModeBadge('wazuhModeBadge', 'Wazuh', d.wazuhMode);
        setModeBadge('suricataModeBadge', 'Suricata', d.suricataMode);

        renderDoughnut('chartSeverity', d.bySeverity, function (key) {
            return SEV_COLORS[splitKey(key).code] || '#8c8c8c';
        });
        renderBar('chartType', d.byType);
        renderDoughnut('chartSource', d.bySource, function (key) {
            return SRC_COLORS[splitKey(key).code] || '#8c8c8c';
        });
        renderLine('chartTrend', d.trend);
    }

    function setText(id, v) {
        var n = document.getElementById(id);
        if (n) n.textContent = (v === undefined || v === null) ? '--' : String(v);
    }

    function setModeBadge(id, name, mode) {
        var b = document.getElementById(id);
        if (!b) return;
        var m = mode || '--';
        b.textContent = name + '：' + m;
        b.className = 'mode-badge ' + (m === 'REAL' ? 'mode-real'
            : m === 'MOCK' ? 'mode-mock' : 'mode-off');
    }

    // 通用：从/销毁并重建/复用 图表
    function getChart(canvasId, config) {
        var existing = charts[canvasId];
        if (existing && !existing.destroyed) {
            existing.data = config.data;
            existing.options = config.options;
            existing.update();
            return existing;
        }
        var ctx = document.getElementById(canvasId);
        if (!ctx) return null;
        var c = new Chart(ctx.getContext('2d'), config);
        charts[canvasId] = c;
        // 交给 common.js，切视图时统一销毁
        if (window.SecUI && SecUI.charts) SecUI.charts.push(c);
        return c;
    }

    function renderDoughnut(canvasId, map, colorFn) {
        if (!map) return;
        var labels = [];
        var values = [];
        var colors = [];
        Object.keys(map).forEach(function (k) {
            labels.push(splitKey(k).label);
            values.push(map[k]);
            colors.push(colorFn(k));
        });
        getChart(canvasId, {
            type: 'doughnut',
            data: { labels: labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 2, borderColor: '#1b1f2a' }] },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { color: '#6b7785', boxWidth: 12 } } }
            }
        });
    }

    function renderBar(canvasId, map) {
        if (!map) return;
        var labels = [];
        var values = [];
        Object.keys(map).forEach(function (k) {
            labels.push(splitKey(k).label);
            values.push(map[k]);
        });
        getChart(canvasId, {
            type: 'bar',
            data: { labels: labels, datasets: [{ data: values, backgroundColor: '#1677ff', borderRadius: 4 }] },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#6b7785' }, grid: { color: 'rgba(255,255,255,0.06)' } },
                    y: { ticks: { color: '#6b7785', precision: 0 }, grid: { color: 'rgba(255,255,255,0.06)' }, beginAtZero: true }
                }
            }
        });
    }

    function renderLine(canvasId, map) {
        if (!map) return;
        var labels = Object.keys(map);
        var values = labels.map(function (k) { return map[k]; });
        getChart(canvasId, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    data: values, label: '告警数',
                    borderColor: '#52c41a', backgroundColor: 'rgba(82,196,26,0.15)',
                    fill: true, tension: 0.3, pointRadius: 2
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#6b7785' } } },
                scales: {
                    x: { ticks: { color: '#6b7785', maxTicksLimit: 12 }, grid: { color: 'rgba(255,255,255,0.06)' } },
                    y: { ticks: { color: '#6b7785', precision: 0 }, grid: { color: 'rgba(255,255,255,0.06)' }, beginAtZero: true }
                }
            }
        });
    }

    // ---------- 渲染告警列表（默认展示聚合后列表） ----------
    function renderList(d) {
        var tbody = document.getElementById('alertsTbody');
        if (!tbody) return;
        tbody.textContent = '';

        var list = d.list || [];
        var count = document.getElementById('alertsListCount');
        if (count) {
            // 聚合模式：显示"聚合后 X 条（原始 Y 条）"
            count.textContent = d.aggregated
                ? '聚合后 ' + (d.total || list.length) + ' 条（原始 ' + (d.rawTotal != null ? d.rawTotal : list.length) + ' 条）'
                : '共 ' + (d.total || list.length) + ' 条';
        }
        // 聚合告警数 KPI
        setText('kpiAggregated', d.aggregatedTotal != null ? d.aggregatedTotal : d.total);

        list.forEach(function (a) {
            var isAgg = a.aggregated === true;
            var tr = document.createElement('tr');
            if (isAgg && (a.count || 1) > 1) {
                tr.addEventListener('click', function () { openAggregated(a.aggId); });
            } else {
                // 单元素聚合 / 原始逐条：直接打开该条详情
                tr.addEventListener('click', function () { openDetail(a.id); });
            }

            // 等级标签
            var tdSev = el('td', '');
            tdSev.appendChild(el('span', 'sev-tag sev-' + (a.severity || 'MEDIUM').toLowerCase(),
                severityLabel(a.severity)));
            tr.appendChild(tdSev);

            // 规则/标题（聚合行带 ×N 徽标 + 时间窗）
            var tdTitle = el('td', 'alerts-td-title');
            var titleLine = el('div', 'alerts-title-line');
            titleLine.appendChild(el('span', 'alerts-rule-name', a.title || a.ruleName || '-'));
            if (isAgg && (a.count || 1) > 1) {
                var badge = el('span', 'agg-badge', '×' + a.count + ' 聚合');
                titleLine.appendChild(badge);
            }
            tdTitle.appendChild(titleLine);
            if (isAgg && a.startTime && a.endTime) {
                tdTitle.appendChild(el('div', 'alerts-rule-sub',
                    '时间窗 ' + a.startTime + ' ~ ' + a.endTime));
            } else if (a.ruleName && a.ruleName !== a.title) {
                tdTitle.appendChild(el('div', 'alerts-rule-sub', a.ruleName));
            }
            tr.appendChild(tdTitle);

            // 来源IP
            tr.appendChild(el('td', 'alerts-td-mono', a.srcIp || '-'));

            // 受影响资产（聚合行展示涉及资产集合摘要）
            var assetText;
            if (isAgg && Array.isArray(a.assets) && a.assets.length) {
                assetText = a.assets.length === 1
                    ? a.assets[0]
                    : a.assets[0] + ' 等 ' + a.assets.length + ' 个资产';
            } else {
                assetText = (a.dstAsset || '-') + (a.dstIp ? '（' + a.dstIp + '）' : '');
            }
            tr.appendChild(el('td', '', assetText));

            // 时间（聚合行展示最新活动时间）
            tr.appendChild(el('td', 'alerts-td-mono', a.occurredAt || '-'));

            // 来源徽标（聚合多源时合并展示）
            var tdSrc = el('td', '');
            if (isAgg && Array.isArray(a.sources) && a.sources.length > 1) {
                tdSrc.appendChild(el('span', 'src-badge src-builtin',
                    a.sources.map(sourceLabel).join(' + ')));
            } else {
                tdSrc.appendChild(el('span', 'src-badge src-' + String(a.source || 'BUILTIN').toLowerCase(),
                    sourceLabel(a.source)));
            }
            tr.appendChild(tdSrc);

            tbody.appendChild(tr);
        });

        if (list.length === 0) {
            var tr = document.createElement('tr');
            tr.appendChild(el('td', 'alerts-empty', '暂无告警数据'));
            tr.firstChild.colSpan = 6;
            tbody.appendChild(tr);
        }
    }

    function severityLabel(s) {
        if (!s) return '-';
        switch (s) {
            case 'CRITICAL': return '严重';
            case 'HIGH': return '高危';
            case 'MEDIUM': return '中危';
            case 'LOW': return '低危';
            case 'INFO': return '提示';
            default: return s;
        }
    }

    function sourceLabel(s) {
        if (!s) return '-';
        switch (s) {
            case 'WAZUH': return 'Wazuh';
            case 'SURICATA': return 'Suricata';
            case 'BUILTIN': return '内置';
            default: return s;
        }
    }

    // 后端 AlertType 枚举按名称序列化（字符串），这里映射成中文标签
    function typeLabel(t) {
        if (!t) return '-';
        var map = {
            BRUTE_FORCE: '暴力破解', SQL_INJECTION: 'SQL注入', XSS: '跨站脚本',
            COMMAND_INJECTION: '命令注入', FILE_UPLOAD: '文件上传', WEBSHELL: 'Webshell',
            SCAN: '扫描探测', C2: '恶意外联/C2', MALWARE: '恶意软件',
            PRIVILEGE_ESCALATION: '权限提升', ACCOUNT_ABUSE: '账号异常',
            DDOS: '拒绝服务', POLICY: '策略违规', OTHER: '其他'
        };
        return map[t] || t;
    }

    // ---------- 详情弹窗 ----------
    function openDetail(id) {
        SecUI.get('/alerts/' + encodeURIComponent(id)).then(function (json) {
            var d = json && json.data;
            if (!d || !d.alert) { SecUI.toast('未取到详情', 'error'); return; }
            var a = d.alert;

            setText('alertsModalTitle', a.title || a.ruleName || '告警详情');

            var meta = document.getElementById('alertsModalMeta');
            meta.textContent = '';
            var pairs = [
                ['等级', severityLabel(a.severity)],
                ['类型', typeLabel(a.type)],
                ['来源', sourceLabel(a.source)],
                ['来源IP', a.srcIp || '-'],
                ['来源地域', a.srcGeo || '-'],
                ['受影响资产', (a.dstAsset || '-') + (a.dstIp ? '（' + a.dstIp + '）' : '')],
                ['端口', a.dstPort != null ? String(a.dstPort) : '-'],
                ['服务', a.service || '-'],
                ['发生时间', a.occurredAt || '-'],
                ['命中次数', String(a.count != null ? a.count : 1)],
                ['状态', a.status || 'ACTIVE']
            ];
            pairs.forEach(function (p) {
                var item = el('div', 'meta-item');
                item.appendChild(el('span', 'meta-k', p[0]));
                item.appendChild(el('span', 'meta-v', p[1]));
                meta.appendChild(item);
            });

            var raw = document.getElementById('alertsModalRaw');
            raw.textContent = a.rawLog || '（无日志原文）';

            var forensic = document.getElementById('alertsModalForensic');
            forensic.textContent = '';
            var logs = d.forensicLogs || [];
            if (logs.length === 0) {
                forensic.appendChild(el('div', 'forensic-empty', '暂无关联取证日志'));
            } else {
                logs.forEach(function (l) {
                    var row = el('div', 'forensic-row');
                    row.appendChild(el('span', 'forensic-time', l.time || '-'));
                    row.appendChild(el('span', 'forensic-level', l.level || ''));
                    row.appendChild(el('span', 'forensic-msg', l.message || ''));
                    forensic.appendChild(row);
                });
            }

            document.getElementById('alertsModalMask').style.display = 'flex';
        }).catch(function (err) {
            SecUI.toast('打开详情失败：' + err.message, 'error');
        });
    }

    // ---------- 聚合下钻弹窗 ----------
    function buildDrillModal() {
        var mask = el('div', 'alerts-modal-mask');
        mask.id = 'drillMask';
        mask.style.display = 'none';

        var dialog = el('div', 'alerts-modal');
        var head = el('div', 'alerts-modal-head');
        var title = el('h3', 'alerts-modal-title', '聚合告警明细');
        title.id = 'drillTitle';
        var close = el('button', 'alerts-modal-close', '×');
        close.addEventListener('click', function () { mask.style.display = 'none'; });
        head.appendChild(title);
        head.appendChild(close);
        dialog.appendChild(head);

        var meta = el('div', 'alerts-modal-meta');
        meta.id = 'drillMeta';
        dialog.appendChild(meta);

        dialog.appendChild(el('div', 'alerts-modal-section-title',
            '原始明细（点击单条可看完整日志/取证）'));
        var list = el('div', 'drill-member-list');
        list.id = 'drillMemberList';
        dialog.appendChild(list);

        mask.appendChild(dialog);
        mask.addEventListener('click', function (e) {
            if (e.target === mask) mask.style.display = 'none';
        });
        return mask;
    }

    function openAggregated(aggId) {
        SecUI.get('/alerts/aggregated/' + encodeURIComponent(aggId)).then(function (json) {
            var d = json && json.data;
            if (!d || !d.aggregated) { SecUI.toast('未取到聚合明细', 'error'); return; }
            var g = d.aggregated;

            setText('drillTitle', '聚合告警明细（共 ' + (g.count || 0) + ' 条）');

            var meta = document.getElementById('drillMeta');
            meta.textContent = '';
            var assets = Array.isArray(g.assets) ? g.assets.join('、') : (g.dstAsset || '-');
            var pairs = [
                ['聚合数', String(g.count != null ? g.count : 1)],
                ['源 IP', g.srcIp || '-'],
                ['攻击类型', typeLabel(g.type)],
                ['时间窗起', g.startTime || '-'],
                ['时间窗止', g.endTime || '-'],
                ['涉及资产', assets],
                ['涉及来源', Array.isArray(g.sources) ? g.sources.map(sourceLabel).join(' + ') : sourceLabel(g.source)]
            ];
            pairs.forEach(function (p) {
                var item = el('div', 'meta-item');
                item.appendChild(el('span', 'meta-k', p[0]));
                item.appendChild(el('span', 'meta-v', p[1]));
                meta.appendChild(item);
            });

            var box = document.getElementById('drillMemberList');
            box.textContent = '';
            var members = d.members || [];
            if (members.length === 0) {
                box.appendChild(el('div', 'forensic-empty', '暂无原始明细'));
            } else {
                members.forEach(function (m) {
                    var row = el('div', 'drill-member-row');
                    row.appendChild(el('span', 'sev-tag sev-' + (m.severity || 'MEDIUM').toLowerCase(),
                        severityLabel(m.severity)));
                    var mid = el('div', 'drill-member-main');
                    var line1 = el('div', 'drill-member-title', m.title || m.ruleName || m.id);
                    mid.appendChild(line1);
                    mid.appendChild(el('div', 'drill-member-sub',
                        (m.srcIp || '-') + ' · ' + (m.occurredAt || '-') + ' · ' + sourceLabel(m.source)));
                    row.appendChild(mid);
                    row.appendChild(el('span', 'src-badge src-' + String(m.source || 'BUILTIN').toLowerCase(),
                        sourceLabel(m.source)));
                    row.style.cursor = 'pointer';
                    row.addEventListener('click', function () {
                        // 关闭下钻面板，再打开该条完整详情
                        document.getElementById('drillMask').style.display = 'none';
                        openDetail(m.id);
                    });
                    box.appendChild(row);
                });
            }

            document.getElementById('drillMask').style.display = 'flex';
        }).catch(function (err) {
            SecUI.toast('打开聚合明细失败：' + err.message, 'error');
        });
    }

    // 注册视图：mount 只跑一次；每次切回该视图时刷新一次
    SecUI.registerView('alerts', mount, function () {
        load();
    });
})();
