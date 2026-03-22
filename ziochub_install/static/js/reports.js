/**
 * reports.js - Intelligence Reports tab (Master-Detail).
 * Lazy-loaded when the Reports tab is activated.
 */
(function () {
    'use strict';

    if (window._reportsInitialized) return;
    window._reportsInitialized = true;

    var currentPeriod = 'week';
    var currentReportData = null;
    var chartInstances = {};

    // ── Period buttons ───────────────────────────────────────────
    document.querySelectorAll('.report-period-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            document.querySelectorAll('.report-period-btn').forEach(function (b) {
                b.classList.remove('border-accent-green', 'text-primary');
                b.classList.add('border-transparent', 'text-secondary');
            });
            btn.classList.add('border-accent-green', 'text-primary');
            btn.classList.remove('border-transparent', 'text-secondary');
            currentPeriod = btn.dataset.period;
            loadReportsList(currentPeriod);
        });
    });

    // ── Load reports list into sidebar ───────────────────────────
    function loadReportsList(period) {
        var container = document.getElementById('reportsList');
        container.innerHTML = '<div class="flex flex-col items-center justify-center py-8 gap-2"><div class="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin"></div><span class="text-xs text-secondary">Loading...</span></div>';

        fetch('/api/reports/periods?period=' + encodeURIComponent(period))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data.success || !data.periods || data.periods.length === 0) {
                    container.innerHTML = '<div class="text-xs text-secondary text-center py-4">No reports available</div>';
                    return;
                }
                container.innerHTML = '';
                data.periods.forEach(function (p, idx) {
                    var btn = document.createElement('button');
                    btn.className = 'w-full text-left px-3 py-2 rounded text-xs transition hover:bg-white/10 text-secondary';
                    btn.textContent = p.label;
                    btn.dataset.date = p.date;
                    btn.dataset.period = p.period;
                    btn.addEventListener('click', function () {
                        container.querySelectorAll('button').forEach(function (b) {
                            b.classList.remove('bg-white/10', 'accent-blue', 'font-semibold');
                        });
                        btn.classList.add('bg-white/10', 'accent-blue', 'font-semibold');
                        loadReport(p.period, p.date);
                    });
                    container.appendChild(btn);

                    if (idx === 0) {
                        btn.click();
                    }
                });
            })
            .catch(function () {
                container.innerHTML = '<div class="text-xs text-red-400 text-center py-4">Failed to load</div>';
            });
    }

    // ── Load a specific report ───────────────────────────────────
    function loadReport(period, dateStr) {
        var emptyState = document.getElementById('reportEmptyState');
        var content = document.getElementById('reportContent');
        var pdfBtn = document.getElementById('reportExportPdfBtn');
        var loadingEl = document.getElementById('reportLoading');

        currentReportData = null;
        if (pdfBtn) pdfBtn.classList.add('hidden');
        emptyState.classList.add('hidden');
        content.classList.add('hidden');

        if (!loadingEl) {
            loadingEl = document.createElement('div');
            loadingEl.id = 'reportLoading';
            loadingEl.className = 'flex flex-col items-center justify-center py-20 gap-3';
            loadingEl.innerHTML = '<div class="w-10 h-10 border-2 border-primary border-t-transparent rounded-full animate-spin"></div><span class="text-secondary">Loading report data...</span>';
            content.parentNode.insertBefore(loadingEl, content);
        }
        loadingEl.classList.remove('hidden');

        fetch('/api/reports/data?period=' + encodeURIComponent(period) + '&date=' + encodeURIComponent(dateStr))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                loadingEl.classList.add('hidden');
                if (!data.success) {
                    loadingEl.innerHTML = '<div class="text-center text-red-400 py-20">Failed to load report</div>';
                    loadingEl.classList.remove('hidden');
                    return;
                }
                currentReportData = data;
                renderReport(data);
                if (pdfBtn) pdfBtn.classList.remove('hidden');
            })
            .catch(function () {
                loadingEl.classList.add('hidden');
                loadingEl.innerHTML = '<div class="text-center text-red-400 py-20">Error loading report</div>';
                loadingEl.classList.remove('hidden');
            });
    }

    // ── Render full report ───────────────────────────────────────
    function renderReport(data) {
        var content = document.getElementById('reportContent');
        resetReportContent();
        content.classList.remove('hidden');

        renderExecutiveDashboard(data.executive);
        renderOperations(data.operations, data.start_date, data.end_date, data.period);
        renderAnalystSpotlight(data.analysts);
    }

    function resetReportContent() {
        Object.keys(chartInstances).forEach(function (k) {
            if (chartInstances[k]) {
                chartInstances[k].destroy();
                delete chartInstances[k];
            }
        });
        ['reportTypeChart', 'reportRateChart', 'reportTldChart', 'reportYaraChart'].forEach(function (id) {
            var el = document.getElementById(id);
            if (el) {
                var parent = el.parentNode;
                var newCanvas = document.createElement('canvas');
                newCanvas.id = id;
                newCanvas.height = el.height || 200;
                parent.replaceChild(newCanvas, el);
            }
        });
        ['reportKpiCards', 'reportExecSummary', 'reportTopCountries', 'reportTopCampaigns',
         'reportSubMethods', 'reportExpiration', 'reportIocQuality', 'reportAnomalies',
         'reportYaraQuality', 'reportRareFinds', 'reportCampaignsCreated', 'reportPodium', 'reportLeaderboard'].forEach(function (id) {
            var el = document.getElementById(id);
            if (el) el.innerHTML = '';
        });
    }

    // ── Executive Dashboard ──────────────────────────────────────
    function renderExecutiveDashboard(exec) {
        var kpiContainer = document.getElementById('reportKpiCards');
        if (!kpiContainer) return;

        var glowColors = {
            cyan: ['rgba(34, 211, 238, 0.6)', 'rgba(34, 211, 238, 0.3)'],
            purple: ['rgba(129, 140, 248, 0.6)', 'rgba(129, 140, 248, 0.3)'],
            green: ['rgba(34, 197, 94, 0.6)', 'rgba(34, 197, 94, 0.3)'],
            yellow: ['rgba(251, 191, 36, 0.6)', 'rgba(251, 191, 36, 0.3)'],
            blue: ['rgba(59, 130, 246, 0.6)', 'rgba(59, 130, 246, 0.3)'],
            emerald: ['rgba(16, 185, 129, 0.6)', 'rgba(16, 185, 129, 0.3)']
        };
        var kpis = [
            { label: t('reports.kpi_active_iocs') || 'Active IOCs', value: exec.active_iocs, prev: exec.active_iocs_prev, icon: '🛡️', color: 'cyan' },
            { label: t('reports.kpi_yara') || 'YARA Rules', value: exec.yara_rules, prev: exec.yara_rules_prev, icon: '📝', color: 'purple' },
            { label: t('reports.kpi_cleanup') || 'Cleanup Score', value: exec.cleanup_count, prev: exec.cleanup_count_prev, icon: '🧹', color: 'green' },
            { label: t('reports.kpi_campaigns') || 'Active Campaigns', value: exec.active_campaigns, prev: exec.active_campaigns_prev, icon: '🎯', color: 'yellow' },
            { label: t('reports.kpi_net_change') || 'Net Change', value: exec.net_change, prev: exec.net_change_prev, icon: '📈', color: 'blue' },
            { label: t('reports.kpi_feed_health') || 'Feed Health', value: exec.feed_health_score + '%', prev: exec.feed_health_score_prev, icon: '💚', color: 'emerald' },
        ];

        kpiContainer.innerHTML = kpis.map(function (kpi) {
            var change = _calcChange(kpi.value, kpi.prev);
            var g = glowColors[kpi.color] || glowColors.cyan;
            var glowStyle = 'filter: drop-shadow(0 0 12px ' + g[0] + ') drop-shadow(0 0 24px ' + g[1] + ');';
            return '<div class="bg-tertiary rounded-lg p-4 border border-slate-700/50 flex flex-row items-center justify-between">' +
                '<span class="text-3xl opacity-90 report-kpi-icon" style="' + glowStyle + '">' + kpi.icon + '</span>' +
                '<div class="text-right flex flex-col items-end">' +
                '<span class="text-2xl font-bold text-primary">' + _formatNum(kpi.value) + '</span>' +
                '<span class="text-xs font-bold text-secondary uppercase tracking-wider mt-0.5">' + kpi.label + '</span>' +
                (change !== null ? '<span class="text-xs mt-0.5 ' + (change >= 0 ? 'accent-green' : 'text-red-400') + '">' + (change >= 0 ? '▲' : '▼') + ' ' + Math.abs(change) + '%</span>' : '') +
                '</div></div>';
        }).join('');

        var summaryEl = document.getElementById('reportExecSummary');
        if (summaryEl) {
            summaryEl.innerHTML = '<span class="accent-blue font-semibold">📝 Executive Summary:</span> ' + escapeHtml(exec.summary_text || '');
        }
    }

    // ── Operations Section ───────────────────────────────────────
    function renderOperations(ops, startDate, endDate, period) {
        renderTypeDistributionChart(ops.type_distribution);
        renderSubmissionRateChart(ops.submission_rate, startDate, endDate, period);
        renderTldDoughnut(ops.top_tlds);
        renderReportLeaderboard('reportTopCountries', ops.top_countries, { type: 'flag', countKey: 'count', labelKey: 'code' });
        renderReportLeaderboard('reportTopCampaigns', ops.top_campaigns, { type: 'target', countKey: 'ioc_count', labelKey: 'name' });
        renderReportLeaderboard('reportSubMethods', ops.submission_methods, {
            type: 'globe', countKey: 'count', labelKey: 'name',
            labelMap: { single: 'Single (Manual)', csv_upload: 'CSV Upload', txt_upload: 'TXT Upload', paste: 'Paste', misp_sync: 'MISP Sync' }
        });
        renderReportLeaderboard('reportExpiration', ops.expiration_policy, {
            type: 'globe', countKey: 'count', labelKey: 'name',
            labelMap: { permanent: 'Permanent', active_expiry: 'Active (with expiry)', expired: 'Expired' }
        });
        renderQuality('reportIocQuality', ops.ioc_quality);
        renderAnomalies(ops.anomalies_summary);
        renderYaraQuality(ops.yara_quality);
        renderYaraQualityChart(ops.yara_quality);
        renderRareFinds(ops.rare_finds);
        renderCampaignsCreated(ops.campaigns_created_by_analyst);
    }

    function renderCampaignsCreated(data) {
        var container = document.getElementById('reportCampaignsCreated');
        if (!container) return;
        data = data || [];
        if (data.length === 0) {
            container.innerHTML = '<div class="flex-1 flex items-center justify-center py-12 px-4">' +
                '<span class="text-secondary text-sm text-center">' + (t('reports.no_campaigns_created') || 'No campaigns created in this period') + '</span>' +
                '</div>';
            return;
        }
        var analystCards = data.map(function (analyst) {
            var campaignsHtml = (analyst.campaigns || []).map(function (c) {
                var typesStr = Object.entries(c.ioc_types || {}).map(function (kv) {
                    return kv[0] + ': ' + kv[1];
                }).join(', ') || '-';
                return '<div class="pl-3 py-1.5 border-l-2 border-cyan-500/40 mb-1.5 last:mb-0">' +
                    '<div class="font-semibold text-primary text-sm">' + escapeHtml(c.name) + '</div>' +
                    '<div class="text-xs text-secondary mt-0.5">' + c.ioc_count + ' IOCs - ' + escapeHtml(typesStr) + '</div>' +
                    '</div>';
            }).join('');
            return '<div class="flex flex-col p-3 rounded-lg border border-white/10 bg-white/[0.02]">' +
                '<div class="font-bold accent-blue text-sm mb-2 pb-1.5 border-b border-white/10">' + escapeHtml(analyst.display_name || analyst.analyst) + '</div>' +
                '<div class="space-y-0 text-sm">' + (campaignsHtml || '<span class="text-secondary text-xs">-</span>') + '</div>' +
                '</div>';
        }).join('');
        container.innerHTML = '<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">' + analystCards + '</div>';
    }

    function renderTypeDistributionChart(dist) {
        var ctx = document.getElementById('reportTypeChart');
        if (!ctx) return;
        var order = ['IP', 'Domain', 'Hash', 'Email', 'URL', 'YARA'];
        var labels = order.filter(function (t) { return dist.hasOwnProperty(t); });
        if (labels.length === 0) labels = Object.keys(dist);
        var values = labels.map(function (t) { return dist[t] || 0; });
        var colors = ['#00d4ff', '#00ff41', '#f59e0b', '#a855f7', '#ef4444', '#ec4899'];
        chartInstances.typeChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'IOCs',
                    data: values,
                    backgroundColor: colors.slice(0, labels.length),
                    borderRadius: 4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.08)' } },
                    y: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.08)' } }
                }
            }
        });
    }

    function renderSubmissionRateChart(rate, startDate, endDate, period) {
        var ctx = document.getElementById('reportRateChart');
        if (!ctx) return;
        period = period || 'week';
        var granularity = (rate && rate.granularity) || 'day';

        var labels, teamData, mispData, totalData;
        if (granularity === 'hour') {
            labels = [];
            for (var h = 0; h < 24; h++) {
                labels.push((h < 10 ? '0' : '') + h + ':00');
            }
            teamData = (rate && rate.team) || [];
            mispData = (rate && rate.misp) || [];
            totalData = (rate && rate.total) || [];
        } else {
            var teamRaw = (rate && rate.team ? rate.team : []).sort(function (a, b) { return (a.date || '').localeCompare(b.date || ''); });
            var mispRaw = (rate && rate.misp ? rate.misp : []).sort(function (a, b) { return (a.date || '').localeCompare(b.date || ''); });
            var totalRaw = (rate && rate.total ? rate.total : []).sort(function (a, b) { return (a.date || '').localeCompare(b.date || ''); });
            var allDates = {};
            teamRaw.forEach(function (d) { if (d.date) allDates[d.date] = true; });
            mispRaw.forEach(function (d) { if (d.date) allDates[d.date] = true; });
            totalRaw.forEach(function (d) { if (d.date) allDates[d.date] = true; });
            labels = Object.keys(allDates).sort();
            if (labels.length === 0 && startDate && endDate) {
                var start = new Date(startDate);
                var end = new Date(endDate);
                for (var d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
                    labels.push(d.toISOString().slice(0, 10));
                }
            }
            teamData = teamRaw;
            mispData = mispRaw;
            totalData = totalRaw;
        }

        var teamMap = {}, mispMap = {}, totalMap = {};
        if (granularity === 'hour') {
            teamData.forEach(function (d) { teamMap[d.hour] = d.count; });
            mispData.forEach(function (d) { mispMap[d.hour] = d.count; });
            totalData.forEach(function (d) { totalMap[d.hour] = d.count; });
        } else {
            teamData.forEach(function (d) { teamMap[d.date] = d.count; });
            mispData.forEach(function (d) { mispMap[d.date] = d.count; });
            totalData.forEach(function (d) { totalMap[d.date] = d.count; });
        }

        var labelShort, keyList;
        if (granularity === 'hour') {
            labelShort = labels;
            keyList = Array.apply(null, { length: 24 }).map(function (_, i) { return i; });
        } else if (period === 'week') {
            labelShort = labels.map(function (d) {
                var dt = new Date(d + 'T12:00:00');
                var days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
                return days[dt.getDay()];
            });
            keyList = labels;
        } else if (period === 'month') {
            var lastDay = 31;
            if (endDate) {
                var endParts = endDate.split('-');
                if (endParts.length >= 3) lastDay = parseInt(endParts[2], 10);
            }
            keyList = [];
            for (var d = 1; d <= lastDay; d++) keyList.push(d);
            labelShort = keyList.slice();
            var teamMapByDate = {}, mispMapByDate = {}, totalMapByDate = {};
            teamData.forEach(function (d) { teamMapByDate[d.date] = d.count; });
            mispData.forEach(function (d) { mispMapByDate[d.date] = d.count; });
            totalData.forEach(function (d) { totalMapByDate[d.date] = d.count; });
            var prefix = (startDate || (labels.length ? labels[0] : '')).substring(0, 7) || '2026-03';
            teamMap = {};
            mispMap = {};
            totalMap = {};
            keyList.forEach(function (day) {
                var dateStr = prefix + '-' + (day < 10 ? '0' : '') + day;
                teamMap[day] = teamMapByDate[dateStr] || 0;
                mispMap[day] = mispMapByDate[dateStr] || 0;
                totalMap[day] = totalMapByDate[dateStr] || 0;
            });
        } else {
            labelShort = labels.map(function (d) { return d.length >= 10 ? d.substring(5) : d; });
            keyList = labels;
        }
        var hasTeamOrMisp = (granularity === 'hour' ? (teamData.length > 0 || mispData.length > 0) : (teamData.length > 0 || mispData.length > 0));

        var isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        var gridColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
        var textColor = isDark ? '#ffffff' : '#64748b';

        var datasets = [];
        if (hasTeamOrMisp) {
            datasets.push({
                label: 'Team Submissions',
                data: keyList.map(function (k) { return teamMap[k] || 0; }),
                borderColor: '#00d4ff',
                backgroundColor: 'rgba(0,212,255,0.2)',
                fill: true,
                tension: 0.3
            });
            datasets.push({
                label: 'MISP Sync',
                data: keyList.map(function (k) { return mispMap[k] || 0; }),
                borderColor: '#eab308',
                backgroundColor: 'rgba(234,179,8,0.15)',
                fill: true,
                tension: 0.3,
                borderDash: [4, 2]
            });
        } else {
            datasets.push({
                label: 'Total Submissions',
                data: keyList.map(function (k) { return totalMap[k] || 0; }),
                borderColor: '#00d4ff',
                backgroundColor: 'rgba(0,212,255,0.2)',
                fill: true,
                tension: 0.3
            });
        }

        chartInstances.rateChart = new Chart(ctx, {
            type: 'line',
            data: { labels: labelShort, datasets: datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: true, labels: { color: textColor } } },
                scales: {
                    x: { ticks: { maxRotation: 45, color: textColor }, grid: { color: gridColor } },
                    y: { beginAtZero: true, ticks: { color: textColor }, grid: { color: gridColor } }
                }
            }
        });
    }

    function renderTldDoughnut(tlds) {
        var ctx = document.getElementById('reportTldChart');
        if (!ctx || !tlds || tlds.length === 0) return;
        var labels = tlds.map(function (t) { return t.tld; });
        var values = tlds.map(function (t) { return t.count; });
        var colors = ['#00d4ff', '#00ff41', '#f59e0b', '#a855f7', '#ef4444', '#3b82f6', '#ec4899', '#8b5cf6', '#f97316', '#14b8a6'];
        chartInstances.tldChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: colors.slice(0, labels.length),
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 10 }, boxWidth: 10 } }
                }
            }
        });
    }

    // ── Analyst Spotlight ─────────────────────────────────────────
    function renderAnalystSpotlight(analysts) {
        renderPodium(analysts.podium || []);
        renderLeaderboard(analysts.leaderboard || []);
        renderTeamGoal(analysts.team_goal);
        renderMentorshipInsights(analysts.mentorship_insights || []);
    }

    function renderPodium(podium) {
        var container = document.getElementById('reportPodium');
        if (!container) return;
        if (podium.length === 0) {
            container.innerHTML = '<div class="col-span-full text-secondary text-sm py-8 text-center">No analyst data available</div>';
            return;
        }

        var order = [1, 0, 2]; // silver, gold, bronze display order
        var rankClasses = ['report-podium-silver', 'report-podium-gold', 'report-podium-bronze'];
        var labels = ['🥈', '🥇', '🥉'];
        var rankLabels = ['2nd', '1st', '3rd'];

        container.innerHTML = order.map(function (idx, pos) {
            var a = podium[idx];
            if (!a) return '';
            var rankCls = rankClasses[pos];
            var emoji = a.nickname_emoji || '🎯';
            var avatar = a.avatar_url
                ? '<div class="report-podium-avatar w-16 h-16 rounded-full overflow-hidden flex-shrink-0 ring-2 ring-white/20">' +
                  '<img src="' + escapeHtml(a.avatar_url) + '" class="w-full h-full object-cover" alt="" onerror="this.style.display=\'none\';this.nextElementSibling.style.display=\'flex\'">' +
                  '<div class="w-full h-full bg-slate-600/50 flex items-center justify-center text-2xl" style="display:none">' + emoji + '</div></div>'
                : '<div class="report-podium-avatar w-16 h-16 rounded-full bg-slate-600/50 flex items-center justify-center text-2xl flex-shrink-0 ring-2 ring-white/20">' + emoji + '</div>';
            return '<div class="report-podium-card champs-spotlight-card ' + rankCls + ' flex flex-col sm:flex-row items-center sm:items-stretch gap-4 p-4 rounded-xl border border-white/10 bg-tertiary shadow-lg min-h-0">' +
                '<div class="flex items-center gap-3 flex-1 min-w-0 w-full">' +
                avatar +
                '<div class="flex-1 min-w-0">' +
                '<div class="flex items-center gap-2 flex-wrap">' +
                '<span class="text-2xl">' + labels[pos] + '</span>' +
                '<span class="text-xs font-bold uppercase tracking-wider text-secondary">' + rankLabels[pos] + '</span>' +
                '</div>' +
                '<div class="text-lg font-bold text-primary truncate mt-0.5">' + escapeHtml(a.display_name) + '</div>' +
                '<div class="report-podium-stats flex flex-wrap items-center gap-3 mt-2">' +
                '<span class="font-mono text-sm font-bold accent-green leading-none">' + a.score + ' pts</span>' +
                '<span class="text-xs text-secondary leading-none">' + a.total_iocs + ' IOCs</span>' +
                '<span class="text-xs text-secondary leading-none">' + a.yara_count + ' YARA</span>' +
                (a.streak_days > 0 ? '<span class="text-xs text-orange-400 font-semibold leading-none">🔥 ' + a.streak_days + 'd streak</span>' : '') +
                '</div></div></div></div>';
        }).join('');
    }

    function renderLeaderboard(leaderboard) {
        var tbody = document.getElementById('reportLeaderboard');
        if (!tbody) return;
        tbody.innerHTML = leaderboard.map(function (r) {
            var rankClass = r.rank <= 3 ? 'accent-green font-bold' : 'text-secondary';
            return '<tr class="border-b border-white/10 hover:bg-white/5">' +
                '<td class="px-3 py-2 ' + rankClass + '">' + r.rank + '</td>' +
                '<td class="px-3 py-2 text-primary">' + escapeHtml(r.display_name) + '</td>' +
                '<td class="px-3 py-2 text-secondary">' + r.total_iocs + '</td>' +
                '<td class="px-3 py-2 text-secondary">' + r.yara_count + '</td>' +
                '<td class="px-3 py-2 text-secondary">' + (r.deletion_count || 0) + '</td>' +
                '<td class="px-3 py-2 accent-blue font-semibold">' + r.score + '</td>' +
                '<td class="px-3 py-2">' + (r.streak_days > 0 ? '<span class="text-orange-400">🔥 ' + r.streak_days + 'd</span>' : '<span class="text-secondary">-</span>') + '</td>' +
                '</tr>';
        }).join('');
    }

    function renderTeamGoal(goal) {
        var container = document.getElementById('reportTeamGoal');
        if (!container) return;
        if (!goal) { container.classList.add('hidden'); return; }
        container.classList.remove('hidden');
        var pct = Math.min(100, goal.percent || 0);
        container.innerHTML = '<div class="flex items-center justify-between mb-2">' +
            '<span class="text-sm font-semibold text-primary">🎯 ' + escapeHtml(goal.title) + '</span>' +
            '<span class="text-xs text-secondary">' + goal.current_value + '/' + goal.target_value + ' ' + escapeHtml(goal.unit || '') + '</span>' +
            '</div>' +
            '<div class="w-full bg-black/40 rounded-full h-3 border border-white/10">' +
            '<div class="h-3 rounded-full bg-gradient-to-r from-cyan-500 via-emerald-500 to-green-400 transition-all" style="width:' + pct + '%"></div>' +
            '</div>' +
            '<div class="text-xs text-secondary mt-1 text-right">' + pct.toFixed(1) + '%</div>';
    }

    function renderMentorshipInsights(insights) {
        var container = document.getElementById('reportMentorshipInsights');
        if (!container) return;
        if (!insights || insights.length === 0) {
            container.classList.add('hidden');
            return;
        }
        container.classList.remove('hidden');
        var sevIcon = { action: '🔴', warning: '🟠', info: '🔵' };
        container.innerHTML = '<div class="flex items-center gap-2 mb-3">' +
            '<span class="text-lg">🤝</span>' +
            '<h4 class="text-sm font-bold accent-blue uppercase tracking-wider">' + (t('reports.mentorship_title') || 'SOC Mentorship Insights') + '</h4>' +
            '<span class="text-xs text-secondary ml-auto">' + (t('reports.admin_only') || 'Admin only') + '</span>' +
            '</div>' +
            '<div class="space-y-2">' +
            insights.map(function (f) {
                return '<div class="flex items-start gap-2 text-sm">' +
                    '<span class="flex-shrink-0 mt-0.5">' + (sevIcon[f.severity] || '🔵') + '</span>' +
                    '<div>' +
                    '<span class="text-primary font-semibold">' + escapeHtml(f.analyst_name) + '</span>' +
                    ' - <span class="text-secondary">' + escapeHtml(f.message) + '</span>' +
                    '<div class="text-xs accent-blue mt-0.5">→ ' + escapeHtml(f.recommendation) + '</div>' +
                    '</div></div>';
            }).join('') +
            '</div>';
    }

    // ── Helper renderers ─────────────────────────────────────────
    function renderSimpleList(containerId, items, formatter) {
        var el = document.getElementById(containerId);
        if (!el) return;
        if (!items || items.length === 0) {
            el.innerHTML = '<span class="text-secondary text-xs">No data</span>';
            return;
        }
        el.innerHTML = items.map(function (item) {
            return '<div class="py-0.5">' + formatter(item) + '</div>';
        }).join('');
    }

    function renderKeyValue(containerId, obj) {
        var el = document.getElementById(containerId);
        if (!el || !obj) return;
        el.innerHTML = Object.entries(obj).map(function (kv) {
            return '<div class="flex justify-between py-0.5">' +
                '<span class="text-secondary capitalize">' + escapeHtml(kv[0]) + '</span>' +
                '<span class="text-primary font-mono">' + _formatNum(kv[1]) + '</span>' +
                '</div>';
        }).join('');
    }

    function renderQuality(containerId, quality) {
        var el = document.getElementById(containerId);
        if (!el || !quality) return;
        var items = [
            { label: 'With Comment', value: quality.with_comment_pct + '%' },
            { label: 'With Ticket', value: quality.with_ticket_pct + '%' },
            { label: 'With Campaign', value: quality.with_campaign_pct + '%' },
            { label: 'With Tags', value: quality.with_tags_pct + '%' },
            { label: 'Avg Comment Len', value: Math.round(quality.avg_comment_length) },
        ];
        el.innerHTML = items.map(function (i) {
            return '<div class="flex justify-between py-0.5">' +
                '<span class="text-secondary text-xs">' + i.label + '</span>' +
                '<span class="text-primary font-mono text-xs">' + i.value + '</span>' +
                '</div>';
        }).join('');
    }

    var anomalyTypeLabels = {
        url_contains_hash: 'URL contains hash',
        local_ip: 'Local/Private IP',
        testnet_ip: 'Test-NET IP',
        bogon_ip: 'Bogon/Reserved IP',
        short_domain: 'Short domain',
        hash_mismatch: 'Hash length mismatch',
        defanged: 'Defanged URL',
        tld_only: 'TLD only',
        critical_infra: 'Critical infra IP',
        popular_domain: 'Popular domain',
        cloud_provider: 'Cloud provider',
        free_email_provider: 'Free email provider',
        punycode_domain: 'Punycode/IDN',
        dga_suspect: 'DGA suspect',
        deep_subdomain: 'Deep subdomain',
        url_credentials: 'URL with credentials',
        url_raw_ip: 'URL with raw IP',
        stale_ioc: 'Stale IOC'
    };

    function renderAnomalies(anomalies) {
        var el = document.getElementById('reportAnomalies');
        if (!el) return;
        if (!anomalies || anomalies.length === 0) {
            el.innerHTML = '<span class="text-secondary text-xs">No anomalies detected</span>';
            return;
        }
        el.innerHTML = anomalies.map(function (a) {
            var label = anomalyTypeLabels[a.type] || a.type.replace(/_/g, ' ');
            var samples = (a.samples || []).map(function (s) {
                var msg = (s.message || '').substring(0, 80);
                if (s.message && s.message.length > 80) msg += '…';
                return '<div class="text-xs text-secondary/90 pl-3 border-l-2 border-amber-500/40 mt-1">' +
                    (s.value ? '<span class="font-mono text-primary/90">' + escapeHtml(s.value) + '</span>' : '') +
                    (msg ? '<br><span class="italic">' + escapeHtml(msg) + '</span>' : '') + '</div>';
            }).join('');
            return '<div class="py-2 border-b border-white/5 last:border-0">' +
                '<span class="text-amber-300 font-semibold">' + escapeHtml(label) + '</span> ' +
                '<span class="text-secondary">×' + a.count + '</span>' +
                (samples ? '<div class="mt-1">' + samples + '</div>' : '') +
                '</div>';
        }).join('');
    }

    var COUNTRY_NAMES = { ad: 'Andorra', ae: 'United Arab Emirates', af: 'Afghanistan', ag: 'Antigua and Barbuda', ai: 'Anguilla', al: 'Albania', am: 'Armenia', ao: 'Angola', aq: 'Antarctica', ar: 'Argentina', as: 'American Samoa', at: 'Austria', au: 'Australia', aw: 'Aruba', ax: 'Åland Islands', az: 'Azerbaijan', ba: 'Bosnia and Herzegovina', bb: 'Barbados', bd: 'Bangladesh', be: 'Belgium', bf: 'Burkina Faso', bg: 'Bulgaria', bh: 'Bahrain', bi: 'Burundi', bj: 'Benin', bl: 'Saint Barthélemy', bm: 'Bermuda', bn: 'Brunei', bo: 'Bolivia', bq: 'Caribbean Netherlands', br: 'Brazil', bs: 'Bahamas', bt: 'Bhutan', bv: 'Bouvet Island', bw: 'Botswana', by: 'Belarus', bz: 'Belize', ca: 'Canada', cc: 'Cocos Islands', cd: 'DR Congo', cf: 'Central African Republic', cg: 'Republic of the Congo', ch: 'Switzerland', ci: 'Ivory Coast', ck: 'Cook Islands', cl: 'Chile', cm: 'Cameroon', cn: 'China', co: 'Colombia', cr: 'Costa Rica', cu: 'Cuba', cv: 'Cape Verde', cw: 'Curaçao', cx: 'Christmas Island', cy: 'Cyprus', cz: 'Czech Republic', de: 'Germany', dj: 'Djibouti', dk: 'Denmark', dm: 'Dominica', do: 'Dominican Republic', dz: 'Algeria', ec: 'Ecuador', ee: 'Estonia', eg: 'Egypt', eh: 'Western Sahara', er: 'Eritrea', es: 'Spain', et: 'Ethiopia', fi: 'Finland', fj: 'Fiji', fk: 'Falkland Islands', fm: 'Micronesia', fo: 'Faroe Islands', fr: 'France', ga: 'Gabon', gb: 'United Kingdom', gd: 'Grenada', ge: 'Georgia', gf: 'French Guiana', gg: 'Guernsey', gh: 'Ghana', gi: 'Gibraltar', gl: 'Greenland', gm: 'Gambia', gn: 'Guinea', gp: 'Guadeloupe', gq: 'Equatorial Guinea', gr: 'Greece', gs: 'South Georgia', gt: 'Guatemala', gu: 'Guam', gw: 'Guinea-Bissau', gy: 'Guyana', hk: 'Hong Kong', hm: 'Heard Island', hn: 'Honduras', hr: 'Croatia', ht: 'Haiti', hu: 'Hungary', id: 'Indonesia', ie: 'Ireland', il: 'Israel', im: 'Isle of Man', in: 'India', io: 'British Indian Ocean', iq: 'Iraq', ir: 'Iran', is: 'Iceland', it: 'Italy', je: 'Jersey', jm: 'Jamaica', jo: 'Jordan', jp: 'Japan', ke: 'Kenya', kg: 'Kyrgyzstan', kh: 'Cambodia', ki: 'Kiribati', km: 'Comoros', kn: 'Saint Kitts and Nevis', kp: 'North Korea', kr: 'South Korea', kw: 'Kuwait', ky: 'Cayman Islands', kz: 'Kazakhstan', la: 'Laos', lb: 'Lebanon', lc: 'Saint Lucia', li: 'Liechtenstein', lk: 'Sri Lanka', lr: 'Liberia', ls: 'Lesotho', lt: 'Lithuania', lu: 'Luxembourg', lv: 'Latvia', ly: 'Libya', ma: 'Morocco', mc: 'Monaco', md: 'Moldova', me: 'Montenegro', mf: 'Saint Martin', mg: 'Madagascar', mh: 'Marshall Islands', mk: 'North Macedonia', ml: 'Mali', mm: 'Myanmar', mn: 'Mongolia', mo: 'Macau', mp: 'Northern Mariana', mq: 'Martinique', mr: 'Mauritania', ms: 'Montserrat', mt: 'Malta', mu: 'Mauritius', mv: 'Maldives', mw: 'Malawi', mx: 'Mexico', my: 'Malaysia', mz: 'Mozambique', na: 'Namibia', nc: 'New Caledonia', ne: 'Niger', nf: 'Norfolk Island', ng: 'Nigeria', ni: 'Nicaragua', nl: 'Netherlands', no: 'Norway', np: 'Nepal', nr: 'Nauru', nu: 'Niue', nz: 'New Zealand', om: 'Oman', pa: 'Panama', pe: 'Peru', pf: 'French Polynesia', pg: 'Papua New Guinea', ph: 'Philippines', pk: 'Pakistan', pl: 'Poland', pm: 'Saint Pierre and Miquelon', pn: 'Pitcairn Islands', pr: 'Puerto Rico', ps: 'Palestine', pt: 'Portugal', pw: 'Palau', py: 'Paraguay', qa: 'Qatar', re: 'Réunion', ro: 'Romania', rs: 'Serbia', ru: 'Russia', rw: 'Rwanda', sa: 'Saudi Arabia', sb: 'Solomon Islands', sc: 'Seychelles', sd: 'Sudan', se: 'Sweden', sg: 'Singapore', sh: 'Saint Helena', si: 'Slovenia', sj: 'Svalbard and Jan Mayen', sk: 'Slovakia', sl: 'Sierra Leone', sm: 'San Marino', sn: 'Senegal', so: 'Somalia', sr: 'Suriname', ss: 'South Sudan', st: 'São Tomé and Príncipe', sv: 'El Salvador', sx: 'Sint Maarten', sy: 'Syria', sz: 'Eswatini', tc: 'Turks and Caicos', td: 'Chad', tf: 'French Southern Lands', tg: 'Togo', th: 'Thailand', tj: 'Tajikistan', tk: 'Tokelau', tl: 'Timor-Leste', tm: 'Turkmenistan', tn: 'Tunisia', to: 'Tonga', tr: 'Turkey', tt: 'Trinidad and Tobago', tv: 'Tuvalu', tw: 'Taiwan', tz: 'Tanzania', ua: 'Ukraine', ug: 'Uganda', um: 'US Minor Outlying', un: 'United Nations', us: 'United States', uy: 'Uruguay', uz: 'Uzbekistan', va: 'Vatican City', vc: 'Saint Vincent and the Grenadines', ve: 'Venezuela', vg: 'British Virgin Islands', vi: 'US Virgin Islands', vn: 'Vietnam', vu: 'Vanuatu', wf: 'Wallis and Futuna', ws: 'Samoa', xk: 'Kosovo', ye: 'Yemen', yt: 'Mayotte', za: 'South Africa', zm: 'Zambia', zw: 'Zimbabwe' };

    function getCountryName(code) {
        if (!code || typeof code !== 'string') return code || '';
        var name = COUNTRY_NAMES[code.toLowerCase()];
        return name || code.toUpperCase();
    }

    function renderRareFinds(items) {
        var el = document.getElementById('reportRareFinds');
        if (!el) return;
        if (!items || items.length === 0) {
            el.innerHTML = '<span class="text-secondary text-xs">No rare finds in this period</span>';
            return;
        }
        var typeLabels = { country: 'First-ever country', tld: 'First-ever TLD', email_domain: 'First-ever email domain' };
        el.innerHTML = items.map(function (r) {
            var label = typeLabels[r.type] || r.type;
            var displayDetail = '';
            if (r.type === 'country' && r.detail) {
                displayDetail = getCountryName(r.detail);
            } else if (r.type === 'tld' && r.detail) {
                displayDetail = (r.detail[0] === '.' ? '' : '.') + r.detail;
            } else if (r.type === 'email_domain' && r.detail) {
                displayDetail = r.detail;
            } else {
                displayDetail = r.value ? r.value.substring(0, 40) : '';
            }
            return '<div class="py-1">' +
                '<span class="accent-green">⭐</span> ' +
                '<span class="font-semibold">' + escapeHtml(label) + ':</span> ' +
                '<span class="text-primary">' + escapeHtml(displayDetail) + '</span>' +
                (r.value ? ' <span class="text-secondary">(' + escapeHtml(r.value.substring(0, 50)) + (r.value.length > 50 ? '…' : '') + ')</span>' : '') +
                ' <span class="text-secondary">by ' + escapeHtml(r.discoverer) + '</span>' +
                '</div>';
        }).join('');
    }

    function renderYaraQuality(yq) {
        var el = document.getElementById('reportYaraQuality');
        if (!el || !yq) return;
        var items = [
            { label: 'Approved', value: yq.total_approved },
            { label: 'Pending', value: yq.pending },
            { label: 'Avg Quality', value: yq.avg_quality + '/50' },
            { label: 'With Campaign', value: yq.with_campaign_pct + '%' },
            { label: 'With Ticket', value: yq.with_ticket_pct + '%' },
        ];
        el.innerHTML = items.map(function (i) {
            return '<div class="flex justify-between py-0.5">' +
                '<span class="text-secondary text-xs">' + i.label + '</span>' +
                '<span class="text-primary font-mono text-xs">' + i.value + '</span>' +
                '</div>';
        }).join('');
    }

    function renderYaraQualityChart(yq) {
        var ctx = document.getElementById('reportYaraChart');
        if (!ctx || !yq) return;
        var approved = yq.total_approved || 0;
        var pending = yq.pending || 0;
        var hasData = approved > 0 || pending > 0;
        if (chartInstances.yaraChart) {
            chartInstances.yaraChart.destroy();
            delete chartInstances.yaraChart;
        }
        chartInstances.yaraChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: hasData ? ['Approved', 'Pending'] : ['No YARA in period'],
                datasets: [{
                    data: hasData ? [approved, pending] : [1],
                    backgroundColor: hasData ? ['#00ff41', '#f59e0b'] : ['rgba(148,163,184,0.3)'],
                    borderWidth: 0,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '60%',
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 9 }, boxWidth: 8 } }
                }
            }
        });
    }

    // ── Utilities ────────────────────────────────────────────────
    function _calcChange(current, prev) {
        var cur = parseFloat(current);
        var prv = parseFloat(prev);
        if (isNaN(cur) || isNaN(prv) || prv === 0) return null;
        return Math.round((cur - prv) / prv * 100);
    }

    function _formatNum(val) {
        if (typeof val === 'number') {
            return val.toLocaleString();
        }
        return val;
    }

    function t(key) {
        return window.t ? window.t(key) : null;
    }

    function escapeHtml(str) {
        if (window.escapeHtml) return window.escapeHtml(str);
        var d = document.createElement('div');
        d.textContent = str || '';
        return d.innerHTML;
    }

    function escapeAttr(str) {
        if (window.escapeAttr) return window.escapeAttr(str);
        if (str == null || str === '') return '';
        return String(str).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    var COUNTRY_NAMES = { ad: 'Andorra', ae: 'United Arab Emirates', af: 'Afghanistan', al: 'Albania', am: 'Armenia', ar: 'Argentina', at: 'Austria', au: 'Australia', az: 'Azerbaijan', ba: 'Bosnia and Herzegovina', bd: 'Bangladesh', be: 'Belgium', bg: 'Bulgaria', br: 'Brazil', by: 'Belarus', ca: 'Canada', ch: 'Switzerland', cn: 'China', co: 'Colombia', cz: 'Czech Republic', de: 'Germany', dk: 'Denmark', ee: 'Estonia', eg: 'Egypt', es: 'Spain', fi: 'Finland', fr: 'France', gb: 'United Kingdom', ge: 'Georgia', gr: 'Greece', hk: 'Hong Kong', hr: 'Croatia', hu: 'Hungary', id: 'Indonesia', ie: 'Ireland', il: 'Israel', in: 'India', ir: 'Iran', it: 'Italy', jp: 'Japan', ke: 'Kenya', kr: 'South Korea', kz: 'Kazakhstan', lb: 'Lebanon', lt: 'Lithuania', lu: 'Luxembourg', lv: 'Latvia', ma: 'Morocco', md: 'Moldova', me: 'Montenegro', mx: 'Mexico', my: 'Malaysia', ng: 'Nigeria', nl: 'Netherlands', no: 'Norway', nz: 'New Zealand', pa: 'Panama', pe: 'Peru', ph: 'Philippines', pk: 'Pakistan', pl: 'Poland', pt: 'Portugal', ro: 'Romania', rs: 'Serbia', ru: 'Russia', sa: 'Saudi Arabia', se: 'Sweden', sg: 'Singapore', si: 'Slovenia', sk: 'Slovakia', th: 'Thailand', tr: 'Turkey', tw: 'Taiwan', ua: 'Ukraine', us: 'United States', vn: 'Vietnam', za: 'South Africa' };

    function getCountryName(code) {
        if (!code || typeof code !== 'string') return code || '';
        var name = COUNTRY_NAMES[code.toLowerCase()];
        return name || code.toUpperCase();
    }

    function renderReportLeaderboard(containerId, items, opts) {
        var el = document.getElementById(containerId);
        if (!el) return;
        opts = opts || {};
        var type = opts.type || 'globe';
        var countKey = opts.countKey || 'count';
        var labelKey = opts.labelKey || 'name';
        var labelMap = opts.labelMap || {};
        if (!items || (Array.isArray(items) && items.length === 0) || (typeof items === 'object' && !Array.isArray(items) && Object.keys(items).length === 0)) {
            el.innerHTML = '<span class="text-secondary text-xs">No data</span>';
            return;
        }
        var arr = Array.isArray(items) ? items : Object.entries(items).map(function (kv) {
            var obj = {};
            obj[labelKey] = kv[0];
            obj[countKey] = kv[1];
            return obj;
        });
        var sorted = arr.filter(function (item) { return (item[countKey] || 0) > 0; })
            .sort(function (a, b) { return (b[countKey] || 0) - (a[countKey] || 0); })
            .slice(0, 50);
        if (sorted.length === 0) {
            el.innerHTML = '<span class="text-secondary text-xs">No data</span>';
            return;
        }
        var maxCount = Math.max.apply(null, sorted.map(function (item) { return item[countKey] || 0; }));
        if (maxCount <= 0) {
            el.innerHTML = '<span class="text-secondary text-xs">No data</span>';
            return;
        }
        el.innerHTML = sorted.map(function (item, index) {
            var count = item[countKey] || 0;
            var rawLabel = item[labelKey] || '';
            var label = labelMap[rawLabel] || (rawLabel && rawLabel.charAt(0).toUpperCase() + rawLabel.slice(1).replace(/_/g, ' ')) || rawLabel;
            var percentage = (count / maxCount) * 100;
            var rank = index + 1;
            var barColor = rank === 1 ? '#00ff41' : rank <= 3 ? '#00d4ff' : rank <= 5 ? '#8b5cf6' : '#3b82f6';
            var iconHtml = '';
            var labelHtml = '';
            if (type === 'flag') {
                var cc = String(label).toLowerCase();
                var countryName = getCountryName(cc);
                iconHtml = '<span class="inline-flex flex-shrink-0 w-6 h-6 rounded-full overflow-hidden border border-white/20" title="' + escapeAttr(countryName) + '"><img src="/static/flags/1x1/' + escapeAttr(cc) + '.svg" alt="" class="w-full h-full object-cover" loading="lazy" onerror="this.style.background=\'var(--bg-tertiary)\'"></span>';
            } else {
                labelHtml = '<span class="text-sm font-semibold" style="color: var(--text-primary);">' + escapeHtml(label) + '</span>';
            }
            return '<div class="country-leaderboard-row flex items-center gap-2 py-1 w-full">' +
                '<div class="flex-shrink-0 flex items-center max-w-[140px] truncate">' + iconHtml + labelHtml + '</div>' +
                '<div class="flex-1 min-w-0 flex flex-col justify-center">' +
                '<div class="country-bar h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden w-full">' +
                '<div class="country-bar-fill h-full rounded-full transition-all duration-300" style="width: ' + percentage + '%; background-color: ' + barColor + ';"></div>' +
                '</div></div>' +
                '<div class="country-count flex-shrink-0 w-auto min-w-[24px] text-right text-base font-bold font-mono" style="color: var(--text-primary);">' + count + '</div>' +
                '</div>';
        }).join('');
    }

    // ── PDF Export ─────────────────────────────────────────────────
    var _pdfLibsLoaded = false;

    function _loadPdfLibs() {
        if (_pdfLibsLoaded) return Promise.resolve();
        var libs = ['/static/js/jspdf.umd.min.js'];
        return Promise.all(libs.map(function (src) {
            return new Promise(function (resolve, reject) {
                if (document.querySelector('script[src="' + src + '"]')) { resolve(); return; }
                var s = document.createElement('script');
                s.src = src;
                s.onload = resolve;
                s.onerror = function () { reject(new Error('Failed to load ' + src)); };
                document.head.appendChild(s);
            });
        })).then(function () { _pdfLibsLoaded = true; });
    }

    window.exportReportPDF = function () {
        if (!currentReportData) {
            if (window.showToast) window.showToast('No report loaded', 'error');
            return;
        }
        _loadPdfLibs().then(function () {
            return _loadLogoImage();
        }).then(function (logos) {
            _generatePDF(currentReportData, logos);
        }).catch(function (err) {
            console.error('PDF export error:', err);
            if (window.showToast) window.showToast(err.message || 'PDF export failed', 'error');
        });
    };

    function _loadLogoImage() {
        return new Promise(function (resolve) {
            function loadOne(url) {
                return new Promise(function (res) {
                    var img = new Image();
                    img.crossOrigin = 'anonymous';
                    img.onload = function () {
                        try {
                            var canvas = document.createElement('canvas');
                            canvas.width = img.width;
                            canvas.height = img.height;
                            var ctx = canvas.getContext('2d');
                            ctx.drawImage(img, 0, 0);
                            res(canvas.toDataURL('image/png'));
                        } catch (e) { res(null); }
                    };
                    img.onerror = function () { res(null); };
                    img.src = url;
                });
            }
            Promise.all([
                loadOne('/static/ziochub.png').then(function (d) { return d || loadOne('/static/ziochub_smaller.png'); }),
                loadOne('/static/ziochub_smaller.png').then(function (d) { return d || loadOne('/static/ziochub.png'); })
            ]).then(function (arr) {
                resolve({ cover: arr[0], header: arr[1] });
            });
        });
    }

    function _generatePDF(data, logos) {
        var coverLogo = (logos && logos.cover) || null;
        var headerLogo = (logos && logos.header) || logos || null;
        var jsPDF = (window.jspdf && window.jspdf.jsPDF) || jspdf.jsPDF;
        var pdf = new jsPDF('p', 'mm', 'a4');
        var pageW = 210;
        var pageH = 297;
        var margin = 18;
        var yMax = pageH - 25;
        var lineH = 6;
        var tocEntries = [];

        function _addPageWithHeader(logo) {
            pdf.addPage();
            pdf.setFillColor(255, 255, 255);
            pdf.rect(0, 0, pageW, pageH, 'F');
            if (logo) {
                pdf.addImage(logo, 'PNG', margin, 8, 12, 12);
            }
            pdf.setFontSize(10);
            pdf.setTextColor(0, 102, 204);
            pdf.setFont(undefined, 'bold');
            pdf.text('ZIoCHub', margin + 14, 14);
            pdf.setFont(undefined, 'normal');
            pdf.setFontSize(9);
            pdf.setTextColor(100, 100, 100);
            pdf.text('IOC & YARA Management', pageW - margin, 14, { align: 'right' });
            pdf.setDrawColor(200, 200, 200);
            pdf.setLineWidth(0.2);
            pdf.line(margin, 20, pageW - margin, 20);
            return 28;
        }

        function _pdfHeader(logo) {
            if (logo) {
                pdf.addImage(logo, 'PNG', margin, 8, 12, 12);
            }
            pdf.setFontSize(10);
            pdf.setTextColor(0, 102, 204);
            pdf.setFont(undefined, 'bold');
            pdf.text('ZIoCHub', margin + 14, 14);
            pdf.setFont(undefined, 'normal');
            pdf.setFontSize(9);
            pdf.setTextColor(100, 100, 100);
            pdf.text('IOC & YARA Management', pageW - margin, 14, { align: 'right' });
            pdf.setDrawColor(200, 200, 200);
            pdf.setLineWidth(0.2);
            pdf.line(margin, 20, pageW - margin, 20);
        }

        function _pdfFooter(pdf, pageW, pageH) {
            var totalPages = pdf.getNumberOfPages();
            for (var i = 1; i <= totalPages; i++) {
                pdf.setPage(i);
                pdf.setFontSize(8);
                pdf.setTextColor(120, 120, 120);
                pdf.text('Page ' + i + ' of ' + totalPages, pageW / 2, pageH - 10, { align: 'center' });
                pdf.text('Confidential', margin, pageH - 10);
                pdf.text(new Date().toISOString().split('T')[0], pageW - margin, pageH - 10, { align: 'right' });
            }
        }

        function _sectionTitle(pdf, margin, y, title) {
            pdf.setFontSize(12);
            pdf.setTextColor(0, 0, 0);
            pdf.setFont(undefined, 'bold');
            pdf.text(title, margin, y);
            pdf.setFont(undefined, 'normal');
            return y + lineH;
        }

        function _sectionDesc(pdf, margin, y, desc) {
            pdf.setFontSize(9);
            pdf.setTextColor(80, 80, 80);
            var lines = pdf.splitTextToSize(desc, pageW - margin * 2);
            lines.forEach(function (line) {
                if (y > yMax) { pdf.addPage(); pdf.setFillColor(255,255,255); pdf.rect(0,0,pageW,pageH,'F'); _pdfHeader(headerLogo); y = 28; }
                pdf.text(line, margin, y);
                y += lineH - 1;
            });
            return y + 3;
        }

        function _checkPage(pdf, y, logo) {
            if (y > yMax) {
                pdf.addPage();
                pdf.setFillColor(255, 255, 255);
                pdf.rect(0, 0, pageW, pageH, 'F');
                _pdfHeader(logo);
                return 28;
            }
            return y;
        }

        function _addChart(pdf, canvasId, margin, y, w, h) {
            var canvas = document.getElementById(canvasId);
            if (canvas && canvas.width > 0 && canvas.height > 0) {
                try {
                    var imgData = canvas.toDataURL('image/png');
                    pdf.addImage(imgData, 'PNG', margin, y, w || 170, h || 55);
                    return y + (h || 55) + 4;
                } catch (e) {}
            }
            return y;
        }

        // ── Page 1: Cover with large logo ───────────────────────────
        pdf.setFillColor(255, 255, 255);
        pdf.rect(0, 0, pageW, pageH, 'F');
        if (coverLogo) {
            pdf.addImage(coverLogo, 'PNG', (pageW - 60) / 2, 35, 60, 60);
        }
        pdf.setFontSize(22);
        pdf.setTextColor(0, 102, 204);
        pdf.setFont(undefined, 'bold');
        pdf.text('ZIoCHub', pageW / 2, coverLogo ? 110 : 50, { align: 'center' });
        pdf.setFont(undefined, 'normal');
        pdf.setFontSize(10);
        pdf.setTextColor(100, 100, 100);
        pdf.text('Intelligence Operations Platform', pageW / 2, (coverLogo ? 118 : 58), { align: 'center' });
        pdf.setFontSize(14);
        pdf.setTextColor(0, 0, 0);
        pdf.setFont(undefined, 'bold');
        var reportName = data.report_name || 'Intelligence Report';
        var reportLines = pdf.splitTextToSize(reportName, pageW - 40);
        var reportY = (coverLogo ? 135 : 75);
        reportLines.forEach(function (line) {
            pdf.text(line, pageW / 2, reportY, { align: 'center' });
            reportY += 8;
        });
        pdf.setFont(undefined, 'normal');
        pdf.setFontSize(10);
        pdf.setTextColor(80, 80, 80);
        pdf.text('Period: ' + data.start_date + ' - ' + data.end_date, pageW / 2, reportY + 10, { align: 'center' });
        pdf.text('Generated: ' + new Date().toISOString().split('T')[0], pageW / 2, reportY + 18, { align: 'center' });

        // ── Page 2: Table of Contents ─────────────────────────────
        pdf.addPage();
        pdf.setFillColor(255, 255, 255);
        pdf.rect(0, 0, pageW, pageH, 'F');
        if (headerLogo) pdf.addImage(headerLogo, 'PNG', margin, 8, 12, 12);
        pdf.setFontSize(10);
        pdf.setTextColor(0, 102, 204);
        pdf.setFont(undefined, 'bold');
        pdf.text('ZIoCHub', margin + 14, 14);
        pdf.setFont(undefined, 'normal');
        pdf.setFontSize(9);
        pdf.setTextColor(100, 100, 100);
        pdf.text('IOC & YARA Management', pageW - margin, 14, { align: 'right' });
        pdf.line(margin, 20, pageW - margin, 20);
        var tocY = 35;
        pdf.setFontSize(14);
        pdf.setTextColor(0, 0, 0);
        pdf.setFont(undefined, 'bold');
        pdf.text('Table of Contents', margin, tocY);
        tocY += 12;
        var tocItems = [
            '1. Executive Dashboard',
            '2. IOC Type Distribution',
            '3. Submission Rate',
            '4. Top Countries',
            '5. Top Campaigns',
            '6. Campaigns Created by Analyst',
            '7. Submission Methods',
            '8. Expiration Policy',
            '9. TLD Intelligence',
            '10. IOC Quality Indicators',
            '11. Feed Anomalies',
            '12. YARA Quality',
            '13. Rare Finds',
            '14. Analyst Spotlight'
        ];
        pdf.setFont(undefined, 'normal');
        pdf.setFontSize(10);
        tocItems.forEach(function (item) {
            pdf.text(item, margin, tocY);
            pdf.text('...', pageW - margin - 25, tocY);
            tocY += 7;
        });

        // ── Section 1: Executive Dashboard ────────────────────────
        var y = _addPageWithHeader(headerLogo);
        tocEntries.push({ title: '1. Executive Dashboard', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '1. Executive Dashboard');
        y = _sectionDesc(pdf, margin, y, 'Key performance indicators (KPIs) for the report period. These metrics provide management with a snapshot of the threat intelligence platform health: total active indicators, YARA rules in production, cleanup activity, active campaigns, net change in the feed, and overall feed health score.');
        y = _checkPage(pdf, y, headerLogo);
        var exec = data.executive || {};
        var kpis = [
            ['Active IOCs', exec.active_iocs, 'Total active indicators at end of period'],
            ['YARA Rules', exec.yara_rules, 'Approved YARA rules in production'],
            ['Cleanup Score', exec.cleanup_count, 'Expired/deleted IOCs removed'],
            ['Active Campaigns', exec.active_campaigns, 'Campaigns with linked IOCs'],
            ['Net Change', exec.net_change, 'New IOCs minus removals'],
            ['Feed Health', exec.feed_health_score + '%', 'Quality score (100 - anomaly rate)'],
        ];
        pdf.setFontSize(9);
        pdf.setTextColor(0, 0, 0);
        kpis.forEach(function (row) {
            y = _checkPage(pdf, y, headerLogo);
            pdf.text(row[0] + ': ' + _formatNum(row[1]), margin, y);
            pdf.setTextColor(100, 100, 100);
            pdf.setFontSize(8);
            pdf.text(' - ' + row[2], margin + 55, y);
            pdf.setFontSize(9);
            pdf.setTextColor(0, 0, 0);
            y += lineH;
        });
        y += 2;
        y = _checkPage(pdf, y, headerLogo);
        pdf.setFontSize(9);
        pdf.setTextColor(60, 60, 60);
        var summary = (exec.summary_text || '').substring(0, 500);
        if (summary) {
            pdf.splitTextToSize(summary, pageW - margin * 2).forEach(function (line) {
                y = _checkPage(pdf, y, headerLogo);
                pdf.text(line, margin, y);
                y += lineH - 1;
            });
        }

        var ops = data.operations || {};

        // ── Section 2: IOC Type Distribution ─────────────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 70) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '2. IOC Type Distribution', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '2. IOC Type Distribution');
        y = _sectionDesc(pdf, margin, y, 'Distribution of IOC types (IP, Domain, Hash, Email, URL, YARA) in the feed. This bar chart shows which indicator types dominate the threat intelligence database and helps identify focus areas for collection.');
        y = _checkPage(pdf, y, headerLogo);
        y = _addChart(pdf, 'reportTypeChart', margin, y, 170, 55);
        if (ops.type_distribution && Object.keys(ops.type_distribution).length > 0) {
            y = _checkPage(pdf, y, headerLogo);
            Object.entries(ops.type_distribution).forEach(function (kv) {
                y = _checkPage(pdf, y, headerLogo);
                pdf.setFontSize(9);
                pdf.text('  ' + kv[0] + ': ' + kv[1], margin, y);
                y += lineH - 1;
            });
        }

        // ── Section 3: Submission Rate ─────────────────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 70) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '3. Submission Rate', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '3. Submission Rate');
        y = _sectionDesc(pdf, margin, y, 'Daily submission volume over the report period. The line chart compares team submissions (manual) versus MISP sync (automated). This helps identify reliance on automation and detect spikes from cyber events.');
        y = _checkPage(pdf, y, headerLogo);
        y = _addChart(pdf, 'reportRateChart', margin, y, 170, 55);

        // ── Section 4: Top Countries ───────────────────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 50) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '4. Top Countries', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '4. Top Countries');
        y = _sectionDesc(pdf, margin, y, 'Geographic distribution of threat indicators by country code (GeoIP). Shows where malicious infrastructure is concentrated and helps prioritize regional threat awareness.');
        y = _checkPage(pdf, y, headerLogo);
        if (ops.top_countries && ops.top_countries.length > 0) {
            ops.top_countries.slice(0, 10).forEach(function (c) {
                y = _checkPage(pdf, y, headerLogo);
                pdf.setFontSize(9);
                pdf.text('  ' + (c.code || '').toUpperCase() + ' (' + getCountryName(c.code || '') + '): ' + c.count, margin, y);
                y += lineH - 1;
            });
        }

        // ── Section 5: Top Campaigns ───────────────────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 50) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '5. Top Campaigns', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '5. Top Campaigns');
        y = _sectionDesc(pdf, margin, y, 'Campaigns with the most linked IOCs and YARA rules. Indicates where the team is most invested and which threat actors or operations are being tracked.');
        y = _checkPage(pdf, y, headerLogo);
        if (ops.top_campaigns && ops.top_campaigns.length > 0) {
            ops.top_campaigns.slice(0, 10).forEach(function (c) {
                y = _checkPage(pdf, y, headerLogo);
                pdf.setFontSize(9);
                pdf.text('  ' + (c.name || '') + ': ' + c.ioc_count + ' IOCs, ' + (c.yara_count || 0) + ' YARA', margin, y);
                y += lineH - 1;
            });
        }

        // ── Section 6: Campaigns Created by Analyst ─────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 50) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '6. Campaigns Created by Analyst', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '6. Campaigns Created by Analyst');
        y = _sectionDesc(pdf, margin, y, 'Campaigns created in the report period, grouped by analyst. Shows which analysts contributed new campaigns and the IOC counts per campaign.');
        y = _checkPage(pdf, y, headerLogo);
        var campaignsByAnalyst = (ops.campaigns_created_by_analyst || []);
        if (campaignsByAnalyst.length > 0) {
            campaignsByAnalyst.forEach(function (analyst) {
                y = _checkPage(pdf, y, headerLogo);
                pdf.setFontSize(10);
                pdf.setFont(undefined, 'bold');
                pdf.setTextColor(0, 102, 204);
                pdf.text((analyst.display_name || analyst.analyst || ''), margin, y);
                pdf.setFont(undefined, 'normal');
                pdf.setTextColor(0, 0, 0);
                y += lineH;
                (analyst.campaigns || []).forEach(function (c) {
                    y = _checkPage(pdf, y, headerLogo);
                    pdf.setFontSize(9);
                    var typesStr = Object.entries(c.ioc_types || {}).map(function (kv) { return kv[0] + ': ' + kv[1]; }).join(', ') || '-';
                    pdf.text('  • ' + (c.name || '') + ' - ' + (c.ioc_count || 0) + ' IOCs (' + typesStr + ')', margin + 5, y);
                    y += lineH - 1;
                });
                y += 2;
            });
        } else {
            pdf.setFontSize(9);
            pdf.setTextColor(100, 100, 100);
            pdf.text('  No campaigns created in this period.', margin, y);
            y += lineH;
        }

        // ── Section 7: Submission Methods ───────────────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 50) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '7. Submission Methods', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '7. Submission Methods');
        y = _sectionDesc(pdf, margin, y, 'Breakdown of how analysts submit indicators: single manual entry, CSV upload, TXT upload, paste, or MISP sync. Reflects team workflow preferences and automation usage.');
        y = _checkPage(pdf, y, headerLogo);
        if (ops.submission_methods && Object.keys(ops.submission_methods).length > 0) {
            Object.entries(ops.submission_methods).forEach(function (kv) {
                y = _checkPage(pdf, y, headerLogo);
                pdf.setFontSize(9);
                var methodLabel = { single: 'Single (Manual)', csv_upload: 'CSV Upload', txt_upload: 'TXT Upload', paste: 'Paste', misp_sync: 'MISP Sync' }[kv[0]] || kv[0];
                pdf.text('  ' + methodLabel + ': ' + kv[1], margin, y);
                y += lineH - 1;
            });
        }

        // ── Section 8: Expiration Policy ───────────────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 50) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '8. Expiration Policy', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '8. Expiration Policy');
        y = _sectionDesc(pdf, margin, y, 'Distribution of IOCs by expiration status: permanent (no expiry date), active with expiry, and expired (not yet cleaned). Shows feed maintenance and how much of the feed is time-bound.');
        y = _checkPage(pdf, y, headerLogo);
        if (ops.expiration_policy) {
            pdf.setFontSize(9);
            pdf.text('  Permanent: ' + (ops.expiration_policy.permanent || 0), margin, y);
            y += lineH - 1;
            pdf.text('  Active (with expiry): ' + (ops.expiration_policy.active_expiry || 0), margin, y);
            y += lineH - 1;
            pdf.text('  Expired: ' + (ops.expiration_policy.expired || 0), margin, y);
        }

        // ── Section 9: TLD Intelligence ───────────────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 70) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '9. TLD Intelligence', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '9. TLD Intelligence');
        y = _sectionDesc(pdf, margin, y, 'Top-level domain distribution of malicious domains. Identifies which TLDs (e.g. .com, .ru, .xyz) host the most threat indicators and supports DNS-based blocking strategies.');
        y = _checkPage(pdf, y, headerLogo);
        y = _addChart(pdf, 'reportTldChart', margin, y, 170, 55);
        if (ops.top_tlds && ops.top_tlds.length > 0) {
            ops.top_tlds.slice(0, 10).forEach(function (t) {
                y = _checkPage(pdf, y, headerLogo);
                pdf.setFontSize(9);
                pdf.text('  .' + (t.tld || '') + ': ' + t.count, margin, y);
                y += lineH - 1;
            });
        }

        // ── Section 10: IOC Quality ─────────────────────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 60) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '10. IOC Quality Indicators', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '10. IOC Quality Indicators');
        y = _sectionDesc(pdf, margin, y, 'Metadata richness of submitted IOCs: percentage with comments, ticket IDs, campaign links, and tags. Higher values indicate better documentation and traceability.');
        y = _checkPage(pdf, y, headerLogo);
        var iq = ops.ioc_quality || {};
        if (Object.keys(iq).length > 0) {
            [
                ['With Comment', (iq.with_comment_pct || 0) + '%'],
                ['With Ticket', (iq.with_ticket_pct || 0) + '%'],
                ['With Campaign', (iq.with_campaign_pct || 0) + '%'],
                ['With Tags', (iq.with_tags_pct || 0) + '%'],
                ['Avg Comment Length', Math.round(iq.avg_comment_length || 0) + ' chars']
            ].forEach(function (row) {
                y = _checkPage(pdf, y, headerLogo);
                pdf.setFontSize(9);
                pdf.text('  ' + row[0] + ': ' + row[1], margin, y);
                y += lineH - 1;
            });
        }

        // ── Section 11: Feed Anomalies ─────────────────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 50) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '11. Feed Anomalies', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '11. Feed Anomalies');
        y = _sectionDesc(pdf, margin, y, 'Quality issues detected in the feed: stale IOCs, private IPs, popular domains, DGA suspects, etc. These anomalies should be reviewed and cleaned to maintain feed integrity.');
        y = _checkPage(pdf, y, headerLogo);
        if (ops.anomalies_summary && ops.anomalies_summary.length > 0) {
            ops.anomalies_summary.forEach(function (a) {
                y = _checkPage(pdf, y, headerLogo);
                var label = anomalyTypeLabels[a.type] || a.type;
                pdf.setFontSize(9);
                pdf.text('  ' + label + ': ' + a.count, margin, y);
                y += lineH - 1;
            });
        }

        // ── Section 12: YARA Quality ───────────────────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 70) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '12. YARA Quality', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '12. YARA Quality');
        y = _sectionDesc(pdf, margin, y, 'Quality metrics for YARA rules: approved count, pending review, average quality score, and linkage to campaigns and tickets. Indicates rule maturity and documentation.');
        y = _checkPage(pdf, y, headerLogo);
        y = _addChart(pdf, 'reportYaraChart', margin, y, 170, 50);
        var yq = ops.yara_quality || {};
        if (Object.keys(yq).length > 0) {
            pdf.setFontSize(9);
            y = _checkPage(pdf, y, headerLogo);
            pdf.text('  Approved: ' + (yq.total_approved || 0) + ', Pending: ' + (yq.pending || 0) + ', Avg Score: ' + (yq.avg_quality || 0), margin, y);
            y += lineH;
        }

        // ── Section 13: Rare Finds ─────────────────────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 50) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '13. Rare Finds', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '13. Rare Finds');
        y = _sectionDesc(pdf, margin, y, 'First-ever discoveries in the system: new countries, TLDs, or email domains never seen before. Highlights unique analyst contributions and emerging threat patterns.');
        y = _checkPage(pdf, y, headerLogo);
        if (ops.rare_finds && ops.rare_finds.length > 0) {
            ops.rare_finds.slice(0, 10).forEach(function (r) {
                y = _checkPage(pdf, y, headerLogo);
                var detail = r.type === 'country' && r.detail ? getCountryName(r.detail) : (r.detail || r.value);
                pdf.setFontSize(9);
                pdf.text('  ' + r.type + ': ' + detail + ' (' + (r.value || '').substring(0, 35) + '...) by ' + (r.discoverer || ''), margin, y);
                y += lineH - 1;
            });
        }

        // ── Section 14: Analyst Spotlight ──────────────────────────
        y = _checkPage(pdf, y, headerLogo);
        if (y > yMax - 50) { y = _addPageWithHeader(headerLogo); }
        if (y > 28) y += lineH;
        tocEntries.push({ title: '14. Analyst Spotlight', page: pdf.getNumberOfPages() });
        y = _sectionTitle(pdf, margin, y, '14. Analyst Spotlight');
        y = _sectionDesc(pdf, margin, y, 'Top analysts by score for the period. Includes IOCs submitted, YARA rules contributed, cleanup activity, and streak. Recognizes team performance and encourages engagement.');
        y = _checkPage(pdf, y, headerLogo);
        var analysts = data.analysts || {};
        var leaderboard = analysts.leaderboard || [];
        if (leaderboard.length > 0) {
            pdf.setFontSize(9);
            leaderboard.slice(0, 15).forEach(function (a, i) {
                y = _checkPage(pdf, y, headerLogo);
                pdf.text('#' + (i + 1) + ' ' + (a.display_name || a.analyst || '') + ' - ' + a.total_iocs + ' IOCs, ' + (a.yara_count || 0) + ' YARA, Score: ' + (a.score || 0), margin, y);
                y += lineH - 1;
            });
        }

        // ── Update TOC with page numbers ───────────────────────────
        var pageMap = {};
        tocEntries.forEach(function (e) { pageMap[e.title] = e.page; });
        pdf.setPage(2);
        tocY = 47;
        tocItems.forEach(function (item) {
            var p = pageMap[item] || '-';
            pdf.text(String(p), pageW - margin - 15, tocY, { align: 'right' });
            tocY += 7;
        });

        _pdfFooter(pdf, pageW, pageH);
        pdf.save(_pdfFilename(data));
        if (window.showToast) window.showToast('PDF exported successfully', 'success');
    }

    function _pdfFilename(data) {
        return 'ZIoCHub_Report_' + (data.period || 'week') + '_' + (data.start_date || 'unknown') + '.pdf';
    }

    // ── Initialize on tab activation ─────────────────────────────
    loadReportsList(currentPeriod);

})();
