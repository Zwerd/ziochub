/**
 * Live Stats tab logic (Step 10.1 - extracted from index.html).
 * Depends on: window.apiFetch, window.escapeHtml, window.escapeAttr, window.copyToClipboard,
 * window.t, window.getThemeColor, window.getIocTypeIcon, window.translations, window.currentLang.
 * Exposes: window.loadStats, window.loadLiveFeed, window.loadHistoricalIocs, window.threatChart.
 */
(function(global) {
    'use strict';

    function escapeHtml(s) {
        if (typeof global.escapeHtml === 'function') return global.escapeHtml(s);
        if (s == null || s === '') return '';
        return String(s);
    }
    function escapeAttr(s) {
        if (typeof global.escapeAttr === 'function') return global.escapeAttr(s);
        if (s == null || s === '') return '';
        return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    let threatChart = null;
    global.threatChart = null;

    let _lastLeaderboardData = { topCountriesList: null, topTLDsList: null, topEmailDomainsList: null, topCampaignsList: null };

    const COUNTRY_NAMES = { ad: 'Andorra', ae: 'United Arab Emirates', af: 'Afghanistan', ag: 'Antigua and Barbuda', ai: 'Anguilla', al: 'Albania', am: 'Armenia', ao: 'Angola', aq: 'Antarctica', ar: 'Argentina', as: 'American Samoa', at: 'Austria', au: 'Australia', aw: 'Aruba', ax: 'Åland Islands', az: 'Azerbaijan', ba: 'Bosnia and Herzegovina', bb: 'Barbados', bd: 'Bangladesh', be: 'Belgium', bf: 'Burkina Faso', bg: 'Bulgaria', bh: 'Bahrain', bi: 'Burundi', bj: 'Benin', bl: 'Saint Barthélemy', bm: 'Bermuda', bn: 'Brunei', bo: 'Bolivia', bq: 'Caribbean Netherlands', br: 'Brazil', bs: 'Bahamas', bt: 'Bhutan', bv: 'Bouvet Island', bw: 'Botswana', by: 'Belarus', bz: 'Belize', ca: 'Canada', cc: 'Cocos (Keeling) Islands', cd: 'Democratic Republic of the Congo', cf: 'Central African Republic', cg: 'Republic of the Congo', ch: 'Switzerland', ci: 'Ivory Coast', ck: 'Cook Islands', cl: 'Chile', cm: 'Cameroon', cn: 'China', co: 'Colombia', cr: 'Costa Rica', cu: 'Cuba', cv: 'Cape Verde', cw: 'Curaçao', cx: 'Christmas Island', cy: 'Cyprus', cz: 'Czech Republic', de: 'Germany', dj: 'Djibouti', dk: 'Denmark', dm: 'Dominica', do: 'Dominican Republic', dz: 'Algeria', ec: 'Ecuador', ee: 'Estonia', eg: 'Egypt', eh: 'Western Sahara', er: 'Eritrea', es: 'Spain', et: 'Ethiopia', fi: 'Finland', fj: 'Fiji', fk: 'Falkland Islands', fm: 'Micronesia', fo: 'Faroe Islands', fr: 'France', ga: 'Gabon', gb: 'United Kingdom', gd: 'Grenada', ge: 'Georgia', gf: 'French Guiana', gg: 'Guernsey', gh: 'Ghana', gi: 'Gibraltar', gl: 'Greenland', gm: 'Gambia', gn: 'Guinea', gp: 'Guadeloupe', gq: 'Equatorial Guinea', gr: 'Greece', gs: 'South Georgia and the South Sandwich Islands', gt: 'Guatemala', gu: 'Guam', gw: 'Guinea-Bissau', gy: 'Guyana', hk: 'Hong Kong', hm: 'Heard Island and McDonald Islands', hn: 'Honduras', hr: 'Croatia', ht: 'Haiti', hu: 'Hungary', id: 'Indonesia', ie: 'Ireland', il: 'Israel', im: 'Isle of Man', in: 'India', io: 'British Indian Ocean Territory', iq: 'Iraq', ir: 'Iran', is: 'Iceland', it: 'Italy', je: 'Jersey', jm: 'Jamaica', jo: 'Jordan', jp: 'Japan', ke: 'Kenya', kg: 'Kyrgyzstan', kh: 'Cambodia', ki: 'Kiribati', km: 'Comoros', kn: 'Saint Kitts and Nevis', kp: 'North Korea', kr: 'South Korea', kw: 'Kuwait', ky: 'Cayman Islands', kz: 'Kazakhstan', la: 'Laos', lb: 'Lebanon', lc: 'Saint Lucia', li: 'Liechtenstein', lk: 'Sri Lanka', lr: 'Liberia', ls: 'Lesotho', lt: 'Lithuania', lu: 'Luxembourg', lv: 'Latvia', ly: 'Libya', ma: 'Morocco', mc: 'Monaco', md: 'Moldova', me: 'Montenegro', mf: 'Saint Martin', mg: 'Madagascar', mh: 'Marshall Islands', mk: 'North Macedonia', ml: 'Mali', mm: 'Myanmar', mn: 'Mongolia', mo: 'Macau', mp: 'Northern Mariana Islands', mq: 'Martinique', mr: 'Mauritania', ms: 'Montserrat', mt: 'Malta', mu: 'Mauritius', mv: 'Maldives', mw: 'Malawi', mx: 'Mexico', my: 'Malaysia', mz: 'Mozambique', na: 'Namibia', nc: 'New Caledonia', ne: 'Niger', nf: 'Norfolk Island', ng: 'Nigeria', ni: 'Nicaragua', nl: 'Netherlands', no: 'Norway', np: 'Nepal', nr: 'Nauru', nu: 'Niue', nz: 'New Zealand', om: 'Oman', pa: 'Panama', pe: 'Peru', pf: 'French Polynesia', pg: 'Papua New Guinea', ph: 'Philippines', pk: 'Pakistan', pl: 'Poland', pm: 'Saint Pierre and Miquelon', pn: 'Pitcairn Islands', pr: 'Puerto Rico', ps: 'Palestine', pt: 'Portugal', pw: 'Palau', py: 'Paraguay', qa: 'Qatar', re: 'Réunion', ro: 'Romania', rs: 'Serbia', ru: 'Russia', rw: 'Rwanda', sa: 'Saudi Arabia', sb: 'Solomon Islands', sc: 'Seychelles', sd: 'Sudan', se: 'Sweden', sg: 'Singapore', sh: 'Saint Helena, Ascension and Tristan da Cunha', si: 'Slovenia', sj: 'Svalbard and Jan Mayen', sk: 'Slovakia', sl: 'Sierra Leone', sm: 'San Marino', sn: 'Senegal', so: 'Somalia', sr: 'Suriname', ss: 'South Sudan', st: 'São Tomé and Príncipe', sv: 'El Salvador', sx: 'Sint Maarten', sy: 'Syria', sz: 'Eswatini', tc: 'Turks and Caicos Islands', td: 'Chad', tf: 'French Southern and Antarctic Lands', tg: 'Togo', th: 'Thailand', tj: 'Tajikistan', tk: 'Tokelau', tl: 'Timor-Leste', tm: 'Turkmenistan', tn: 'Tunisia', to: 'Tonga', tr: 'Turkey', tt: 'Trinidad and Tobago', tv: 'Tuvalu', tw: 'Taiwan', tz: 'Tanzania', ua: 'Ukraine', ug: 'Uganda', um: 'United States Minor Outlying Islands', un: 'United Nations', us: 'United States', uy: 'Uruguay', uz: 'Uzbekistan', va: 'Vatican City', vc: 'Saint Vincent and the Grenadines', ve: 'Venezuela', vg: 'British Virgin Islands', vi: 'United States Virgin Islands', vn: 'Vietnam', vu: 'Vanuatu', wf: 'Wallis and Futuna', ws: 'Samoa', xk: 'Kosovo', ye: 'Yemen', yt: 'Mayotte', za: 'South Africa', zm: 'Zambia', zw: 'Zimbabwe' };

    function getCountryName(code) {
        if (!code || typeof code !== 'string') return code || '';
        const name = COUNTRY_NAMES[code.toLowerCase()];
        return name || code.toUpperCase();
    }

    function renderGenericLeaderboard(containerId, data, iconClass) {
        try {
            const container = document.getElementById(containerId);
            if (!container) return;
            if (!data || typeof data !== 'object' || Object.keys(data).length === 0) {
                container.innerHTML = '<div class="text-center text-secondary py-8 text-sm">No data available</div>';
                return;
            }
            const sorted = Object.keys(data).filter(key => data[key] > 0).sort((a, b) => data[b] - data[a]).slice(0, 50);
            if (sorted.length === 0) {
                container.innerHTML = '<div class="text-center text-secondary py-8 text-sm">No data available</div>';
                return;
            }
            const maxCount = Math.max(...sorted.map(key => data[key]));
            if (maxCount <= 0) {
                container.innerHTML = '<div class="text-center text-secondary py-8 text-sm">No data available</div>';
                return;
            }
                container.innerHTML = sorted.map((key, index) => {
                const count = data[key];
                const percentage = (count / maxCount) * 100;
                const rank = index + 1;
                let barColor = rank === 1 ? '#00ff41' : rank <= 3 ? '#00d4ff' : rank <= 5 ? '#8b5cf6' : '#3b82f6';
                let iconHtml = '', labelHtml = '';
                if (iconClass === 'flag') {
                    const cc = key.toLowerCase();
                    const countryName = getCountryName(cc);
                    iconHtml = `<span class="inline-flex flex-shrink-0 w-6 h-6 rounded-full overflow-hidden border border-white/20" title="${escapeHtml(countryName)}"><img src="/static/flags/1x1/${escapeHtml(cc)}.svg" alt="" class="w-full h-full object-cover" loading="lazy" onerror="this.style.background='var(--bg-tertiary)'"></span>`;
                } else if (iconClass === 'globe' || iconClass === 'envelope' || iconClass === 'target') {
                    labelHtml = `<span class="text-sm font-semibold" style="color: var(--text-primary);" title="${escapeAttr(key)}">${escapeHtml(key)}</span>`;
                }
                return `
                    <div class="country-leaderboard-row flex items-center gap-2 py-1 w-full">
                        <div class="flex-shrink-0 flex items-center max-w-[140px] truncate">${iconHtml}${labelHtml}</div>
                        <div class="flex-1 min-w-0 flex flex-col justify-center">
                            <div class="country-bar h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden w-full">
                                <div class="country-bar-fill h-full rounded-full transition-all duration-300" style="width: ${percentage}%; background-color: ${barColor};"></div>
                            </div>
                        </div>
                        <div class="country-count flex-shrink-0 w-auto min-w-[24px] text-right text-base font-bold font-mono" style="color: var(--text-primary);">${count}</div>
                    </div>
                `;
            }).join('');
        } catch (error) {
            console.error('Error rendering leaderboard ' + containerId, error);
            const container = document.getElementById(containerId);
            if (container) container.innerHTML = '<div class="text-center text-secondary py-8 text-sm">Error loading data</div>';
        }
    }

    const dataLabelsPlugin = {
        id: 'dataLabels',
        afterDatasetsDraw: (chart) => {
            const ctx = chart.ctx;
            ctx.save();
            ctx.font = 'bold 14px Arial';
            const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            ctx.fillStyle = isDark ? '#FFFFFF' : '#000000';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.strokeStyle = isDark ? '#000000' : '#FFFFFF';
            ctx.lineWidth = 2;
            chart.data.datasets.forEach((dataset, datasetIndex) => {
                const meta = chart.getDatasetMeta(datasetIndex);
                meta.data.forEach((bar, index) => {
                    const value = dataset.data[index];
                    if (value != null && value > 0) {
                        let x, y;
                        if (chart.config.type === 'bar' && chart.config.options.indexAxis === 'y') {
                            x = bar.x + (bar.width / 2); y = bar.y;
                        } else if (chart.config.type === 'bar') {
                            x = bar.x; y = bar.y - 15;
                        } else if (chart.config.type === 'doughnut') {
                            const arc = bar;
                            const angle = (arc.startAngle + arc.endAngle) / 2;
                            const radius = (arc.innerRadius + arc.outerRadius) / 2;
                            x = arc.x + Math.cos(angle) * radius; y = arc.y + Math.sin(angle) * radius;
                        } else return;
                        ctx.strokeText(value.toString(), x, y);
                        ctx.fillText(value.toString(), x, y);
                    }
                });
            });
            ctx.restore();
        }
    };

    const cyberColors = { blue: '#3b82f6', purple: '#8b5cf6', red: '#ef4444', green: '#00ff41', cyan: '#00d4ff', orange: '#f97316', yellow: '#eab308', pink: '#ec4899' };

    function getThemeColor(type) {
        if (typeof global.getThemeColor === 'function') return global.getThemeColor(type);
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        return isDark ? '#ffffff' : '#1a1a1a';
    }

    function renderCharts(iocs) {
        try {
            if (typeof Chart === 'undefined') return;
            const champsTabActive = !document.getElementById('tab-champs')?.classList.contains('hidden');
            if (!champsTabActive) return;
            if (threatChart) {
                try { threatChart.destroy(); } catch (e) {}
                threatChart = null;
                global.threatChart = null;
            }
            const dateCounts = {};
            (iocs || []).forEach(item => {
                if (item.date) {
                    const dateStr = item.date.split('T')[0];
                    dateCounts[dateStr] = (dateCounts[dateStr] || 0) + 1;
                }
            });
            const sortedDates = Object.keys(dateCounts).sort();
            if (champsTabActive) {
                const velocityCtx = document.getElementById('threatVelocityChart');
                if (velocityCtx) {
                    threatChart = new Chart(velocityCtx.getContext('2d'), {
                        type: 'line',
                        plugins: [dataLabelsPlugin],
                        data: {
                            labels: sortedDates,
                            datasets: [{ label: 'IOCs Added', data: sortedDates.map(d => dateCounts[d]), borderColor: cyberColors.blue, backgroundColor: cyberColors.blue + '40', borderWidth: 2, fill: true, tension: 0.4, pointRadius: 3, pointHoverRadius: 5 }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: { legend: { display: true, labels: { color: getThemeColor('text') } } },
                            scales: {
                                x: { ticks: { color: getThemeColor('text'), maxRotation: 45, minRotation: 45 }, grid: { color: getThemeColor('grid') } },
                                y: { beginAtZero: true, ticks: { color: getThemeColor('text'), stepSize: 1 }, grid: { color: getThemeColor('grid') } }
                            }
                        }
                    });
                    global.threatChart = threatChart;
                }
            }
        } catch (error) {
            console.error('Error in renderCharts:', error);
        }
    }

    function updateLiveFeed(iocs) {
        const t = typeof global.t === 'function' ? global.t : function(k) { return k; };
        const getIocTypeIcon = typeof global.getIocTypeIcon === 'function' ? global.getIocTypeIcon : () => '';
        const copyToClipboard = typeof global.copyToClipboard === 'function' ? global.copyToClipboard : () => {};
        try {
            const sortedIocs = [...(iocs || [])].sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0)).slice(0, 50);
            const feedContainer = document.getElementById('liveFeed');
            if (!feedContainer) return;
            const now = new Date();
            const syncDiv = `<div class="col-span-full mb-3 pb-3 border-b border-white/10 text-center"><div class="text-xs text-secondary font-mono">${t('feed.last_sync')}: ${now.toLocaleTimeString()}</div></div>`;
            if (sortedIocs.length > 0) {
                    const itemsHtml = sortedIocs.map(item => {
                    const icon = getIocTypeIcon(item.file_type, item.ioc, item.country_code);
                    const comment = (item.comment && item.comment.trim()) ? escapeHtml(item.comment.trim()) : '';
                    const meta = [item.file_type, escapeHtml(item.user || ''), comment, new Date(item.date).toLocaleDateString()].filter(Boolean).join(' • ');
                    return `<div class="bg-tertiary rounded p-3 text-sm">
                        <div class="font-mono accent-blue flex items-center justify-between gap-2 min-w-0">
                            <span class="flex-1 min-w-0 truncate">${icon} ${escapeHtml(item.ioc || '')}</span>
                            <button type="button" class="copy-ioc-btn btn-cmd-neutral text-xs flex-shrink-0 ml-2" onclick="copyToClipboard(this.getAttribute('data-ioc'))" data-ioc="${escapeAttr(item.ioc || '')}" title="${t('actions.copy')}">${t('actions.copy')}</button>
                        </div>
                        <div class="text-secondary text-xs mt-1">${meta}</div>
                    </div>`;
                }).join('');
                feedContainer.innerHTML = syncDiv + itemsHtml;
            } else {
                feedContainer.innerHTML = syncDiv + `<div class="col-span-full text-center text-secondary py-8 text-sm">${t('feed.no_data')}</div>`;
            }
        } catch (error) {
            console.error('Error updating live feed:', error);
        }
    }

    function updateCharts(iocs) {
        try {
            const champsTabActive = !document.getElementById('tab-champs')?.classList.contains('hidden');
            if (threatChart && champsTabActive && iocs && iocs.length > 0) {
                const dateCounts = {};
                iocs.forEach(item => {
                    if (item.date) {
                        const dateStr = item.date.split('T')[0];
                        dateCounts[dateStr] = (dateCounts[dateStr] || 0) + 1;
                    }
                });
                const sortedDates = Object.keys(dateCounts).sort();
                threatChart.data.labels = sortedDates;
                threatChart.data.datasets[0].data = sortedDates.map(d => dateCounts[d]);
                threatChart.update('none');
            }
        } catch (error) {
            console.error('Error updating charts:', error);
        }
    }

    async function loadStats() {
        const apiFetch = global.apiFetch;
        if (typeof apiFetch !== 'function') return;
        const el = id => document.getElementById(id);
        function animateCounter(element, newValue) {
            if (!element) return;
            const target = parseInt(newValue, 10);
            if (isNaN(target)) { element.textContent = newValue ?? '-'; return; }
            if (element._statsAnimationTimer) {
                clearInterval(element._statsAnimationTimer);
                element._statsAnimationTimer = null;
            }
            const current = parseInt(element.textContent, 10) || 0;
            if (current === target) return;
            const diff = target - current;
            const duration = 400;
            const steps = 20;
            const stepTime = duration / steps;
            let step = 0;
            const timer = setInterval(() => {
                step++;
                const progress = step / steps;
                const eased = 1 - Math.pow(1 - progress, 3);
                element.textContent = Math.round(current + diff * eased);
                if (step >= steps) {
                    clearInterval(timer);
                    element._statsAnimationTimer = null;
                    element.textContent = target;
                }
            }, stepTime);
            element._statsAnimationTimer = timer;
        }
        function applyCounts(s, yaraCount) {
            if (!s) return;
            animateCounter(el('statIP'), s['IP'] ?? s['ip']);
            animateCounter(el('statDomain'), s['Domain'] ?? s['domain']);
            animateCounter(el('statHash'), s['Hash'] ?? s['hash']);
            animateCounter(el('statEmail'), s['Email'] ?? s['email']);
            animateCounter(el('statURL'), s['URL'] ?? s['url']);
            animateCounter(el('statYara'), yaraCount);
        }
        const ts = new Date().getTime();
        try {
            const [countsResult, result] = await Promise.all([
                apiFetch('/api/stats/counts?_t=' + ts),
                apiFetch('/api/stats?_t=' + ts)
            ]);
            if (countsResult && countsResult.success) applyCounts(countsResult.stats || {}, countsResult.yara_count);
            if (result && result.success) {
                const s = result.stats || {};
                applyCounts(s, result.yara_count);
                function stableDataKey(obj) {
                    if (!obj || typeof obj !== 'object') return JSON.stringify(obj);
                    return JSON.stringify(Object.keys(obj).sort().map(k => [k, obj[k]]));
                }
                function renderIfChanged(containerId, data, iconClass) {
                    const key = stableDataKey(data);
                    if (_lastLeaderboardData[containerId] === key) return;
                    _lastLeaderboardData[containerId] = key;
                    renderGenericLeaderboard(containerId, data, iconClass);
                }
                renderIfChanged('topCampaignsList', result.campaign_stats || {}, 'target');
                renderIfChanged('topCountriesList', result.country_counts || {}, 'flag');
                renderIfChanged('topTLDsList', result.tld_counts || {}, 'globe');
                renderIfChanged('topEmailDomainsList', result.email_domain_counts || {}, 'envelope');
            }
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }

    async function loadLiveFeed() {
        const t = typeof global.t === 'function' ? global.t : k => k;
        const translations = global.translations || {};
        const currentLang = global.currentLang || 'en';
        try {
            const response = await fetch('/api/recent?limit=50');
            const result = await response.json();
            const feedContainer = document.getElementById('liveFeed');
            if (!feedContainer) return;
            const syncDiv = `<div class="col-span-full mb-3 pb-3 border-b border-white/10 text-center"><div class="text-xs text-secondary font-mono">${t('feed.last_sync')}: ${new Date().toLocaleTimeString()}</div></div>`;
            if (result.success && result.recent && result.recent.length > 0) {
                const getIocTypeIcon = typeof global.getIocTypeIcon === 'function' ? global.getIocTypeIcon : () => '';
                const itemsHtml = result.recent.map(item => {
                    const isYara = item.type === 'YARA' || item.file_type === 'YARA';
                    const icon = getIocTypeIcon(item.file_type || item.type, item.ioc || item.value, item.country_code);
                    const date = item.date ? new Date(item.date).toLocaleDateString() : '';
                    const comment = (item.comment && item.comment.trim()) ? escapeHtml(item.comment.trim()) : '';
                    const meta = [item.file_type || item.type, escapeHtml(item.user || item.analyst || ''), comment, date].filter(Boolean).join(' • ');
                    const displayValue = item.ioc || item.value || '';
                    const valueClass = isYara ? 'font-mono text-amber-400 flex items-center justify-between gap-2 min-w-0' : 'font-mono accent-blue flex items-center justify-between gap-2 min-w-0';
                    return `<div class="bg-tertiary rounded p-3 text-sm ${isYara ? 'border-l-2 border-amber-400/60' : ''}">
                        <div class="${valueClass}">
                            <span class="flex-1 min-w-0 truncate">${icon} ${escapeHtml(displayValue)}</span>
                            <button type="button" class="copy-ioc-btn btn-cmd-neutral text-xs flex-shrink-0 ml-2" onclick="copyToClipboard(this.getAttribute('data-ioc'))" data-ioc="${escapeAttr(displayValue)}" title="${t('actions.copy')}">${t('actions.copy')}</button>
                        </div>
                        <div class="text-secondary text-xs mt-1">${meta}</div>
                    </div>`;
                }).join('');
                feedContainer.innerHTML = syncDiv + itemsHtml;
            } else {
                const loadingMsg = (translations[currentLang] && translations[currentLang].feed && translations[currentLang].feed.loading) ? translations[currentLang].feed.loading : 'Loading...';
                feedContainer.innerHTML = syncDiv + `<div class="col-span-full text-center text-secondary py-8">${loadingMsg}</div>`;
            }
        } catch (error) {
            console.error('Error loading feed:', error);
            const feedContainer = document.getElementById('liveFeed');
            if (feedContainer) feedContainer.innerHTML = '<div class="col-span-full text-center text-secondary py-8">Error loading feed</div>';
        }
    }

    async function loadHistoricalIocs(updateOnly) {
        const loadingSpinner = document.getElementById('loading-spinner');
        try {
            const response = await fetch('/api/all-iocs?limit=500');
            const result = await response.json();
            if (result.success && result.iocs && result.iocs.length > 0) {
                if (updateOnly) {
                    updateCharts(result.iocs);
                    loadLiveFeed();
                    loadStats();
                } else {
                    renderCharts(result.iocs);
                    loadLiveFeed();
                }
                loadStats();
            } else {
                if (threatChart) {
                    try { threatChart.destroy(); } catch (e) {}
                    threatChart = null;
                    global.threatChart = null;
                }
            }
        } catch (error) {
            console.error('Error loading historical IOCs:', error);
        } finally {
            if (loadingSpinner) loadingSpinner.style.display = 'none';
        }
    }

    global.loadStats = loadStats;
    global.loadLiveFeed = loadLiveFeed;
    global.loadHistoricalIocs = loadHistoricalIocs;
    global.threatChart = threatChart;
})(typeof window !== 'undefined' ? window : this);
