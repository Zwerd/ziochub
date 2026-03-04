/**
 * Champs Analysis tab logic (Step 10.3 — extracted from index.html).
 * Depends on globals: escapeHtml, escapeAttr, showToast, t, authState, Chart, loadStats, loadLiveFeed.
 * Exposes: loadChampsAnalysis, startChampsTickerPolling, champsSpotlightChart.
 */
(function(global) {
    'use strict';

    let champsLeaderboardData = [];
    let champsSpotlightChart = null;
    let champsTickerMessages = [];
    let champsTickerPollInterval = null;
    let champsMispVisible = false;
    let champsMispData = null;

    const champsBadgeDescriptions = {
        on_fire: '5-day submission streak', warm_streak: '3-4 day streak', night_owl: 'Activity between 22:00-04:00',
        early_bird: 'Activity between 05:00-07:00', weekend_warrior: 'Activity on Friday or Saturday',
        rare_find: 'First-ever in system: new country, TLD, or email domain', dedicated: '30+ IOCs total', veteran: '80+ IOCs total',
        clean_slate: 'Removed at least one expired IOC', janitor: '5+ expired IOCs removed', cleanup_crew: '15+ expired IOCs removed',
        team_player: 'At least one IOC linked to a campaign', campaign_master: '10+ IOCs linked to campaigns',
        yara_rookie: 'Uploaded at least one YARA rule', yara_master: '3+ YARA rules', yara_legend: '8+ YARA rules',
        hash_hunter: '10+ hashes', domain_scout: '15+ domains', ip_tracker: '25+ IPs', url_surfer: '10+ URLs', phish_buster: '5+ emails',
        triple_threat: 'Submitted at least 3 IOC types', all_rounder: 'Submitted all 5 IOC types',
        consistent: 'Activity on 7+ different days (last 30)', ever_present: 'Activity on 15+ different days'
    };

    const BADGE_LABELS = {
        on_fire: '🔥 On Fire', night_owl: '🦉 Night Owl', rare_find: '💎 Rare Find', janitor: '🧹 Janitor',
        warm_streak: '🌡️ Warm Streak', early_bird: '🌞 Early Bird', weekend_warrior: '🗓️ Weekend Warrior',
        dedicated: '💪 Dedicated', veteran: '🎖️ Veteran', clean_slate: '✨ Clean Slate', cleanup_crew: '🧼 Cleanup Crew',
        team_player: '🤝 Team Player', campaign_master: '🎯 Campaign Master',
        yara_rookie: '📜 YARA Rookie', yara_master: '👑 YARA Master', yara_legend: '🏆 YARA Legend',
        hash_hunter: '🔐 Hash Hunter', domain_scout: '🌐 Domain Scout', ip_tracker: '📍 IP Tracker',
        url_surfer: '🏄 URL Surfer', phish_buster: '🎣 Phish Buster',
        triple_threat: '🎪 Triple Threat', all_rounder: '🌟 All-Rounder',
        consistent: '📅 Consistent', ever_present: '⚡ Ever Present'
    };

    const BADGE_CLASSES = {
        on_fire: 'champs-badge-fire', night_owl: 'champs-badge-owl', rare_find: 'champs-badge-rare', janitor: 'champs-badge-janitor',
        warm_streak: 'champs-badge-warm', early_bird: 'champs-badge-early', weekend_warrior: 'champs-badge-weekend',
        dedicated: 'champs-badge-dedicated', veteran: 'champs-badge-veteran', clean_slate: 'champs-badge-clean', cleanup_crew: 'champs-badge-cleanup',
        team_player: 'champs-badge-team', campaign_master: 'champs-badge-campaign',
        yara_rookie: 'champs-badge-yara-r', yara_master: 'champs-badge-yara-m', yara_legend: 'champs-badge-yara-l',
        hash_hunter: 'champs-badge-hash', domain_scout: 'champs-badge-domain', ip_tracker: 'champs-badge-ip',
        url_surfer: 'champs-badge-url', phish_buster: 'champs-badge-phish',
        triple_threat: 'champs-badge-triple', all_rounder: 'champs-badge-allround',
        consistent: 'champs-badge-consistent', ever_present: 'champs-badge-ever'
    };

    const BADGE_NAMES = {
        on_fire: 'On Fire', night_owl: 'Night Owl', rare_find: 'Rare Find', janitor: 'Janitor',
        warm_streak: 'Warm Streak', early_bird: 'Early Bird', weekend_warrior: 'Weekend Warrior',
        dedicated: 'Dedicated', veteran: 'Veteran', clean_slate: 'Clean Slate', cleanup_crew: 'Cleanup Crew',
        team_player: 'Team Player', campaign_master: 'Campaign Master',
        yara_rookie: 'YARA Rookie', yara_master: 'YARA Master', yara_legend: 'YARA Legend',
        hash_hunter: 'Hash Hunter', domain_scout: 'Domain Scout', ip_tracker: 'IP Tracker',
        url_surfer: 'URL Surfer', phish_buster: 'Phish Buster',
        triple_threat: 'Triple Threat', all_rounder: 'All-Rounder',
        consistent: 'Consistent', ever_present: 'Ever Present'
    };

    async function loadChampsAnalysis() {
        const listEl = document.getElementById('champsLadderList');
        if (!listEl) return;
        try {
            listEl.querySelectorAll('.champs-ladder-row').forEach(b => b.classList.remove('champs-ladder-selected'));
            const response = await fetch('/api/champs/leaderboard');
            const result = await response.json();
            if (result.success && result.leaderboard && result.leaderboard.length > 0) {
                champsLeaderboardData = result.leaderboard;
                listEl.innerHTML = result.leaderboard.map((a, i) => {
                    const rankClass = a.rank === 1 ? 'champs-rank-1' : a.rank === 2 ? 'champs-rank-2' : a.rank === 3 ? 'champs-rank-3' : '';
                    const scoreColorClass = a.rank === 1 ? 'champs-score-gold' : a.rank === 2 ? 'champs-score-silver' : a.rank === 3 ? 'champs-score-bronze' : 'champs-score-default';
                    const trendHtml = a.trend ? `<span class="champs-trend-bracket champs-trend-glow text-xs font-mono font-semibold ${a.trend.includes('▲') ? 'champs-trend-up' : a.trend.includes('▼') ? 'champs-trend-down' : ''}">${escapeHtml(a.trend)}</span>` : '';
                    const medal = a.medal || '';
                    const rankText = `#${a.rank}`;
                    const avatarUrl = a.avatar_url || '';
                    const displayName = escapeHtml(a.display_name || a.username || a.analyst);
                    const avatarSize = 'w-11 h-11';
                    const avatarHtml = avatarUrl
                        ? `<img src="${escapeAttr(avatarUrl)}" alt="" class="w-full h-full object-cover" onerror="this.onerror=null;this.parentElement.innerHTML='<span class=\\'text-lg\\'>👤</span>'">`
                        : '<span class="text-sm">👤</span>';
                    const rankSlot = a.rank <= 3
                        ? `<span class="champs-medal-circle champs-medal-circle-${a.rank} champs-rank-slot flex-shrink-0 w-12 h-12 rounded-full flex items-center justify-center text-2xl border-2" title="Rank ${a.rank}">${medal}</span>`
                        : `<span class="champs-rank-slot champs-rank-num flex-shrink-0 w-12 h-12 flex items-center justify-center font-extrabold text-secondary text-lg">${a.rank}</span>`;
                    return `
                        <button type="button" class="champs-ladder-row ${rankClass} w-full flex items-center gap-3 px-3 py-2.5 rounded-xl border border-transparent hover:border-white/10 hover:bg-white/5 transition-all text-left" data-index="${i}" title="${a.score} pts">
                            ${rankSlot}
                            <span class="flex-shrink-0 ${avatarSize} rounded-full overflow-hidden bg-slate-600/50 flex items-center justify-center ring-2 ring-white/5">
                                ${avatarHtml}
                            </span>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center gap-1.5 flex-wrap">
                                    <span class="font-bold text-sm truncate">${displayName}</span>
                                </div>
                                <div class="flex items-center gap-2 mt-1 flex-wrap">
                                    <span class="champs-ladder-score font-mono text-xl font-extrabold ${scoreColorClass}">${a.score}</span>
                                    <span class="text-sm font-semibold opacity-90">${rankText}</span>
                                    ${trendHtml}
                                </div>
                            </div>
                        </button>
                    `;
                }).join('');
                listEl.querySelectorAll('.champs-ladder-row').forEach(btn => {
                    btn.addEventListener('click', () => {
                        listEl.querySelectorAll('.champs-ladder-row').forEach(b => b.classList.remove('champs-ladder-selected'));
                        btn.classList.add('champs-ladder-selected');
                        showChampsSpotlight(parseInt(btn.getAttribute('data-index'), 10));
                    });
                });
            } else {
                const t = global.t || (k => k);
                listEl.innerHTML = `<div class="text-secondary text-sm py-4 text-center">${t('champs.no_data') || 'No analyst data yet'}</div>`;
            }
        } catch (error) {
            console.error('Error loading champs leaderboard:', error);
            listEl.innerHTML = `<div class="text-red-400 text-sm py-4 text-center">Error loading data</div>`;
        }
        loadChampsTeamHud();
        loadChampsTicker();
    }

    (function initChampsGoalModal() {
        const btn = document.getElementById('champsSetGoalBtn');
        const modal = document.getElementById('champsGoalModal');
        const cancelBtn = document.getElementById('champsGoalCancel');
        const form = document.getElementById('champsGoalForm');
        async function openGoalModal() {
            try {
                const r = await fetch('/api/champs/team-goal');
                const j = await r.json();
                const g = j.success && j.goal ? j.goal : null;
                const setVal = (id, value) => {
                    const el = document.getElementById(id);
                    if (el) el.value = (value != null && value !== '') ? String(value) : '';
                };
                setVal('champsGoalTitle', g ? g.title : '');
                setVal('champsGoalDescription', g ? (g.description || '') : '');
                setVal('champsGoalTarget', g && g.target_value != null ? g.target_value : '');
                setVal('champsGoalType', g && g.goal_type ? g.goal_type : 'ioc_add');
                setVal('champsGoalPeriod', g && g.period ? g.period : 'weekly');
                setVal('champsGoalUnit', g ? (g.unit || '') : '');
            } catch (e) { /* leave fields empty on error */ }
            if (modal) modal.classList.remove('hidden');
        }
        if (btn) btn.addEventListener('click', openGoalModal);
        if (cancelBtn) cancelBtn.addEventListener('click', () => { if (modal) modal.classList.add('hidden'); });
        if (modal) modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.add('hidden'); });
        if (form) form.addEventListener('submit', async (e) => {
            e.preventDefault();
            try {
                const r = await fetch('/api/champs/team-goal', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        title: document.getElementById('champsGoalTitle').value.trim(),
                        description: (document.getElementById('champsGoalDescription') && document.getElementById('champsGoalDescription').value.trim()) || undefined,
                        target_value: parseInt(document.getElementById('champsGoalTarget').value, 10),
                        goal_type: document.getElementById('champsGoalType').value,
                        period: document.getElementById('champsGoalPeriod').value,
                        unit: (document.getElementById('champsGoalUnit') && document.getElementById('champsGoalUnit').value.trim()) || undefined
                    })
                });
                const j = await r.json();
                if (j.success) {
                    modal.classList.add('hidden');
                    loadChampsTeamHud();
                    loadChampsAnalysis();
                    showToast(j.message || 'Goal set', 'success');
                } else showToast(j.message || 'Failed', 'error');
            } catch (err) { showToast('Failed to set goal', 'error'); }
        });
    })();

    (function initChampsTickerMsgModal() {
        const ROWS = 5;
        const btn = document.getElementById('champsTickerMsgSettingsBtn');
        const modal = document.getElementById('champsTickerMsgModal');
        const rowsContainer = document.getElementById('champsTickerMsgRows');
        const rowTpl = document.getElementById('champsTickerMsgRowTpl');
        const cancelBtn = document.getElementById('champsTickerMsgCancel');
        const saveBtn = document.getElementById('champsTickerMsgSave');
        if (!modal || !rowsContainer || !rowTpl) return;
        function ensureRows() {
            rowsContainer.innerHTML = '';
            for (let i = 0; i < ROWS; i++) {
                const row = rowTpl.content.cloneNode(true);
                const textInp = row.querySelector('.champs-ticker-msg-text');
                const colorInp = row.querySelector('.champs-ticker-msg-color');
                if (textInp) textInp.setAttribute('data-idx', i);
                if (colorInp) colorInp.setAttribute('data-idx', i);
                rowsContainer.appendChild(row);
            }
        }
        ensureRows();
        async function openMsgModal() {
            try {
                const r = await fetch('/api/champs/ticker-messages');
                const j = await r.json();
                const messages = (j.messages || []).slice(0, ROWS);
                rowsContainer.querySelectorAll('.champs-ticker-msg-text').forEach((inp, i) => {
                    inp.value = (messages[i] && messages[i].text) || '';
                });
                rowsContainer.querySelectorAll('.champs-ticker-msg-color').forEach((inp, i) => {
                    inp.value = (messages[i] && messages[i].color) || '#ffffff';
                });
                rowsContainer.querySelectorAll('.champs-ticker-msg-dir').forEach((sel, i) => {
                    const d = (messages[i] && (messages[i].dir || messages[i].direction)) || 'ltr';
                    sel.value = (d === 'rtl') ? 'rtl' : 'ltr';
                });
            } catch (e) { /* leave empty */ }
            modal.classList.remove('hidden');
        }
        if (btn) btn.addEventListener('click', openMsgModal);
        if (cancelBtn) cancelBtn.addEventListener('click', () => { modal.classList.add('hidden'); });
        if (modal) modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.add('hidden'); });
        if (saveBtn) saveBtn.addEventListener('click', async () => {
            const messages = [];
            rowsContainer.querySelectorAll('.champs-ticker-msg-row').forEach((row, i) => {
                const textInp = row.querySelector('.champs-ticker-msg-text');
                const colorInp = row.querySelector('.champs-ticker-msg-color');
                const dirSel = row.querySelector('.champs-ticker-msg-dir');
                const text = (textInp && textInp.value) ? textInp.value.trim() : '';
                const color = (colorInp && colorInp.value) ? colorInp.value : '#ffffff';
                const dir = (dirSel && dirSel.value === 'rtl') ? 'rtl' : 'ltr';
                messages.push({ text: text, color: color, dir: dir });
            });
            try {
                const r = await fetch('/api/champs/ticker-messages', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ messages: messages })
                });
                const j = await r.json();
                const t = global.t || (k => k);
                if (j.success) {
                    modal.classList.add('hidden');
                    loadChampsTicker();
                    showToast(typeof t === 'function' && t('champs.msg_settings_saved') ? t('champs.msg_settings_saved') : 'Ticker messages saved', 'success');
                } else showToast(j.message || 'Failed', 'error');
            } catch (err) { showToast('Failed to save', 'error'); }
        });
    })();

    async function loadChampsTeamHud() {
        const authState = global.authState || {};
        const t = global.t || (k => k);
        const hud = document.getElementById('champsTeamHud');
        const setBtn = document.getElementById('champsSetGoalBtn');
        const barArea = document.getElementById('champsTeamHudBarArea');
        if (!hud) return;
        try {
            const r = await fetch('/api/champs/team-goal');
            const j = await r.json();
            if (setBtn) setBtn.classList.toggle('hidden', !authState.is_admin);
            const msgSettingsBtn = document.getElementById('champsTickerMsgSettingsBtn');
            if (msgSettingsBtn) msgSettingsBtn.classList.toggle('hidden', !authState.is_admin);
            if (!j.success || !j.goal) {
                if (barArea) barArea.style.display = 'none';
                const subEl = document.getElementById('champsTeamHudSub');
                if (subEl) subEl.textContent = '';
                document.getElementById('champsTeamHudTitle').textContent = authState.is_admin ? (t('champs.no_goal') || 'No team goal - Set one') : '';
                if (!authState.is_admin) hud.style.display = 'none';
                else hud.style.display = 'block';
                return;
            }
            hud.style.display = 'block';
            const g = j.goal;
            if (barArea) barArea.style.display = 'flex';
            const titleEl = document.getElementById('champsTeamHudTitle');
            titleEl.textContent = g.title;
            if (g.description) {
                titleEl.setAttribute('title', g.description);
            } else {
                titleEl.removeAttribute('title');
            }
            document.getElementById('champsTeamHudBar').style.width = Math.min(100, g.percent || 0) + '%';
            document.getElementById('champsTeamHudPercent').textContent = (g.percent || 0) + '%';
            document.getElementById('champsTeamHudSub').textContent = (g.current_value || 0) + ' / ' + (g.target_value || 0) + ' ' + (g.unit || '');
        } catch (e) { if (barArea) barArea.style.display = 'none'; }
    }

    function champsTickerHighlightKeywords(text) {
        if (!text) return '';
        const escaped = escapeHtml(text);
        return escaped
            .replace(/#(\d+)/g, '<span class="champs-ticker-kw">#$1</span>')
            .replace(/(\d+)%/g, '<span class="champs-ticker-kw">$1%</span>')
            .replace(/\b(overtook|rose|reached|added|uploaded|removed|goal|Team goal|new IOC|YARA rule)\b/gi, '<span class="champs-ticker-kw">$&</span>');
    }

    async function loadChampsTicker() {
        const t = global.t || (k => k);
        const stripEl = document.getElementById('champsTickerStrip');
        const scrollEl = document.getElementById('champsTickerScroll');
        if (!stripEl || !scrollEl) return;
        const sep = '<span class="champs-ticker-sep"> | </span>';
        try {
            const r = await fetch('/api/champs/ticker?limit=10');
            const j = await r.json();
            if (j.source === 'custom' && j.messages && j.messages.length > 0) {
                champsTickerMessages = j.messages.map(m => ({
                    text: m.text || '',
                    color: m.color || '#ffffff',
                    dir: (m.dir || m.direction || 'ltr') === 'rtl' ? 'rtl' : 'ltr'
                }));
                stripEl.classList.remove('champs-ticker-placeholder');
                scrollEl.classList.add('champs-ticker-marquee');
                const parts = champsTickerMessages.map(m => {
                    const color = (m.color || '#ffffff').replace(/"/g, '&quot;');
                    const dirAttr = m.dir === 'rtl' ? ' dir="rtl"' : ' dir="ltr"';
                    return '<span class="champs-ticker-msg champs-ticker-custom" style="color:' + color + '"' + dirAttr + '>' + escapeHtml(m.text) + '</span>';
                });
                const oneStrip = parts.join(sep);
                stripEl.innerHTML = oneStrip + sep + oneStrip;
                return;
            }
            champsTickerMessages = (j.messages || []).map(m => ({ text: m.text || '', category: m.category || 'analyst_success' }));
            if (champsTickerMessages.length === 0) {
                const placeholder = (typeof t === 'function' && t('champs.ticker_no_activity')) ? t('champs.ticker_no_activity') : 'No recent activity — new submissions, rank changes and goal updates will appear here.';
                stripEl.innerHTML = '<span class="champs-ticker-msg">' + escapeHtml(placeholder) + '</span>';
                stripEl.classList.add('champs-ticker-placeholder');
                scrollEl.classList.remove('champs-ticker-marquee');
                return;
            }
            stripEl.classList.remove('champs-ticker-placeholder');
            scrollEl.classList.add('champs-ticker-marquee');
            const catClass = (c) => {
                if (c === 'team') return 'champs-ticker-team';
                if (c === 'important' || c === 'warning') return 'champs-ticker-warning';
                if (c === 'negative') return 'champs-ticker-negative';
                return 'champs-ticker-success';
            };
            const parts = champsTickerMessages.map(m => '<span class="champs-ticker-msg ' + catClass(m.category) + '">' + champsTickerHighlightKeywords(m.text) + '</span>');
            const oneStrip = parts.join(sep);
            stripEl.innerHTML = oneStrip + sep + oneStrip;
        } catch (e) {
            stripEl.innerHTML = '<span class="champs-ticker-msg">' + escapeHtml((typeof t === 'function' && t('champs.ticker_error')) ? t('champs.ticker_error') : 'Could not load activity.') + '</span>';
            scrollEl.classList.remove('champs-ticker-marquee');
        }
    }

    function startChampsTickerPolling() {
        loadChampsTicker();
        if (champsTickerPollInterval) clearInterval(champsTickerPollInterval);
        champsTickerPollInterval = setInterval(() => {
            if (!document.getElementById('tab-champs') || document.getElementById('tab-champs').classList.contains('hidden')) return;
            loadChampsTicker();
        }, 10000);
    }

    async function showChampsSpotlight(index) {
        const data = champsLeaderboardData[index];
        const placeholder = document.getElementById('champsSpotlightPlaceholder');
        const content = document.getElementById('champsSpotlightContent');
        if (!data || !placeholder || !content) return;
        placeholder.classList.add('hidden');
        content.classList.remove('hidden');
        content.innerHTML = '<div class="text-secondary">Loading...</div>';
        const uid = data.user_id;
        if (uid) {
            try {
                const r = await fetch('/api/champs/analyst/' + uid);
                const j = await r.json();
                if (j.success && j.analyst) {
                    renderChampsSpotlightFull(content, j.analyst, data);
                    return;
                }
            } catch (e) { console.warn('Analyst detail fetch failed:', e); }
        }
        renderChampsSpotlightBasic(content, data);
    }

    function renderChampsSpotlightBasic(content, data) {
        const streakText = (data.streak_days || 0) >= 3 ? ` 🔥 ${data.streak_days}d` : '';
        const avatarHtml = data.avatar_url ? `<img src="${escapeAttr(data.avatar_url)}" alt="" class="w-full h-full object-cover" onerror="this.parentElement.innerHTML='<span class=\\'text-2xl\\'>👤</span>'">` : '<span class="text-2xl">👤</span>';
        const name = escapeHtml(data.display_name || data.username || data.analyst);
        const nicknamePart = data.nickname_emoji ? data.nickname_emoji + ' ' + escapeHtml(data.nickname || '') : escapeHtml(data.nickname || '');
        const roleDesc = (data.role_description || '').trim();
        const nameLineHtml = nicknamePart
            ? `<div class="flex items-baseline gap-2 flex-wrap min-w-0"><h3 class="text-2xl font-extrabold accent-blue truncate">${name}</h3><span class="text-secondary font-medium text-base whitespace-nowrap">${nicknamePart}</span></div>`
            : `<h3 class="text-2xl font-extrabold accent-blue truncate">${name}</h3>`;
        const roleDescHtml = roleDesc ? `<p class="text-secondary font-medium mt-0.5">${escapeHtml(roleDesc)}</p>` : '';
        content.innerHTML = `
            <div class="champs-spotlight-card rounded-lg border border-white/10 bg-tertiary/80 p-4 flex-1 min-h-0 flex flex-col overflow-auto">
                <div class="flex items-center gap-5 mb-4 flex-shrink-0">
                    <span class="champs-spotlight-avatar w-20 h-20 rounded-full overflow-hidden bg-slate-600/50 flex items-center justify-center ring-4 ring-cyan-500/30 flex-shrink-0">${avatarHtml}</span>
                    <div class="min-w-0 flex-1">
                        ${nameLineHtml}
                        ${roleDescHtml}
                        <p class="text-secondary font-medium mt-1">Rank <span class="font-bold text-white">#${data.rank}</span> • <span class="font-mono accent-green">${data.score}</span> pts${streakText}</p>
                    </div>
                </div>
                <div class="champs-stats-grid grid grid-cols-2 gap-3">
                    <div class="champs-stat-card rounded-lg p-4 bg-black/25 border border-white/5"><span class="text-secondary text-xs uppercase tracking-wider block mb-1">IOCs</span><span class="font-mono text-lg font-bold accent-green">${data.total_iocs || 0}</span></div>
                    <div class="champs-stat-card rounded-lg p-4 bg-black/25 border border-white/5"><span class="text-secondary text-xs uppercase tracking-wider block mb-1">YARA</span><span class="font-mono text-lg font-bold text-amber-400">${data.yara_count || 0}</span></div>
                </div>
            </div>`;
        renderChampsTrophyCabinet([]);
    }

    function renderChampsTrophyCabinet(badgeKeys) {
        const listEl = document.getElementById('champsTrophyCabinetList');
        const placeholderEl = document.getElementById('champsTrophyCabinetPlaceholder');
        if (!listEl) return;
        if (!badgeKeys || badgeKeys.length === 0) {
            listEl.innerHTML = '<div id="champsTrophyCabinetPlaceholder" class="w-full py-8 text-center text-secondary text-sm">Select an analyst</div>';
            return;
        }
        const items = badgeKeys.map(key => {
            const label = BADGE_LABELS[key] || key;
            const name = BADGE_NAMES[key] || key;
            const cls = BADGE_CLASSES[key] || '';
            const tooltip = champsBadgeDescriptions[key] || '';
            return `<div class="champs-trophy-item ${cls}" title="${escapeAttr(tooltip)}">
                <span class="champs-trophy-symbol">${escapeHtml(label.split(' ')[0] || label)}</span>
                <span class="champs-trophy-label">${escapeHtml(name)}</span>
            </div>`;
        }).join('');
        listEl.innerHTML = (placeholderEl ? '<div id="champsTrophyCabinetPlaceholder" class="hidden w-full py-8 text-center text-secondary text-sm">Select an analyst</div>' : '') + items;
    }

    function renderChampsSpotlightFull(content, a, ladderData) {
        const name = escapeHtml(a.display_name || a.nickname || a.analyst || '');
        const nicknamePart = a.nickname_emoji ? a.nickname_emoji + ' ' + escapeHtml(a.nickname || '') : escapeHtml(a.nickname || '');
        const roleDesc = (a.role_description || '').trim();
        const nameLineHtml = nicknamePart
            ? `<div class="flex items-baseline gap-2 flex-wrap min-w-0"><h3 class="text-2xl font-extrabold accent-blue truncate">${name}</h3><span class="text-secondary font-medium text-base whitespace-nowrap">${nicknamePart}</span></div>`
            : `<h3 class="text-2xl font-extrabold accent-blue truncate">${name}</h3>`;
        const roleDescHtml = roleDesc ? `<p class="text-secondary font-medium mt-0.5">${escapeHtml(roleDesc)}</p>` : '';
        const xpPct = a.level_width ? Math.min(100, 100 * (a.xp_in_level || 0) / a.level_width) : 0;
        const badges = (a.badges || []).map(b => ({ key: b, label: BADGE_LABELS[b] || b, cls: BADGE_CLASSES[b] || '' })).filter(x => x.label);
        const avatarHtml = a.avatar_url ? `<img src="${escapeAttr(a.avatar_url)}" alt="" class="w-full h-full object-cover" onerror="this.parentElement.innerHTML='<span class=\\'text-2xl\\'>👤</span>'">` : '<span class="text-2xl">👤</span>';
        const analystChartName = (a.display_name || a.nickname || a.analyst || 'You').trim() || 'You';
        let chartHtml = '';
        champsMispData = (a.misp_per_day && a.misp_per_day.length > 0) ? a.misp_per_day : null;
        champsMispVisible = false;
        if (a.activity_per_day && a.activity_per_day.length > 0 && typeof Chart !== 'undefined') {
            const mispBtnHtml = champsMispData
                ? ' <button type="button" id="champsMispToggle" class="champs-misp-toggle" title="Toggle MISP sync overlay">'
                  + '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" xmlns="http://www.w3.org/2000/svg">'
                  + '<circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5"/>'
                  + '<circle cx="12" cy="8" r="2" fill="currentColor"/>'
                  + '<circle cx="7" cy="15" r="2" fill="currentColor"/>'
                  + '<circle cx="17" cy="15" r="2" fill="currentColor"/>'
                  + '<line x1="12" y1="10" x2="7" y2="13" stroke="currentColor" stroke-width="1.2"/>'
                  + '<line x1="12" y1="10" x2="17" y2="13" stroke="currentColor" stroke-width="1.2"/>'
                  + '<line x1="7" y1="15" x2="17" y2="15" stroke="currentColor" stroke-width="1.2" stroke-dasharray="2 2"/>'
                  + '</svg></button>'
                : '';
            chartHtml = '<div class="champs-activity-block flex-1 min-h-0 flex flex-col mt-4 p-4 rounded-xl bg-black/20 border border-white/5">'
                + '<div class="flex items-center justify-between mb-3 flex-shrink-0">'
                + '<h4 class="text-xs font-bold text-secondary uppercase tracking-wider">Activity (30 days) — ' + escapeHtml(analystChartName) + ' vs team avg</h4>'
                + mispBtnHtml
                + '</div>'
                + '<div class="champs-spotlight-chart-wrap flex-1 min-h-[260px]"><canvas id="champsSpotlightChart"></canvas></div></div>';
        }
        renderChampsTrophyCabinet(a.badges || []);
        content.innerHTML = `
            <div class="champs-spotlight-card rounded-lg border border-white/10 bg-tertiary/80 p-4 champs-spotlight-glow flex-1 min-h-0 flex flex-col overflow-auto">
                <div class="flex items-center gap-5 mb-4 flex-shrink-0">
                    <span class="champs-spotlight-avatar w-24 h-24 rounded-full overflow-hidden bg-slate-600/50 flex items-center justify-center ring-4 ring-cyan-500/40 flex-shrink-0">${avatarHtml}</span>
                    <div class="flex-1 min-w-0">
                        ${nameLineHtml}
                        ${roleDescHtml}
                        <p class="text-secondary text-sm mt-2">Level <strong class="text-white">${a.level || 1}</strong> → <strong class="text-white">${(a.level || 1) + 1}</strong> <span class="opacity-90">(${a.xp_to_next || 0} XP to go)</span></p>
                        <div class="mt-2 h-3 bg-black/40 rounded-full overflow-hidden max-w-xs">
                            <div class="champs-xp-fill h-full bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full transition-all duration-500" style="width: ${xpPct}%"></div>
                        </div>
                    </div>
                </div>
                <div class="champs-stats-grid grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4 flex-shrink-0">
                    <div class="champs-stat-card rounded-lg p-4 bg-black/25 border border-white/5"><span class="text-secondary text-xs uppercase tracking-wider block mb-1">IOCs</span><span class="font-mono text-xl font-bold accent-green">${a.total_iocs || 0}</span></div>
                    <div class="champs-stat-card rounded-lg p-4 bg-black/25 border border-white/5"><span class="text-secondary text-xs uppercase tracking-wider block mb-1">YARA</span><span class="font-mono text-xl font-bold text-amber-400">${a.yara_count || 0}</span></div>
                    <div class="champs-stat-card rounded-lg p-4 bg-black/25 border border-white/5"><span class="text-secondary text-xs uppercase tracking-wider block mb-1">Deletions</span><span class="font-mono text-xl font-bold">${a.deletion_count || 0}</span></div>
                    <div class="champs-stat-card rounded-lg p-4 bg-black/25 border border-white/5"><span class="text-secondary text-xs uppercase tracking-wider block mb-1">Streak</span><span class="font-mono text-xl font-bold">${a.streak_days || 0} days</span></div>
                </div>
                ${chartHtml}`;
        if (chartHtml && a.activity_per_day && typeof Chart !== 'undefined') {
            setTimeout(() => {
                const ctx = document.getElementById('champsSpotlightChart');
                if (ctx) {
                    if (champsSpotlightChart) { champsSpotlightChart.destroy(); champsSpotlightChart = null; }
                    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
                    const gridColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
                    const textColor = isDark ? '#ffffff' : '#64748b';
                    const labels = a.activity_per_day.map(d => d.date.slice(5));
                    const data = a.activity_per_day.map(d => d.points);
                    const teamAvg = (a.team_avg_per_day || []).map(d => d.points);
                    const analystLabel = (a && (a.display_name || a.nickname || a.analyst)) ? (a.display_name || a.nickname || a.analyst).trim() : 'You';
                    const datasets = [
                        { label: analystLabel, data, borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.2)', fill: true, tension: 0.3 },
                        { label: 'Team avg', data: teamAvg.length ? teamAvg : labels.map(() => 0), borderColor: 'rgba(128,128,128,0.8)', backgroundColor: 'rgba(128,128,128,0.1)', fill: true, tension: 0.3, borderDash: [4, 2] }
                    ];
                    champsSpotlightChart = new Chart(ctx.getContext('2d'), {
                        type: 'line',
                        data: { labels, datasets },
                        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: true, labels: { color: textColor } } }, scales: { x: { ticks: { maxRotation: 45, color: textColor }, grid: { color: gridColor } }, y: { beginAtZero: true, ticks: { color: textColor }, grid: { color: gridColor } } } }
                    });
                    global.champsSpotlightChart = champsSpotlightChart;

                    const mispBtn = document.getElementById('champsMispToggle');
                    if (mispBtn && champsMispData) {
                        mispBtn.addEventListener('click', function() {
                            if (!champsSpotlightChart) return;
                            champsMispVisible = !champsMispVisible;
                            mispBtn.classList.toggle('champs-misp-active', champsMispVisible);
                            if (champsMispVisible) {
                                const mispCounts = champsMispData.map(d => d.count);
                                champsSpotlightChart.data.datasets.push({
                                    label: 'MISP sync',
                                    data: mispCounts,
                                    borderColor: '#eab308',
                                    backgroundColor: 'rgba(234,179,8,0.08)',
                                    fill: false,
                                    tension: 0.3,
                                    borderDash: [6, 3],
                                    borderWidth: 2,
                                    pointRadius: 2,
                                });
                            } else {
                                const idx = champsSpotlightChart.data.datasets.findIndex(ds => ds.label === 'MISP sync');
                                if (idx !== -1) champsSpotlightChart.data.datasets.splice(idx, 1);
                            }
                            champsSpotlightChart.update();
                        });
                    }
                }
            }, 100);
        }
    }

    global.loadChampsAnalysis = loadChampsAnalysis;
    global.startChampsTickerPolling = startChampsTickerPolling;
    global.champsSpotlightChart = champsSpotlightChart;
})(typeof window !== 'undefined' ? window : this);
