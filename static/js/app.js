/* app.js - Core application bootstrap (extracted from inline <script>) */

// ---------------------------------------------------------------------------
// RTL/LTR detection (Hebrew vs English) - used by delete reason, team goal, profile
// ---------------------------------------------------------------------------
function detectDir(text) {
    if (!text || typeof text !== 'string') return 'ltr';
    var t = text.trim();
    if (!t.length) return 'ltr';
    var heCount = 0;
    for (var i = 0; i < t.length; i++) {
        var c = t.charCodeAt(i);
        if ((c >= 0x0590 && c <= 0x05FF) || (c >= 0xFB1D && c <= 0xFB4F)) heCount++;
    }
    return heCount > t.length / 2 ? 'rtl' : 'ltr';
}
window.detectDir = detectDir;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
var translations = {};
var currentLang = localStorage.getItem('language') || 'en';
var currentTheme = localStorage.getItem('theme') || 'dark';
var authState = {
    authenticated: false,
    username: null,
    display_name: null,
    is_admin: false,
    avatar_url: null
};
var statsPollInterval = null;
var liveFeedInterval = null;

// ---------------------------------------------------------------------------
// Fetch wrapper - on 401, redirect to login (preserves next URL)
// ---------------------------------------------------------------------------
const _originalFetch = window.fetch;
window.fetch = async function (url, opts) {
    const res = await _originalFetch.apply(this, arguments);
    if (res.status === 401 && typeof url === 'string' && !url.includes('/login')) {
        const next = encodeURIComponent(
            window.location.pathname + window.location.search + (window.location.hash || '')
        );
        window.location.href = '/login?next=' + next;
        throw new Error('Unauthorized - redirecting to login');
    }
    return res;
};

// ---------------------------------------------------------------------------
// i18n - load translations from JSON files
// ---------------------------------------------------------------------------
const SUPPORTED_LANGUAGES = ['en', 'he'];

async function loadTranslations() {
    const i18nBase = window.TG_CONFIG.i18nBase;
    const loads = SUPPORTED_LANGUAGES.map(async (lang) => {
        const res = await fetch(i18nBase + lang + '.json');
        if (!res.ok) throw new Error('Failed to load language: ' + lang);
        return [lang, await res.json()];
    });
    const results = await Promise.all(loads);
    const version = (document.documentElement.dataset && document.documentElement.dataset.version) || '2.0 Beta'; /* fallback: match constants.VERSION */
    results.forEach(([lang, data]) => {
        if (data.title && typeof data.title === 'string') {
            data.title = data.title.replace(/\$VERSION/g, version);
        }
        translations[lang] = data;
    });
}

function setLanguage(lang) {
    currentLang = lang;
    localStorage.setItem('language', lang);
    const html = document.getElementById('htmlRoot');
    if (lang === 'he') {
        html.setAttribute('dir', 'rtl');
    } else {
        html.setAttribute('dir', 'ltr');
    }
    updateTranslations();
    if (typeof window.setYaraMode === 'function' && window._yaraCurrentMode) {
        window.setYaraMode(window._yaraCurrentMode, { skipReload: true });
    }
}

function updateTranslations() {
    const tr = translations[currentLang] || translations.en;
    if (!tr) return;
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        const keys = key.split('.');
        let value = tr;
        for (const k of keys) {
            if (value) value = value[k];
        }
        if (value) el.textContent = value;
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        const keys = key.split('.');
        let value = tr;
        for (const k of keys) {
            if (value) value = value[k];
        }
        if (value) el.placeholder = value;
    });
}

function t(key, replacements) {
    const keys = key.split('.');
    let value = translations[currentLang] || translations.en;
    for (const k of keys) {
        if (value) value = value[k];
    }
    if (!value) return key;
    if (replacements) {
        Object.keys(replacements).forEach(rk => {
            value = value.replace('{' + rk + '}', replacements[rk]);
        });
    }
    return value;
}

document.getElementById('langToggle').addEventListener('click', () => {
    currentLang = currentLang === 'en' ? 'he' : 'en';
    document.getElementById('langIcon').textContent = currentLang.toUpperCase();
    setLanguage(currentLang);
});

// ---------------------------------------------------------------------------
// Auth state
// ---------------------------------------------------------------------------
async function loadAuthState() {
    try {
        const res = await _originalFetch('/api/auth/me');
        const data = await res.json();
        if (data.success) {
            authState = {
                authenticated: !!data.authenticated,
                username: data.username || null,
                display_name: data.display_name || data.username || null,
                is_admin: !!data.is_admin,
                avatar_url: data.avatar_url || null
            };
        }
    } catch (e) {
        console.error('Failed to load auth state:', e);
    }
    updateAuthUI();
}

// ---------------------------------------------------------------------------
// Admin Inbox (bell) - pending actions snapshot
// ---------------------------------------------------------------------------
let _adminInboxPoll = null;
async function loadAdminInboxBadge() {
    try {
        if (!authState || !authState.authenticated || !authState.is_admin) return;
        const res = await fetch('/api/admin/inbox', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
        const data = await res.json().catch(() => ({}));
        if (!data || !data.success) return;
        const total = (data.total_pending != null) ? Number(data.total_pending) : 0;
        const btn = document.getElementById('adminInboxBtn');
        const badge = document.getElementById('adminInboxBadge');
        if (btn) btn.classList.remove('hidden');
        if (badge) {
            if (total > 0) {
                badge.textContent = String(total);
                badge.classList.remove('hidden');
            } else {
                badge.textContent = '';
                badge.classList.add('hidden');
            }
        }
        window._adminInboxLatest = data;
    } catch (e) {
        /* ignore */
    }
}

function _renderAdminInboxModal(data) {
    const modal = document.getElementById('adminInboxModal');
    const content = document.getElementById('adminInboxContent');
    if (!modal || !content) return;
    const d = (data && data.success) ? data : (window._adminInboxLatest || {});
    const yara = (d.yara_pending || []);
    const tags = (d.tag_suggestions || []);
    const yaraCount = d.yara_pending_count != null ? d.yara_pending_count : yara.length;
    const tagCount = d.tag_suggestions_count != null ? d.tag_suggestions_count : tags.length;
    function esc(s) { return (s == null ? '' : String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
    const yaraHtml = `
        <div class="bg-tertiary rounded-xl border border-white/10 p-4">
            <div class="flex items-center justify-between gap-2 mb-2">
                <h4 class="font-semibold text-primary">YARA pending approvals</h4>
                <a href="/admin" class="text-cyan-300 hover:underline text-sm">Go to Admin</a>
            </div>
            <div class="text-secondary text-sm mb-2">Pending: <span class="text-primary font-bold">${esc(yaraCount)}</span></div>
            ${yara.length ? `<ul class="space-y-2 text-sm">` + yara.map(r => `
                <li class="border border-white/10 rounded-lg p-3">
                    <div class="font-mono text-amber-200 break-all">${esc(r.display_name != null && r.display_name !== '' ? r.display_name : r.filename)}</div>
                    <div class="text-secondary mt-1">By <span class="text-primary">${esc(r.analyst || '—')}</span> • ${esc((r.uploaded_at||'').slice(0,19).replace('T',' '))}</div>
                    ${r.ticket_id ? `<div class="text-secondary">Ticket: <span class="text-primary font-mono">${esc(r.ticket_id)}</span></div>` : ``}
                    ${r.comment ? `<div class="text-secondary mt-1">${esc(r.comment)}</div>` : ``}
                </li>
            `).join('') + `</ul>` : `<div class="text-secondary text-sm">No pending YARA.</div>`}
        </div>`;
    const tagsHtml = `
        <div class="bg-tertiary rounded-xl border border-white/10 p-4">
            <div class="flex items-center justify-between gap-2 mb-2">
                <h4 class="font-semibold text-primary">Tag suggestions</h4>
                <a href="/admin/settings" class="text-cyan-300 hover:underline text-sm">Settings → Tags</a>
            </div>
            <div class="text-secondary text-sm mb-2">Pending: <span class="text-primary font-bold">${esc(tagCount)}</span></div>
            ${tags.length ? `<ul class="space-y-2 text-sm">` + tags.map(r => `
                <li class="border border-white/10 rounded-lg p-3">
                    <div class="font-mono text-cyan-200">${esc(r.tag)}</div>
                    <div class="text-secondary mt-1">By <span class="text-primary">${esc(r.suggested_by || '—')}</span> • ${esc((r.suggested_at||'').slice(0,19).replace('T',' '))}</div>
                </li>
            `).join('') + `</ul>` : `<div class="text-secondary text-sm">No pending tag suggestions.</div>`}
        </div>`;
    content.innerHTML = yaraHtml + tagsHtml;
    modal.classList.remove('hidden');
}

function initAdminInboxUI() {
    const btn = document.getElementById('adminInboxBtn');
    const modal = document.getElementById('adminInboxModal');
    const close = document.getElementById('adminInboxClose');
    if (btn) {
        btn.addEventListener('click', async function() {
            await loadAdminInboxBadge();
            _renderAdminInboxModal(window._adminInboxLatest || {});
        });
    }
    if (close && modal) close.addEventListener('click', () => modal.classList.add('hidden'));
    if (modal) modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.add('hidden'); });
}

function updateAuthUI() {
    const loginEl = document.getElementById('authLogin');
    const profileEl = document.getElementById('authProfile');
    const avatarImg = document.getElementById('authAvatar');
    const avatarPlaceholder = document.getElementById('authAvatarPlaceholder');
    const adminEl = document.getElementById('authAdmin');
    const logoutEl = document.getElementById('authLogout');
    if (!loginEl || !logoutEl) return;
    if (authState.authenticated) {
        loginEl.classList.add('hidden');
        if (profileEl) {
            profileEl.classList.remove('hidden');
            profileEl.title = authState.display_name || authState.username || 'User';
        }
        logoutEl.classList.remove('hidden');
        if (authState.avatar_url && avatarImg) {
            avatarImg.src = authState.avatar_url;
            avatarImg.classList.remove('hidden');
            if (avatarPlaceholder) avatarPlaceholder.classList.add('hidden');
        } else {
            if (avatarImg) avatarImg.classList.add('hidden');
            if (avatarPlaceholder) avatarPlaceholder.classList.remove('hidden');
        }
        if (adminEl) {
            if (authState.is_admin) adminEl.classList.remove('hidden');
            else adminEl.classList.add('hidden');
        }
        const inboxBtn = document.getElementById('adminInboxBtn');
        if (inboxBtn) {
            if (authState.is_admin) inboxBtn.classList.remove('hidden');
            else inboxBtn.classList.add('hidden');
        }
        const feedPulseAllowlistBtn = document.getElementById('feedPulseAllowlistBtn');
        if (feedPulseAllowlistBtn) feedPulseAllowlistBtn.classList.remove('hidden');
        const playbookAdminActions = document.getElementById('playbookAdminActions');
        if (playbookAdminActions) {
            if (authState.is_admin) playbookAdminActions.classList.remove('hidden');
            else playbookAdminActions.classList.add('hidden');
        }
        const yaraPendingSection = document.getElementById('yaraPendingSection');
        if (yaraPendingSection) yaraPendingSection.classList.remove('hidden');
    } else {
        loginEl.classList.remove('hidden');
        if (profileEl) profileEl.classList.add('hidden');
        logoutEl.classList.add('hidden');
        if (adminEl) adminEl.classList.add('hidden');
        const inboxBtn = document.getElementById('adminInboxBtn');
        if (inboxBtn) inboxBtn.classList.add('hidden');
        const yaraPendingSection = document.getElementById('yaraPendingSection');
        if (yaraPendingSection) yaraPendingSection.classList.add('hidden');
        const feedPulseAllowlistBtn = document.getElementById('feedPulseAllowlistBtn');
        if (feedPulseAllowlistBtn) feedPulseAllowlistBtn.classList.add('hidden');
    }
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------
function getThemeColor(type) {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const root = getComputedStyle(document.documentElement);
    switch (type) {
        case 'text':
            return root.getPropertyValue('--text-primary').trim() || (isDark ? '#ffffff' : '#1a1a1a');
        case 'grid':
            return isDark ? 'rgba(0, 255, 65, 0.2)' : 'rgba(0, 0, 0, 0.1)';
        case 'border':
            return root.getPropertyValue('--border-color').trim() || (isDark ? '#00ff41' : '#d1d5db');
        default:
            return isDark ? '#ffffff' : '#1a1a1a';
    }
}

function setTheme(theme) {
    currentTheme = theme;
    localStorage.setItem('theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
    document.getElementById('themeIcon').textContent = theme === 'dark' ? '☀️' : '🌙';

    if (typeof Chart !== 'undefined') {
        Chart.defaults.color = getThemeColor('text');
        Chart.defaults.borderColor = getThemeColor('grid');

        if (threatChart) {
            try {
                threatChart.options.scales = threatChart.options.scales || {};
                if (threatChart.options.scales.x) {
                    threatChart.options.scales.x.ticks = threatChart.options.scales.x.ticks || {};
                    threatChart.options.scales.x.ticks.color = getThemeColor('text');
                    threatChart.options.scales.x.grid = threatChart.options.scales.x.grid || {};
                    threatChart.options.scales.x.grid.color = getThemeColor('grid');
                }
                if (threatChart.options.scales.y) {
                    threatChart.options.scales.y.ticks = threatChart.options.scales.y.ticks || {};
                    threatChart.options.scales.y.ticks.color = getThemeColor('text');
                    threatChart.options.scales.y.grid = threatChart.options.scales.y.grid || {};
                    threatChart.options.scales.y.grid.color = getThemeColor('grid');
                }
                if (threatChart.options.plugins && threatChart.options.plugins.legend) {
                    threatChart.options.plugins.legend.labels = threatChart.options.plugins.legend.labels || {};
                    threatChart.options.plugins.legend.labels.color = getThemeColor('text');
                }
                threatChart.update('none');
            } catch (e) {
                console.error('Error updating threatChart:', e);
            }
        }

        if (window.champsSpotlightChart) {
            try {
                const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
                const champsGridColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
                const champsTextColor = isDark ? '#ffffff' : '#64748b';
                window.champsSpotlightChart.options.scales = window.champsSpotlightChart.options.scales || {};
                if (window.champsSpotlightChart.options.scales.x) {
                    window.champsSpotlightChart.options.scales.x.ticks = window.champsSpotlightChart.options.scales.x.ticks || {};
                    window.champsSpotlightChart.options.scales.x.ticks.color = champsTextColor;
                    window.champsSpotlightChart.options.scales.x.grid = window.champsSpotlightChart.options.scales.x.grid || {};
                    window.champsSpotlightChart.options.scales.x.grid.color = champsGridColor;
                }
                if (window.champsSpotlightChart.options.scales.y) {
                    window.champsSpotlightChart.options.scales.y.ticks = window.champsSpotlightChart.options.scales.y.ticks || {};
                    window.champsSpotlightChart.options.scales.y.ticks.color = champsTextColor;
                    window.champsSpotlightChart.options.scales.y.grid = window.champsSpotlightChart.options.scales.y.grid || {};
                    window.champsSpotlightChart.options.scales.y.grid.color = champsGridColor;
                }
                if (window.champsSpotlightChart.options.plugins && window.champsSpotlightChart.options.plugins.legend) {
                    window.champsSpotlightChart.options.plugins.legend.labels = window.champsSpotlightChart.options.plugins.legend.labels || {};
                    window.champsSpotlightChart.options.plugins.legend.labels.color = champsTextColor;
                }
                window.champsSpotlightChart.update('none');
            } catch (e) {
                console.error('Error updating champsSpotlightChart:', e);
            }
        }
    }
}

document.getElementById('themeToggle').addEventListener('click', () => {
    setTheme(currentTheme === 'dark' ? 'light' : 'dark');
});

// ---------------------------------------------------------------------------
// Lazy script loader
// ---------------------------------------------------------------------------
const _loadedScripts = new Set();

function lazyLoad(src) {
    if (_loadedScripts.has(src)) return Promise.resolve();
    return new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = src;
        s.onload = () => { _loadedScripts.add(src); resolve(); };
        s.onerror = () => reject(new Error('Failed to load: ' + src));
        document.head.appendChild(s);
    });
}

const _scriptUrls = window.TG_CONFIG.scriptUrls;

const _tabScripts = {
    'champs':       [_scriptUrls.champs],
    'yara':         [_scriptUrls.yara],
    'feed-pulse':   [_scriptUrls.feedPulse],
    'campaigns':    [_scriptUrls.campaigns],
    'bulk-unified': [_scriptUrls.campaigns],
    'reports':      [_scriptUrls.reports],
    'search':       [_scriptUrls.search, _scriptUrls.yara, _scriptUrls.campaigns]
};

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------
let currentTab = 'live-stats';
const _validTabs = new Set([
    'live-stats', 'feed-pulse', 'search', 'bulk-unified',
    'yara', 'champs', 'campaigns', 'playbook', 'reports'
]);

function _getTabFromHash() {
    const h = (location.hash || '').replace(/^#/, '').trim();
    return _validTabs.has(h) ? h : null;
}

async function switchTab(tabId, skipHash) {
    // Require login for sensitive pages
    const requireAuthTabs = new Set(['search', 'bulk-unified', 'yara', 'champs', 'campaigns', 'playbook', 'reports']);
    const isAuthed = document.body.getAttribute('data-authenticated') === '1';
    if (requireAuthTabs.has(tabId) && !isAuthed) {
        try { showToast('Login required', 'warning', 2500); } catch (e) { /* ignore */ }
        // Preserve intended destination
        const next = '/#' + tabId;
        window.location.href = '/login?next=' + encodeURIComponent(next);
        return;
    }

    currentTab = tabId;
    if (!skipHash) {
        history.replaceState(null, '', '#' + tabId);
    }

    document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
    const activeBtn = document.querySelector(`.tab-button[data-tab="${tabId}"]`);
    if (activeBtn) activeBtn.classList.add('active');

    document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));

    const activeTab = document.getElementById(`tab-${tabId}`);
    if (activeTab) activeTab.classList.remove('hidden');

    // Show loading state immediately for heavy tabs (Champs / Reports) before scripts run
    var loadingText = (typeof window.t === 'function' ? (window.t('champs.loading') || window.t('reports.loading')) : null) || 'Loading...';
    var loadingHtml = '<div class="flex flex-col items-center justify-center py-12 gap-3"><div class="w-10 h-10 border-2 border-primary border-t-transparent rounded-full animate-spin"></div><span class="text-secondary text-sm">' + loadingText + '</span></div>';
    if (tabId === 'champs') {
        var listEl = document.getElementById('champsLadderList');
        if (listEl) listEl.innerHTML = loadingHtml;
    }
    if (tabId === 'reports') {
        var listElR = document.getElementById('reportsList');
        if (listElR) listElR.innerHTML = loadingHtml;
    }

    if (statsPollInterval) {
        clearInterval(statsPollInterval);
        statsPollInterval = null;
    }
    if (liveFeedInterval) {
        clearInterval(liveFeedInterval);
        liveFeedInterval = null;
    }
    const liveIndicator = document.getElementById('liveIndicator');
    if (liveIndicator) liveIndicator.style.display = 'none';

    const scripts = _tabScripts[tabId];
    if (scripts) {
        try {
            await Promise.all(scripts.map(lazyLoad));
        } catch (e) {
            console.error('Failed to load tab scripts:', e);
            showToast('Failed to load tab resources', 'error');
            return;
        }
    }

    if (tabId === 'search') {
        try {
            if (typeof window.loadSearchCountryCodes === 'function') {
                window.loadSearchCountryCodes();
            }
        } catch (e) { /* ignore */ }
    }

    if (tabId === 'live-stats') {
        loadStats();
        loadHistoricalIocs();
        loadLiveFeed();
        if (liveIndicator) liveIndicator.style.display = 'flex';
        statsPollInterval = setInterval(() => {
            loadHistoricalIocs(true);
            loadStats();
        }, 10000);
        liveFeedInterval = setInterval(loadLiveFeed, 30000);
    }

    if (tabId === 'champs') {
        loadChampsAnalysis();
        loadHistoricalIocs();
        startChampsTickerPolling();
        setTimeout(() => {
            if (threatChart) {
                try { threatChart.resize(); } catch (e) { console.error('Error resizing threatChart:', e); }
            }
        }, 100);
    }

    if (tabId === 'yara') {
        var pendingSec = document.getElementById('yaraPendingSection');
        if (authState && authState.authenticated && pendingSec) pendingSec.classList.remove('hidden');
        loadYaraRules();
        if (authState && authState.authenticated) loadYaraPending();
    }

    if (tabId === 'campaigns') {
        loadCampaigns();
    }

    if (tabId === 'bulk-unified') {
        loadUsersForAssignDropdown();
    }

    if (tabId === 'feed-pulse') {
        loadFeedPulse();
    }

    if (tabId === 'playbook') {
        activePlaybookTagFilter = null;
        loadPlaybookCustom();
        const firstTab = document.querySelector('#playbookTabs .playbook-tab-item');
        if (firstTab) firstTab.click();
    }
}

document.querySelectorAll('.tab-button').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.getAttribute('data-tab')));
});

window.addEventListener('hashchange', () => {
    const tab = _getTabFromHash();
    if (tab && tab !== currentTab) switchTab(tab, true);
});

// ---------------------------------------------------------------------------
// Toast notification system
// ---------------------------------------------------------------------------
function showToast(message, type = 'success', durationMs = 3000) {
    const icons = { success: '\u2713', error: '\u2717', warning: '\u26A0' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const iconSpan = document.createElement('span');
    iconSpan.className = 'toast-icon';
    iconSpan.textContent = icons[type] || '';
    const msgSpan = document.createElement('span');
    msgSpan.textContent = message;
    if ((typeof message === 'string') && message.indexOf('\n') !== -1) {
        msgSpan.style.whiteSpace = 'pre-line';
    }
    const progressSpan = document.createElement('span');
    progressSpan.className = 'toast-progress';
    progressSpan.style.animation = `toastProgress ${durationMs}ms linear forwards`;
    toast.appendChild(iconSpan);
    toast.appendChild(msgSpan);
    toast.appendChild(progressSpan);
    document.getElementById('toastContainer').appendChild(toast);
    setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 300);
    }, durationMs);
}

// ---------------------------------------------------------------------------
// Achievement modal - short pleasant chime when popup opens
// ---------------------------------------------------------------------------
function playAchievementSound() {
    if (document.body.getAttribute('data-mute-sound') === '1') return;
    try {
        var C = window.AudioContext || window.webkitAudioContext;
        if (!C) return;
        var ctx = new C();
        function playTones() {
            var gain = ctx.createGain();
            gain.connect(ctx.destination);
            gain.gain.setValueAtTime(0.25, ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.5);
            function tone(freq, start, dur) {
                var o = ctx.createOscillator();
                o.type = 'sine';
                o.frequency.setValueAtTime(freq, start);
                o.connect(gain);
                o.start(start);
                o.stop(start + dur);
            }
            tone(523.25, ctx.currentTime, 0.12);       // C5
            tone(659.25, ctx.currentTime + 0.08, 0.2); // E5
        }
        if (ctx.state === 'suspended') {
            ctx.resume().then(playTones);
        } else {
            playTones();
        }
    } catch (e) { /* ignore if audio blocked or unsupported */ }
}

function showAchievementModal(result) {
    if (document.body.getAttribute('data-achievement-popup-disabled') === '1') return;
    var badges = result.new_badges;
    var levelUp = result.level_up;
    var rankUp = result.rank_up;
    var pointsEarned = result.points_earned;
    var levelInfo = result.level_info;
    var newNickname = result.new_nickname;
    var hasAny = (badges && badges.length > 0) || levelUp || rankUp || (pointsEarned !== undefined) || levelInfo || newNickname;
    if (!hasAny) return;
    var modal = document.getElementById('badgeEarnedModal');
    var list = document.getElementById('badgeEarnedList');
    var titleEl = document.getElementById('badgeEarnedTitle');
    var pointsEl = document.getElementById('achievementPointsEarned');
    var gaugeEl = document.getElementById('achievementLevelGauge');
    var levelEl = document.getElementById('achievementLevelUp');
    var rankEl = document.getElementById('achievementRankUp');
    var nicknameEl = document.getElementById('achievementNewNickname');
    if (!modal || !list) return;
    // Play sound first so it starts with (or before) the popup; avoids delay from modal render + AudioContext resume
    playAchievementSound();
    list.innerHTML = '';
    if (pointsEl) { pointsEl.classList.add('hidden'); pointsEl.innerHTML = ''; }
    if (gaugeEl) { gaugeEl.classList.add('hidden'); gaugeEl.innerHTML = ''; }
    if (levelEl) { levelEl.classList.add('hidden'); levelEl.innerHTML = ''; }
    if (rankEl) { rankEl.classList.add('hidden'); rankEl.innerHTML = ''; }
    if (nicknameEl) { nicknameEl.classList.add('hidden'); nicknameEl.innerHTML = ''; }

    var parts = [];
    if (pointsEarned !== undefined && pointsEarned > 0) parts.push('+' + pointsEarned + ' pts');
    if (levelUp) parts.push('Level Up!');
    if (rankUp) parts.push('Rank Up!');
    if (newNickname && newNickname.label) parts.push('New Title!');
    if (badges && badges.length === 1) parts.push('New Badge!');
    else if (badges && badges.length > 1) parts.push(badges.length + ' New Badges!');
    titleEl.textContent = parts.length > 0 ? parts.join(' • ') : 'Achievement Unlocked!';

    if (pointsEl) {
        var ptsText = '';
        if (pointsEarned !== undefined && pointsEarned > 0) {
            ptsText = '+' + pointsEarned + ' points';
        } else if (levelInfo && levelInfo.score !== undefined && levelInfo.score !== null) {
            var total = Number(levelInfo.score);
            if (!isNaN(total)) ptsText = total + ' points total';
        }
        if (ptsText) {
            pointsEl.classList.remove('hidden');
            pointsEl.innerHTML = '<div class="achievement-section achievement-points-section">'
                + '<span class="achievement-icon">⭐</span>'
                + '<span class="achievement-text"><strong class="achievement-highlight-points">' + ptsText + '</strong></span>'
                + '</div>';
        }
    }

    if (levelInfo && gaugeEl) {
        var lvl = Number(levelInfo.level) || 1;
        var xpIn = Number(levelInfo.xp_in_level) || 0;
        var xpTo = Number(levelInfo.xp_to_next) || 0;
        var width = Number(levelInfo.level_width) || 1;
        var scoreTotal = levelInfo.score !== undefined ? Number(levelInfo.score) : null;
        var pct = width > 0 ? Math.min(100, Math.round((xpIn / width) * 100)) : 0;
        gaugeEl.classList.remove('hidden');
        var headerText = 'Level ' + lvl + ' &nbsp; ' + xpIn + ' / ' + width + ' XP';
        if (scoreTotal !== null && !isNaN(scoreTotal)) headerText = scoreTotal + ' pts &nbsp; · &nbsp; ' + headerText;
        gaugeEl.innerHTML = '<div class="achievement-section achievement-gauge-section">'
            + '<span class="achievement-icon">📊</span>'
            + '<div class="achievement-gauge-wrap w-full">'
            + '<div class="achievement-gauge-header text-sm text-slate-400 mb-1">' + headerText + '</div>'
            + '<div class="achievement-gauge-track"><div class="achievement-gauge-fill" style="width:' + pct + '%"></div></div>'
            + '<div class="achievement-gauge-next text-xs text-slate-500 mt-0.5">' + xpTo + ' XP to next level</div>'
            + '</div></div>';
    }

    if (levelUp && levelEl) {
        levelEl.classList.remove('hidden');
        levelEl.innerHTML = '<div class="achievement-section achievement-level-section">'
            + '<span class="achievement-icon">⬆️</span>'
            + '<span class="achievement-text"><strong>Level ' + levelUp.old_level + '</strong>'
            + ' <span class="achievement-arrow">→</span> '
            + '<strong class="achievement-highlight-level">Level ' + levelUp.new_level + '</strong></span>'
            + '</div>';
    }

    if (rankUp && rankEl) {
        rankEl.classList.remove('hidden');
        rankEl.innerHTML = '<div class="achievement-section achievement-rank-section">'
            + '<span class="achievement-icon">🏅</span>'
            + '<span class="achievement-text"><strong>#' + rankUp.old_rank + '</strong>'
            + ' <span class="achievement-arrow">→</span> '
            + '<strong class="achievement-highlight-rank">#' + rankUp.new_rank + '</strong></span>'
            + '</div>';
    }

    if (newNickname && newNickname.label && nicknameEl) {
        nicknameEl.classList.remove('hidden');
        var emoji = newNickname.emoji || '🎯';
        nicknameEl.innerHTML = '<div class="achievement-section achievement-nickname-section">'
            + '<span class="achievement-icon">' + emoji + '</span>'
            + '<span class="achievement-text"><strong class="achievement-highlight-nickname">' + emoji + ' ' + (newNickname.label || 'Threat Hunter') + '</strong></span>'
            + '</div>';
    }

    if (badges && badges.length > 0) {
        badges.forEach(function (b, i) {
            var item = document.createElement('div');
            item.className = 'badge-earned-item flex flex-col items-center gap-2';
            item.style.animationDelay = (0.08 * i) + 's';
            var symbol = document.createElement('span');
            symbol.className = 'badge-earned-symbol';
            symbol.textContent = b.emoji || '🏅';
            var label = document.createElement('span');
            label.className = 'badge-earned-label font-bold text-sm text-white';
            label.textContent = b.label || b.key;
            var desc = document.createElement('span');
            desc.className = 'text-xs text-slate-400 max-w-[120px]';
            desc.textContent = b.description || '';
            item.appendChild(symbol);
            item.appendChild(label);
            item.appendChild(desc);
            list.appendChild(item);
        });
    }
    modal.classList.remove('hidden');
    // Refresh Champs/LAVAL so points and ladder show updated score
    if (typeof window.loadChampsAnalysis === 'function') window.loadChampsAnalysis();
}

document.getElementById('badgeEarnedClose').addEventListener('click', function () {
    document.getElementById('badgeEarnedModal').classList.add('hidden');
});
document.getElementById('badgeEarnedModal').addEventListener('click', function (e) {
    if (e.target === this) this.classList.add('hidden');
});

// ---------------------------------------------------------------------------
// Smart paste - strip "ip: " prefixes
// ---------------------------------------------------------------------------
document.getElementById('iocValue').addEventListener('paste', function (e) {
    setTimeout(() => {
        let value = this.value;
        value = value.replace(/^(ip|IP|Ip):\s*/i, '');
        this.value = value;
    }, 10);
});

// ---------------------------------------------------------------------------
// IOC type icon helper
// ---------------------------------------------------------------------------
function getIocTypeIcon(iocType, iocValue, countryCode) {
    if (iocType === 'IP') {
        return countryCode ? `<span class="fi fi-${countryCode}"></span>` : '🛡️';
    } else if (iocType === 'Domain') {
        return '🌐';
    } else if (iocType === 'URL') {
        return '🔗';
    } else if (iocType === 'Email') {
        return '📧';
    } else if (iocType === 'YARA') {
        return '<span>📜</span>';
    } else if (iocType === 'Campaign') {
        return '🎯';
    } else if (iocType === 'Hash') {
        const len = iocValue ? iocValue.length : 0;
        if (len === 32) {
            return '<span class="badge-md5">[MD5]</span>';
        } else if (len === 64) {
            return '<span class="badge-sha256">[SHA256]</span>';
        } else {
            return '<span class="badge-hash">[HASH]</span>';
        }
    }
    return '';
}

// ---------------------------------------------------------------------------
// Global exposure - accessible from other scripts and inline code
// ---------------------------------------------------------------------------
window.t = t;
window.showToast = showToast;
window.getIocTypeIcon = getIocTypeIcon;
window.switchTab = switchTab;
window.loadAuthState = loadAuthState;
window.showAchievementModal = showAchievementModal;
window.getThemeColor = getThemeColor;
window.lazyLoad = lazyLoad;
window.setLanguage = setLanguage;
window.updateAuthUI = updateAuthUI;

// ---------------------------------------------------------------------------
// App initializer
// ---------------------------------------------------------------------------
async function initApp() {
    await Promise.all([loadAuthState(), loadTranslations()]);
    if (!translations[currentLang]) currentLang = 'en';
    const langIcon = document.getElementById('langIcon');
    if (langIcon) langIcon.textContent = currentLang.toUpperCase();
    setLanguage(currentLang);
    setTheme(currentTheme);
    switchTab(_getTabFromHash() || 'live-stats');
    initAdminInboxUI();
    try {
        if (_adminInboxPoll) clearInterval(_adminInboxPoll);
        _adminInboxPoll = setInterval(loadAdminInboxBadge, 60000);
        loadAdminInboxBadge();
    } catch (e) { /* ignore */ }
    lazyLoad(_scriptUrls.campaigns).then(function () {
        if (typeof populateCampaignDropdowns === 'function') populateCampaignDropdowns();
    }).catch(function (e) {
        console.error('Failed to preload campaigns module:', e);
    });
}

initApp();

// ---------------------------------------------------------------------------
// Feed Catalog modal
// ---------------------------------------------------------------------------
(function () {
    const modal = document.getElementById('feedCatalogModal');
    const openBtn = document.getElementById('feedCatalogBtn');
    const closeBtn = document.getElementById('feedCatalogClose');
    const closeBtnBottom = document.getElementById('feedCatalogCloseBottom');
    if (!modal) return;
    const hide = () => modal.classList.add('hidden');
    if (openBtn) openBtn.addEventListener('click', () => modal.classList.remove('hidden'));
    if (closeBtn) closeBtn.addEventListener('click', hide);
    if (closeBtnBottom) closeBtnBottom.addEventListener('click', hide);
    modal.addEventListener('click', (e) => { if (e.target === modal) hide(); });
    const openTaxiiBtn = document.getElementById('feedCatalogOpenTaxiiCatalog');
    if (openTaxiiBtn) {
        openTaxiiBtn.addEventListener('click', () => {
            hide();
            const taxiiModal = document.getElementById('taxiiCatalogModal');
            if (taxiiModal) taxiiModal.classList.remove('hidden');
        });
    }
})();

// ---------------------------------------------------------------------------
// TAXII Catalog modal
// ---------------------------------------------------------------------------
(function () {
    const modal = document.getElementById('taxiiCatalogModal');
    const openBtn = document.getElementById('taxiiCatalogBtn');
    const closeBtn = document.getElementById('taxiiCatalogClose');
    const closeBtnBottom = document.getElementById('taxiiCatalogCloseBottom');
    if (!modal) return;
    const hide = () => modal.classList.add('hidden');
    if (openBtn) openBtn.addEventListener('click', () => modal.classList.remove('hidden'));
    if (closeBtn) closeBtn.addEventListener('click', hide);
    if (closeBtnBottom) closeBtnBottom.addEventListener('click', hide);
    modal.addEventListener('click', (e) => { if (e.target === modal) hide(); });
})();

// ---------------------------------------------------------------------------
// Global ESC key handler to close any open modal
// ---------------------------------------------------------------------------
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        ['editModal', 'deleteIocModal', 'yaraConfirmModal', 'yaraPreviewModal', 'yaraEditModal', 'campaignEditModal', 'yaraMetaEditModal', 'addNoteModal', 'feedCatalogModal', 'feedPulseAllowlistModal', 'feedConnectionsModal', 'taxiiCatalogModal'].forEach(id => {
            const m = document.getElementById(id);
            if (m && !m.classList.contains('hidden')) m.classList.add('hidden');
        });
    }
});

// IOC tag fields: autocomplete + lowercase on blur (server also normalizes)
if (typeof initTagAutocomplete === 'function') {
    initTagAutocomplete(['iocTags', 'editTags', 'txtTagsForAll', 'pasteTagsForAll', 'csvTagsForAll']);
}
