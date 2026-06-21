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
    avatar_url: null,
    ui: { champs_tab_enabled: true, yara_approval_required: true, ioc_approval_required: true }
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
    if (typeof window.loadSearchBrowseSelect === 'function') {
        window.loadSearchBrowseSelect();
    }
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
    // nav drawer removed
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
                avatar_url: data.avatar_url || null,
                ui: data.ui || authState.ui || {}
            };
            window.authState = authState;
            applyUiWorkflowSettings(authState.ui);
        }
    } catch (e) {
        console.error('Failed to load auth state:', e);
    }
    updateAuthUI();
}

function applyUiWorkflowSettings(ui) {
    ui = ui || {};
    var champsOn = ui.champs_tab_enabled !== false;
    var bodyFlag = document.body && document.body.dataset && document.body.dataset.champsTabEnabled;
    if (bodyFlag === '0') champsOn = false;
    if (bodyFlag === '1' && ui.champs_tab_enabled === undefined) champsOn = true;
    var champsBtn = document.querySelector('#mainNavbarTabs .tab-button[data-tab="champs"]');
    if (champsBtn) {
        champsBtn.style.display = champsOn ? '' : 'none';
    }
    window.TG_UI = ui;
}

(function initUiWorkflowFromDom() {
    var bodyFlag = document.body && document.body.dataset && document.body.dataset.champsTabEnabled;
    if (bodyFlag !== undefined) {
        applyUiWorkflowSettings({ champs_tab_enabled: bodyFlag !== '0' });
    }
})();

// ---------------------------------------------------------------------------
// Unified Inbox (single bell): user notifications + admin pending (if admin)
// ---------------------------------------------------------------------------
let _inboxPoll = null;

function _inboxOutcomeLabel(category, outcome) {
    const tr = translations[currentLang] || translations.en || {};
    const inbox = tr.inbox || {};
    if (outcome === 'approved') return inbox.approved || 'Approved';
    if (outcome === 'rejected') return inbox.rejected || 'Rejected';
    return outcome || '';
}

var _YARA_REJECT_GENERIC_EN = 'Your YARA rule was rejected by an administrator.';

function _inboxYaraRejectionReason(n, inboxTr) {
    if (!n || n.category !== 'yara' || n.outcome !== 'rejected') return '';
    const payload = (n.payload && typeof n.payload === 'object') ? n.payload : {};
    const fromPayload = (payload.reason || '').trim();
    if (fromPayload) return fromPayload;
    const generic = ((inboxTr && inboxTr.yara_rejected_body) || _YARA_REJECT_GENERIC_EN).trim();
    const fromBody = (n.body || '').trim();
    if (!fromBody || fromBody === _YARA_REJECT_GENERIC_EN || fromBody === generic) return '';
    return fromBody;
}

function _inboxBodyText(n, inboxTr) {
    if (!n) return '';
    inboxTr = inboxTr || {};
    if (n.category === 'tag') {
        if (n.outcome === 'approved') return inboxTr.tag_approved_body || n.body || '';
        if (n.outcome === 'rejected') return inboxTr.tag_rejected_body || n.body || '';
    }
    if (n.category === 'yara') {
        if (n.outcome === 'approved') return inboxTr.yara_approved_body || n.body || '';
        if (n.outcome === 'rejected') {
            const generic = (inboxTr.yara_rejected_body || _YARA_REJECT_GENERIC_EN).trim();
            const reason = _inboxYaraRejectionReason(n, inboxTr);
            if (reason) {
                const reasonLabel = inboxTr.reason || 'Reason';
                return generic + '\n' + reasonLabel + ': ' + reason;
            }
            return generic;
        }
    }
    return (n.body || '').trim();
}

function _inboxDisplayTitle(n) {
    let title = (n && n.title ? String(n.title) : '').trim();
    if (!title) return '';
    if (n.category === 'yara') {
        title = title.replace(/^YARA\s+(approved|rejected)\s*:\s*/i, '');
    } else if (n.category === 'tag') {
        title = title.replace(/^Tag\s+(approved|rejected)\s*:\s*/i, '');
    }
    return title;
}

function _renderAdminPendingSection(adminData, inboxTr) {
    if (!adminData || !adminData.success) return '';
    const yara = adminData.yara_pending || [];
    const iocs = adminData.ioc_pending || [];
    const tags = adminData.tag_suggestions || [];
    const yaraCount = adminData.yara_pending_count != null ? adminData.yara_pending_count : yara.length;
    const iocCount = adminData.ioc_pending_count != null ? adminData.ioc_pending_count : iocs.length;
    const tagCount = adminData.tag_suggestions_count != null ? adminData.tag_suggestions_count : tags.length;
    if (!yaraCount && !iocCount && !tagCount) return '';
    function esc(s) { return (s == null ? '' : String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
    const yaraHtml = `
        <div class="bg-tertiary rounded-xl border border-amber-400/20 p-4">
            <div class="flex items-center justify-between gap-2 mb-2">
                <h4 class="font-semibold text-amber-200">${esc(inboxTr.admin_yara_title || 'YARA pending approvals')}</h4>
                <button type="button" class="inbox-go-yara-status text-cyan-300 hover:underline text-sm">${esc(inboxTr.admin_yara_status_link || 'YARA Manager → Status')}</button>
            </div>
            <div class="text-secondary text-sm mb-2">${esc(inboxTr.pending || 'Pending')}: <span class="text-primary font-bold">${esc(yaraCount)}</span></div>
            ${yara.length ? `<ul class="space-y-2 text-sm">` + yara.map(r => `
                <li class="border border-white/10 rounded-lg p-3">
                    <div class="font-mono text-amber-200 break-all">${esc(r.display_name != null && r.display_name !== '' ? r.display_name : r.filename)}</div>
                    <div class="text-secondary mt-1">${esc(inboxTr.by || 'By')} <span class="text-primary">${esc(r.analyst || '—')}</span> • ${esc(typeof formatUtcToLocal === 'function' ? formatUtcToLocal(r.uploaded_at) : (r.uploaded_at||'').slice(0,19).replace('T',' '))}</div>
                    ${r.ticket_id ? `<div class="text-secondary">${esc(inboxTr.ticket || 'Ticket')}: <span class="text-primary font-mono">${esc(r.ticket_id)}</span></div>` : ``}
                    ${r.comment ? `<div class="text-secondary mt-1">${esc(r.comment)}</div>` : ``}
                </li>
            `).join('') + `</ul>` : `<div class="text-secondary text-sm">${esc(inboxTr.admin_no_yara || 'No pending YARA.')}</div>`}
        </div>`;
    const iocHtml = `
        <div class="bg-tertiary rounded-xl border border-amber-400/20 p-4 mb-4">
            <div class="flex items-center justify-between gap-2 mb-2">
                <h4 class="font-semibold text-amber-200">${esc(inboxTr.admin_ioc_title || 'IOC pending approvals')}</h4>
                <button type="button" class="inbox-go-search text-cyan-300 hover:underline text-sm">${esc(inboxTr.admin_ioc_search_link || 'Search & Investigate')}</button>
            </div>
            <div class="text-secondary text-sm mb-2">${esc(inboxTr.pending || 'Pending')}: <span class="text-primary font-bold">${esc(iocCount)}</span></div>
            ${iocs.length ? `<ul class="space-y-2 text-sm">` + iocs.map(r => `
                <li class="border border-white/10 rounded-lg p-3">
                    <div class="font-mono text-amber-200 break-all">${esc(r.type)}: ${esc(r.value)}</div>
                    <div class="text-secondary mt-1">${esc(inboxTr.by || 'By')} <span class="text-primary">${esc(r.analyst || '—')}</span> • ${esc(typeof formatUtcToLocal === 'function' ? formatUtcToLocal(r.created_at) : (r.created_at||'').slice(0,19).replace('T',' '))}</div>
                    ${r.comment ? `<div class="text-secondary mt-1">${esc(r.comment)}</div>` : ``}
                </li>
            `).join('') + `</ul>` : `<div class="text-secondary text-sm">${esc(inboxTr.admin_no_ioc || 'No pending IOCs.')}</div>`}
        </div>`;
    const tagsHtml = `
        <div class="bg-tertiary rounded-xl border border-amber-400/20 p-4">
            <div class="flex items-center justify-between gap-2 mb-2">
                <h4 class="font-semibold text-amber-200">${esc(inboxTr.admin_tags_title || 'Tag suggestions')}</h4>
                <a href="/admin/settings" class="text-cyan-300 hover:underline text-sm">${esc(inboxTr.admin_tags_link || 'Settings → Tags')}</a>
            </div>
            <div class="text-secondary text-sm mb-2">${esc(inboxTr.pending || 'Pending')}: <span class="text-primary font-bold">${esc(tagCount)}</span></div>
            ${tags.length ? `<ul class="space-y-2 text-sm">` + tags.map(r => `
                <li class="border border-white/10 rounded-lg p-3">
                    <div class="font-mono text-cyan-200">${esc(r.tag)}</div>
                    <div class="text-secondary mt-1">${esc(inboxTr.by || 'By')} <span class="text-primary">${esc(r.suggested_by || '—')}</span> • ${esc(typeof formatUtcToLocal === 'function' ? formatUtcToLocal(r.suggested_at) : (r.suggested_at||'').slice(0,19).replace('T',' '))}</div>
                </li>
            `).join('') + `</ul>` : `<div class="text-secondary text-sm">${esc(inboxTr.admin_no_tags || 'No pending tag suggestions.')}</div>`}
        </div>`;
    return yaraHtml + iocHtml + tagsHtml;
}

function _renderUserNotificationsSection(userData, inboxTr) {
    const items = (userData && userData.notifications) ? userData.notifications : [];
    function esc(s) { return (s == null ? '' : String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
    if (!items.length) {
        return '<div class="text-secondary text-sm">' + esc(inboxTr.empty || 'No notifications yet.') + '</div>';
    }
    const heading = items.some(function(n) { return !n.read; })
        ? '<h4 class="font-semibold text-primary mb-2">' + esc(inboxTr.my_updates || 'Your updates') + '</h4>'
        : '<h4 class="font-semibold text-secondary mb-2">' + esc(inboxTr.my_updates || 'Your updates') + '</h4>';
    const list = items.map(function(n) {
        const unread = !n.read;
        const outcomeCls = n.outcome === 'approved' ? 'text-emerald-300' : 'text-red-300';
        const catLabel = n.category === 'tag' ? (inboxTr.category_tag || 'Tag') : (inboxTr.category_yara || 'YARA');
        const outcomeLabel = _inboxOutcomeLabel(n.category, n.outcome);
        const when = typeof formatUtcToLocal === 'function'
            ? formatUtcToLocal(n.created_at)
            : (n.created_at || '').slice(0, 19).replace('T', ' ');
        const displayTitle = _inboxDisplayTitle(n);
        const body = _inboxBodyText(n, inboxTr);
        const showBody = body && body !== displayTitle;
        const isYaraRejected = n.category === 'yara' && n.outcome === 'rejected';
        const rejFilename = isYaraRejected && n.payload && n.payload.filename ? String(n.payload.filename) : '';
        const resubmitLink = rejFilename
            ? '<button type="button" class="inbox-go-yara-rejected text-cyan-300 hover:underline text-xs mt-2 block text-left" data-filename="' + esc(rejFilename) + '">'
                + esc(inboxTr.yara_rejected_link || 'Edit & resubmit in YARA Manager →') + '</button>'
            : '';
        return '<div class="border rounded-xl p-4 ' + (unread ? 'border-cyan-400/40 bg-cyan-950/20' : 'border-white/10 bg-tertiary/40') + '">'
            + '<div class="flex items-start justify-between gap-2">'
            + '<div class="min-w-0 flex-1">'
            + '<div class="text-xs uppercase tracking-wide text-secondary mb-1">' + esc(catLabel) + ' · <span class="' + outcomeCls + '">' + esc(outcomeLabel) + '</span></div>'
            + '<div class="font-semibold text-primary break-words font-mono">' + esc(displayTitle) + '</div>'
            + (showBody ? '<div class="text-secondary text-sm mt-1 whitespace-pre-line">' + esc(body) + '</div>' : '')
            + resubmitLink
            + '</div>'
            + '<div class="text-xs text-secondary whitespace-nowrap shrink-0">' + esc(when) + '</div>'
            + '</div></div>';
    }).join('');
    return heading + '<div class="space-y-3">' + list + '</div>';
}

async function loadInboxBadge() {
    try {
        if (!authState || !authState.authenticated) return;
        const userRes = await fetch('/api/inbox', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
        const userData = await userRes.json().catch(() => ({}));
        let adminData = null;
        if (authState.is_admin) {
            const adminRes = await fetch('/api/admin/inbox', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
            adminData = await adminRes.json().catch(() => ({}));
        }
        window._userInboxLatest = userData && userData.success ? userData : null;
        window._adminInboxLatest = adminData && adminData.success ? adminData : null;

        const unread = (userData && userData.unread_count != null) ? Number(userData.unread_count) : 0;
        const adminPending = (adminData && adminData.total_pending != null) ? Number(adminData.total_pending) : 0;
        const total = unread + adminPending;

        const btn = document.getElementById('userInboxBtn');
        const badge = document.getElementById('userInboxBadge');
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
    } catch (e) {
        /* ignore */
    }
}

function _renderInboxModal() {
    const modal = document.getElementById('userInboxModal');
    const content = document.getElementById('userInboxContent');
    if (!modal || !content) return;
    const tr = translations[currentLang] || translations.en || {};
    const inboxTr = tr.inbox || {};
    function esc(s) { return (s == null ? '' : String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
    const userData = window._userInboxLatest || {};
    const items = userData.notifications || [];
    const adminHtml = authState.is_admin ? _renderAdminPendingSection(window._adminInboxLatest, inboxTr) : '';
    const userHtml = _renderUserNotificationsSection(userData, inboxTr);
    const markAllBtn = document.getElementById('userInboxMarkAllRead');
    const hasUnread = (userData.unread_count || 0) > 0;
    if (markAllBtn) markAllBtn.classList.toggle('hidden', !hasUnread);
    if (!adminHtml && !items.length) {
        content.innerHTML = '<div class="text-secondary text-sm">' + esc(inboxTr.empty || 'No notifications yet.') + '</div>';
    } else {
        content.innerHTML = adminHtml + userHtml;
    }
    modal.classList.remove('hidden');
}

async function markUserInboxRead(all) {
    try {
        const body = all ? { all: true } : {};
        await fetch('/api/inbox/mark-read', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify(body),
        });
        if (window._userInboxLatest) {
            window._userInboxLatest.notifications = (window._userInboxLatest.notifications || []).map(function(n) {
                return Object.assign({}, n, { read: true });
            });
            window._userInboxLatest.unread_count = 0;
        }
        await loadInboxBadge();
    } catch (e) {
        console.warn('markUserInboxRead failed', e);
    }
}

async function goToYaraStatus() {
    const modal = document.getElementById('userInboxModal');
    if (modal) modal.classList.add('hidden');
    await switchTab('yara');
    if (typeof window.setYaraMode === 'function') {
        window.setYaraMode('status');
    }
    const pendingSec = document.getElementById('yaraPendingSection');
    if (pendingSec) {
        pendingSec.classList.remove('hidden');
        setTimeout(function () {
            pendingSec.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 150);
    }
}

async function goToYaraRejected(filename) {
    const modal = document.getElementById('userInboxModal');
    if (modal) modal.classList.add('hidden');
    await switchTab('yara');
    if (filename && typeof window.editAndResubmitRejectedRule === 'function') {
        await window.editAndResubmitRejectedRule(filename);
        return;
    }
    if (typeof window.setYaraMode === 'function') {
        window.setYaraMode('status');
    }
    const rejectedSec = document.getElementById('yaraRejectedSection');
    if (rejectedSec) {
        rejectedSec.classList.remove('hidden');
        setTimeout(function () {
            rejectedSec.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 150);
    }
}

function initInboxUI() {
    const btn = document.getElementById('userInboxBtn');
    const modal = document.getElementById('userInboxModal');
    const close = document.getElementById('userInboxClose');
    const markAll = document.getElementById('userInboxMarkAllRead');
    const content = document.getElementById('userInboxContent');
    if (content) {
        content.addEventListener('click', function (e) {
            if (e.target.closest('.inbox-go-yara-status')) {
                e.preventDefault();
                goToYaraStatus();
                return;
            }
            const rejBtn = e.target.closest('.inbox-go-yara-rejected');
            if (rejBtn) {
                e.preventDefault();
                goToYaraRejected(rejBtn.getAttribute('data-filename') || '');
            }
        });
    }
    if (btn) {
        btn.addEventListener('click', async function() {
            await loadInboxBadge();
            _renderInboxModal();
            if ((window._userInboxLatest || {}).unread_count > 0) {
                await markUserInboxRead(true);
                _renderInboxModal();
            }
        });
    }
    if (markAll) {
        markAll.addEventListener('click', async function() {
            await markUserInboxRead(true);
            _renderInboxModal();
        });
    }
    if (close && modal) close.addEventListener('click', () => modal.classList.add('hidden'));
    if (modal) modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.add('hidden'); });
}
window.loadInboxBadge = loadInboxBadge;

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
        // Logout/Admin live in the profile modal now (header buttons are hidden via CSS)
        logoutEl.classList.add('hidden');
        if (authState.avatar_url && avatarImg) {
            avatarImg.src = authState.avatar_url;
            avatarImg.classList.remove('hidden');
            if (avatarPlaceholder) avatarPlaceholder.classList.add('hidden');
        } else {
            if (avatarImg) avatarImg.classList.add('hidden');
            if (avatarPlaceholder) avatarPlaceholder.classList.remove('hidden');
        }
        if (adminEl) adminEl.classList.add('hidden');
        const userInboxBtn = document.getElementById('userInboxBtn');
        if (userInboxBtn) userInboxBtn.classList.remove('hidden');
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
        // Anonymous mode: profile button stays visible (acts as Login entrypoint)
        loginEl.classList.add('hidden');
        if (profileEl) {
            profileEl.classList.remove('hidden');
            profileEl.title = 'Anonymous';
        }
        if (avatarImg) avatarImg.classList.add('hidden');
        if (avatarPlaceholder) avatarPlaceholder.classList.remove('hidden');
        logoutEl.classList.add('hidden');
        if (adminEl) adminEl.classList.add('hidden');
        const userInboxBtn = document.getElementById('userInboxBtn');
        if (userInboxBtn) userInboxBtn.classList.add('hidden');
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
        s.onerror = () => reject(new Error('Failed to load script: ' + src));
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
    // Live Stats is intentionally public; Feed Pulse contains sensitive connection/push status.
    const requireAuthTabs = new Set(['feed-pulse', 'search', 'bulk-unified', 'yara', 'champs', 'campaigns', 'playbook', 'reports']);
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
            if (typeof window.performSearch !== 'function') {
                showToast('Search module did not load. Hard-refresh the page (Ctrl+Shift+R).', 'error', 6000);
                console.error('search.js missing: window.performSearch is not a function');
            } else if (typeof window.loadSearchCountryCodes === 'function') {
                window.loadSearchCountryCodes();
            }
        } catch (e) {
            console.error('Search tab init failed:', e);
        }
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
        if (authState && authState.authenticated) {
            loadYaraPending();
            if (typeof loadYaraRejected === 'function') loadYaraRejected(true);
        }
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
function showToast(message, type = 'success', durationMs = 10000) {
    const icons = { success: '\u2713', error: '\u2717', warning: '\u26A0' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    // Ensure the progress bar is visible even if CSS is stale/overridden.
    // Also clips the bar to the toast rounded corners.
    toast.style.overflow = 'hidden';
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
    // Inline fallback styles (CSS should still apply; this just guarantees visibility).
    progressSpan.style.display = 'block';
    progressSpan.style.position = 'absolute';
    progressSpan.style.left = '0';
    progressSpan.style.right = '0';
    progressSpan.style.bottom = '0';
    progressSpan.style.height = '4px';
    progressSpan.style.background = 'rgba(255, 255, 255, 0.75)';
    progressSpan.style.boxShadow = '0 -1px 6px rgba(0,0,0,0.25)';
    progressSpan.style.transformOrigin = 'right center';
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
window.goToYaraStatus = goToYaraStatus;
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
    initInboxUI();
    try {
        if (_inboxPoll) clearInterval(_inboxPoll);
        _inboxPoll = setInterval(loadInboxBadge, 30000);
        loadInboxBadge();
        document.addEventListener('visibilitychange', function () {
            if (document.visibilityState === 'visible') loadInboxBadge();
        });
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

    // No demo-specific behavior here; demo rewrites links at build time.
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
        ['editModal', 'deleteIocModal', 'yaraConfirmModal', 'yaraPreviewModal', 'yaraEditModal', 'campaignEditModal', 'yaraMetaEditModal', 'addNoteModal', 'feedCatalogModal', 'feedPulseAllowlistModal', 'feedConnectionsModal', 'taxiiCatalogModal', 'userInboxModal'].forEach(id => {
            const m = document.getElementById(id);
            if (m && !m.classList.contains('hidden')) m.classList.add('hidden');
        });
    }
});

// IOC tag fields: autocomplete + lowercase on blur (server also normalizes)
if (typeof initTagAutocomplete === 'function') {
    initTagAutocomplete(['iocTags', 'editTags', 'txtTagsForAll', 'pasteTagsForAll', 'csvTagsForAll', 'campaignCreateTags', 'campaignEditTags']);
}
