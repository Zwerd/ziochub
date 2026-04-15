// ============================================================
// submit.js - IOC submission, validation, staging & bulk logic
// Extracted from inline <script> in templates/index.html
// ============================================================

// Bulk Upload tab: TXT / CSV mode toggle
function getBulkUploadInfoTxt() {
    return `<h4 class="font-bold mb-1" data-i18n="bulk.info_txt_title">📝 ${t('bulk.info_txt_title')}</h4>
                <p class="mb-1" data-i18n="bulk.info_txt_desc">${t('bulk.info_txt_desc')}</p>`;
}
function getBulkUploadInfoCsv() {
    return `<h4 class="font-bold mb-1" data-i18n="bulk.info_csv_title">📊 ${t('bulk.info_csv_title')}</h4>
                <p class="mb-1" data-i18n="bulk.info_csv_desc">${t('bulk.info_csv_desc')}</p>`;
}
function getBulkUploadInfoSingle() {
    return `<h4 class="font-bold mb-1" data-i18n="submit.title">${t('submit.title')}</h4>
                <p class="mb-1" data-i18n="bulk.info_single_desc">${t('bulk.info_single_desc')}</p>`;
}
function getBulkUploadInfoPaste() {
    return `<h4 class="font-bold mb-1" data-i18n="bulk.info_paste_title">${t('bulk.info_paste_title')}</h4>
                <p class="mb-1" data-i18n="bulk.info_paste_desc">${t('bulk.info_paste_desc')}</p>`;
}

function setBulkUploadMode(mode) {
    const isSingle = mode === 'single';
    const isTxt = mode === 'txt';
    const isCsv = mode === 'csv';
    const isPaste = mode === 'paste';
    const wrapperSingle = document.getElementById('bulk-wrapper-single');
    const wrapperTxt = document.getElementById('bulk-wrapper-txt');
    const wrapperCsv = document.getElementById('bulk-wrapper-csv');
    const wrapperPaste = document.getElementById('bulk-wrapper-paste');
    const btnSingle = document.getElementById('btnModeSingle');
    const btnTxt = document.getElementById('btnModeTxt');
    const btnCsv = document.getElementById('btnModeCsv');
    const btnPaste = document.getElementById('btnModePaste');
    const infoCard = document.getElementById('bulkUploadInfoCard');
    const csvFile = document.getElementById('csvFile');
    const txtFile = document.getElementById('txtFile');
    const txtStaging = document.getElementById('txtStagingArea');
    const csvStaging = document.getElementById('csvStagingArea');
    const singleStaging = document.getElementById('singleStagingArea');
    const pasteStaging = document.getElementById('pasteStagingArea');

    if (wrapperSingle) wrapperSingle.classList.toggle('hidden', !isSingle);
    if (wrapperTxt) wrapperTxt.classList.toggle('hidden', !isTxt);
    if (wrapperCsv) wrapperCsv.classList.toggle('hidden', !isCsv);
    if (wrapperPaste) wrapperPaste.classList.toggle('hidden', !isPaste);
    if (txtStaging) txtStaging.classList.toggle('hidden', !isTxt);
    if (csvStaging) csvStaging.classList.toggle('hidden', !isCsv);
    if (singleStaging) singleStaging.classList.toggle('hidden', !isSingle);
    if (pasteStaging) pasteStaging.classList.toggle('hidden', !isPaste);

    function setActive(btn, active) {
        if (!btn) return;
        if (active) { btn.classList.add('bg-blue-600', 'text-white'); btn.classList.remove('bg-transparent', 'text-secondary'); }
        else { btn.classList.remove('bg-blue-600', 'text-white'); btn.classList.add('bg-transparent', 'text-secondary'); }
    }
    setActive(btnSingle, isSingle);
    setActive(btnTxt, isTxt);
    setActive(btnCsv, isCsv);
    setActive(btnPaste, isPaste);

    if (infoCard) {
        if (isSingle) infoCard.innerHTML = getBulkUploadInfoSingle();
        else if (isTxt) infoCard.innerHTML = getBulkUploadInfoTxt();
        else if (isCsv) infoCard.innerHTML = getBulkUploadInfoCsv();
        else infoCard.innerHTML = getBulkUploadInfoPaste();
    }
    if (txtFile) txtFile.setAttribute('accept', '.txt');
    if (csvFile) csvFile.setAttribute('accept', '.csv');
}

document.getElementById('btnModeSingle').addEventListener('click', () => setBulkUploadMode('single'));
document.getElementById('btnModeTxt').addEventListener('click', () => setBulkUploadMode('txt'));
document.getElementById('btnModeCsv').addEventListener('click', () => setBulkUploadMode('csv'));
document.getElementById('btnModePaste').addEventListener('click', () => setBulkUploadMode('paste'));
setBulkUploadMode('single');

// ---- IOC Validation ----

function validateIocFormat(value, type) {
    if (!value) return 'IOC value is required';
    switch (type) {
        case 'IP': {
            // IPv4 or IPv6 basic check
            const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
            const ipv6 = /^[0-9a-fA-F:]+$/;
            if (!ipv4.test(value) && !ipv6.test(value)) return 'Invalid IP address format';
            if (ipv4.test(value)) {
                const parts = value.split('.');
                if (parts.some(p => parseInt(p) > 255)) return 'IP octet exceeds 255';
            }
            break;
        }
        case 'Domain':
            if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) return 'Invalid domain format';
            break;
        case 'Email':
            if (!value.includes('@') || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'Invalid email format';
            break;
        case 'URL':
            if (!/^https?:\/\/.+/i.test(value)) return 'URL must start with http:// or https://';
            break;
        case 'Hash':
            if (!/^[a-fA-F0-9]+$/.test(value)) return 'Hash must be hexadecimal characters only';
            if (![32, 40, 64].includes(value.length)) return 'Hash length must be 32 (MD5), 40 (SHA1), or 64 (SHA256)';
            break;
    }
    return null; // Valid
}

// ---- Client Refanger ----

/** Refanger: auto-fix defanged hxxp->http, [.]->., (.)->., [dot]->. */
function clientRefanger(value) {
    if (!value) return { cleaned: value, changed: false };
    const original = value;
    let v = value;
    v = v.replace(/hxxps?/gi, m => (m.toLowerCase().indexOf('s') >= 0 ? 'https' : 'http'));
    v = v.replace(/h\*\*ps?/gi, m => (m.toLowerCase().indexOf('s') >= 0 ? 'https' : 'http'));
    v = v.replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.').replace(/\[dot\]/gi, '.');
    v = v.trim();
    return { cleaned: v, changed: v !== original };
}

// ---- Critical / Private Checks ----

/** Critical checks - block. Returns error message or null. (Defanged auto-fixed by refanger.) */
function getClientCriticalCheck(value, iocType) {
    const v = (value || '').trim();
    if (!v) return null;
    if (iocType === 'IP' && ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'].includes(v)) return (t('sanity.critical_infra') || 'Critical infrastructure IP - blocking would break DNS.');
    if ((iocType === 'Domain' || iocType === 'URL') && /^\.?[a-z]{2,6}$|^\.?[a-z]{2}\.[a-z]{2}$/i.test(v.replace(/^\.+/, ''))) return (t('sanity.tld_only') || 'Blocking entire TLD would break the internet.');
    return null;
}

/** Returns list of warning strings if value is private/internal (IP or Domain). Used for two-step confirmation. */
function getClientPrivateWarnings(value, iocType) {
    const v = (value || '').trim();
    const warnings = [];
    if (iocType === 'IP') {
        const parts = v.split('.').map(Number);
        if (parts.length === 4 && parts.every(n => !isNaN(n) && n >= 0 && n <= 255)) {
            if (parts[0] === 10) warnings.push('Private IP (10.0.0.0/8)');
            else if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) warnings.push('Private IP (172.16.0.0/12)');
            else if (parts[0] === 192 && parts[1] === 168) warnings.push('Private IP (192.168.0.0/16)');
            else if (parts[0] === 127) warnings.push('Loopback / localhost');
        }
    }
    if (iocType === 'Domain') {
        const lower = v.toLowerCase();
        if (lower.endsWith('.local')) warnings.push('.local domain');
        if (lower === 'localhost' || lower === 'localhost.') warnings.push('Localhost hostname');
        if (lower.endsWith('.internal') || lower.includes('.internal.')) warnings.push('.internal domain');
    }
    return warnings;
}

// ---- Private Confirm Modal ----

let pendingSubmitData = null;
const privateConfirmModal = document.getElementById('privateConfirmModal');
const privateConfirmTitle = document.getElementById('privateConfirmTitle');
const privateConfirmMessage = document.getElementById('privateConfirmMessage');
const privateConfirmCancel = document.getElementById('privateConfirmCancel');
const privateConfirmYes = document.getElementById('privateConfirmYes');

async function maybeSuggestInvalidTags(result) {
    try {
        if (!result || !Array.isArray(result.invalid_tags) || !result.invalid_tags.length) return false;
        if (!result.suggest_allowed) return false;
        if (typeof window.appConfirm !== 'function') return false;
        const list = result.invalid_tags.slice(0, 10).join(', ') + (result.invalid_tags.length > 10 ? '…' : '');
        const ok = await window.appConfirm({
            title: t('tags.suggest_title') || 'Suggest new tag(s)?',
            message: (t('tags.suggest_message') || 'These tags are not allowed yet:') + '\n\n' + list,
            okText: t('tags.suggest_ok') || 'Suggest',
            cancelText: t('tags.suggest_cancel') || 'Cancel'
        });
        if (!ok) return true;
        const res = await fetch('/api/tags/suggest', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tags: result.invalid_tags })
        });
        const data = await res.json().catch(() => ({}));
        if (data && data.success) {
            showToast(t('tags.suggested') || 'Suggestion submitted to admin for approval.', 'success');
        } else {
            showToast((data && data.message) ? data.message : 'Failed to suggest tags', 'error');
        }
        return true;
    } catch (e) {
        return false;
    }
}

function showPrivateConfirmStep(step, value) {
    const displayVal = value ? (value.length > 50 ? value.substring(0, 47) + '...' : value) : '';
    if (step === 1) {
        privateConfirmTitle.textContent = t('private_confirm.step1_title');
        privateConfirmMessage.textContent = t('private_confirm.step1_message') + (displayVal ? '\n\n' + (currentLang === 'he' ? 'אינדיקטור: ' : 'Indicator: ') + displayVal : '');
        privateConfirmYes.textContent = t('private_confirm.yes_continue');
    } else {
        privateConfirmTitle.textContent = t('private_confirm.step2_title');
        privateConfirmMessage.textContent = t('private_confirm.step2_message');
        privateConfirmYes.textContent = t('private_confirm.yes_proceed');
    }
    privateConfirmModal.classList.remove('hidden');
}

function hidePrivateConfirm() {
    privateConfirmModal.classList.add('hidden');
    pendingSubmitData = null;
}

if (privateConfirmCancel) privateConfirmCancel.addEventListener('click', hidePrivateConfirm);
if (privateConfirmModal) privateConfirmModal.addEventListener('click', (e) => { if (e.target === privateConfirmModal) hidePrivateConfirm(); });

if (privateConfirmYes) {
    privateConfirmYes.addEventListener('click', async () => {
        if (!pendingSubmitData) { hidePrivateConfirm(); return; }
        const step = pendingSubmitData._step || 1;
        if (step === 1) {
            pendingSubmitData._step = 2;
            showPrivateConfirmStep(2, pendingSubmitData.value);
        } else {
            const data = { ...pendingSubmitData };
            delete data._step;
            hidePrivateConfirm();
            try {
                const response = await fetch('/api/submit-ioc', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const result = await response.json().catch(() => ({}));
                if (response.status === 409) {
                    showToast(t('toast.duplicate_entry'), 'error');
                    return;
                }
                if (result.success) {
                    showToast(result.message, 'success');
                    if (result.auto_corrected) showToast(t('toast.auto_corrected'), 'warning');
                    if (result.warnings && result.warnings.length) showToast(result.warnings.join('\n'), 'warning');
                    if (result.new_badges || result.level_up || result.rank_up || result.points_earned !== undefined || result.level_info || result.new_nickname) showAchievementModal(result);
                    document.getElementById('iocForm').reset();
                    loadStats();
                    loadLiveFeed();
                } else {
                    if (await maybeSuggestInvalidTags(result)) return;
                    showToast(result.message || 'Submission failed', 'error');
                }
            } catch (error) {
                showToast(t('toast.error_submit') + ': ' + error.message, 'error');
            }
        }
    });
}

// ---- doSubmitIoc ----

async function doSubmitIoc(data) {
    try {
        const response = await fetch('/api/submit-ioc', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        const result = await response.json().catch(() => ({}));
        if (response.status === 409) {
            showToast(t('toast.duplicate_entry'), 'error');
            return;
        }
        if (result.success) {
            showToast(result.message, 'success');
            if (result.auto_corrected) showToast(t('toast.auto_corrected'), 'warning');
            if (result.warnings && result.warnings.length) {
                showToast(result.warnings.join('\n'), 'warning');
            }
            if (result.new_badges || result.level_up || result.rank_up || result.points_earned !== undefined || result.level_info || result.new_nickname) showAchievementModal(result);
            document.getElementById('iocForm').reset();
            loadStats();
            loadLiveFeed();
        } else {
            if (await maybeSuggestInvalidTags(result)) return;
            showToast(result.message || 'Submission failed', 'error');
        }
    } catch (error) {
        showToast(t('toast.error_submit') + ': ' + error.message, 'error');
    }
}

// ---- addSingleToStaging ----

/** Add current Single form as one row to Single staging table. Calls /api/preview-single to get existing_permanent and show "Already exists" + disable Approve when IOC is in DB. */
async function addSingleToStaging() {
    if (!authState || !authState.authenticated) {
        showToast(t('auth.login_required') || 'Please log in to submit IOCs', 'error');
        return;
    }
    const rawInput = (document.getElementById('iocValue') && document.getElementById('iocValue').value) || '';
    let value = rawInput.trim();
    const { cleaned: refangValue, changed: wasRefanged } = clientRefanger(value);
    value = refangValue;
    const type = document.getElementById('iocType').value;
    const assignToEl = document.getElementById('iocAssignTo');
    const username = (assignToEl && assignToEl.value) ? assignToEl.value.trim() : (authState.username || '');
    const validationError = validateIocFormat(value, type);
    if (validationError) {
        showToast(validationError, 'error');
        return;
    }
    /* Critical sanity (e.g. 8.8.8.8, TLD-only) is enforced by the server based on Admin → Sanity Check setting (block_all / block_non_admin / warn_all). Do not block here. */
    const ticket_id = (document.getElementById('iocTicketId') && document.getElementById('iocTicketId').value) ? document.getElementById('iocTicketId').value.trim() : '';
    const comment = (document.getElementById('iocComment') && document.getElementById('iocComment').value) ? document.getElementById('iocComment').value.trim() : '';
    const expiration = (document.getElementById('iocTTL') && document.getElementById('iocTTL').value) ? document.getElementById('iocTTL').value : 'Permanent';
    const tagsInput = document.getElementById('iocTags');
    const tagsStr = (tagsInput && tagsInput.value)
        ? (typeof normalizeTagsInputValue === 'function'
            ? normalizeTagsInputValue(tagsInput.value)
            : tagsInput.value.trim())
        : '';

    const tbody = document.getElementById('singleStagingTableBody');
    const countEl = document.getElementById('singleStagingCount');
    const area = document.getElementById('singleStagingArea');
    if (!tbody || !countEl || !area) return;

    try {
        const res = await fetch('/api/preview-single', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                type,
                value,
                ticket_id: ticket_id || undefined,
                ttl: expiration,
                comment,
                tags: tagsStr ? tagsStr.split(',').map(s => s.trim()).filter(Boolean) : undefined,
                assign_to: username || undefined
            })
        });
        const result = await res.json();
        if (!result.success || !result.item) {
            showToast(result.message || 'Preview failed', 'error');
            return;
        }
        const item = result.item;
        const serverWarnings = Array.isArray(result.warnings) ? result.warnings : [];
        const conflict = !!item.existing_permanent;
        const rowClass = conflict ? 'txt-staging-row txt-staging-row-conflict bg-amber-900/20' : 'txt-staging-row';
        const dataPerm = conflict ? ' data-existing-permanent="true"' : '';
        const ioc = escapeHtml(item.ioc || '');
        const typeEsc = escapeHtml(item.type || '');
        const tagsDisplay = Array.isArray(item.tags) ? (item.tags || []).join(', ') : (item.tags || '');
        const tagsEsc = escapeHtml(tagsDisplay);
        const ticketEsc = escapeHtml(item.ticket_id || '');
        const analystEsc = escapeHtml(item.analyst || '');
        const dateEsc = escapeHtml(item.date || '');
        const commentEsc = escapeHtml(item.comment || '');
        const expirationEsc = escapeHtml(item.expiration || 'Permanent');
        const permTip = conflict ? (item.existing_analyst || item.existing_comment ? 'Existing: ' + (item.existing_analyst || '').replace(/"/g, '') + ' | ' + (item.existing_comment || '').substring(0, 60).replace(/"/g, '') : 'Already in DB') : '';
        const permTitle = permTip ? ' title="' + permTip.replace(/"/g, '&quot;') + '"' : '';
        const approveDisabled = conflict ? ' disabled' : '';
        const approveClass = conflict ? 'txt-staging-approve btn-cmd-primary btn-cmd-sm opacity-50 cursor-not-allowed' : 'txt-staging-approve btn-cmd-primary btn-cmd-sm';
        const permBadge = conflict ? `<span class="txt-staging-perm-badge text-amber-400 text-xs mr-1"${permTitle}>⚠️ Already exists</span>` : '';
        const row = document.createElement('tr');
        row.className = rowClass;
        if (dataPerm) row.setAttribute('data-existing-permanent', 'true');
        row.innerHTML = `
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ioc">${ioc}</td>
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="type">${typeEsc}</td>
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="tags">${tagsEsc}</td>
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ticket_id">${ticketEsc}</td>
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="analyst">${analystEsc}</td>
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="date">${dateEsc}</td>
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="comment" dir="${typeof detectTextDir==='function'?detectTextDir(commentEsc):'auto'}">${commentEsc}</td>
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="expiration">${expirationEsc}</td>
            <td class="border border-white/10 px-3 py-2">
                <div class="flex items-center gap-1.5 justify-center flex-wrap">
                    ${permBadge}
                    <button type="button" class="${approveClass}"${approveDisabled} title="Approve this row">Approve</button>
                    <button type="button" class="txt-staging-edit btn-cmd-primary btn-cmd-sm" title="${t('actions.edit_row')}">${t('actions.edit')}</button>
                    <button type="button" class="txt-staging-delete btn-cmd-danger btn-cmd-sm" title="${t('actions.delete_row')}">${t('actions.delete')}</button>
                </div>
            </td>`;
        tbody.appendChild(row);
        const n = tbody.querySelectorAll('tr').length;
        countEl.textContent = t('bulk.found_count', { count: n });
        area.classList.remove('hidden');
        attachStagingRowActionsForRow(row, 'iocTTL', 'iocCampaignSelect', 'single');
        fetchStagingAnalystUsers().catch(() => {});
        const privateWarnings = getClientPrivateWarnings(value, type);
        const sanityWarnings = [];
        if (type === 'URL' && /[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}/.test(value)) sanityWarnings.push(t('sanity.url_hash') || 'URL contains hash-like string. Verify.');
        if (type === 'Hash' && /^[a-fA-F0-9]+$/.test(value) && ![32, 40, 64].includes(value.length)) sanityWarnings.push(t('sanity.hash_mismatch') || 'Hash length: MD5=32, SHA1=40, SHA256=64.');
        if (type === 'Domain' && value.split('.').every(p => p.length <= 2)) sanityWarnings.push(t('sanity.short_domain') || 'Very short domain. Possible typo.');
        if (rawInput !== rawInput.trim()) sanityWarnings.push(t('sanity.whitespace') || 'Whitespace was trimmed.');
        if (wasRefanged) sanityWarnings.push(t('sanity.auto_refanged') || 'Defanged URL/domain was auto-fixed (hxxp->http, [.]->.).');
        const allWarnings = [...serverWarnings, ...privateWarnings, ...sanityWarnings];
        if (allWarnings.length > 0) showToast(allWarnings.join('\n'), 'warning');
        if (conflict) showToast(t('bulk.already_exists') || 'This IOC already exists in the system. Approve is disabled.', 'warning');
        const iocValue = document.getElementById('iocValue');
        const iocType = document.getElementById('iocType');
        const iocTags = document.getElementById('iocTags');
        const iocTicketId = document.getElementById('iocTicketId');
        const iocTTL = document.getElementById('iocTTL');
        if (iocValue) iocValue.value = '';
        if (iocType) iocType.value = '';
        if (iocTags) iocTags.value = '';
        if (iocTicketId) iocTicketId.value = '';
        if (iocTTL) iocTTL.value = 'Permanent';
        showToast(t('toast.item_added_to_list') || 'Added to list', 'success');
    } catch (err) {
        showToast((t('toast.error_generic') || 'Error') + ': ' + err.message, 'error');
    }
}

document.getElementById('singleAddToListBtn').addEventListener('click', (e) => {
    e.preventDefault();
    addSingleToStaging();
});

document.getElementById('iocForm').addEventListener('submit', (e) => {
    e.preventDefault();
    addSingleToStaging();
});

// ---- CSV form prevention ----

document.getElementById('csvForm').addEventListener('submit', (e) => { e.preventDefault(); });

// ---- Staging Helpers ----

const TXT_STAGING_TTL_OPTIONS = ['Permanent', '1 Week', '1 Month', '3 Months', '1 Year'];
const STAGING_EDITABLE_FIELDS = new Set(['ticket_id', 'comment', 'expiration', 'tags']);

let _cachedStagingAnalystUsers = null;

/** Load analysts for staging row edit (same source as Assign-to dropdowns). Cached until invalidateStagingAnalystCache. */
async function fetchStagingAnalystUsers() {
    if (_cachedStagingAnalystUsers !== null) return _cachedStagingAnalystUsers;
    try {
        const res = await fetch('/api/users');
        const data = await res.json().catch(() => ({}));
        _cachedStagingAnalystUsers = (data.success && Array.isArray(data.users)) ? data.users : [];
    } catch (e) {
        _cachedStagingAnalystUsers = [];
    }
    return _cachedStagingAnalystUsers;
}

function _buildStagingAnalystSelectHtml(selectedUsername) {
    const users = _cachedStagingAnalystUsers || [];
    const meLabel = (typeof t === 'function' && t('submit.me')) ? t('submit.me') : '- Me -';
    const escAttr = typeof escapeAttr === 'function' ? escapeAttr : function (s) {
        return String(s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
    };
    const raw = (selectedUsername || '').trim();
    const selLower = raw.toLowerCase();
    let html = '<select class="staging-analyst-select w-full max-w-[14rem] bg-tertiary border border-white/20 text-white rounded px-2 py-1 text-sm">';
    html += `<option value=""${!selLower ? ' selected' : ''}>${escapeHtml(meLabel)}</option>`;
    const seen = new Set(['']);
    users.forEach((u) => {
        const un = (u && u.username) ? String(u.username).trim() : '';
        if (!un || seen.has(un.toLowerCase())) return;
        seen.add(un.toLowerCase());
        const optSel = un.toLowerCase() === selLower ? ' selected' : '';
        html += `<option value="${escAttr(un)}"${optSel}>${escapeHtml(un)}</option>`;
    });
    if (selLower && !seen.has(selLower)) {
        html += `<option value="${escAttr(raw)}" selected>${escapeHtml(raw)}</option>`;
    }
    html += '</select>';
    return html;
}

function validateStagingItem(item) {
    if (!item || !item.ioc || !item.type) return 'IOC value and type are required';
    const { cleaned } = clientRefanger(item.ioc);
    return validateIocFormat(cleaned, item.type);
}

async function _enableStagingEdit(row, btn) {
    row.classList.add('txt-staging-row-editing');
    await fetchStagingAnalystUsers();
    const analystCell = row.querySelector('td[data-field="analyst"]');
    if (analystCell) {
        const currentVal = (analystCell.textContent || '').trim();
        analystCell.innerHTML = _buildStagingAnalystSelectHtml(currentVal);
    }
    const cells = row.querySelectorAll('td[data-field]');
    const expCell = row.querySelector('td[data-field="expiration"]');
    cells.forEach((c) => {
        const field = c.getAttribute('data-field');
        if (!STAGING_EDITABLE_FIELDS.has(field)) return;
        if (field === 'expiration') return;
        c.setAttribute('contenteditable', 'true');
        if (field === 'comment' && typeof detectTextDir === 'function') {
            c.addEventListener('input', function() { this.dir = detectTextDir(this.textContent); });
        }
    });
    if (expCell) {
        const currentVal = (expCell.textContent || '').trim();
        const match = TXT_STAGING_TTL_OPTIONS.find(o => o === currentVal) ? currentVal : 'Permanent';
        const options = TXT_STAGING_TTL_OPTIONS.map(o => `<option value="${escapeHtml(o)}"${o === match ? ' selected' : ''}>${escapeHtml(o)}</option>`).join('');
        expCell.innerHTML = `<select class="w-full bg-tertiary border border-white/20 text-white rounded px-2 py-1 text-sm">${options}</select>`;
    }
    const analystSel = row.querySelector('select.staging-analyst-select');
    if (analystSel) analystSel.focus();
    else {
        const firstEditable = row.querySelector('td[data-field="ticket_id"]');
        if (firstEditable) firstEditable.focus();
    }
    btn.classList.add('ring-2', 'ring-blue-400');
}

function _disableStagingEdit(row, btn) {
    row.classList.remove('txt-staging-row-editing');
    const cells = row.querySelectorAll('td[data-field]');
    const expCell = row.querySelector('td[data-field="expiration"]');
    const analystCell = row.querySelector('td[data-field="analyst"]');
    cells.forEach(c => { c.setAttribute('contenteditable', 'false'); });
    if (analystCell) {
        const asel = analystCell.querySelector('select.staging-analyst-select');
        if (asel) {
            const v = (asel.value || '').trim();
            analystCell.textContent = v || ((typeof authState !== 'undefined' && authState && authState.username) ? authState.username : '');
        }
    }
    if (expCell) {
        const sel = expCell.querySelector('select');
        if (sel) expCell.textContent = sel.value;
    }
    btn.classList.remove('ring-2', 'ring-blue-400');
}

function attachStagingRowActionsForRow(tr, ttlSelectId, campaignSelectId, source) {
    if (!tr) return;
    const _src = source || 'single';
    const tbody = tr.closest('tbody');
    [tr].forEach(row => {
        row.querySelectorAll('.txt-staging-approve').forEach(btn => {
            btn.addEventListener('click', async () => {
                const item = getTxtStagingRowData(row);
                if (!item) { showToast(t('toast.invalid_row'), 'error'); return; }
                const valErr = validateStagingItem(item);
                if (valErr) { showToast(valErr, 'error'); return; }
                const ttlEl = document.getElementById(ttlSelectId);
                const campaignSel = document.getElementById(campaignSelectId);
                const ttl = ttlEl ? ttlEl.value : 'Permanent';
                const campaign_name = campaignSel && campaignSel.value ? campaignSel.value : '';
                try {
                    const response = await fetch('/api/submit-staging', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ items: [item], ttl, campaign_name, source: _src })
                    });
                    const result = await response.json().catch(() => ({}));
                    if (result.success) {
                        showToast(t('toast.item_imported'), 'success');
                        if (result.new_badges || result.level_up || result.rank_up || result.points_earned !== undefined || result.level_info || result.new_nickname) showAchievementModal(result);
                        row.remove();
                        const n = tbody ? tbody.querySelectorAll('tr').length : 0;
                        const countEl = document.getElementById('singleStagingCount');
                        if (countEl) countEl.textContent = n ? t('bulk.found_count', { count: n }) : t('bulk.found_items');
                        loadStats();
                        loadLiveFeed();
                    } else {
                        showToast(result.message || 'Import failed', 'error');
                    }
                } catch (e) {
                    showToast(t('toast.error_generic') + ': ' + e.message, 'error');
                }
            });
        });
        row.querySelectorAll('.txt-staging-edit').forEach(btn => {
            btn.addEventListener('click', async () => {
                const isEditing = row.classList.contains('txt-staging-row-editing');
                if (isEditing) {
                    _disableStagingEdit(row, btn);
                } else {
                    await _enableStagingEdit(row, btn);
                }
            });
        });
        row.querySelectorAll('.txt-staging-delete').forEach(btn => {
            btn.addEventListener('click', () => {
                row.remove();
                const n = tbody ? tbody.querySelectorAll('tr').length : 0;
                const countEl = document.getElementById('singleStagingCount');
                if (countEl) countEl.textContent = n ? t('bulk.found_count', { count: n }) : t('bulk.found_items');
            });
        });
    });
}

/** Parse "Tags (for all)" input into array (comma-separated, max 50). */
function getTagsForAllFromInput(inputId) {
    const el = document.getElementById(inputId);
    if (!el || !el.value) return [];
    const raw = typeof normalizeTagsInputValue === 'function'
        ? normalizeTagsInputValue(el.value)
        : el.value.trim();
    return raw.split(',').map(s => s.trim()).filter(Boolean).slice(0, 50);
}

/** Assign-to dropdown value for bulk preview; empty = current user (server resolves like Single). */
function getBulkAssignToValue(selectId) {
    const el = document.getElementById(selectId);
    return (el && el.value) ? el.value.trim() : '';
}

/** Attach Approve/Edit/Delete to staging rows in a tbody. ttlSelectId, campaignSelectId, source; optional tagsInputId for "Tags (for all)". */
function attachStagingRowActions(tbody, ttlSelectId, campaignSelectId, source, tagsInputId) {
    if (!tbody) return;
    const _src = source || 'single';
    tbody.querySelectorAll('.txt-staging-approve').forEach(btn => {
        btn.addEventListener('click', async () => {
            const tr = btn.closest('tr');
            if (!tr) return;
            const item = getTxtStagingRowData(tr);
            if (!item) { showToast(t('toast.invalid_row'), 'error'); return; }
            const valErr = validateStagingItem(item);
            if (valErr) { showToast(valErr, 'error'); return; }
            const ttlEl = document.getElementById(ttlSelectId);
            const campaignSel = document.getElementById(campaignSelectId);
            const ttl = ttlEl ? ttlEl.value : 'Permanent';
            const campaign_name = campaignSel && campaignSel.value ? campaignSel.value : '';
            const payload = { items: [item], ttl, campaign_name, source: _src };
            if (tagsInputId) payload.tags = getTagsForAllFromInput(tagsInputId);
            try {
                const response = await fetch('/api/submit-staging', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const result = await response.json().catch(() => ({}));
                if (result.success) {
                    showToast(t('toast.item_imported'), 'success');
                    if (result.new_badges || result.level_up || result.rank_up || result.points_earned !== undefined || result.level_info || result.new_nickname) showAchievementModal(result);
                    tr.style.opacity = '0';
                    tr.style.transition = 'opacity 0.25s ease';
                    setTimeout(() => { tr.remove(); }, 250);
                    loadStats();
                    loadLiveFeed();
                    const feedPulseTab = document.getElementById('tab-feed-pulse');
                    if (feedPulseTab && !feedPulseTab.classList.contains('hidden')) {
                        loadFeedPulse();
                    }
                } else {
                    showToast(result.message || 'Import failed', 'error');
                }
            } catch (e) {
                showToast(t('toast.error_generic') + ': ' + e.message, 'error');
            }
        });
    });
    tbody.querySelectorAll('.txt-staging-edit').forEach(btn => {
        btn.addEventListener('click', async () => {
            const tr = btn.closest('tr');
            if (!tr) return;
            const isEditing = tr.classList.contains('txt-staging-row-editing');
            if (isEditing) {
                _disableStagingEdit(tr, btn);
            } else {
                await _enableStagingEdit(tr, btn);
            }
        });
    });
    tbody.querySelectorAll('.txt-staging-delete').forEach(btn => {
        btn.addEventListener('click', () => { btn.closest('tr').remove(); });
    });
}

// ---- CSV Preview + Approve ----

document.getElementById('csvPreviewBtn').addEventListener('click', async () => {
    if (!authState || !authState.authenticated) {
        showToast(t('auth.login_required') || 'Please log in to submit IOCs', 'error');
        return;
    }
    const fileInput = document.getElementById('csvFile');
    const file = fileInput && fileInput.files[0];
    if (!file) {
        showToast(t('toast.select_csv'), 'error');
        return;
    }
    const formData = new FormData();
    formData.append('file', file);
    formData.append('ttl', document.getElementById('csvTTL').value);
    formData.append('comment', document.getElementById('csvComment').value);
    formData.append('assign_to', getBulkAssignToValue('csvAssignTo'));
    const csvTicket = document.getElementById('csvTicketId');
    if (csvTicket && csvTicket.value.trim()) formData.append('ticket_id', csvTicket.value.trim());
    try {
        showToast(t('toast.parsing_csv'), 'success');
        const response = await fetch('/api/preview-csv', { method: 'POST', body: formData });
        const result = await response.json().catch(() => ({}));
        if (result.success && result.items) {
            const tbody = document.getElementById('csvStagingTableBody');
            const countEl = document.getElementById('csvStagingCount');
            const area = document.getElementById('csvStagingArea');
            if (!tbody || !countEl || !area) return;

            tbody.innerHTML = result.items.map((item, idx) => {
                const conflict = !!item.existing_permanent;
                const rowClass = conflict ? 'txt-staging-row txt-staging-row-conflict bg-amber-900/20' : 'txt-staging-row';
                const dataPerm = conflict ? ' data-existing-permanent="true"' : '';
                const ioc = escapeHtml(item.ioc || '');
                const type = escapeHtml(item.type || '');
                const tagsDisplay = Array.isArray(item.tags) ? (item.tags || []).join(', ') : (item.tags || '');
                const tags = escapeHtml(tagsDisplay);
                const ticket = escapeHtml(item.ticket_id || '');
                const analyst = escapeHtml(item.analyst || '');
                const date = escapeHtml(item.date || '');
                const comment = escapeHtml(item.comment || '');
                const expiration = escapeHtml(item.expiration || 'Permanent');
                const permTip = conflict ? (item.existing_analyst || item.existing_comment ? 'Existing: ' + (item.existing_analyst || '').replace(/"/g, '') + ' | ' + (item.existing_comment || '').substring(0, 60).replace(/"/g, '') : 'Already in DB') : '';
                const permTitle = permTip ? ' title="' + permTip.replace(/"/g, '&quot;') + '"' : '';
                const approveDisabled = conflict ? ' disabled' : '';
                const approveClass = conflict ? 'txt-staging-approve btn-cmd-primary btn-cmd-sm opacity-50 cursor-not-allowed' : 'txt-staging-approve btn-cmd-primary btn-cmd-sm';
                const permBadge = conflict ? `<span class="txt-staging-perm-badge text-amber-400 text-xs mr-1"${permTitle}>⚠️ Already exists</span>` : '';
                return `<tr data-idx="${idx}" class="${rowClass}"${dataPerm}>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ioc">${ioc}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="type">${type}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="tags">${tags}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ticket_id">${ticket}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="analyst">${analyst}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="date">${date}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="comment" dir="${typeof detectTextDir==='function'?detectTextDir(comment):'auto'}">${comment}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="expiration">${expiration}</td>
                    <td class="border border-white/10 px-3 py-2">
                        <div class="flex items-center gap-1.5 justify-center flex-wrap">
                            ${permBadge}
                            <button type="button" class="${approveClass}"${approveDisabled} title="Approve this row">Approve</button>
                            <button type="button" class="txt-staging-edit btn-cmd-primary btn-cmd-sm" title="${t('actions.edit_row')}">${t('actions.edit')}</button>
                            <button type="button" class="txt-staging-delete btn-cmd-danger btn-cmd-sm" title="${t('actions.delete_row')}">${t('actions.delete')}</button>
                        </div>
                    </td>
                </tr>`;
            }).join('');
            countEl.textContent = t('bulk.found_count', {count: result.items.length});
            area.classList.remove('hidden');
            attachStagingRowActions(tbody, 'csvTTL', 'csvCampaignSelect', 'csv', 'csvTagsForAll');
            fetchStagingAnalystUsers().catch(() => {});
        } else {
            showToast(result.message || 'Preview failed', 'error');
        }
    } catch (error) {
        showToast(t('toast.error_generic') + ': ' + error.message, 'error');
    }
});

// Bulk CSV: Approve All Valid
document.getElementById('csvApproveAllBtn').addEventListener('click', async () => {
    const tbody = document.getElementById('csvStagingTableBody');
    if (!tbody) return;
    const rows = tbody.querySelectorAll('tr');
    const items = [];
    rows.forEach(tr => {
        if (tr.querySelector('.txt-staging-approve[disabled]')) return;
        const item = getTxtStagingRowData(tr);
        if (item && !validateStagingItem(item)) items.push(item);
    });
    if (items.length === 0) {
        showToast(t('toast.no_items'), 'error');
        return;
    }
    const ttl = document.getElementById('csvTTL').value;
    const campaignSel = document.getElementById('csvCampaignSelect');
    const campaign_name = campaignSel && campaignSel.value ? campaignSel.value : '';
    const tags = getTagsForAllFromInput('csvTagsForAll');
    try {
        showToast(t('toast.importing_items', {count: items.length}), 'success');
        const itemsWithExp = items.map(it => ({ ...it, expiration: it.expiration || ttl }));
        const body = { items: itemsWithExp, ttl, campaign_name, source: 'csv' };
        if (tags.length) body.tags = tags;
        const response = await fetch('/api/submit-staging', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const result = await response.json().catch(() => ({}));
        if (result.success) {
            showToast(result.message || 'Import complete', 'success');
            if (result.new_badges || result.level_up || result.rank_up || result.points_earned !== undefined || result.level_info || result.new_nickname) showAchievementModal(result);
            tbody.innerHTML = '';
            document.getElementById('csvStagingArea').classList.add('hidden');
            loadStats();
            loadLiveFeed();
            // Refresh Feed Pulse if its tab is active
            const feedPulseTab = document.getElementById('tab-feed-pulse');
            if (feedPulseTab && !feedPulseTab.classList.contains('hidden')) {
                loadFeedPulse();
            }
        } else {
            showToast(result.message || 'Import failed', 'error');
        }
    } catch (error) {
        showToast(t('toast.error_generic') + ': ' + error.message, 'error');
    }
});

// ---- Single Approve All ----

document.getElementById('singleApproveAllBtn').addEventListener('click', async () => {
    const tbody = document.getElementById('singleStagingTableBody');
    if (!tbody) return;
    const rows = tbody.querySelectorAll('tr');
    const items = [];
    rows.forEach(tr => {
        if (tr.querySelector('.txt-staging-approve[disabled]')) return;
        const item = getTxtStagingRowData(tr);
        if (item && !validateStagingItem(item)) items.push(item);
    });
    if (items.length === 0) {
        showToast(t('toast.no_items'), 'error');
        return;
    }
    const privateInBatch = items.filter(it => it && it.type === 'IP' && getClientPrivateWarnings(it.ioc, 'IP').length > 0);
    if (privateInBatch.length > 0) {
        showToast(t('toast.private_ip_warning') || 'Contains private/internal IPs - blocking may cut internal access', 'warning');
    }
    const ttl = (document.getElementById('iocTTL') && document.getElementById('iocTTL').value) ? document.getElementById('iocTTL').value : 'Permanent';
    const campaignSel = document.getElementById('iocCampaignSelect');
    const campaign_name = campaignSel && campaignSel.value ? campaignSel.value : '';
    try {
        showToast(t('toast.importing_items', { count: items.length }), 'success');
        const itemsWithExp = items.map(it => ({ ...it, expiration: it.expiration || ttl }));
        const response = await fetch('/api/submit-staging', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ items: itemsWithExp, ttl, campaign_name, source: 'single' })
        });
        const result = await response.json().catch(() => ({}));
        if (result.success) {
            showToast(result.message || 'Import complete', 'success');
            if (result.new_badges || result.level_up || result.rank_up || result.points_earned !== undefined || result.level_info || result.new_nickname) showAchievementModal(result);
            tbody.innerHTML = '';
            document.getElementById('singleStagingArea').classList.add('hidden');
            document.getElementById('singleStagingCount').textContent = t('bulk.found_items');
            loadStats();
            loadLiveFeed();
            // Refresh Feed Pulse if its tab is active
            const feedPulseTab = document.getElementById('tab-feed-pulse');
            if (feedPulseTab && !feedPulseTab.classList.contains('hidden')) {
                loadFeedPulse();
            }
        } else {
            showToast(result.message || 'Import failed', 'error');
        }
    } catch (error) {
        showToast(t('toast.error_generic') + ': ' + error.message, 'error');
    }
});

// ---- getTxtStagingRowData ----

function getTxtStagingRowData(tr) {
    const cells = tr.querySelectorAll('td[data-field]');
    if (!cells || cells.length < 8) return null;
    const ioc = (cells[0] && cells[0].textContent) ? cells[0].textContent.trim() : '';
    const type = (cells[1] && cells[1].textContent) ? cells[1].textContent.trim() : '';
    const tagsRaw = (cells[2] && cells[2].textContent) ? cells[2].textContent.trim() : '';
    const tags = tagsRaw ? tagsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
    const ticket_id = (cells[3] && cells[3].textContent) ? cells[3].textContent.trim() : '';
    let analyst = '';
    const analystCell = cells[4];
    if (analystCell) {
        const asel = analystCell.querySelector('select.staging-analyst-select');
        if (asel) analyst = (asel.value || '').trim();
        else analyst = (analystCell.textContent || '').trim();
    }
    const date = (cells[5] && cells[5].textContent) ? cells[5].textContent.trim() : '';
    const comment = (cells[6] && cells[6].textContent) ? cells[6].textContent.trim() : '';
    const expCell = cells[7];
    let expiration = '';
    if (expCell) {
        const sel = expCell.querySelector('select');
        expiration = sel ? sel.value : (expCell.textContent || '').trim();
    }
    if (!ioc || !type) return null;
    return { ioc, type, tags, ticket_id, analyst, date, comment, expiration: expiration || 'Permanent' };
}

// ---- TXT Preview + Approve ----

document.getElementById('txtPreviewBtn').addEventListener('click', async () => {
    if (!authState || !authState.authenticated) {
        showToast(t('auth.login_required') || 'Please log in to submit IOCs', 'error');
        return;
    }
    const fileInput = document.getElementById('txtFile');
    const file = fileInput && fileInput.files[0];
    if (!file) {
        showToast(t('toast.select_txt'), 'error');
        return;
    }
    const formData = new FormData();
    formData.append('file', file);
    formData.append('default_ticket', document.getElementById('txtTicketId').value.trim());
    formData.append('default_ttl', document.getElementById('txtTTL').value);
    formData.append('default_comment', document.getElementById('txtDefaultComment').value.trim());
    formData.append('assign_to', getBulkAssignToValue('txtAssignTo'));
    try {
        showToast(t('toast.parsing_file'), 'success');
        const response = await fetch('/api/preview-txt', { method: 'POST', body: formData });
        const result = await response.json().catch(() => ({}));
        if (result.success && result.items) {
            const tbody = document.getElementById('txtStagingTableBody');
            const countEl = document.getElementById('txtStagingCount');
            const area = document.getElementById('txtStagingArea');
            if (!tbody || !countEl || !area) return;

            tbody.innerHTML = result.items.map((item, idx) => {
                const conflict = !!item.existing_permanent;
                const rowClass = conflict ? 'txt-staging-row txt-staging-row-conflict bg-amber-900/20' : 'txt-staging-row';
                const dataPerm = conflict ? ' data-existing-permanent="true"' : '';
                const ioc = escapeHtml(item.ioc || '');
                const type = escapeHtml(item.type || '');
                const tagsDisplay = Array.isArray(item.tags) ? (item.tags || []).join(', ') : (item.tags || '');
                const tags = escapeHtml(tagsDisplay);
                const ticket = escapeHtml(item.ticket_id || '');
                const analyst = escapeHtml(item.analyst || '');
                const date = escapeHtml(item.date || '');
                const comment = escapeHtml(item.comment || '');
                const expiration = escapeHtml(item.expiration || 'Permanent');
                const permTip = conflict ? (item.existing_analyst || item.existing_comment ? 'Existing: ' + (item.existing_analyst || '').replace(/"/g, '') + ' | ' + (item.existing_comment || '').substring(0, 60).replace(/"/g, '') : 'Already in DB') : '';
                const permTitle = permTip ? ' title="' + permTip.replace(/"/g, '&quot;') + '"' : '';
                const approveDisabled = conflict ? ' disabled' : '';
                const approveClass = conflict ? 'txt-staging-approve btn-cmd-primary btn-cmd-sm opacity-50 cursor-not-allowed' : 'txt-staging-approve btn-cmd-primary btn-cmd-sm';
                const permBadge = conflict ? `<span class="txt-staging-perm-badge text-amber-400 text-xs mr-1"${permTitle}>⚠️ Already exists</span>` : '';
                return `<tr data-idx="${idx}" class="${rowClass}"${dataPerm}>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ioc">${ioc}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="type">${type}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="tags">${tags}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ticket_id">${ticket}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="analyst">${analyst}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="date">${date}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="comment" dir="${typeof detectTextDir==='function'?detectTextDir(comment):'auto'}">${comment}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="expiration">${expiration}</td>
                    <td class="border border-white/10 px-3 py-2">
                        <div class="flex items-center gap-1.5 justify-center flex-wrap">
                            ${permBadge}
                            <button type="button" class="${approveClass}"${approveDisabled} title="Approve this row">Approve</button>
                            <button type="button" class="txt-staging-edit btn-cmd-primary btn-cmd-sm" title="${t('actions.edit_row')}">${t('actions.edit')}</button>
                            <button type="button" class="txt-staging-delete btn-cmd-danger btn-cmd-sm" title="${t('actions.delete_row')}">${t('actions.delete')}</button>
                        </div>
                    </td>
                </tr>`;
            }).join('');
            countEl.textContent = t('bulk.found_count', {count: result.items.length});
            area.classList.remove('hidden');
            attachStagingRowActions(tbody, 'txtTTL', 'txtCampaignSelect', 'txt', 'txtTagsForAll');
            fetchStagingAnalystUsers().catch(() => {});
        } else {
            showToast(result.message || 'Preview failed', 'error');
        }
    } catch (error) {
        showToast(t('toast.error_generic') + ': ' + error.message, 'error');
    }
});

// Bulk TXT Staging: Approve All Valid (skip rows with Approve disabled = existing Permanent)
document.getElementById('txtApproveAllBtn').addEventListener('click', async () => {
    const tbody = document.getElementById('txtStagingTableBody');
    if (!tbody) return;
    const rows = tbody.querySelectorAll('tr');
    const items = [];
    rows.forEach(tr => {
        if (tr.querySelector('.txt-staging-approve[disabled]')) return;
        const item = getTxtStagingRowData(tr);
        if (item && !validateStagingItem(item)) items.push(item);
    });
    if (items.length === 0) {
        showToast(t('toast.no_items'), 'error');
        return;
    }
    const ttl = document.getElementById('txtTTL').value;
    const campaignSel = document.getElementById('txtCampaignSelect');
    const campaign_name = campaignSel && campaignSel.value ? campaignSel.value : '';
    const tags = getTagsForAllFromInput('txtTagsForAll');
    try {
        showToast(t('toast.importing_items', {count: items.length}), 'success');
        const ttlVal = document.getElementById('txtTTL').value;
        const itemsWithExp = items.map(it => ({ ...it, expiration: it.expiration || ttlVal }));
        const body = { items: itemsWithExp, ttl: ttlVal, campaign_name, source: 'txt' };
        if (tags.length) body.tags = tags;
        const response = await fetch('/api/submit-staging', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const result = await response.json().catch(() => ({}));
        if (result.success) {
            showToast(result.message || 'Import complete', 'success');
            if (result.new_badges || result.level_up || result.rank_up || result.points_earned !== undefined || result.level_info || result.new_nickname) showAchievementModal(result);
            tbody.innerHTML = '';
            document.getElementById('txtStagingArea').classList.add('hidden');
            loadStats();
            loadLiveFeed();
        } else {
            showToast(result.message || 'Import failed', 'error');
        }
    } catch (error) {
        showToast(t('toast.error_generic') + ': ' + error.message, 'error');
    }
});

// ---- Paste Preview + Approve ----

document.getElementById('pastePreviewBtn').addEventListener('click', async () => {
    if (!authState || !authState.authenticated) {
        showToast(t('auth.login_required') || 'Please log in to submit IOCs', 'error');
        return;
    }
    const textarea = document.getElementById('pasteText');
    const text = textarea && textarea.value ? textarea.value.trim() : '';
    if (!text) {
        showToast(t('bulk.paste_empty') || 'Paste some text first', 'error');
        return;
    }
    try {
        showToast(t('toast.parsing_file') || 'Extracting IOCs...', 'success');
        const response = await fetch('/api/preview-paste', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                text: text,
                default_ticket: document.getElementById('pasteTicketId').value.trim(),
                default_ttl: document.getElementById('pasteTTL').value,
                default_comment: document.getElementById('pasteDefaultComment').value.trim(),
                assign_to: getBulkAssignToValue('pasteAssignTo') || undefined
            })
        });
        const result = await response.json().catch(() => ({}));
        if (result.success && result.items) {
            const tbody = document.getElementById('pasteStagingTableBody');
            const countEl = document.getElementById('pasteStagingCount');
            const area = document.getElementById('pasteStagingArea');
            if (!tbody || !countEl || !area) return;
            tbody.innerHTML = result.items.map((item, idx) => {
                const conflict = !!item.existing_permanent;
                const rowClass = conflict ? 'txt-staging-row txt-staging-row-conflict bg-amber-900/20' : 'txt-staging-row';
                const dataPerm = conflict ? ' data-existing-permanent="true"' : '';
                const ioc = escapeHtml(item.ioc || '');
                const type = escapeHtml(item.type || '');
                const tagsDisplay = Array.isArray(item.tags) ? (item.tags || []).join(', ') : (item.tags || '');
                const tags = escapeHtml(tagsDisplay);
                const ticket = escapeHtml(item.ticket_id || '');
                const analyst = escapeHtml(item.analyst || '');
                const date = escapeHtml(item.date || '');
                const comment = escapeHtml(item.comment || '');
                const expiration = escapeHtml(item.expiration || 'Permanent');
                const permTip = conflict ? (item.existing_analyst || item.existing_comment ? 'Existing: ' + (item.existing_analyst || '').replace(/"/g, '') + ' | ' + (item.existing_comment || '').substring(0, 60).replace(/"/g, '') : 'Already in DB') : '';
                const permTitle = permTip ? ' title="' + permTip.replace(/"/g, '&quot;') + '"' : '';
                const approveDisabled = conflict ? ' disabled' : '';
                const approveClass = conflict ? 'txt-staging-approve btn-cmd-primary btn-cmd-sm opacity-50 cursor-not-allowed' : 'txt-staging-approve btn-cmd-primary btn-cmd-sm';
                const permBadge = conflict ? `<span class="txt-staging-perm-badge text-amber-400 text-xs mr-1"${permTitle}>⚠️ Already exists</span>` : '';
                return `<tr data-idx="${idx}" class="${rowClass}"${dataPerm}>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ioc">${ioc}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="type">${type}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="tags">${tags}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ticket_id">${ticket}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="analyst">${analyst}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="date">${date}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="comment" dir="${typeof detectTextDir==='function'?detectTextDir(comment):'auto'}">${comment}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="expiration">${expiration}</td>
                    <td class="border border-white/10 px-3 py-2">
                        <div class="flex items-center gap-1.5 justify-center flex-wrap">
                            ${permBadge}
                            <button type="button" class="${approveClass}"${approveDisabled} title="Approve this row">Approve</button>
                            <button type="button" class="txt-staging-edit btn-cmd-primary btn-cmd-sm" title="${t('actions.edit_row')}">${t('actions.edit')}</button>
                            <button type="button" class="txt-staging-delete btn-cmd-danger btn-cmd-sm" title="${t('actions.delete')}">${t('actions.delete')}</button>
                        </div>
                    </td>
                </tr>`;
            }).join('');
            countEl.textContent = t('bulk.found_count', { count: result.items.length });
            area.classList.remove('hidden');
            attachStagingRowActions(tbody, 'pasteTTL', 'pasteCampaignSelect', 'paste', 'pasteTagsForAll');
            fetchStagingAnalystUsers().catch(() => {});
        } else {
            showToast(result.message || 'Preview failed', 'error');
        }
    } catch (error) {
        showToast(t('toast.error_generic') + ': ' + error.message, 'error');
    }
});

// Bulk Paste: Approve All Valid
document.getElementById('pasteApproveAllBtn').addEventListener('click', async () => {
    const tbody = document.getElementById('pasteStagingTableBody');
    if (!tbody) return;
    const rows = tbody.querySelectorAll('tr');
    const items = [];
    rows.forEach(tr => {
        if (tr.querySelector('.txt-staging-approve[disabled]')) return;
        const item = getTxtStagingRowData(tr);
        if (item && !validateStagingItem(item)) items.push(item);
    });
    if (items.length === 0) {
        showToast(t('toast.no_items'), 'error');
        return;
    }
    const ttl = document.getElementById('pasteTTL').value;
    const campaignSel = document.getElementById('pasteCampaignSelect');
    const campaign_name = campaignSel && campaignSel.value ? campaignSel.value : '';
    const tags = getTagsForAllFromInput('pasteTagsForAll');
    try {
        showToast(t('toast.importing_items', {count: items.length}), 'success');
        const itemsWithExp = items.map(it => ({ ...it, expiration: it.expiration || ttl }));
        const body = { items: itemsWithExp, ttl, campaign_name, source: 'paste' };
        if (tags.length) body.tags = tags;
        const response = await fetch('/api/submit-staging', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const result = await response.json().catch(() => ({}));
        if (result.success) {
            showToast(result.message || 'Import complete', 'success');
            if (result.new_badges || result.level_up || result.rank_up || result.points_earned !== undefined || result.level_info || result.new_nickname) showAchievementModal(result);
            tbody.innerHTML = '';
            document.getElementById('pasteStagingArea').classList.add('hidden');
            loadStats();
            loadLiveFeed();
        } else {
            showToast(result.message || 'Import failed', 'error');
        }
    } catch (error) {
        showToast(t('toast.error_generic') + ': ' + error.message, 'error');
    }
});

// ---- Delete All ----

function _clearStagingArea(tbodyId, countId) {
    const tbody = document.getElementById(tbodyId);
    if (tbody) tbody.innerHTML = '';
    const countEl = countId && document.getElementById(countId);
    if (countEl) countEl.textContent = t('bulk.found_count', { count: 0 });
}
document.getElementById('txtDeleteAllBtn').addEventListener('click', () => _clearStagingArea('txtStagingTableBody', 'txtStagingCount'));
document.getElementById('csvDeleteAllBtn').addEventListener('click', () => _clearStagingArea('csvStagingTableBody', 'csvStagingCount'));
document.getElementById('singleDeleteAllBtn').addEventListener('click', () => _clearStagingArea('singleStagingTableBody', 'singleStagingCount'));
document.getElementById('pasteDeleteAllBtn').addEventListener('click', () => _clearStagingArea('pasteStagingTableBody', 'pasteStagingCount'));

// ---- Expose on window for cross-file references ----

window.validateIocFormat = validateIocFormat;
window.clientRefanger = clientRefanger;
window.getClientCriticalCheck = getClientCriticalCheck;
window.getClientPrivateWarnings = getClientPrivateWarnings;
window.getTxtStagingRowData = getTxtStagingRowData;
window.attachStagingRowActions = attachStagingRowActions;
window.attachStagingRowActionsForRow = attachStagingRowActionsForRow;
window.validateStagingItem = validateStagingItem;
window.setBulkUploadMode = setBulkUploadMode;
window.addSingleToStaging = addSingleToStaging;
window.invalidateStagingAnalystCache = function () { _cachedStagingAnalystUsers = null; };

// Auto-detect RTL/LTR direction for all comment fields
if (typeof initAutoDirFields === 'function') {
    initAutoDirFields([
        'iocComment',          // Single mode
        'txtDefaultComment',   // TXT mode
        'csvComment',          // CSV mode
        'pasteDefaultComment', // Paste mode
        'yaraComment',         // YARA upload
        'yaraWriteComment',    // YARA write
    ]);
}
