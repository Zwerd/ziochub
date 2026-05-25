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

const UNIFIED_STAGING_TBODY = 'unifiedStagingTableBody';
const UNIFIED_STAGING_AREA = 'unifiedStagingArea';
const UNIFIED_STAGING_COUNT = 'unifiedStagingCount';

function getUnifiedStagingTbody() {
    return document.getElementById(UNIFIED_STAGING_TBODY);
}

/** Show/hide staging panel and refresh count from unified tbody row count. */
function updateUnifiedStagingChrome() {
    const tbody = getUnifiedStagingTbody();
    const area = document.getElementById(UNIFIED_STAGING_AREA);
    const countEl = document.getElementById(UNIFIED_STAGING_COUNT);
    const n = tbody ? tbody.querySelectorAll('tr').length : 0;
    if (countEl) countEl.textContent = n ? t('bulk.found_count', { count: n }) : t('bulk.found_items');
    if (area) area.classList.toggle('hidden', n === 0);
}

function getActiveBulkMode() {
    const s = document.getElementById('btnModeSingle');
    if (s && s.classList.contains('bg-blue-600')) return 'single';
    const txtBtn = document.getElementById('btnModeTxt');
    if (txtBtn && txtBtn.classList.contains('bg-blue-600')) return 'txt';
    const csvBtn = document.getElementById('btnModeCsv');
    if (csvBtn && csvBtn.classList.contains('bg-blue-600')) return 'csv';
    const pasteBtn = document.getElementById('btnModePaste');
    if (pasteBtn && pasteBtn.classList.contains('bg-blue-600')) return 'paste';
    return 'single';
}

/** TTL / campaign / tags-for-all / source for Approve All — taken from the visible mode toolbar. */
function getActiveBulkStagingContext() {
    const mode = getActiveBulkMode();
    if (mode === 'txt') return { ttlId: 'txtTTL', campaignId: 'txtCampaignSelect', tagsId: 'txtTagsForAll', source: 'txt' };
    if (mode === 'csv') return { ttlId: 'csvTTL', campaignId: 'csvCampaignSelect', tagsId: 'csvTagsForAll', source: 'csv' };
    if (mode === 'paste') return { ttlId: 'pasteTTL', campaignId: 'pasteCampaignSelect', tagsId: 'pasteTagsForAll', source: 'paste' };
    return { ttlId: 'iocTTL', campaignId: 'iocCampaignSelect', tagsId: null, source: 'single' };
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

    if (wrapperSingle) wrapperSingle.classList.toggle('hidden', !isSingle);
    if (wrapperTxt) wrapperTxt.classList.toggle('hidden', !isTxt);
    if (wrapperCsv) wrapperCsv.classList.toggle('hidden', !isCsv);
    if (wrapperPaste) wrapperPaste.classList.toggle('hidden', !isPaste);

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

/** Native file input uses OS locale for its button; use hidden input + English label for IOC bulk pickers. */
function _wireEnglishBulkFilePicker(inputId, chosenLabelId) {
    const inp = document.getElementById(inputId);
    const chosen = document.getElementById(chosenLabelId);
    if (!inp || !chosen) return;
    const emptyText = 'No file chosen';
    function sync() {
        const f = inp.files && inp.files[0];
        chosen.textContent = f ? f.name : emptyText;
        chosen.title = f ? f.name : '';
    }
    inp.addEventListener('change', sync);
    sync();
}
_wireEnglishBulkFilePicker('txtFile', 'txtFileChosenLabel');
_wireEnglishBulkFilePicker('csvFile', 'csvFileChosenLabel');

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

    const tbody = getUnifiedStagingTbody();
    const countEl = document.getElementById(UNIFIED_STAGING_COUNT);
    const area = document.getElementById(UNIFIED_STAGING_AREA);
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
        const privateParts = getClientPrivateWarnings(value, type);
        const serverSanity = (item.sanity_check || '').trim();
        const sanityDisplay = [serverSanity, ...privateParts].filter(Boolean).join(' · ');
        const sanityCol = formatStagingSanityHtml(sanityDisplay);
        row.innerHTML = `
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ioc">${ioc}</td>
            <td class="border border-white/10 px-3 py-2 text-sm align-top" contenteditable="false" data-field="type">${typeEsc}</td>
            <td class="border border-white/10 px-2 py-2 text-sm align-top">${sanityCol}</td>
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="tags">${tagsEsc}</td>
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ticket_id">${ticketEsc}</td>
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="analyst">${analystEsc}</td>
            <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="date">${dateEsc}</td>
            <td class="border border-white/10 px-3 py-2 text-sm align-top" contenteditable="false" data-field="comment" dir="${typeof detectTextDir==='function'?detectTextDir(item.comment||''):'auto'}">${formatStagingCommentHtml(item.comment || '')}</td>
            <td class="border border-white/10 px-3 py-2 text-sm align-top" contenteditable="false" data-field="expiration">${expirationEsc}</td>
            <td class="border border-white/10 px-3 py-2">
                <div class="flex items-center gap-1.5 justify-center flex-wrap">
                    ${permBadge}
                    <button type="button" class="${approveClass}"${approveDisabled} title="Approve this row">Approve</button>
                    <button type="button" class="txt-staging-edit btn-cmd-primary btn-cmd-sm" title="${t('actions.edit_row')}">${t('actions.edit')}</button>
                    <button type="button" class="txt-staging-delete btn-cmd-danger btn-cmd-sm" title="${t('actions.delete_row')}">${t('actions.delete')}</button>
                </div>
            </td>`;
        tbody.appendChild(row);
        row.setAttribute('data-staging-bound', '1');
        updateUnifiedStagingChrome();
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

/** Staging table: sanity column HTML (cell has no data-field so getTxtStagingRowData indices stay correct). */
function formatStagingSanityHtml(raw) {
    const s = (raw == null ? '' : String(raw)).trim();
    if (!s) return '<span class="text-secondary/80 text-xs">—</span>';
    const esc = typeof escapeHtml === 'function' ? escapeHtml(s) : String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
    const titleEsc = typeof escapeAttr === 'function' ? escapeAttr(s) : esc.replace(/"/g, '&quot;');
    return '<span class="staging-sanity-text text-amber-200/90 text-xs leading-snug block align-top" title="' + titleEsc + '">' + esc + '</span>';
}

/** Staging table: comment cell — wrap long text; title tooltip on hover. */
function formatStagingCommentHtml(raw) {
    const s = (raw == null ? '' : String(raw)).trim();
    if (!s) return '';
    const esc = typeof escapeHtml === 'function' ? escapeHtml(s) : String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
    const titleEsc = typeof escapeAttr === 'function' ? escapeAttr(s) : esc.replace(/"/g, '&quot;');
    return '<span class="staging-comment-text text-xs leading-snug" title="' + titleEsc + '">' + esc + '</span>';
}

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

/** Toggle Edit button label/style while row is in edit mode. */
function _setStagingEditButtonState(btn, editing) {
    if (!btn) return;
    const label = editing
        ? (typeof t === 'function' ? t('actions.done_editing') : 'Done')
        : (typeof t === 'function' ? t('actions.edit') : 'Edit');
    const title = editing
        ? (typeof t === 'function' ? t('actions.edit_row_active') : 'Finish editing — saves changes to this row')
        : (typeof t === 'function' ? t('actions.edit_row') : 'Edit row');
    btn.textContent = label;
    btn.title = title;
    btn.setAttribute('aria-pressed', editing ? 'true' : 'false');
    btn.classList.toggle('txt-staging-edit--active', !!editing);
}

/** If row is mid-edit, commit inline edits to the staging row (same as clicking Done). */
function _finishStagingEditIfOpen(row) {
    if (!row || !row.classList.contains('txt-staging-row-editing')) return;
    const editBtn = row.querySelector('.txt-staging-edit');
    if (editBtn) _disableStagingEdit(row, editBtn);
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
        if (field === 'comment') {
            const rawComment = (c.textContent || '').trim();
            c.textContent = rawComment;
            if (typeof detectTextDir === 'function') c.dir = detectTextDir(rawComment);
        }
        c.setAttribute('contenteditable', 'true');
        if (field === 'comment' && typeof detectTextDir === 'function') {
            c.addEventListener('input', function commentDirInput() {
                this.dir = detectTextDir(this.textContent);
            });
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
    _setStagingEditButtonState(btn, true);
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
    const commentCell = row.querySelector('td[data-field="comment"]');
    if (commentCell) {
        const rawComment = (commentCell.textContent || '').trim();
        commentCell.innerHTML = formatStagingCommentHtml(rawComment);
        if (typeof detectTextDir === 'function') commentCell.dir = detectTextDir(rawComment);
    }
    _setStagingEditButtonState(btn, false);
}

function attachStagingRowActionsForRow(tr, ttlSelectId, campaignSelectId, source) {
    if (!tr) return;
    const _src = source || 'single';
    const tbody = tr.closest('tbody');
    [tr].forEach(row => {
        row.querySelectorAll('.txt-staging-approve').forEach(btn => {
            btn.addEventListener('click', async () => {
                _finishStagingEditIfOpen(row);
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
                        updateUnifiedStagingChrome();
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
                updateUnifiedStagingChrome();
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

/** Attach Approve/Edit/Delete to staging rows in a tbody. Only rows without data-staging-bound are wired (avoids duplicate handlers when appending). */
function attachStagingRowActions(tbody, ttlSelectId, campaignSelectId, source, tagsInputId) {
    if (!tbody) return;
    const _src = source || 'single';
    const rows = tbody.querySelectorAll('tr:not([data-staging-bound])');
    rows.forEach((tr) => {
        tr.setAttribute('data-staging-bound', '1');
        tr.querySelectorAll('.txt-staging-approve').forEach(btn => {
            btn.addEventListener('click', async () => {
                if (!tr) return;
                _finishStagingEditIfOpen(tr);
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
                        setTimeout(() => {
                            tr.remove();
                            updateUnifiedStagingChrome();
                        }, 250);
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
        tr.querySelectorAll('.txt-staging-edit').forEach(btn => {
            btn.addEventListener('click', async () => {
                if (!tr) return;
                const isEditing = tr.classList.contains('txt-staging-row-editing');
                if (isEditing) {
                    _disableStagingEdit(tr, btn);
                } else {
                    await _enableStagingEdit(tr, btn);
                }
            });
        });
        tr.querySelectorAll('.txt-staging-delete').forEach(btn => {
            btn.addEventListener('click', () => {
                tr.remove();
                updateUnifiedStagingChrome();
            });
        });
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
            const tbody = getUnifiedStagingTbody();
            if (!tbody) return;

            const rowsHtml = result.items.map((item, idx) => {
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
                const sanityCol = formatStagingSanityHtml(item.sanity_check || '');
                const permTip = conflict ? (item.existing_analyst || item.existing_comment ? 'Existing: ' + (item.existing_analyst || '').replace(/"/g, '') + ' | ' + (item.existing_comment || '').substring(0, 60).replace(/"/g, '') : 'Already in DB') : '';
                const permTitle = permTip ? ' title="' + permTip.replace(/"/g, '&quot;') + '"' : '';
                const approveDisabled = conflict ? ' disabled' : '';
                const approveClass = conflict ? 'txt-staging-approve btn-cmd-primary btn-cmd-sm opacity-50 cursor-not-allowed' : 'txt-staging-approve btn-cmd-primary btn-cmd-sm';
                const permBadge = conflict ? `<span class="txt-staging-perm-badge text-amber-400 text-xs mr-1"${permTitle}>⚠️ Already exists</span>` : '';
                return `<tr data-idx="${idx}" class="${rowClass}"${dataPerm}>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ioc">${ioc}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm align-top" contenteditable="false" data-field="type">${type}</td>
                    <td class="border border-white/10 px-2 py-2 text-sm align-top">${sanityCol}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="tags">${tags}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ticket_id">${ticket}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="analyst">${analyst}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="date">${date}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm align-top" contenteditable="false" data-field="comment" dir="${typeof detectTextDir==='function'?detectTextDir(item.comment||''):'auto'}">${formatStagingCommentHtml(item.comment || '')}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm align-top" contenteditable="false" data-field="expiration">${expiration}</td>
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
            tbody.insertAdjacentHTML('beforeend', rowsHtml);
            updateUnifiedStagingChrome();
            attachStagingRowActions(tbody, 'csvTTL', 'csvCampaignSelect', 'csv', 'csvTagsForAll');
            fetchStagingAnalystUsers().catch(() => {});
        } else {
            showToast(result.message || 'Preview failed', 'error');
        }
    } catch (error) {
        showToast(t('toast.error_generic') + ': ' + error.message, 'error');
    }
});

// Unified queue: Approve All Valid (uses TTL / campaign / tags from the active mode toolbar)
document.getElementById('unifiedApproveAllBtn').addEventListener('click', async () => {
    const tbody = getUnifiedStagingTbody();
    if (!tbody) return;
    const rows = tbody.querySelectorAll('tr');
    const items = [];
    rows.forEach(tr => {
        if (tr.querySelector('.txt-staging-approve[disabled]')) return;
        _finishStagingEditIfOpen(tr);
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
    const ctx = getActiveBulkStagingContext();
    const ttlEl = document.getElementById(ctx.ttlId);
    const ttl = ttlEl ? ttlEl.value : 'Permanent';
    const campaignSel = document.getElementById(ctx.campaignId);
    const campaign_name = campaignSel && campaignSel.value ? campaignSel.value : '';
    const tags = ctx.tagsId ? getTagsForAllFromInput(ctx.tagsId) : [];
    try {
        showToast(t('toast.importing_items', { count: items.length }), 'success');
        const itemsWithExp = items.map(it => ({ ...it, expiration: it.expiration || ttl }));
        const body = { items: itemsWithExp, ttl, campaign_name, source: ctx.source };
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
            updateUnifiedStagingChrome();
            loadStats();
            loadLiveFeed();
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
            const tbody = getUnifiedStagingTbody();
            if (!tbody) return;

            const rowsHtml = result.items.map((item, idx) => {
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
                const sanityCol = formatStagingSanityHtml(item.sanity_check || '');
                const permTip = conflict ? (item.existing_analyst || item.existing_comment ? 'Existing: ' + (item.existing_analyst || '').replace(/"/g, '') + ' | ' + (item.existing_comment || '').substring(0, 60).replace(/"/g, '') : 'Already in DB') : '';
                const permTitle = permTip ? ' title="' + permTip.replace(/"/g, '&quot;') + '"' : '';
                const approveDisabled = conflict ? ' disabled' : '';
                const approveClass = conflict ? 'txt-staging-approve btn-cmd-primary btn-cmd-sm opacity-50 cursor-not-allowed' : 'txt-staging-approve btn-cmd-primary btn-cmd-sm';
                const permBadge = conflict ? `<span class="txt-staging-perm-badge text-amber-400 text-xs mr-1"${permTitle}>⚠️ Already exists</span>` : '';
                return `<tr data-idx="${idx}" class="${rowClass}"${dataPerm}>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ioc">${ioc}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm align-top" contenteditable="false" data-field="type">${type}</td>
                    <td class="border border-white/10 px-2 py-2 text-sm align-top">${sanityCol}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="tags">${tags}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ticket_id">${ticket}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="analyst">${analyst}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="date">${date}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm align-top" contenteditable="false" data-field="comment" dir="${typeof detectTextDir==='function'?detectTextDir(item.comment||''):'auto'}">${formatStagingCommentHtml(item.comment || '')}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm align-top" contenteditable="false" data-field="expiration">${expiration}</td>
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
            tbody.insertAdjacentHTML('beforeend', rowsHtml);
            updateUnifiedStagingChrome();
            attachStagingRowActions(tbody, 'txtTTL', 'txtCampaignSelect', 'txt', 'txtTagsForAll');
            fetchStagingAnalystUsers().catch(() => {});
        } else {
            showToast(result.message || 'Preview failed', 'error');
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
            const tbody = getUnifiedStagingTbody();
            if (!tbody) return;
            const rowsHtml = result.items.map((item, idx) => {
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
                const sanityCol = formatStagingSanityHtml(item.sanity_check || '');
                const permTip = conflict ? (item.existing_analyst || item.existing_comment ? 'Existing: ' + (item.existing_analyst || '').replace(/"/g, '') + ' | ' + (item.existing_comment || '').substring(0, 60).replace(/"/g, '') : 'Already in DB') : '';
                const permTitle = permTip ? ' title="' + permTip.replace(/"/g, '&quot;') + '"' : '';
                const approveDisabled = conflict ? ' disabled' : '';
                const approveClass = conflict ? 'txt-staging-approve btn-cmd-primary btn-cmd-sm opacity-50 cursor-not-allowed' : 'txt-staging-approve btn-cmd-primary btn-cmd-sm';
                const permBadge = conflict ? `<span class="txt-staging-perm-badge text-amber-400 text-xs mr-1"${permTitle}>⚠️ Already exists</span>` : '';
                return `<tr data-idx="${idx}" class="${rowClass}"${dataPerm}>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ioc">${ioc}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm align-top" contenteditable="false" data-field="type">${type}</td>
                    <td class="border border-white/10 px-2 py-2 text-sm align-top">${sanityCol}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="tags">${tags}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="ticket_id">${ticket}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="analyst">${analyst}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm" contenteditable="false" data-field="date">${date}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm align-top" contenteditable="false" data-field="comment" dir="${typeof detectTextDir==='function'?detectTextDir(item.comment||''):'auto'}">${formatStagingCommentHtml(item.comment || '')}</td>
                    <td class="border border-white/10 px-3 py-2 text-sm align-top" contenteditable="false" data-field="expiration">${expiration}</td>
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
            tbody.insertAdjacentHTML('beforeend', rowsHtml);
            updateUnifiedStagingChrome();
            attachStagingRowActions(tbody, 'pasteTTL', 'pasteCampaignSelect', 'paste', 'pasteTagsForAll');
            fetchStagingAnalystUsers().catch(() => {});
        } else {
            showToast(result.message || 'Preview failed', 'error');
        }
    } catch (error) {
        showToast(t('toast.error_generic') + ': ' + error.message, 'error');
    }
});

// ---- Delete All (unified queue) ----

function _clearStagingArea(tbodyId, countId) {
    const tbody = document.getElementById(tbodyId);
    if (tbody) tbody.innerHTML = '';
    const countEl = countId && document.getElementById(countId);
    if (countEl) countEl.textContent = t('bulk.found_count', { count: 0 });
    updateUnifiedStagingChrome();
}
document.getElementById('unifiedDeleteAllBtn').addEventListener('click', () => _clearStagingArea(UNIFIED_STAGING_TBODY, UNIFIED_STAGING_COUNT));

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
window.maybeSuggestInvalidTags = maybeSuggestInvalidTags;

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
