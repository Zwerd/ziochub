/**
 * YARA Manager tab logic (Step 10.4 - extracted from index.html).
 * Depends on globals: escapeHtml, escapeAttr, showToast, t, authState, apiFetch, Prism,
 *                     loadLiveFeed, searchInput, searchButton.
 * Exposes: loadYaraRules, loadYaraPending, openYaraMetaEditModal.
 */
(function(global) {
    'use strict';

    let selectedYaraFile = null;
    let editingYaraFilename = null;
    let yaraEditOriginalContent = '';
    let yaraRejectTargetFilename = null;
    const yaraDropZone = document.getElementById('yaraDropZone');
    const yaraFileInput = document.getElementById('yaraFileInput');
    const yaraSelectedFilename = document.getElementById('yaraSelectedFilename');

    function sanitizeYaraFilename(raw) {
        const base = String(raw || '').trim().split(/[/\\]/).pop() || '';
        if (!base) return { sanitized: null, changed: false, raw: base };
        let name = base;
        if (!name.toLowerCase().endsWith('.yar')) {
            if (name.indexOf('.') === -1) name = name + '.yar';
            else if (!name.toLowerCase().endsWith('.yar')) return { sanitized: null, changed: false, raw: base };
        }
        let sanitized = name.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/_+/g, '_').replace(/^[._]+|[._]+$/g, '');
        if (!sanitized || !sanitized.toLowerCase().endsWith('.yar')) sanitized = 'rule.yar';
        return { sanitized: sanitized, changed: sanitized !== name, raw: name };
    }

    async function yaraFileWithSafeName(file) {
        if (!file) return { file: null, changed: false, sanitized: null };
        const info = sanitizeYaraFilename(file.name);
        if (!info.sanitized) return { file: file, changed: false, sanitized: null };
        if (!info.changed) return { file: file, changed: false, sanitized: info.sanitized };
        const content = await readFileAsText(file);
        return {
            file: new File([content], info.sanitized, { type: file.type || 'text/plain' }),
            changed: true,
            sanitized: info.sanitized
        };
    }

    function clearYaraResubmitMode() {
        global._yaraResubmitFilename = null;
        const submitBtn = document.getElementById('yaraWriteSubmitBtn');
        if (submitBtn) {
            submitBtn.textContent = t('yara.write_submit_btn') || 'Submit written rule';
        }
        const wf = document.getElementById('yaraWriteFilename');
        if (wf) wf.readOnly = false;
    }

    function setYaraResubmitMode(filename) {
        global._yaraResubmitFilename = filename || null;
        const submitBtn = document.getElementById('yaraWriteSubmitBtn');
        if (submitBtn) {
            submitBtn.textContent = t('yara.resubmit_btn') || 'Resubmit for approval';
        }
    }

    function updateYaraRejectedBadge(unseen) {
        const badge = document.getElementById('yaraRejectedBadge');
        if (!badge) return;
        const n = Number(unseen) || 0;
        if (n > 0) {
            badge.textContent = String(n > 9 ? '9+' : n);
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }
    }

    function showYaraRejectModal(filename) {
        return new Promise((resolve) => {
            const modal = document.getElementById('yaraAdminRejectModal');
            const reasonEl = document.getElementById('yaraAdminRejectReason');
            const submitBtn = document.getElementById('yaraAdminRejectSubmit');
            const cancelBtn = document.getElementById('yaraAdminRejectCancel');
            if (!modal || !submitBtn || !cancelBtn) {
                resolve({ ok: false, reason: '' });
                return;
            }
            yaraRejectTargetFilename = filename;
            if (reasonEl) reasonEl.value = '';
            modal.classList.remove('hidden');
            function cleanup() {
                submitBtn.removeEventListener('click', onConfirm);
                cancelBtn.removeEventListener('click', onCancel);
                modal.classList.add('hidden');
                yaraRejectTargetFilename = null;
            }
            function onConfirm() {
                const reason = reasonEl ? reasonEl.value.trim() : '';
                cleanup();
                resolve({ ok: true, reason: reason });
            }
            function onCancel() {
                cleanup();
                resolve({ ok: false, reason: '' });
            }
            submitBtn.addEventListener('click', onConfirm);
            cancelBtn.addEventListener('click', onCancel);
        });
    }

    function showYaraConfirm(title, message, confirmLabel) {
        return new Promise((resolve) => {
            const modal = document.getElementById('yaraConfirmModal');
            const titleEl = document.getElementById('yaraConfirmTitle');
            const msgEl = document.getElementById('yaraConfirmMessage');
            const submitBtn = document.getElementById('yaraConfirmSubmit');
            const cancelBtn = document.getElementById('yaraConfirmCancel');
            if (!modal) { resolve(false); return; }

            titleEl.textContent = title;
            msgEl.textContent = message;
            submitBtn.textContent = confirmLabel || title;
            modal.classList.remove('hidden');

            function cleanup() {
                submitBtn.removeEventListener('click', onConfirm);
                cancelBtn.removeEventListener('click', onCancel);
                modal.classList.add('hidden');
            }
            function onConfirm() { cleanup(); resolve(true); }
            function onCancel()  { cleanup(); resolve(false); }

            submitBtn.addEventListener('click', onConfirm);
            cancelBtn.addEventListener('click', onCancel);
        });
    }

    function setYaraSelected(file) {
        selectedYaraFile = file;
        invalidateYaraUploadValidation();
        clearYaraSyntaxBanner('yaraUploadSyntaxResult');
        if (yaraSelectedFilename) {
            if (file) {
                const info = sanitizeYaraFilename(file.name);
                const displayName = info.sanitized || file.name;
                yaraSelectedFilename.textContent = t('yara.selected') + ': ' + displayName;
                yaraSelectedFilename.classList.remove('hidden');
            } else {
                yaraSelectedFilename.textContent = '';
                yaraSelectedFilename.classList.add('hidden');
            }
        }
    }

    if (yaraDropZone) {
        yaraDropZone.addEventListener('click', () => yaraFileInput.click());
        yaraDropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            yaraDropZone.classList.add('dragover');
        });
        yaraDropZone.addEventListener('dragleave', () => {
            yaraDropZone.classList.remove('dragover');
        });
        yaraDropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            yaraDropZone.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0 && files[0].name.toLowerCase().endsWith('.yar')) {
                setYaraSelected(files[0]);
            } else if (files.length > 0) {
                showToast(t('toast.only_yar'), 'error');
            }
        });
    }

    if (yaraFileInput) {
        yaraFileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                setYaraSelected(e.target.files[0]);
            } else {
                setYaraSelected(null);
            }
        });
    }

    let yaraWriteHighlightTimer = null;
    /** Source string that last passed /api/yara/validate-syntax (exact match required to enable Submit). */
    let yaraWriteValidatedSource = null;
    /** Upload: validated file text + fingerprint (name|size|lastModified) after successful Check syntax. */
    let yaraUploadValidatedSource = null;
    let yaraUploadValidatedFileKey = '';

    function readFileAsText(file) {
        return new Promise(function (resolve, reject) {
            if (!file) { reject(new Error('No file')); return; }
            const r = new FileReader();
            r.onload = function () { resolve(String(r.result || '')); };
            r.onerror = function () { reject(r.error || new Error('read failed')); };
            r.readAsText(file);
        });
    }

    function yaraUploadFileFingerprint(file) {
        if (!file) return '';
        return file.name + '|' + file.size + '|' + file.lastModified;
    }

    var YARA_SUBMIT_TOAST_MS = 5500;

    function setYaraWriteSubmitEnabled(enabled) {
        const btn = document.getElementById('yaraWriteSubmitBtn');
        if (!btn) return;
        btn.removeAttribute('disabled');
        btn.setAttribute('aria-disabled', enabled ? 'false' : 'true');
        if (enabled) {
            btn.classList.remove('yara-submit-locked');
            btn.title = '';
        } else {
            btn.classList.add('yara-submit-locked');
            btn.title = t('yara.syntax_required_hint') || '';
        }
    }

    function setYaraUploadSubmitEnabled(enabled) {
        const btn = document.getElementById('yaraSubmitBtn');
        if (!btn) return;
        btn.removeAttribute('disabled');
        btn.setAttribute('aria-disabled', enabled ? 'false' : 'true');
        if (enabled) {
            btn.classList.remove('yara-submit-locked');
            btn.title = '';
        } else {
            btn.classList.add('yara-submit-locked');
            btn.title = t('yara.syntax_required_hint') || '';
        }
    }

    function toastYaraSubmitBlocked() {
        const msg = t('yara.submit_blocked_toast') || t('yara.submit_requires_valid_syntax') || 'Run Check syntax successfully before submitting.';
        if (typeof showToast === 'function') {
            showToast(msg, 'error', YARA_SUBMIT_TOAST_MS);
        }
    }

    function invalidateYaraWriteValidation() {
        yaraWriteValidatedSource = null;
        setYaraWriteSubmitEnabled(false);
    }

    function invalidateYaraUploadValidation() {
        yaraUploadValidatedSource = null;
        yaraUploadValidatedFileKey = '';
        setYaraUploadSubmitEnabled(false);
    }

    function refreshYaraWriteHighlight() {
        const ta = document.getElementById('yaraWriteSource');
        const codeEl = document.getElementById('yaraWriteHighlighted');
        if (!ta || !codeEl) return;
        codeEl.textContent = ta.value;
        if (typeof Prism !== 'undefined' && typeof Prism.highlightElement === 'function') {
            try {
                Prism.highlightElement(codeEl);
            } catch (e) {
                console.warn('YARA write Prism highlight:', e);
            }
        }
    }

    function scheduleYaraWriteHighlight() {
        if (yaraWriteHighlightTimer) clearTimeout(yaraWriteHighlightTimer);
        yaraWriteHighlightTimer = setTimeout(function () {
            yaraWriteHighlightTimer = null;
            refreshYaraWriteHighlight();
        }, 120);
    }

    document.getElementById('yaraSubmitBtn')?.addEventListener('click', async () => {
        if (!selectedYaraFile) {
            showToast(t('toast.select_yara_file'), 'error');
            return;
        }
        let text = '';
        try {
            text = await readFileAsText(selectedYaraFile);
        } catch (e) {
            showToast((e && e.message) ? e.message : 'Could not read file', 'error');
            return;
        }
        const fp = yaraUploadFileFingerprint(selectedYaraFile);
        if (yaraUploadValidatedSource !== text || yaraUploadValidatedFileKey !== fp) {
            toastYaraSubmitBlocked();
            return;
        }
        await handleYaraUpload(selectedYaraFile);
    });

    function filterYaraTable() {
        const query = (document.getElementById('yaraTableFilter')?.value || '').toLowerCase().trim();
        const tbody = document.getElementById('yaraRulesTableBody');
        if (!tbody) return;
        const rows = tbody.querySelectorAll('tr');
        rows.forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length === 1 && row.querySelector('td[colspan]')) {
                row.style.display = '';
                return;
            }
            if (cells.length < 7) return;
            const ruleName = (cells[0]?.textContent || '').toLowerCase();
            const comment = (cells[1]?.textContent || '').toLowerCase();
            const analyst = (cells[4]?.textContent || '').toLowerCase();
            const ticket = (cells[5]?.textContent || '').toLowerCase();
            const match = !query || ruleName.includes(query) || comment.includes(query) || analyst.includes(query) || ticket.includes(query);
            row.style.display = match ? '' : 'none';
        });
    }

    document.getElementById('yaraTableFilter')?.addEventListener('keyup', filterYaraTable);

    async function loadYaraRules() {
        const tbody = document.getElementById('yaraRulesTableBody');
        if (!tbody) return;
        try {
            const result = await apiFetch('/api/list-yara');
            if (result && result.success && result.files && result.files.length > 0) {
                tbody.innerHTML = result.files.map(f => {
                    const canEdit = f.can_edit === true;
                    const canDelete = f.can_delete === true;
                    const displayName = (f.display_name != null && f.display_name !== '') ? f.display_name : f.filename;
                    const storeTitle = (f.filename && displayName !== f.filename)
                        ? ` title="${escapeAttr('Stored file: ' + f.filename)}"`
                        : '';
                    const editBtn = canEdit ? `<button type="button" class="btn-cmd-primary btn-cmd-sm edit-yara-btn" data-filename="${escapeHtml(f.filename)}">${t('actions.edit')}</button>` : '';
                    const deleteBtn = canDelete ? `<button type="button" class="btn-cmd-danger btn-cmd-sm delete-yara-btn" data-filename="${escapeHtml(f.filename)}">${t('actions.delete')}</button>` : '';
                    return `
                    <tr class="border border-white/10">
                        <td class="border border-white/10 px-4 py-2 text-sm font-mono"${storeTitle}>${escapeHtml(displayName)}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm text-secondary truncate max-w-xs" title="${escapeHtml((f.comment || '').trim()).replace(/"/g, '&quot;')}" dir="${typeof detectTextDir==='function'?detectTextDir(f.comment||''):'auto'}">${escapeHtml(f.comment || '-')}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${f.size_kb} KB</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(typeof formatUtcToLocal === 'function' ? formatUtcToLocal(f.upload_date) : (f.upload_date || ''))}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(f.user || '-')}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(f.ticket_id || '-')}</td>
                        <td class="border border-white/10 px-3 py-2">
                            <div class="flex items-center gap-1.5">
                                <button type="button" class="btn-cmd-primary btn-cmd-sm view-yara-btn" data-filename="${escapeHtml(f.filename)}">${t('actions.view')}</button>
                                ${editBtn}
                                ${deleteBtn}
                            </div>
                        </td>
                    </tr>
                `;
                }).join('');
                tbody.querySelectorAll('.view-yara-btn').forEach(btn => {
                    btn.addEventListener('click', () => viewYaraRule(btn.getAttribute('data-filename')));
                });
                tbody.querySelectorAll('.edit-yara-btn').forEach(btn => {
                    btn.addEventListener('click', () => editYaraRule(btn.getAttribute('data-filename')));
                });
                tbody.querySelectorAll('.delete-yara-btn').forEach(btn => {
                    btn.addEventListener('click', () => deleteYaraRule(btn.getAttribute('data-filename')));
                });
            } else if (result && result.success) {
                tbody.innerHTML = '<tr><td colspan="7" class="border border-white/10 px-4 py-6 text-center text-secondary text-sm">No YARA rules found</td></tr>';
            } else {
                tbody.innerHTML = '<tr><td colspan="7" class="border border-white/10 px-4 py-6 text-center text-secondary text-sm">Error loading rules</td></tr>';
            }
        } catch (error) {
            console.error('Error loading YARA rules:', error);
            tbody.innerHTML = '<tr><td colspan="7" class="border border-white/10 px-4 py-6 text-center text-secondary text-sm">Error loading rules</td></tr>';
        }
    }

    function showYaraDeleteReasonModal(filename) {
        return new Promise((resolve) => {
            const modal = document.getElementById('yaraAdminDeleteModal');
            const titleEl = document.getElementById('yaraAdminDeleteTitle');
            const ta = document.getElementById('yaraAdminDeleteReason');
            const submitBtn = document.getElementById('yaraAdminDeleteSubmit');
            const cancelBtn = document.getElementById('yaraAdminDeleteCancel');
            if (!modal || !ta) { resolve(null); return; }
            const titleBase = t('yara.admin_delete_title') || 'Delete YARA rule';
            titleEl.textContent = titleBase + ': ' + filename;
            ta.value = '';
            modal.classList.remove('hidden');
            function finish(val) {
                submitBtn.removeEventListener('click', onOk);
                cancelBtn.removeEventListener('click', onCancel);
                modal.classList.add('hidden');
                resolve(val);
            }
            function onOk() {
                const v = ta.value.trim();
                if (!v) {
                    showToast(t('yara.admin_delete_reason_required') || 'Enter a deletion reason.', 'error');
                    return;
                }
                finish(v);
            }
            function onCancel() { finish(null); }
            submitBtn.addEventListener('click', onOk);
            cancelBtn.addEventListener('click', onCancel);
            ta.focus();
        });
    }

    async function deleteYaraRule(filename) {
        if (!filename) return;
        const auth = global.authState || {};
        let reason = '';
        if (auth.is_admin) {
            const r = await showYaraDeleteReasonModal(filename);
            if (r === null) return;
            reason = r;
        } else {
            const ok = await showYaraConfirm('Delete YARA Rule', `Are you sure you want to delete "${filename}"? This cannot be undone.`, 'Delete');
            if (!ok) return;
        }
        try {
            const body = { filename: filename };
            if (reason) body.reason = reason;
            const response = await fetch('/api/delete-yara', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            const result = await response.json();
            if (result.success) {
                showToast(result.message, 'success');
                loadYaraRules();
            } else {
                showToast(result.message || 'Delete failed', 'error');
            }
        } catch (error) {
            showToast(t('toast.error_delete_rule') + ': ' + error.message, 'error');
        }
    }

    async function viewYaraRule(filename) {
        if (!filename) return;
        const modal = document.getElementById('yaraPreviewModal');
        const titleEl = document.getElementById('yaraPreviewTitle');
        const contentEl = document.getElementById('yaraPreviewContent');
        if (!modal || !titleEl || !contentEl) return;
        titleEl.textContent = filename;
        contentEl.innerHTML = '<code class="language-clike">Loading...</code>';
        modal.classList.remove('hidden');
        try {
            const response = await fetch('/api/view-yara/' + encodeURIComponent(filename));
            const result = await response.json();
            if (result.success) {
                const raw = result.content || '(empty file)';
                contentEl.innerHTML = '<code class="language-clike">' + escapeHtml(raw) + '</code>';
                const codeEl = contentEl.querySelector('code');
                if (typeof Prism !== 'undefined' && codeEl) Prism.highlightElement(codeEl);
            } else {
                contentEl.innerHTML = '<code class="language-clike">Error: ' + escapeHtml(result.message || 'Failed to load') + '</code>';
            }
        } catch (error) {
            contentEl.innerHTML = '<code class="language-clike">Error: ' + escapeHtml(error.message) + '</code>';
        }
    }

    document.getElementById('yaraPreviewClose')?.addEventListener('click', () => {
        document.getElementById('yaraPreviewModal')?.classList.add('hidden');
    });

    async function editYaraRule(filename) {
        if (!filename) return;
        const modal = document.getElementById('yaraEditModal');
        const titleEl = document.getElementById('yaraEditTitle');
        const textarea = document.getElementById('yaraEditContent');
        const reasonEl = document.getElementById('yaraEditChangeReason');
        if (!modal || !titleEl || !textarea) return;
        editingYaraFilename = filename;
        yaraEditOriginalContent = '';
        if (reasonEl) reasonEl.value = '';
        titleEl.textContent = t('modal.yara_edit') + ': ' + filename;
        textarea.value = '';
        modal.classList.remove('hidden');
        try {
            const response = await fetch('/api/view-yara/' + encodeURIComponent(filename));
            const result = await response.json();
            if (result.success) {
                textarea.value = result.content ?? '';
                yaraEditOriginalContent = textarea.value;
            } else {
                showToast(result.message || 'Failed to load rule', 'error');
                modal.classList.add('hidden');
            }
        } catch (error) {
            showToast(t('toast.error_load_rule') + ': ' + error.message, 'error');
            modal.classList.add('hidden');
        }
    }

    async function saveYaraRule() {
        if (!editingYaraFilename) return;
        const textarea = document.getElementById('yaraEditContent');
        const reasonEl = document.getElementById('yaraEditChangeReason');
        const modal = document.getElementById('yaraEditModal');
        if (!textarea || !modal) return;
        const reason = reasonEl ? reasonEl.value.trim() : '';
        if (textarea.value !== yaraEditOriginalContent && !reason) {
            showToast(t('toast.yara_edit_reason_required') || 'Describe why you changed the rule', 'error');
            if (reasonEl) reasonEl.focus();
            return;
        }
        try {
            const response = await fetch('/api/update-yara', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename: editingYaraFilename, content: textarea.value, reason: reason })
            });
            const result = await response.json();
            if (result.success) {
                showToast(result.message, 'success');
                modal.classList.add('hidden');
                editingYaraFilename = null;
                yaraEditOriginalContent = '';
                if (reasonEl) reasonEl.value = '';
                loadYaraRules();
                if (result.moved_to_pending || (result.message && result.message.indexOf('pending') !== -1)) {
                    const pendingSec = document.getElementById('yaraPendingSection');
                    if (pendingSec) pendingSec.classList.remove('hidden');
                    if (typeof loadYaraPending === 'function') await loadYaraPending();
                    setTimeout(function () { pendingSec && pendingSec.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }, 100);
                }
            } else {
                showToast(result.message || 'Update failed', 'error');
            }
        } catch (error) {
            showToast(t('toast.error_save_rule') + ': ' + error.message, 'error');
        }
    }

    document.getElementById('yaraEditCancel')?.addEventListener('click', () => {
        document.getElementById('yaraEditModal')?.classList.add('hidden');
        editingYaraFilename = null;
        yaraEditOriginalContent = '';
        const re = document.getElementById('yaraEditChangeReason');
        if (re) re.value = '';
    });
    document.getElementById('yaraEditSave')?.addEventListener('click', saveYaraRule);

    async function handleYaraUpload(file, opts) {
        opts = opts || {};
        const ticketElId = opts.ticketId || 'yaraTicketId';
        const commentElId = opts.comment || 'yaraComment';
        const campaignElId = opts.campaign || 'yaraCampaignSelect';
        const clearWrite = !!opts.clearWrite;

        const authState = global.authState || {};
        if (!authState.authenticated) {
            showToast(t('auth.login_required') || 'Please log in to submit YARA rules', 'error');
            return;
        }
        if (!file.name.toLowerCase().endsWith('.yar')) {
            showToast(t('toast.invalid_file_type'), 'error');
            return;
        }
        const namePrep = await yaraFileWithSafeName(file);
        file = namePrep.file;
        if (namePrep.changed && namePrep.sanitized) {
            showToast(
                (t('yara.filename_normalized') || 'Filename adjusted to "{name}" (spaces replaced with underscores).')
                    .replace('{name}', namePrep.sanitized),
                'warn'
            );
            setYaraSelected(file);
        }
        const ticketEl = document.getElementById(ticketElId);
        const commentEl = document.getElementById(commentElId);
        const campaignEl = document.getElementById(campaignElId);
        const formData = new FormData();
        formData.append('file', file);
        formData.append('ticket_id', (ticketEl && ticketEl.value ? ticketEl.value : '').trim());
        formData.append('comment', (commentEl && commentEl.value ? commentEl.value : '').trim());
        const cn = (campaignEl && campaignEl.value ? campaignEl.value : '').trim();
        if (cn) formData.append('campaign_name', cn);
        try {
            const response = await fetch('/api/upload-yara', { method: 'POST', body: formData });
            const result = await response.json().catch(() => ({}));
            if (response.status === 409) {
                showToast((result && result.message) ? result.message : t('toast.duplicate_entry'), 'error');
                return;
            }
            if (result.success) {
                showToast(result.message, 'success');
                if (clearWrite) {
                    const ws = document.getElementById('yaraWriteSource');
                    const wf = document.getElementById('yaraWriteFilename');
                    if (ws) ws.value = '';
                    if (wf) wf.value = '';
                    refreshYaraWriteHighlight();
                    clearYaraSyntaxResult();
                    invalidateYaraWriteValidation();
                } else {
                    clearYaraSyntaxBanner('yaraUploadSyntaxResult');
                    setYaraSelected(null);
                    if (yaraFileInput) yaraFileInput.value = '';
                }
                if (typeof loadLiveFeed === 'function') loadLiveFeed();
                loadYaraRules();
                if (authState.authenticated) {
                    const pendingSec = document.getElementById('yaraPendingSection');
                    if (pendingSec) pendingSec.classList.remove('hidden');
                    await loadYaraPending();
                    setTimeout(function () { pendingSec && pendingSec.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }, 100);
                }
            } else {
                showToast(result.message || 'Upload failed', 'error');
            }
        } catch (error) {
            showToast(t('toast.error_upload_yara') + ': ' + error.message, 'error');
        }
    }

    function clearYaraSyntaxBanner(bannerId) {
        const el = document.getElementById(bannerId || 'yaraWriteSyntaxResult');
        if (!el) return;
        el.classList.add('hidden');
        el.textContent = '';
        ['border-emerald-500/40', 'bg-emerald-950/30', 'text-emerald-100',
            'border-amber-500/40', 'bg-amber-950/30', 'text-amber-100',
            'border-red-500/40', 'bg-red-950/30', 'text-red-100'].forEach(function (c) {
            el.classList.remove(c);
        });
    }

    function showYaraSyntaxBanner(kind, text, bannerId) {
        const id = bannerId || 'yaraWriteSyntaxResult';
        const el = document.getElementById(id);
        if (!el) return;
        clearYaraSyntaxBanner(id);
        el.classList.remove('hidden');
        el.textContent = text || '';
        const palette = {
            ok: ['border-emerald-500/40', 'bg-emerald-950/30', 'text-emerald-100'],
            warn: ['border-amber-500/40', 'bg-amber-950/30', 'text-amber-100'],
            err: ['border-red-500/40', 'bg-red-950/30', 'text-red-100']
        };
        (palette[kind] || palette.err).forEach(function (c) { el.classList.add(c); });
    }

    function clearYaraSyntaxResult() {
        clearYaraSyntaxBanner('yaraWriteSyntaxResult');
    }

    function showYaraSyntaxResult(kind, text) {
        showYaraSyntaxBanner(kind, text, 'yaraWriteSyntaxResult');
    }

    async function handleYaraSyntaxCheck() {
        const authState = global.authState || {};
        if (!authState.authenticated) {
            showToast(t('auth.login_required') || 'Login required', 'error');
            return;
        }
        const source = document.getElementById('yaraWriteSource') ? document.getElementById('yaraWriteSource').value : '';
        const btn = document.getElementById('yaraWriteCheckSyntaxBtn');
        if (btn) btn.disabled = true;
        setYaraWriteSubmitEnabled(false);
        const bannerId = 'yaraWriteSyntaxResult';
        try {
            const response = await fetch('/api/yara/validate-syntax', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source: source })
            });
            const result = await response.json().catch(function () { return {}; });
            if (!response.ok) {
                showYaraSyntaxBanner('err', (result && result.message) ? result.message : 'Request failed', bannerId);
                invalidateYaraWriteValidation();
                return;
            }
            if (result.success && result.valid) {
                yaraWriteValidatedSource = source;
                setYaraWriteSubmitEnabled(true);
                showYaraSyntaxBanner('ok', t('yara.syntax_ok'), bannerId);
                return;
            }
            if (result.code === 'no_compiler') {
                showYaraSyntaxBanner('warn', (result && result.message) ? result.message : 'Compiler unavailable', bannerId);
                invalidateYaraWriteValidation();
                return;
            }
            showYaraSyntaxBanner('err', (result && result.message) ? result.message : (t('yara.syntax_invalid') || 'Invalid'), bannerId);
            invalidateYaraWriteValidation();
        } catch (err) {
            showYaraSyntaxBanner('err', err && err.message ? err.message : 'Network error', bannerId);
            invalidateYaraWriteValidation();
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function handleYaraUploadSyntaxCheck() {
        const authState = global.authState || {};
        if (!authState.authenticated) {
            showToast(t('auth.login_required') || 'Login required', 'error');
            return;
        }
        if (!selectedYaraFile) {
            showToast(t('toast.select_yara_file'), 'error');
            return;
        }
        const btn = document.getElementById('yaraUploadCheckSyntaxBtn');
        if (btn) btn.disabled = true;
        setYaraUploadSubmitEnabled(false);
        const bannerId = 'yaraUploadSyntaxResult';
        let source = '';
        try {
            source = await readFileAsText(selectedYaraFile);
            const response = await fetch('/api/yara/validate-syntax', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source: source })
            });
            const result = await response.json().catch(function () { return {}; });
            if (!response.ok) {
                showYaraSyntaxBanner('err', (result && result.message) ? result.message : 'Request failed', bannerId);
                invalidateYaraUploadValidation();
                return;
            }
            if (result.success && result.valid) {
                yaraUploadValidatedSource = source;
                yaraUploadValidatedFileKey = yaraUploadFileFingerprint(selectedYaraFile);
                setYaraUploadSubmitEnabled(true);
                showYaraSyntaxBanner('ok', t('yara.syntax_ok'), bannerId);
                return;
            }
            if (result.code === 'no_compiler') {
                showYaraSyntaxBanner('warn', (result && result.message) ? result.message : 'Compiler unavailable', bannerId);
                invalidateYaraUploadValidation();
                return;
            }
            showYaraSyntaxBanner('err', (result && result.message) ? result.message : (t('yara.syntax_invalid') || 'Invalid'), bannerId);
            invalidateYaraUploadValidation();
        } catch (err) {
            showYaraSyntaxBanner('err', err && err.message ? err.message : 'Network error', bannerId);
            invalidateYaraUploadValidation();
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function handleYaraResubmit() {
        const filename = global._yaraResubmitFilename;
        if (!filename) return;
        const ta = document.getElementById('yaraWriteSource');
        const sourceRaw = ta ? ta.value : '';
        const source = sourceRaw.trim();
        if (!source) {
            showToast(t('yara.write_error_empty_source'), 'error');
            return;
        }
        if (yaraWriteValidatedSource !== sourceRaw) {
            toastYaraSubmitBlocked();
            return;
        }
        const ticketEl = document.getElementById('yaraWriteTicketId');
        const commentEl = document.getElementById('yaraWriteComment');
        const campaignEl = document.getElementById('yaraWriteCampaignSelect');
        const payload = {
            filename: filename,
            content: sourceRaw,
            ticket_id: (ticketEl && ticketEl.value ? ticketEl.value : '').trim(),
            comment: (commentEl && commentEl.value ? commentEl.value : '').trim(),
            campaign_name: (campaignEl && campaignEl.value ? campaignEl.value : '').trim(),
        };
        try {
            const response = await fetch('/api/yara/resubmit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const result = await response.json().catch(() => ({}));
            if (response.status === 409) {
                showToast((result && result.message) ? result.message : t('toast.duplicate_entry'), 'error');
                return;
            }
            if (result.success) {
                showToast(result.message, 'success');
                clearYaraResubmitMode();
                const ws = document.getElementById('yaraWriteSource');
                const wf = document.getElementById('yaraWriteFilename');
                if (ws) ws.value = '';
                if (wf) wf.value = '';
                refreshYaraWriteHighlight();
                clearYaraSyntaxResult();
                invalidateYaraWriteValidation();
                await loadYaraRejected();
                if (typeof window.loadInboxBadge === 'function') {
                    window.loadInboxBadge();
                }
                const pendingSec = document.getElementById('yaraPendingSection');
                if (pendingSec) pendingSec.classList.remove('hidden');
                await loadYaraPending();
                setYaraMode('status');
                setTimeout(function () { pendingSec && pendingSec.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }, 100);
            } else {
                showToast(result.message || 'Resubmit failed', 'error');
            }
        } catch (error) {
            showToast((t('toast.error_upload_yara') || 'Error') + ': ' + error.message, 'error');
        }
    }

    async function handleYaraWriteSubmit() {
        if (global._yaraResubmitFilename) {
            await handleYaraResubmit();
            return;
        }
        const rawName = (document.getElementById('yaraWriteFilename') && document.getElementById('yaraWriteFilename').value || '').trim();
        const ta = document.getElementById('yaraWriteSource');
        const sourceRaw = ta ? ta.value : '';
        const source = sourceRaw.trim();
        if (!rawName) {
            showToast(t('yara.write_error_empty_filename'), 'error');
            return;
        }
        if (!source) {
            showToast(t('yara.write_error_empty_source'), 'error');
            return;
        }
        if (yaraWriteValidatedSource !== sourceRaw) {
            toastYaraSubmitBlocked();
            return;
        }
        const base = rawName.split(/[/\\]/).pop() || rawName;
        const withExt = base.toLowerCase().endsWith('.yar') ? base : (base + '.yar');
        const nameInfo = sanitizeYaraFilename(withExt);
        if (!nameInfo.sanitized) {
            showToast(t('yara.write_error_invalid_filename') || t('yara.write_error_empty_filename'), 'error');
            return;
        }
        if (nameInfo.changed) {
            const wf = document.getElementById('yaraWriteFilename');
            if (wf) wf.value = nameInfo.sanitized.replace(/\.yar$/i, '');
            showToast(
                (t('yara.filename_normalized') || 'Filename adjusted to "{name}" (spaces replaced with underscores).')
                    .replace('{name}', nameInfo.sanitized),
                'warn'
            );
        }
        const finalName = nameInfo.sanitized;
        const file = new File([source], finalName, { type: 'text/plain' });
        await handleYaraUpload(file, {
            ticketId: 'yaraWriteTicketId',
            comment: 'yaraWriteComment',
            campaign: 'yaraWriteCampaignSelect',
            clearWrite: true
        });
    }

    function getYaraInfoUploadHtml() {
        return `<h4 class="font-bold mb-1">${t('yara.info_upload_title')}</h4>
                <p class="mb-1">${t('yara.info_upload_desc')}</p>`;
    }
    function getYaraInfoWriteHtml() {
        return `<h4 class="font-bold mb-1">${t('yara.info_write_title')}</h4>
                <p class="mb-1">${t('yara.info_write_desc')}</p>`;
    }
    function getYaraInfoStatusHtml() {
        return `<h4 class="font-bold mb-1">${t('yara.info_status_title')}</h4>
                <p class="mb-1">${t('yara.info_status_desc')}</p>`;
    }

    function setYaraMode(mode, options) {
        const skipReload = options && options.skipReload;
        const prevYaraMode = global._yaraCurrentMode;
        global._yaraCurrentMode = mode;
        const isUpload = mode === 'upload';
        const isWrite = mode === 'write';
        const isStatus = mode === 'status';
        const wUpload = document.getElementById('yara-wrapper-upload');
        const wWrite = document.getElementById('yara-wrapper-write');
        const wStatus = document.getElementById('yara-wrapper-status');
        const btnU = document.getElementById('btnModeYaraUpload');
        const btnW = document.getElementById('btnModeYaraWrite');
        const btnS = document.getElementById('btnModeYaraStatus');
        const infoCard = document.getElementById('yaraModeInfoCard');
        const authState = global.authState || {};

        if (wUpload) wUpload.classList.toggle('hidden', !isUpload);
        if (wWrite) wWrite.classList.toggle('hidden', !isWrite);
        if (wStatus) wStatus.classList.toggle('hidden', !isStatus);

        function setActive(btn, active) {
            if (!btn) return;
            if (active) { btn.classList.add('bg-blue-600', 'text-white'); btn.classList.remove('bg-transparent', 'text-secondary'); }
            else { btn.classList.remove('bg-blue-600', 'text-white'); btn.classList.add('bg-transparent', 'text-secondary'); }
        }
        setActive(btnU, isUpload);
        setActive(btnW, isWrite);
        setActive(btnS, isStatus);

        if (infoCard) {
            if (isUpload) infoCard.innerHTML = getYaraInfoUploadHtml();
            else if (isWrite) infoCard.innerHTML = getYaraInfoWriteHtml();
            else infoCard.innerHTML = getYaraInfoStatusHtml();
        }

        if (isWrite && prevYaraMode !== 'write') {
            invalidateYaraWriteValidation();
            clearYaraSyntaxResult();
        }

        if (isUpload && prevYaraMode !== 'upload') {
            invalidateYaraUploadValidation();
            clearYaraSyntaxBanner('yaraUploadSyntaxResult');
        }

        if (isWrite && prevYaraMode === 'write' && mode !== 'write') {
            clearYaraResubmitMode();
        }

        if (isStatus && !skipReload) {
            loadYaraRules();
            if (authState.authenticated) {
                loadYaraPending();
                loadYaraRejected();
            }
        }
    }

    async function loadYaraRejected(showToastIfUnseen) {
        const section = document.getElementById('yaraRejectedSection');
        const tbody = document.getElementById('yaraRejectedTableBody');
        const auth = (typeof window !== 'undefined' && window.authState) || (typeof global !== 'undefined' && global.authState);
        const isAdmin = auth && auth.is_admin;
        if (isAdmin) {
            if (section) section.classList.add('hidden');
            updateYaraRejectedBadge(0);
            return;
        }
        if (!tbody) return;
        if (section) section.classList.remove('hidden');
        try {
            const response = await fetch('/api/yara/my-rejected?_=' + Date.now());
            const result = await response.json();
            const unseen = (result && result.unseen_count != null) ? Number(result.unseen_count) : 0;
            updateYaraRejectedBadge(unseen);
            if (showToastIfUnseen && unseen > 0) {
                const key = 'yara_rejection_toast_' + unseen;
                try {
                    if (!sessionStorage.getItem(key)) {
                        const msg = unseen === 1
                            ? (t('yara.rejection_toast_one') || 'One YARA rule was rejected by an administrator.')
                            : (t('yara.rejection_toast_many') || '').replace('{n}', String(unseen)) || (unseen + ' YARA rules were rejected.');
                        showToast(msg, 'warning');
                        sessionStorage.setItem(key, '1');
                    }
                } catch (e) {
                    showToast(t('yara.rejection_toast_one') || 'A YARA rule was rejected by an administrator.', 'warning');
                }
            }
            if (result.success && result.files && result.files.length > 0) {
                tbody.innerHTML = result.files.map(f => {
                    const reason = (f.rejection_reason || '').trim() || '—';
                    const rejectedAt = typeof formatUtcToLocal === 'function' ? formatUtcToLocal(f.rejected_at) : (f.rejected_at || '-');
                    const unseenDot = f.seen ? '' : '<span class="inline-block w-2 h-2 rounded-full bg-red-400 flex-shrink-0" title="New"></span>';
                    const rejectedBadge = '<span class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-semibold bg-red-500/20 text-red-300 border border-red-500/40 mr-2 flex-shrink-0">Rejected</span>';
                    const displayRej = (f.display_name != null && f.display_name !== '') ? f.display_name : f.filename;
                    return `<tr class="border border-white/10">
                        <td class="border border-white/10 px-4 py-2 text-sm font-mono"><span class="inline-flex items-center gap-1 flex-wrap">${unseenDot}${rejectedBadge}${escapeHtml(displayRej)}</span></td>
                        <td class="border border-white/10 px-4 py-2 text-sm text-secondary truncate max-w-xs" title="${escapeAttr(reason)}" dir="${typeof detectTextDir==='function'?detectTextDir(reason):'auto'}">${escapeHtml(reason)}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(rejectedAt)}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(f.rejected_by || '-')}</td>
                        <td class="border border-white/10 px-3 py-2"><div class="flex items-center gap-1.5 flex-wrap">
                            <button type="button" class="btn-cmd-primary btn-cmd-sm view-rejected-yara-btn" data-filename="${escapeAttr(f.filename)}">${t('actions.view')}</button>
                            <button type="button" class="btn-cmd-primary btn-cmd-sm resubmit-rejected-yara-btn" data-filename="${escapeAttr(f.filename)}">${t('yara.resubmit_btn') || 'Resubmit'}</button>
                        </div></td>
                    </tr>`;
                }).join('');
                tbody.querySelectorAll('.view-rejected-yara-btn').forEach(btn => {
                    btn.addEventListener('click', () => viewRejectedYaraRule(btn.getAttribute('data-filename')));
                });
                tbody.querySelectorAll('.resubmit-rejected-yara-btn').forEach(btn => {
                    btn.addEventListener('click', () => editAndResubmitRejectedRule(btn.getAttribute('data-filename')));
                });
            } else {
                tbody.innerHTML = '<tr><td colspan="5" class="border border-white/10 px-4 py-4 text-center text-secondary text-sm">' + (t('yara.no_rejected') || 'No rejected rules') + '</td></tr>';
            }
        } catch (error) {
            console.error('Error loading rejected YARA:', error);
            tbody.innerHTML = '<tr><td colspan="5" class="border border-white/10 px-4 py-4 text-center text-secondary text-sm">Error loading rejected</td></tr>';
        }
    }

    async function markYaraRejectionSeen(filename) {
        try {
            await fetch('/api/yara/mark-rejection-seen', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(filename ? { filename: filename } : { all: true }),
            });
            await loadYaraRejected();
        } catch (e) {
            console.warn('mark-rejection-seen failed', e);
        }
    }

    async function viewRejectedYaraRule(filename) {
        if (!filename) return;
        await markYaraRejectionSeen(filename);
        const modal = document.getElementById('yaraPreviewModal');
        const titleEl = document.getElementById('yaraPreviewTitle');
        const contentEl = document.getElementById('yaraPreviewContent');
        if (!modal || !titleEl || !contentEl) return;
        titleEl.textContent = 'Rejected: ' + filename;
        contentEl.innerHTML = '<code class="language-clike">Loading...</code>';
        modal.classList.remove('hidden');
        try {
            const response = await fetch('/api/yara/rejected-content/' + encodeURIComponent(filename));
            const result = await response.json();
            if (result.success) {
                const reason = (result.rejection_reason || '').trim();
                const reasonHtml = reason
                    ? '<p class="text-sm text-red-300 mb-3 border border-red-500/30 rounded-lg px-3 py-2 bg-red-950/30"><strong>Reason:</strong> ' + escapeHtml(reason) + '</p>'
                    : '';
                const raw = result.content || '(empty file)';
                contentEl.innerHTML = reasonHtml + '<code class="language-clike">' + escapeHtml(raw) + '</code>';
                const codeEl = contentEl.querySelector('code');
                if (typeof Prism !== 'undefined' && codeEl) Prism.highlightElement(codeEl);
            } else {
                contentEl.innerHTML = '<code class="language-clike">Error: ' + escapeHtml(result.message || 'Failed to load') + '</code>';
            }
        } catch (error) {
            contentEl.innerHTML = '<code class="language-clike">Error: ' + escapeHtml(error.message) + '</code>';
        }
    }

    async function editAndResubmitRejectedRule(filename) {
        if (!filename) return;
        try {
            const response = await fetch('/api/yara/rejected-content/' + encodeURIComponent(filename));
            const result = await response.json();
            if (!result.success) {
                showToast(result.message || 'Failed to load rule', 'error');
                return;
            }
            await markYaraRejectionSeen(filename);
            const wf = document.getElementById('yaraWriteFilename');
            const ws = document.getElementById('yaraWriteSource');
            const ticketEl = document.getElementById('yaraWriteTicketId');
            const commentEl = document.getElementById('yaraWriteComment');
            const campaignEl = document.getElementById('yaraWriteCampaignSelect');
            if (wf) {
                wf.value = result.filename || filename;
                wf.readOnly = true;
            }
            if (ws) ws.value = result.content || '';
            if (ticketEl) ticketEl.value = result.ticket_id || '';
            if (commentEl) {
                commentEl.value = result.comment || '';
                if (typeof detectTextDir === 'function') commentEl.dir = detectTextDir(commentEl.value);
            }
            yaraWriteValidatedSource = null;
            invalidateYaraWriteValidation();
            refreshYaraWriteHighlight();
            clearYaraSyntaxResult();
            if (campaignEl) {
                const campRes = await fetch('/api/campaigns');
                const campData = await campRes.json();
                campaignEl.innerHTML = '<option value="">-- None --</option>';
                let selectedName = '';
                if (campData.success && campData.campaigns) {
                    campData.campaigns.forEach(c => {
                        const opt = document.createElement('option');
                        opt.value = c.name;
                        opt.textContent = c.name;
                        if (result.campaign_id && c.id === result.campaign_id) {
                            opt.selected = true;
                            selectedName = c.name;
                        }
                        campaignEl.appendChild(opt);
                    });
                }
                if (!selectedName && result.campaign_id) {
                    campaignEl.value = '';
                }
            }
            setYaraResubmitMode(result.filename || filename);
            setYaraMode('status', { skipReload: true });
            setYaraMode('write');
            showToast(t('yara.resubmit_edit_hint') || 'Edit the rule and click Resubmit for approval.', 'info');
        } catch (error) {
            showToast('Failed to load rule: ' + error.message, 'error');
        }
    }

    async function loadYaraPending() {
        const tbody = document.getElementById('yaraPendingTableBody');
        if (!tbody) return;
        const auth = (typeof window !== 'undefined' && window.authState) || (typeof global !== 'undefined' && global.authState);
        const isAdmin = auth && auth.is_admin;
        const baseUrl = isAdmin ? '/api/yara/pending' : '/api/yara/my-pending';
        const apiUrl = baseUrl + (baseUrl.indexOf('?') >= 0 ? '&' : '?') + '_=' + Date.now();
        try {
            const response = await fetch(apiUrl);
            const result = await response.json();
            if (result.success && result.files && result.files.length > 0) {
                tbody.innerHTML = result.files.map(f => {
                    const analystCell = isAdmin ? escapeHtml(f.user || '-') : '-';
                    const actionsHtml = isAdmin
                        ? `<button type="button" class="btn-cmd-primary btn-cmd-sm view-pending-yara-btn" data-filename="${escapeAttr(f.filename)}">${t('actions.view')}</button>
                           <button type="button" class="btn-cmd-primary btn-cmd-sm approve-pending-yara-btn" data-filename="${escapeAttr(f.filename)}">Approve</button>
                           <button type="button" class="btn-cmd-danger btn-cmd-sm reject-pending-yara-btn" data-filename="${escapeAttr(f.filename)}">Reject</button>`
                        : `<button type="button" class="btn-cmd-primary btn-cmd-sm view-pending-yara-btn" data-filename="${escapeAttr(f.filename)}">${t('actions.view')}</button>`;
                    const pendingBadge = '<span class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/40 mr-2 flex-shrink-0">Pending</span>';
                    const displayPend = (f.display_name != null && f.display_name !== '') ? f.display_name : f.filename;
                    const storeTitlePend = (f.filename && displayPend !== f.filename)
                        ? ` title="${escapeAttr('Stored file: ' + f.filename)}"`
                        : '';
                    return `<tr class="border border-white/10">
                        <td class="border border-white/10 px-4 py-2 text-sm font-mono"${storeTitlePend}><span class="inline-flex items-center gap-1 flex-wrap">${pendingBadge}${escapeHtml(displayPend)}</span></td>
                        <td class="border border-white/10 px-4 py-2 text-sm text-secondary truncate max-w-xs" title="${escapeAttr((f.comment || '').trim())}" dir="${typeof detectTextDir==='function'?detectTextDir(f.comment||''):'auto'}">${escapeHtml(f.comment || '-')}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(typeof formatUtcToLocal === 'function' ? formatUtcToLocal(f.upload_date) : (f.upload_date || '-'))}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${analystCell}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(f.ticket_id || '-')}</td>
                        <td class="border border-white/10 px-3 py-2"><div class="flex items-center gap-1.5">${actionsHtml}</div></td>
                    </tr>`;
                }).join('');
                tbody.querySelectorAll('.view-pending-yara-btn').forEach(btn => {
                    btn.addEventListener('click', () => viewPendingYaraRule(btn.getAttribute('data-filename')));
                });
                if (isAdmin) {
                    tbody.querySelectorAll('.approve-pending-yara-btn').forEach(btn => {
                        btn.addEventListener('click', () => approvePendingYaraRule(btn.getAttribute('data-filename')));
                    });
                    tbody.querySelectorAll('.reject-pending-yara-btn').forEach(btn => {
                        btn.addEventListener('click', () => rejectPendingYaraRule(btn.getAttribute('data-filename')));
                    });
                }
            } else {
                tbody.innerHTML = '<tr><td colspan="6" class="border border-white/10 px-4 py-4 text-center text-secondary text-sm">No pending rules</td></tr>';
            }
        } catch (error) {
            console.error('Error loading pending YARA:', error);
            tbody.innerHTML = '<tr><td colspan="6" class="border border-white/10 px-4 py-4 text-center text-secondary text-sm">Error loading pending</td></tr>';
        }
    }

    async function viewPendingYaraRule(filename) {
        if (!filename) return;
        const modal = document.getElementById('yaraPreviewModal');
        const titleEl = document.getElementById('yaraPreviewTitle');
        const contentEl = document.getElementById('yaraPreviewContent');
        if (!modal || !titleEl || !contentEl) return;
        titleEl.textContent = 'Pending: ' + filename;
        contentEl.innerHTML = '<code class="language-clike">Loading...</code>';
        modal.classList.remove('hidden');
        try {
            const response = await fetch('/api/yara/pending-content/' + encodeURIComponent(filename));
            const result = await response.json();
            if (result.success) {
                const raw = result.content || '(empty file)';
                contentEl.innerHTML = '<code class="language-clike">' + escapeHtml(raw) + '</code>';
                const codeEl = contentEl.querySelector('code');
                if (typeof Prism !== 'undefined' && codeEl) Prism.highlightElement(codeEl);
            } else {
                contentEl.innerHTML = '<code class="language-clike">Error: ' + escapeHtml(result.message || 'Failed to load') + '</code>';
            }
        } catch (error) {
            contentEl.innerHTML = '<code class="language-clike">Error: ' + escapeHtml(error.message) + '</code>';
        }
    }

    async function approvePendingYaraRule(filename) {
        if (!filename) return;
        try {
            const response = await fetch('/api/yara/approve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename: filename })
            });
            const result = await response.json();
            if (result.success) {
                showToast(result.message, 'success');
                loadYaraPending();
                loadYaraRules();
                if (typeof loadLiveFeed === 'function') loadLiveFeed();
                if (result.fireeye_pending) {
                    showToast('Uploading to external API(s)...', 'info');
                    const pollFireeye = async () => {
                        try {
                            const r = await fetch('/api/yara/fireeye-status?filename=' + encodeURIComponent(filename));
                            const d = await r.json();
                            if (d.success && d.data) {
                                const status = d.data.status;
                                if (status === 'pending') {
                                    setTimeout(pollFireeye, 1500);
                                    return;
                                }
                                if (status === 'success') {
                                    showToast('YARA push: SUCCESS', 'success');
                                } else {
                                    showToast('YARA push: ERROR - ' + (d.data.message || 'Unknown'), 'error');
                                }
                                return;
                            }
                            setTimeout(pollFireeye, 1500);
                        } catch (e) {
                            showToast('YARA push status check failed', 'error');
                        }
                    };
                    setTimeout(pollFireeye, 1500);
                }
            } else {
                showToast(result.message || 'Approve failed', 'error');
            }
        } catch (error) {
            showToast('Approve failed: ' + error.message, 'error');
        }
    }

    async function rejectPendingYaraRule(filename) {
        if (!filename) return;
        const modalResult = await showYaraRejectModal(filename);
        if (!modalResult.ok) return;
        try {
            const response = await fetch('/api/yara/reject', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename: filename, reason: modalResult.reason || '' })
            });
            const result = await response.json();
            if (result.success) {
                showToast(result.message, 'success');
                loadYaraPending();
            } else {
                showToast(result.message || 'Reject failed', 'error');
            }
        } catch (error) {
            showToast('Reject failed: ' + error.message, 'error');
        }
    }

    // YARA Metadata Edit Modal (used from search results)
    function openYaraMetaEditModal(filename, ticketId, comment, campaignName) {
        document.getElementById('yaraMetaFilename').value = filename;
        document.getElementById('yaraMetaDisplay').value = filename;
        document.getElementById('yaraMetaTicketId').value = ticketId || '';
        const yaraMetaCommentEl = document.getElementById('yaraMetaComment');
        yaraMetaCommentEl.value = comment || '';
        if (typeof detectTextDir === 'function') yaraMetaCommentEl.dir = detectTextDir(comment || '');
        const select = document.getElementById('yaraMetaCampaignSelect');
        select.innerHTML = '<option value="">-- None --</option>';
        fetch('/api/campaigns').then(r => r.json()).then(d => {
            if (d.success && d.campaigns) {
                d.campaigns.forEach(c => {
                    const opt = document.createElement('option');
                    opt.value = c.name;
                    opt.textContent = c.name;
                    if (c.name === campaignName) opt.selected = true;
                    select.appendChild(opt);
                });
            }
        }).catch(() => {});
        document.getElementById('yaraMetaEditModal').classList.remove('hidden');
    }

    function closeYaraMetaEditModal() {
        document.getElementById('yaraMetaEditModal').classList.add('hidden');
    }

    document.getElementById('yaraMetaEditCancel')?.addEventListener('click', closeYaraMetaEditModal);
    document.getElementById('yaraMetaEditModal')?.addEventListener('click', (e) => {
        if (e.target === e.currentTarget) closeYaraMetaEditModal();
    });
    document.getElementById('yaraMetaEditForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const filename = document.getElementById('yaraMetaFilename').value;
        const ticket_id = document.getElementById('yaraMetaTicketId').value.trim();
        const comment = document.getElementById('yaraMetaComment').value.trim();
        const campaign_name = document.getElementById('yaraMetaCampaignSelect').value;
        try {
            const r = await fetch('/api/edit-yara-meta', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename, ticket_id, comment, campaign_name })
            });
            const d = await r.json().catch(() => ({}));
            showToast(d.message || (d.success ? 'Updated' : 'Failed'), d.success ? 'success' : 'error');
            if (d.success) {
                closeYaraMetaEditModal();
                if (d.moved_to_pending) {
                    if (typeof loadYaraRules === 'function') loadYaraRules();
                    const pendingSec = document.getElementById('yaraPendingSection');
                    if (pendingSec) pendingSec.classList.remove('hidden');
                    if (typeof loadYaraPending === 'function') await loadYaraPending();
                    setTimeout(function () { pendingSec && pendingSec.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }, 100);
                }
                const searchInput = document.getElementById('searchInput');
                const searchButton = document.getElementById('searchButton');
                if (searchInput && searchInput.value.trim() && searchButton) {
                    searchButton.click();
                }
            }
        } catch (err) { showToast(t('toast.error_generic') + ': ' + err.message, 'error'); }
    });

    if (typeof applyAutoDir === 'function') {
        applyAutoDir(document.getElementById('yaraMetaComment'));
        applyAutoDir(document.getElementById('yaraWriteComment'));
    }

    document.getElementById('btnModeYaraUpload')?.addEventListener('click', () => setYaraMode('upload'));
    document.getElementById('btnModeYaraWrite')?.addEventListener('click', () => setYaraMode('write'));
    document.getElementById('btnModeYaraStatus')?.addEventListener('click', () => setYaraMode('status'));
    document.getElementById('yaraWriteSubmitBtn')?.addEventListener('click', () => { handleYaraWriteSubmit(); });
    document.getElementById('yaraWriteCheckSyntaxBtn')?.addEventListener('click', () => { handleYaraSyntaxCheck(); });
    document.getElementById('yaraUploadCheckSyntaxBtn')?.addEventListener('click', () => { handleYaraUploadSyntaxCheck(); });
    document.getElementById('yaraWriteFilename')?.addEventListener('focus', function () {
        if (!global._yaraResubmitFilename) this.readOnly = false;
    });

    document.getElementById('yaraWriteSource')?.addEventListener('input', function () {
        clearYaraSyntaxResult();
        invalidateYaraWriteValidation();
        scheduleYaraWriteHighlight();
    });

    global.loadYaraRules = loadYaraRules;
    global.loadYaraPending = loadYaraPending;
    global.loadYaraRejected = loadYaraRejected;
    global.editAndResubmitRejectedRule = editAndResubmitRejectedRule;
    global.openYaraMetaEditModal = openYaraMetaEditModal;
    global.setYaraMode = setYaraMode;
    setYaraMode('upload');
})(typeof window !== 'undefined' ? window : this);
