/**
 * YARA Manager tab logic (Step 10.4 — extracted from index.html).
 * Depends on globals: escapeHtml, escapeAttr, showToast, t, authState, apiFetch, Prism,
 *                     loadLiveFeed, searchInput, searchButton.
 * Exposes: loadYaraRules, loadYaraPending, loadYaraMyPending, openYaraMetaEditModal.
 */
(function(global) {
    'use strict';

    let selectedYaraFile = null;
    let editingYaraFilename = null;
    const yaraDropZone = document.getElementById('yaraDropZone');
    const yaraFileInput = document.getElementById('yaraFileInput');
    const yaraSelectedFilename = document.getElementById('yaraSelectedFilename');

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
        if (yaraSelectedFilename) {
            if (file) {
                yaraSelectedFilename.textContent = t('yara.selected') + ': ' + file.name;
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

    document.getElementById('yaraSubmitBtn')?.addEventListener('click', () => {
        if (!selectedYaraFile) {
            showToast(t('toast.select_yara_file'), 'error');
            return;
        }
        handleYaraUpload(selectedYaraFile);
        setYaraSelected(null);
        if (yaraFileInput) yaraFileInput.value = '';
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
                    return `
                    <tr class="border border-white/10">
                        <td class="border border-white/10 px-4 py-2 text-sm font-mono">${escapeHtml(f.filename)}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm text-secondary truncate max-w-xs" title="${escapeHtml((f.comment || '').trim()).replace(/"/g, '&quot;')}">${escapeHtml(f.comment || '—')}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${f.size_kb} KB</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(f.upload_date || '')}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(f.user || '—')}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(f.ticket_id || '—')}</td>
                        <td class="border border-white/10 px-3 py-2">
                            <div class="flex items-center gap-1.5">
                                <button type="button" class="btn-cmd-primary btn-cmd-sm view-yara-btn" data-filename="${escapeHtml(f.filename)}">${t('actions.view')}</button>
                                <button type="button" class="btn-cmd-primary btn-cmd-sm edit-yara-btn" data-filename="${escapeHtml(f.filename)}">${t('actions.edit')}</button>
                                <button type="button" class="btn-cmd-danger btn-cmd-sm delete-yara-btn" data-filename="${escapeHtml(f.filename)}">${t('actions.delete')}</button>
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

    async function deleteYaraRule(filename) {
        if (!filename) return;
        const ok = await showYaraConfirm('Delete YARA Rule', `Are you sure you want to delete "${filename}"? This cannot be undone.`, 'Delete');
        if (!ok) return;
        try {
            const response = await fetch('/api/delete-yara', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename: filename })
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
        if (!modal || !titleEl || !textarea) return;
        editingYaraFilename = filename;
        titleEl.textContent = t('modal.yara_edit') + ': ' + filename;
        textarea.value = '';
        modal.classList.remove('hidden');
        try {
            const response = await fetch('/api/view-yara/' + encodeURIComponent(filename));
            const result = await response.json();
            if (result.success) {
                textarea.value = result.content ?? '';
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
        const modal = document.getElementById('yaraEditModal');
        if (!textarea || !modal) return;
        try {
            const response = await fetch('/api/update-yara', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename: editingYaraFilename, content: textarea.value })
            });
            const result = await response.json();
            if (result.success) {
                showToast(result.message, 'success');
                modal.classList.add('hidden');
                editingYaraFilename = null;
                loadYaraRules();
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
    });
    document.getElementById('yaraEditSave')?.addEventListener('click', saveYaraRule);

    async function handleYaraUpload(file) {
        const authState = global.authState || {};
        if (!authState.authenticated) {
            showToast(t('auth.login_required') || 'Please log in to submit YARA rules', 'error');
            return;
        }
        if (!file.name.toLowerCase().endsWith('.yar')) {
            showToast(t('toast.invalid_file_type'), 'error');
            return;
        }
        const formData = new FormData();
        formData.append('file', file);
        formData.append('ticket_id', document.getElementById('yaraTicketId').value.trim());
        formData.append('comment', document.getElementById('yaraComment').value.trim());
        try {
            const response = await fetch('/api/upload-yara', { method: 'POST', body: formData });
            const result = await response.json().catch(() => ({}));
            if (response.status === 409) {
                showToast(t('toast.duplicate_entry'), 'error');
                return;
            }
            if (result.success) {
                showToast(result.message, 'success');
                if (typeof loadLiveFeed === 'function') loadLiveFeed();
                loadYaraRules();
                if (authState.is_admin) loadYaraPending();
                if (authState.authenticated) loadYaraMyPending();
            } else {
                showToast(result.message || 'Upload failed', 'error');
            }
        } catch (error) {
            showToast(t('toast.error_upload_yara') + ': ' + error.message, 'error');
        }
    }

    async function loadYaraPending() {
        const tbody = document.getElementById('yaraPendingTableBody');
        if (!tbody) return;
        const section = document.getElementById('yaraPendingSection');
        if (section && section.classList.contains('hidden')) return;
        try {
            const response = await fetch('/api/yara/pending');
            const result = await response.json();
            if (result.success && result.files && result.files.length > 0) {
                tbody.innerHTML = result.files.map(f => `
                    <tr class="border border-white/10">
                        <td class="border border-white/10 px-4 py-2 text-sm font-mono">${escapeHtml(f.filename)}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm text-secondary truncate max-w-xs" title="${escapeAttr((f.comment || '').trim())}">${escapeHtml(f.comment || '—')}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(f.upload_date || '—')}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(f.user || '—')}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(f.ticket_id || '—')}</td>
                        <td class="border border-white/10 px-3 py-2">
                            <div class="flex items-center gap-1.5">
                                <button type="button" class="btn-cmd-primary btn-cmd-sm view-pending-yara-btn" data-filename="${escapeAttr(f.filename)}">${t('actions.view')}</button>
                                <button type="button" class="btn-cmd-primary btn-cmd-sm approve-pending-yara-btn" data-filename="${escapeAttr(f.filename)}">Approve</button>
                                <button type="button" class="btn-cmd-danger btn-cmd-sm reject-pending-yara-btn" data-filename="${escapeAttr(f.filename)}">Reject</button>
                            </div>
                        </td>
                    </tr>
                `).join('');
                tbody.querySelectorAll('.view-pending-yara-btn').forEach(btn => {
                    btn.addEventListener('click', () => viewPendingYaraRule(btn.getAttribute('data-filename')));
                });
                tbody.querySelectorAll('.approve-pending-yara-btn').forEach(btn => {
                    btn.addEventListener('click', () => approvePendingYaraRule(btn.getAttribute('data-filename')));
                });
                tbody.querySelectorAll('.reject-pending-yara-btn').forEach(btn => {
                    btn.addEventListener('click', () => rejectPendingYaraRule(btn.getAttribute('data-filename')));
                });
            } else {
                tbody.innerHTML = '<tr><td colspan="6" class="border border-white/10 px-4 py-4 text-center text-secondary text-sm">No pending rules</td></tr>';
            }
        } catch (error) {
            console.error('Error loading pending YARA:', error);
            tbody.innerHTML = '<tr><td colspan="6" class="border border-white/10 px-4 py-4 text-center text-secondary text-sm">Error loading pending</td></tr>';
        }
    }

    async function loadYaraMyPending() {
        const tbody = document.getElementById('yaraMyPendingTableBody');
        if (!tbody) return;
        const section = document.getElementById('yaraMyPendingSection');
        if (section && section.classList.contains('hidden')) return;
        try {
            const response = await fetch('/api/yara/my-pending');
            const result = await response.json();
            if (result.success && result.files && result.files.length > 0) {
                tbody.innerHTML = result.files.map(f => `
                    <tr class="border border-white/10">
                        <td class="border border-white/10 px-4 py-2 text-sm font-mono">${escapeHtml(f.filename)}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm text-secondary truncate max-w-xs" title="${escapeAttr((f.comment || '').trim())}">${escapeHtml(f.comment || '—')}</td>
                        <td class="border border-white/10 px-4 py-2 text-sm">${escapeHtml(f.upload_date || '—')}</td>
                        <td class="border border-white/10 px-4 py-2"><span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-500/20 text-amber-400 border border-amber-500/40">Pending</span></td>
                        <td class="border border-white/10 px-3 py-2">
                            <button type="button" class="btn-cmd-primary btn-cmd-sm view-my-pending-yara-btn" data-filename="${escapeAttr(f.filename)}">${t('actions.view')}</button>
                        </td>
                    </tr>
                `).join('');
                tbody.querySelectorAll('.view-my-pending-yara-btn').forEach(btn => {
                    btn.addEventListener('click', () => viewPendingYaraRule(btn.getAttribute('data-filename')));
                });
            } else {
                tbody.innerHTML = '<tr><td colspan="5" class="border border-white/10 px-4 py-4 text-center text-secondary text-sm">No pending uploads</td></tr>';
            }
        } catch (error) {
            console.error('Error loading my pending YARA:', error);
            tbody.innerHTML = '<tr><td colspan="5" class="border border-white/10 px-4 py-4 text-center text-secondary text-sm">Error loading</td></tr>';
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
            } else {
                showToast(result.message || 'Approve failed', 'error');
            }
        } catch (error) {
            showToast('Approve failed: ' + error.message, 'error');
        }
    }

    async function rejectPendingYaraRule(filename) {
        if (!filename) return;
        const ok = await showYaraConfirm('Reject YARA Rule', `Are you sure you want to reject "${filename}"? The file will be permanently removed.`, 'Reject');
        if (!ok) return;
        try {
            const response = await fetch('/api/yara/reject', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename: filename })
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
        document.getElementById('yaraMetaComment').value = comment || '';
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
                const searchInput = document.getElementById('searchInput');
                const searchButton = document.getElementById('searchButton');
                if (searchInput && searchInput.value.trim() && searchButton) {
                    searchButton.click();
                }
            }
        } catch (err) { showToast(t('toast.error_generic') + ': ' + err.message, 'error'); }
    });

    global.loadYaraRules = loadYaraRules;
    global.loadYaraPending = loadYaraPending;
    global.loadYaraMyPending = loadYaraMyPending;
    global.openYaraMetaEditModal = openYaraMetaEditModal;
})(typeof window !== 'undefined' ? window : this);
