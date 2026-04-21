// Playbook Edit Modal - single item (moved from index.html)
(function () {
    'use strict';

    let currentEditIndex = -1;
    let groupSitesData = [];

    function htmlToMarkdown(htmlString) {
        if (!htmlString || typeof htmlString !== 'string') return htmlString || '';
        if (typeof TurndownService === 'undefined') return htmlString;
        try {
            var td = new TurndownService();
            var div = document.createElement('div');
            div.innerHTML = htmlString;
            return td.turndown(div);
        } catch (e) {
            return htmlString;
        }
    }

    function openPlaybookEditModal(id, type) {
        if (!authState.is_admin) {
            showToast('Admin access required', 'error');
            return;
        }
        const modal = document.getElementById('playbookEditModal');
        const titleEl = document.getElementById('playbookEditTitle');
        const groupFields = document.getElementById('playbookEditGroupFields');
        const siteFields = document.getElementById('playbookEditSiteFields');
        const workflowFields = document.getElementById('playbookEditWorkflowFields');
        const form = document.getElementById('playbookEditForm');

        if (id == null || id === '') {
            currentEditIndex = -1;
            if (type === 'group') {
                titleEl.textContent = 'Add New Group';
                document.getElementById('playbookEditType').value = 'group';
                groupFields.classList.remove('hidden');
                siteFields.classList.add('hidden');
                if (workflowFields) workflowFields.classList.add('hidden');
                document.getElementById('playbookEditName').value = '';
                document.getElementById('playbookEditGroupId').value = 'new-group-' + Date.now();
                document.getElementById('playbookEditGroupTags').value = '';
                document.getElementById('playbookEditGroupSites').innerHTML = '';
                groupSitesData = [];
            } else if (type === 'workflow') {
                titleEl.textContent = 'Add New Workflow';
                document.getElementById('playbookEditType').value = 'workflow';
                groupFields.classList.add('hidden');
                siteFields.classList.add('hidden');
                if (workflowFields) workflowFields.classList.remove('hidden');
                document.getElementById('playbookEditWorkflowName').value = '';
                document.getElementById('playbookEditWorkflowId').value = 'new-workflow-' + Date.now();
                document.getElementById('playbookEditWorkflowContent').value = '';
                updatePlaybookWorkflowPreview();
            } else {
                titleEl.textContent = 'Add New Site';
                document.getElementById('playbookEditType').value = 'site';
                groupFields.classList.add('hidden');
                siteFields.classList.remove('hidden');
                if (workflowFields) workflowFields.classList.add('hidden');
                document.getElementById('playbookEditSiteName').value = '';
                document.getElementById('playbookEditSiteId').value = 'new-site-' + Date.now();
                document.getElementById('playbookEditUrl').value = '';
                document.getElementById('playbookEditTags').value = '';
                document.getElementById('playbookEditEssential').checked = false;
                document.getElementById('playbookEditDescription').value = '';
                document.getElementById('playbookEditExamples').value = '';
                document.getElementById('playbookEditTips').value = '';
            }
        } else {
            const idStr = String(id).trim();
            const index = playbookSites.findIndex(s => s.id === idStr);
            if (index === -1) {
                showToast('Item not found: ' + (idStr || '(empty)'), 'error');
                return;
            }
            if (!playbookCustomFromApi.some(c => c.id === idStr)) {
                showToast('Built-in items cannot be edited', 'error');
                return;
            }
            currentEditIndex = index;
            const item = playbookSites[index];

            if (item.type === 'group') {
                titleEl.textContent = 'Edit Group';
                document.getElementById('playbookEditType').value = 'group';
                groupFields.classList.remove('hidden');
                siteFields.classList.add('hidden');
                if (workflowFields) workflowFields.classList.add('hidden');
                document.getElementById('playbookEditName').value = item.name || '';
                document.getElementById('playbookEditGroupId').value = item.id || '';
                document.getElementById('playbookEditGroupTags').value = Array.isArray(item.tags) ? item.tags.join(', ') : '';
                groupSitesData = JSON.parse(JSON.stringify(item.sites || []));
                groupSitesData.forEach(function (site) {
                    var d = site.description || '';
                    if (d.trim().startsWith('<')) {
                        try { site.description = htmlToMarkdown(d); } catch (e) { /* keep original */ }
                    }
                });
                renderGroupSitesEdit();
            } else if (item.type === 'workflow') {
                titleEl.textContent = 'Edit Workflow';
                document.getElementById('playbookEditType').value = 'workflow';
                groupFields.classList.add('hidden');
                siteFields.classList.add('hidden');
                if (workflowFields) workflowFields.classList.remove('hidden');
                document.getElementById('playbookEditWorkflowName').value = item.name || '';
                document.getElementById('playbookEditWorkflowId').value = item.id || '';
                var rawContent = item.content ?? '';
                var contentForEdit = rawContent;
                if (rawContent.trim().startsWith('<')) {
                    try {
                        contentForEdit = htmlToMarkdown(rawContent);
                    } catch (e) {
                        contentForEdit = rawContent;
                    }
                }
                document.getElementById('playbookEditWorkflowContent').value = contentForEdit;
                updatePlaybookWorkflowPreview();
            } else {
                titleEl.textContent = 'Edit Site';
                document.getElementById('playbookEditType').value = 'site';
                groupFields.classList.add('hidden');
                siteFields.classList.remove('hidden');
                if (workflowFields) workflowFields.classList.add('hidden');
                document.getElementById('playbookEditSiteName').value = item.name || '';
                document.getElementById('playbookEditSiteId').value = item.id || '';
                document.getElementById('playbookEditUrl').value = item.url || '';
                document.getElementById('playbookEditTags').value = Array.isArray(item.tags) ? item.tags.join(', ') : '';
                document.getElementById('playbookEditEssential').checked = !!item.isEssential;
                var rawDesc = item.description ?? '';
                var descForEdit = rawDesc;
                if (rawDesc.trim().startsWith('<')) {
                    try { descForEdit = htmlToMarkdown(rawDesc); } catch (e) { descForEdit = rawDesc; }
                }
                document.getElementById('playbookEditDescription').value = descForEdit;
                var rawExamples = item.examples ?? '';
                var examplesForEdit = rawExamples;
                if (rawExamples.trim().startsWith('<')) {
                    try { examplesForEdit = htmlToMarkdown(rawExamples); } catch (e) { examplesForEdit = rawExamples; }
                }
                document.getElementById('playbookEditExamples').value = examplesForEdit;
                var rawTips = item.tips ?? '';
                var tipsForEdit = rawTips;
                if (rawTips.trim().startsWith('<')) {
                    try { tipsForEdit = htmlToMarkdown(rawTips); } catch (e) { tipsForEdit = rawTips; }
                }
                document.getElementById('playbookEditTips').value = tipsForEdit;
            }
        }
        _refreshPlaybookEditDirs();
        modal.classList.remove('hidden');
    }

    function _refreshPlaybookEditDirs() {
        if (typeof detectTextDir !== 'function') return;
        ['playbookEditName', 'playbookEditDescription', 'playbookEditExamples',
         'playbookEditTips', 'playbookEditWorkflowContent', 'playbookEditWorkflowName'
        ].forEach(function(id) {
            var el = document.getElementById(id);
            if (el) el.dir = detectTextDir(el.value);
        });
    }

    function closePlaybookEditModal() {
        document.getElementById('playbookEditModal').classList.add('hidden');
        currentEditIndex = -1;
        groupSitesData = [];
    }

    function updatePlaybookWorkflowPreview() {
        const ta = document.getElementById('playbookEditWorkflowContent');
        const preview = document.getElementById('playbookEditWorkflowPreview');
        if (!ta || !preview) return;
        const raw = ta.value || '';
        const looksLikeHtml = raw.trim().startsWith('<');
        if (raw.trim() === '') {
            preview.innerHTML = '<span class="text-secondary">Preview will appear here.</span>';
            return;
        }
        if (looksLikeHtml) {
            preview.innerHTML = raw;
            return;
        }
        if (typeof marked !== 'undefined') {
            try {
                preview.innerHTML = marked.parse(raw);
            } catch (e) {
                preview.textContent = raw;
            }
        } else {
            preview.textContent = raw;
        }
    }

    function renderGroupSitesEdit() {
        const container = document.getElementById('playbookEditGroupSites');
        container.innerHTML = groupSitesData.map((site, index) => `
            <div class="bg-black/20 rounded p-3 flex items-start justify-between gap-2" data-site-index="${index}">
                <div class="flex-1 space-y-2">
                    <input type="text" class="w-full bg-black/30 border border-white/10 rounded px-2 py-1 text-sm" value="${escapeHtml(site.name)}" placeholder="Site Name" data-field="name">
                    <input type="text" class="w-full bg-black/30 border border-white/10 rounded px-2 py-1 text-sm font-mono" value="${escapeHtml(site.url)}" placeholder="URL" data-field="url">
                    <textarea class="w-full bg-black/30 border border-white/10 rounded px-2 py-1 text-sm" rows="2" placeholder="Description" data-field="description">${escapeHtml(site.description || '')}</textarea>
                </div>
                <button type="button" data-action="remove-site" class="btn-cmd-danger text-xs">Remove</button>
            </div>
        `).join('');
    }

    function addGroupSiteToEdit() {
        groupSitesData.push({ name: '', url: '', description: '' });
        renderGroupSitesEdit();
    }

    function removeGroupSiteFromEdit(index) {
        appConfirm({ title: 'Remove Site', message: 'Remove this site from group?', okText: 'Remove' }).then(function(ok) {
            if (ok) {
                groupSitesData.splice(index, 1);
                renderGroupSitesEdit();
            }
        });
    }

    function savePlaybookItem() {
        const type = document.getElementById('playbookEditType').value;
        let item;

        if (type === 'group') {
            const name = document.getElementById('playbookEditName').value.trim();
            const id = document.getElementById('playbookEditGroupId').value.trim();
            const tagsStr = document.getElementById('playbookEditGroupTags').value.trim();
            const tags = tagsStr ? tagsStr.split(',').map(t => t.trim()).filter(Boolean) : [];
            if (!name || !id) {
                showToast('Name and ID are required', 'error');
                return;
            }
            item = {
                type: 'group',
                id: id,
                name: name,
                tags: tags,
                dir: (typeof detectTextDir === 'function') ? detectTextDir(name) : 'ltr',
                sites: groupSitesData.filter(s => s.name.trim() && s.url.trim())
            };
            if (currentEditIndex === -1) {
                playbookSites.unshift(item);
                playbookCustomFromApi = [item].concat(playbookCustomFromApi);
            } else {
                playbookSites[currentEditIndex] = item;
            }
        } else if (type === 'workflow') {
            const name = document.getElementById('playbookEditWorkflowName').value.trim();
            const id = document.getElementById('playbookEditWorkflowId').value.trim();
            const content = document.getElementById('playbookEditWorkflowContent').value;
            if (!name || !id) {
                showToast('Name and ID are required', 'error');
                return;
            }
            item = {
                type: 'workflow',
                id: id,
                name: name,
                dir: (typeof detectTextDir === 'function') ? detectTextDir(content || name) : 'ltr',
                content: content
            };
            if (currentEditIndex === -1) {
                playbookSites.unshift(item);
                playbookCustomFromApi = [item].concat(playbookCustomFromApi);
            } else {
                playbookSites[currentEditIndex] = item;
            }
        } else {
            const name = document.getElementById('playbookEditSiteName').value.trim();
            const id = document.getElementById('playbookEditSiteId').value.trim();
            const url = document.getElementById('playbookEditUrl').value.trim();
            if (!name || !id || !url) {
                showToast('Name, ID, and URL are required', 'error');
                return;
            }
            const tagsStr = document.getElementById('playbookEditTags').value.trim();
            const tags = tagsStr ? tagsStr.split(',').map(t => t.trim()).filter(Boolean) : [];
            const descVal = document.getElementById('playbookEditDescription').value;
            item = {
                id: id,
                name: name,
                url: url,
                isEssential: document.getElementById('playbookEditEssential').checked,
                tags: tags,
                dir: (typeof detectTextDir === 'function') ? detectTextDir(descVal || name) : 'ltr',
                description: descVal,
                examples: document.getElementById('playbookEditExamples').value,
                tips: document.getElementById('playbookEditTips').value
            };
            if (currentEditIndex === -1) {
                playbookSites.unshift(item);
                playbookCustomFromApi = [item].concat(playbookCustomFromApi);
            } else {
                playbookSites[currentEditIndex] = item;
            }
        }

        var isCustom = currentEditIndex === -1 || playbookCustomFromApi.some(c => c.id === item.id);
        if (isCustom) {
            fetch('/api/playbook', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ item: item })
            })
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (data.success && Array.isArray(data.custom)) {
                        playbookCustomFromApi = data.custom;
                        playbookSites = playbookCustomFromApi.concat(playbookSitesBuiltIn);
                        renderPlaybookTagFilters();
                        renderPlaybookTabs();
                    }
                    closePlaybookEditModal();
                    showToast('Saved successfully', 'success');
                })
                .catch(function() {
                    closePlaybookEditModal();
                    showToast('Failed to save to server', 'error');
                });
        } else {
            renderPlaybookTagFilters();
            renderPlaybookTabs();
            closePlaybookEditModal();
            showToast('Saved (built-in; changes not persisted)', 'success');
        }
    }

    var pendingDeletePlaybookId = null;

    function showPlaybookDeleteConfirm(id) {
        pendingDeletePlaybookId = id;
        var modal = document.getElementById('playbookDeleteConfirmModal');
        if (modal) modal.classList.remove('hidden');
    }

    function hidePlaybookDeleteConfirm() {
        pendingDeletePlaybookId = null;
        var modal = document.getElementById('playbookDeleteConfirmModal');
        if (modal) modal.classList.add('hidden');
    }

    function doDeletePlaybookItem(id) {
        if (!id) return;
        fetch('/api/playbook/' + encodeURIComponent(id), { method: 'DELETE' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.success && Array.isArray(data.custom)) {
                    playbookCustomFromApi = data.custom;
                    playbookSites = playbookCustomFromApi.concat(playbookSitesBuiltIn);
                    renderPlaybookTagFilters();
                    renderPlaybookTabs();
                    showToast('Deleted successfully', 'success');
                } else {
                    showToast(data.message || 'Delete failed', 'error');
                }
            })
            .catch(function() {
                showToast('Failed to delete on server', 'error');
            });
    }

    function deletePlaybookItem(id) {
        if (!authState.is_admin) {
            showToast('Admin access required', 'error');
            return;
        }
        if (!playbookCustomFromApi.some(function(c) { return c.id === id; })) {
            showToast('Built-in items cannot be deleted', 'error');
            return;
        }
        showPlaybookDeleteConfirm(id);
    }

    function initPlaybookDeleteModal() {
        var modal = document.getElementById('playbookDeleteConfirmModal');
        var cancelBtn = document.getElementById('playbookDeleteConfirmCancel');
        var yesBtn = document.getElementById('playbookDeleteConfirmYes');
        if (modal) {
            modal.addEventListener('click', function(e) {
                if (e.target === modal) hidePlaybookDeleteConfirm();
            });
        }
        if (cancelBtn) cancelBtn.addEventListener('click', hidePlaybookDeleteConfirm);
        if (yesBtn) {
            yesBtn.addEventListener('click', function() {
                var id = pendingDeletePlaybookId;
                hidePlaybookDeleteConfirm();
                doDeletePlaybookItem(id);
            });
        }
    }

    function initGroupSitesDelegation() {
        var container = document.getElementById('playbookEditGroupSites');
        if (!container) return;
        container.addEventListener('input', function(e) {
            var field = e.target.dataset.field;
            if (!field) return;
            var row = e.target.closest('[data-site-index]');
            if (!row) return;
            var idx = parseInt(row.dataset.siteIndex, 10);
            if (groupSitesData[idx]) groupSitesData[idx][field] = e.target.value;
        });
        container.addEventListener('click', function(e) {
            if (e.target.dataset.action !== 'remove-site') return;
            var row = e.target.closest('[data-site-index]');
            if (!row) return;
            var idx = parseInt(row.dataset.siteIndex, 10);
            removeGroupSiteFromEdit(idx);
        });
    }

    function _initAll() {
        initPlaybookDeleteModal();
        initGroupSitesDelegation();
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _initAll);
    } else {
        _initAll();
    }

    function _rebuildPlaybookSites() {
        playbookSites = playbookCustomFromApi.concat(playbookSitesBuiltIn);
    }

    function movePlaybookItemUp(id) {
        if (!authState.is_admin) return;
        var ci = playbookCustomFromApi.findIndex(function(c) { return c.id === id; });
        if (ci <= 0) return;
        var temp = playbookCustomFromApi[ci];
        playbookCustomFromApi[ci] = playbookCustomFromApi[ci - 1];
        playbookCustomFromApi[ci - 1] = temp;
        _rebuildPlaybookSites();
        persistPlaybookOrderIfCustom();
        renderPlaybookTagFilters();
        renderPlaybookTabs();
    }

    function movePlaybookItemDown(id) {
        if (!authState.is_admin) return;
        var ci = playbookCustomFromApi.findIndex(function(c) { return c.id === id; });
        if (ci === -1 || ci >= playbookCustomFromApi.length - 1) return;
        var temp = playbookCustomFromApi[ci];
        playbookCustomFromApi[ci] = playbookCustomFromApi[ci + 1];
        playbookCustomFromApi[ci + 1] = temp;
        _rebuildPlaybookSites();
        persistPlaybookOrderIfCustom();
        renderPlaybookTagFilters();
        renderPlaybookTabs();
    }

    function persistPlaybookOrderIfCustom() {
        var customIds = playbookCustomFromApi.map(function(c) { return c.id; });
        if (customIds.length === 0) return;
        fetch('/api/playbook/reorder', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ ids: customIds })
        })
            .then(function(r) {
                if (!r.ok) {
                    throw new Error(r.status === 401 ? 'Login required' : 'Save failed');
                }
                return r.json();
            })
            .then(function(data) {
                if (data.success && Array.isArray(data.custom)) {
                    playbookCustomFromApi = data.custom;
                    // Do not overwrite playbookSites with the response: we already reordered it locally.
                } else {
                    throw new Error(data.message || 'Save failed');
                }
            })
            .catch(function(err) {
                if (typeof showToast === 'function') {
                    showToast(err && err.message ? err.message : 'Order could not be saved', 'error');
                }
            });
    }

    document.addEventListener('DOMContentLoaded', function() {
        if (typeof applyAutoDir === 'function') {
            ['playbookEditName', 'playbookEditDescription', 'playbookEditExamples',
             'playbookEditTips', 'playbookEditWorkflowContent', 'playbookEditWorkflowName'
            ].forEach(function(id) { applyAutoDir(document.getElementById(id)); });
        }
    });

    window.openPlaybookEditModal = openPlaybookEditModal;
    window.closePlaybookEditModal = closePlaybookEditModal;
    window.savePlaybookItem = savePlaybookItem;
    window.deletePlaybookItem = deletePlaybookItem;
    window.movePlaybookItemUp = movePlaybookItemUp;
    window.movePlaybookItemDown = movePlaybookItemDown;
    window.addGroupSiteToEdit = addGroupSiteToEdit;
    window.updatePlaybookWorkflowPreview = updatePlaybookWorkflowPreview;
})();
