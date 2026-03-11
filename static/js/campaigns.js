/**
 * Campaign Graph tab logic (Step 10.4 - extracted from index.html).
 * Depends on globals: escapeHtml, escapeAttr, showToast, t, vis (vis-network).
 * Exposes: populateCampaignDropdowns, loadUsersForAssignDropdown, loadCampaigns, renderGraph.
 */
(function(global) {
    'use strict';

    let campaignNetwork = null;
    let currentCampaignId = null;

    async function populateCampaignDropdowns() {
        try {
            const res = await fetch('/api/campaigns');
            const data = await res.json().catch(() => ({}));
            const campaigns = (data.success && data.campaigns) ? data.campaigns : [];
            const noneOption = '<option value="">- None -</option>';
            const noneUnassignedOption = '<option value="">None / Unassigned</option>';
            const selectOption = '<option value="">-- Select campaign --</option>';
            const formSelectIds = ['iocCampaignSelect', 'csvCampaignSelect', 'txtCampaignSelect', 'pasteCampaignSelect', 'yaraCampaignSelect', 'editCampaignSelect'];
            formSelectIds.forEach(id => {
                const sel = document.getElementById(id);
                if (!sel) return;
                sel.innerHTML = (id === 'editCampaignSelect') ? noneUnassignedOption : noneOption;
                campaigns.forEach(c => {
                    const opt = document.createElement('option');
                    opt.value = c.name || 'Unnamed';
                    opt.textContent = c.name || 'Unnamed';
                    sel.appendChild(opt);
                });
            });
            const linkSelect = document.getElementById('linkCampaignSelect');
            if (linkSelect) {
                linkSelect.innerHTML = selectOption;
                campaigns.forEach(c => {
                    const opt = document.createElement('option');
                    opt.value = c.id;
                    opt.textContent = c.name || 'Unnamed';
                    linkSelect.appendChild(opt);
                });
            }
        } catch (err) {
            console.warn('populateCampaignDropdowns:', err);
        }
    }

    async function loadUsersForAssignDropdown() {
        const authState = global.authState || {};
        if (!authState.authenticated) return;
        try {
            const res = await fetch('/api/users');
            const data = await res.json().catch(() => ({}));
            const users = (data.success && data.users) ? data.users : [];
            const meOption = '<option value="">' + (typeof t === 'function' && t('submit.me') ? t('submit.me') : '- Me -') + '</option>';
            ['iocAssignTo', 'editAssignTo'].forEach(id => {
                const sel = document.getElementById(id);
                if (!sel) return;
                sel.innerHTML = meOption;
                users.forEach(u => {
                    const opt = document.createElement('option');
                    opt.value = u.username || '';
                    opt.textContent = u.username || ('#' + (u.id || ''));
                    sel.appendChild(opt);
                });
            });
        } catch (err) {
            console.warn('loadUsersForAssignDropdown:', err);
        }
    }

    async function loadCampaigns() {
        const listEl = document.getElementById('campaignList');
        if (!listEl) return;
        try {
            const res = await fetch('/api/campaigns');
            const data = await res.json().catch(() => ({}));
            if (!data.success || !data.campaigns) {
                listEl.innerHTML = `<li class="text-secondary">${t('campaign.loading')}</li>`;
                return;
            }
            const campaigns = data.campaigns;
            listEl.innerHTML = campaigns.map(c => {
                const safeName = escapeHtml(c.name || 'Unnamed');
                const attrName = (c.name || '').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                const attrDesc = (c.description || '').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r?\n/g, ' ');
                const attrDir = (c.dir || 'ltr').replace(/"/g, '&quot;');
                const titleAttr = c.description ? ` title="${attrDesc}"` : '';
                return `
                <li class="py-2 px-2 rounded campaign-list-item border border-transparent transition"
                    data-campaign-id="${c.id}">
                    <div class="flex items-start justify-between gap-2">
                        <div class="flex-1 min-w-0 cursor-pointer campaign-select-area" data-cid="${c.id}">
                            <span class="font-medium block truncate" dir="${attrDir}"${titleAttr}>${safeName}</span>
                        </div>
                        <div class="flex items-center gap-1.5 flex-shrink-0">
                            <button type="button" class="btn-cmd-primary btn-cmd-sm campaign-edit-btn"
                                data-cid="${c.id}" data-cname="${attrName}" data-cdesc="${attrDesc}" data-cdir="${attrDir}">${t('actions.edit')}</button>
                            <button type="button" class="btn-cmd-danger btn-cmd-sm campaign-delete-btn"
                                data-cid="${c.id}" data-cname="${attrName}">${t('actions.delete')}</button>
                        </div>
                    </div>
                </li>`;
            }).join('');
            listEl.querySelectorAll('.campaign-select-area').forEach(el => {
                el.addEventListener('click', () => renderGraph(parseInt(el.getAttribute('data-cid'), 10)));
            });
            listEl.querySelectorAll('.campaign-edit-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    openCampaignEditModal(
                        btn.getAttribute('data-cid'),
                        btn.getAttribute('data-cname'),
                        btn.getAttribute('data-cdesc'),
                        btn.getAttribute('data-cdir')
                    );
                });
            });
            listEl.querySelectorAll('.campaign-delete-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    openCampaignDeleteModal(btn.getAttribute('data-cid'), btn.getAttribute('data-cname'));
                });
            });
            await populateCampaignDropdowns();
        } catch (err) {
            listEl.innerHTML = '<li class="text-secondary">Error loading campaigns</li>';
        }
    }

    function openCampaignEditModal(id, name, desc, dir) {
        document.getElementById('campaignEditId').value = id;
        document.getElementById('campaignEditName').value = name || '';
        document.getElementById('campaignEditDesc').value = desc || '';
        const dirSel = document.getElementById('campaignEditDir');
        const d = dir || 'ltr';
        if (dirSel) dirSel.value = d;
        const nameInp = document.getElementById('campaignEditName');
        const descInp = document.getElementById('campaignEditDesc');
        if (nameInp) nameInp.setAttribute('dir', d);
        if (descInp) descInp.setAttribute('dir', d);
        document.getElementById('campaignEditModal').classList.remove('hidden');
    }

    function applyCampaignFormDir(formPrefix, dir) {
        const d = dir || 'ltr';
        const nameInp = document.getElementById(formPrefix === 'create' ? 'campaignName' : 'campaignEditName');
        const descInp = document.getElementById(formPrefix === 'create' ? 'campaignDesc' : 'campaignEditDesc');
        if (nameInp) nameInp.setAttribute('dir', d);
        if (descInp) descInp.setAttribute('dir', d);
    }

    function closeCampaignEditModal() {
        document.getElementById('campaignEditModal').classList.add('hidden');
    }

    function openCampaignDeleteModal(cid, cname) {
        const modal = document.getElementById('campaignDeleteConfirmModal');
        const msgEl = document.getElementById('campaignDeleteConfirmMessage');
        if (!modal || !msgEl) return;
        const msg = (typeof t === 'function' && t('campaign.delete_confirm_message'))
            ? t('campaign.delete_confirm_message')
            : 'Linked IOCs will be unlinked (not deleted).';
        msgEl.textContent = (cname ? `"${cname}" - ` : '') + msg;
        modal.dataset.pendingCid = cid || '';
        modal.classList.remove('hidden');
    }

    function closeCampaignDeleteModal() {
        const modal = document.getElementById('campaignDeleteConfirmModal');
        if (modal) {
            modal.classList.add('hidden');
            delete modal.dataset.pendingCid;
        }
    }

    async function doDeleteCampaign(cid) {
        try {
            const r = await fetch(`/api/campaigns/${cid}`, { method: 'DELETE' });
            const d = await r.json().catch(() => ({}));
            showToast(d.message || (d.success ? 'Deleted' : 'Failed'), d.success ? 'success' : 'error');
            if (d.success) {
                loadCampaigns();
                if (currentCampaignId === parseInt(cid, 10)) {
                    currentCampaignId = null;
                    const container = document.getElementById('campaign-network');
                    if (container) container.innerHTML = '';
                }
            }
        } catch (err) {
            showToast(t('toast.error_generic') + ': ' + err.message, 'error');
        }
    }

    document.getElementById('campaignEditCancel')?.addEventListener('click', closeCampaignEditModal);
    document.getElementById('campaignDeleteConfirmCancel')?.addEventListener('click', closeCampaignDeleteModal);
    document.getElementById('campaignDeleteConfirmModal')?.addEventListener('click', function(e) {
        if (e.target === e.currentTarget) closeCampaignDeleteModal();
    });
    document.getElementById('campaignDeleteConfirmYes')?.addEventListener('click', function() {
        const modal = document.getElementById('campaignDeleteConfirmModal');
        const cid = modal?.dataset.pendingCid;
        closeCampaignDeleteModal();
        if (cid) doDeleteCampaign(cid);
    });
    document.getElementById('campaignEditDir')?.addEventListener('change', function() {
        applyCampaignFormDir('edit', this.value);
    });
    document.getElementById('campaignEditModal')?.addEventListener('click', (e) => {
        if (e.target === e.currentTarget) closeCampaignEditModal();
    });
    document.getElementById('campaignEditForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = document.getElementById('campaignEditId').value;
        const name = document.getElementById('campaignEditName').value.trim();
        const description = document.getElementById('campaignEditDesc').value.trim();
        const dirSel = document.getElementById('campaignEditDir');
        const dir = dirSel ? dirSel.value : 'ltr';
        if (!name) { showToast(t('toast.campaign_name_required'), 'error'); return; }
        try {
            const r = await fetch(`/api/campaigns/${id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, description, dir: dir || 'ltr' })
            });
            const d = await r.json().catch(() => ({}));
            showToast(d.message || (d.success ? 'Updated' : 'Failed'), d.success ? 'success' : 'error');
            if (d.success) {
                closeCampaignEditModal();
                loadCampaigns();
                renderGraph(parseInt(id, 10));
            }
        } catch (err) { showToast(t('toast.error_generic') + ': ' + err.message, 'error'); }
    });

    function renderGraph(campaignId) {
        const container = document.getElementById('campaign-network');
        if (!container || typeof vis === 'undefined') return;
        if (campaignNetwork) { campaignNetwork.destroy(); campaignNetwork = null; }
        container.innerHTML = '';
        currentCampaignId = campaignId;
        const exportBtn = document.getElementById('exportCampaignBtn');
        const exportJsonBtn = document.getElementById('exportCampaignJsonBtn');
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const options = {
            layout: { randomSeed: 1 },
            physics: { enabled: false },
            nodes: {
                font: { color: isDark ? '#e2e8f0' : '#1e293b', size: 14, face: 'Consolas, monospace' },
                borderWidth: 2,
                shadow: { enabled: true, color: isDark ? 'rgba(0,0,0,0.5)' : 'rgba(0,0,0,0.15)', size: 8, x: 2, y: 3 }
            },
            edges: {
                smooth: { type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.5 },
                arrows: { to: { enabled: true, scaleFactor: 0.5, type: 'arrow' } },
                width: 2,
                color: { color: isDark ? 'rgba(255, 255, 255, 0.2)' : 'rgba(0, 0, 0, 0.25)', highlight: '#00d4ff' }
            },
            interaction: { hover: true, tooltipDelay: 100, zoomView: true, dragNodes: true, dragView: true }
        };
        fetch(`/api/campaign-graph/${campaignId}`)
            .then(r => r.json())
            .then(data => {
                if (!data.success || !data.nodes || data.nodes.length === 0) {
                    container.innerHTML = '<div class="flex items-center justify-center h-full text-secondary">No data for this campaign</div>';
                    if (exportBtn) exportBtn.classList.add('hidden');
                    if (exportJsonBtn) exportJsonBtn.classList.add('hidden');
                    return;
                }
                const labelColor = isDark ? '#e2e8f0' : '#1e293b';
                const campaignLabelColor = isDark ? '#ffffff' : '#0f172a';
                data.nodes.forEach(n => {
                    if (n.font) {
                        if (String(n.id).startsWith('camp_')) {
                            n.font.color = campaignLabelColor;
                            if (n.font.bold && typeof n.font.bold === 'object') {
                                n.font.bold.color = campaignLabelColor;
                            }
                        } else if (!String(n.id).startsWith('header_')) {
                            n.font.color = labelColor;
                        }
                    }
                });
                const nodes = new vis.DataSet(data.nodes);
                const edges = new vis.DataSet(data.edges || []);
                const netData = { nodes, edges };
                campaignNetwork = new vis.Network(container, netData, options);
                if (exportBtn) exportBtn.classList.remove('hidden');
                if (exportJsonBtn) exportJsonBtn.classList.remove('hidden');
                setTimeout(() => campaignNetwork.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } }), 150);
            })
            .catch(() => {
                container.innerHTML = '<div class="flex items-center justify-center h-full text-secondary">Failed to load graph</div>';
                if (exportBtn) exportBtn.classList.add('hidden');
                if (exportJsonBtn) exportJsonBtn.classList.add('hidden');
            });
    }

    document.getElementById('exportCampaignBtn')?.addEventListener('click', () => {
        if (!currentCampaignId) { showToast(t('toast.select_campaign_first'), 'error'); return; }
        window.location.href = `/api/campaigns/${currentCampaignId}/export`;
    });
    document.getElementById('exportCampaignJsonBtn')?.addEventListener('click', () => {
        if (!currentCampaignId) { showToast(t('toast.select_campaign_first'), 'error'); return; }
        window.location.href = `/api/campaigns/${currentCampaignId}/export-json`;
    });

    document.getElementById('campaignCreateDir')?.addEventListener('change', function() {
        applyCampaignFormDir('create', this.value);
    });
    document.getElementById('campaignCreateForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn && submitBtn.disabled) return;  // prevent double submit
        const name = document.getElementById('campaignName').value.trim();
        const description = document.getElementById('campaignDesc').value.trim();
        const dirSel = document.getElementById('campaignCreateDir');
        const dir = dirSel ? dirSel.value : 'ltr';
        if (submitBtn) submitBtn.disabled = true;
        try {
            const res = await fetch('/api/campaigns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, description: description || undefined, dir: dir || 'ltr' })
            });
            const data = await res.json().catch(() => ({}));
            if (data.success) {
                showToast(data.message || 'Campaign created', 'success');
                if (typeof showAchievementModal === 'function' && (data.new_badges || data.level_up || data.rank_up || data.points_earned !== undefined || data.level_info || data.new_nickname)) {
                    showAchievementModal(data);
                }
                document.getElementById('campaignName').value = '';
                document.getElementById('campaignDesc').value = '';
                if (dirSel) dirSel.value = 'ltr';
                loadCampaigns();
            } else {
                showToast(data.message || 'Failed', 'error');
            }
        } catch (err) {
            showToast(t('toast.error_generic') + ': ' + err.message, 'error');
        } finally {
            if (submitBtn) submitBtn.disabled = false;
        }
    });

    document.getElementById('campaignLinkForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const ioc_value = document.getElementById('linkIocValue').value.trim();
        const campaign_id = parseInt(document.getElementById('linkCampaignSelect').value, 10);
        if (!campaign_id) {
            showToast(t('toast.select_campaign'), 'error');
            return;
        }
        try {
            const res = await fetch('/api/campaigns/link', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ioc_value, campaign_id })
            });
            const data = await res.json().catch(() => ({}));
            if (data.success) {
                showToast(data.message || 'IOC linked', 'success');
                if (typeof showAchievementModal === 'function' && (data.new_badges || data.level_up || data.rank_up || data.points_earned !== undefined || data.level_info || data.new_nickname)) {
                    showAchievementModal(data);
                }
                document.getElementById('linkIocValue').value = '';
                const cid = document.getElementById('linkCampaignSelect').value;
                if (cid && campaignNetwork) renderGraph(parseInt(cid, 10));
            } else {
                showToast(data.message || 'Failed', 'error');
            }
        } catch (err) {
            showToast(t('toast.error_generic') + ': ' + err.message, 'error');
        }
    });

    global.populateCampaignDropdowns = populateCampaignDropdowns;
    global.loadUsersForAssignDropdown = loadUsersForAssignDropdown;
    global.loadCampaigns = loadCampaigns;
    global.renderGraph = renderGraph;
})(typeof window !== 'undefined' ? window : this);
