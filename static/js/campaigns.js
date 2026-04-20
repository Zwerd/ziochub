/**
 * Campaign Graph tab logic (Step 10.4 - extracted from index.html).
 * Depends on globals: escapeHtml, escapeAttr, showToast, t, vis (vis-network), copyToClipboard.
 * Exposes: populateCampaignDropdowns, loadUsersForAssignDropdown, loadCampaigns, renderGraph.
 */
(function(global) {
    'use strict';

    let campaignNetwork = null;
    let currentCampaignId = null;
    /** Timer for applying dir to vis-network tooltip after it mounts */
    let campaignGraphTooltipDirTimer = null;

    /**
     * RTL if Hebrew letters are strictly more than Latin letters; ties use first-strong (detectTextDir).
     */
    function tooltipDirFromMajorityHebrew(text) {
        if (!text || typeof text !== 'string') return 'ltr';
        let he = 0;
        let lat = 0;
        for (let i = 0; i < text.length; i++) {
            const cp = text.codePointAt(i);
            if (cp >= 0x0590 && cp <= 0x05FF) he++;
            else if ((cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A)) lat++;
            if (cp > 0xFFFF) i++;
        }
        if (he > lat) return 'rtl';
        if (lat > he) return 'ltr';
        return typeof detectTextDir === 'function' ? detectTextDir(text) : 'ltr';
    }

    /** vis-network renders tooltips in a floating div; remove so it does not cover the image modal */
    function hideCampaignGraphTooltip() {
        document.querySelectorAll('div.vis-tooltip, div.vis-network-tooltip').forEach(function(el) {
            el.remove();
        });
    }

    async function populateCampaignDropdowns() {
        try {
            const res = await fetch('/api/campaigns');
            const data = await res.json().catch(() => ({}));
            const campaigns = (data.success && data.campaigns) ? data.campaigns : [];
            const noneOption = '<option value="">- None -</option>';
            const noneUnassignedOption = '<option value="">None / Unassigned</option>';
            const selectOption = '<option value="">-- Select campaign --</option>';
            const formSelectIds = ['iocCampaignSelect', 'csvCampaignSelect', 'txtCampaignSelect', 'pasteCampaignSelect', 'yaraCampaignSelect', 'yaraWriteCampaignSelect', 'editCampaignSelect'];
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
            ['iocAssignTo', 'editAssignTo', 'txtAssignTo', 'csvAssignTo', 'pasteAssignTo'].forEach(id => {
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
            if (typeof window.invalidateStagingAnalystCache === 'function') window.invalidateStagingAnalystCache();
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
            const emptyDescLabelEsc = escapeHtml((typeof t === 'function') ? t('campaign.no_description') : '—');
            listEl.innerHTML = campaigns.map(c => {
                const rawName = c.name || 'Unnamed';
                const rawDesc = (c.description != null && String(c.description).trim() !== '') ? String(c.description) : '';
                const safeName = escapeHtml(rawName);
                const safeDesc = rawDesc ? escapeHtml(rawDesc) : '';
                const attrName = (c.name || '').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                const attrDesc = (c.description || '').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r?\n/g, ' ');
                const attrDir = (c.dir || 'ltr').replace(/"/g, '&quot;');
                const nameDir = typeof detectTextDir === 'function' ? detectTextDir(rawName) : (c.dir || 'ltr');
                const descDir = rawDesc ? tooltipDirFromMajorityHebrew(rawDesc) : (c.dir || 'ltr');
                const hasRef = !!c.has_reference_image;
                const descBlock = rawDesc
                    ? `<p class="campaign-list-desc mt-2 text-xs leading-relaxed text-secondary whitespace-pre-wrap break-words cursor-pointer campaign-select-area" data-cid="${c.id}" dir="${descDir}">${safeDesc}</p>`
                    : `<p class="campaign-list-desc mt-2 text-xs leading-relaxed whitespace-pre-wrap break-words cursor-pointer campaign-select-area text-secondary/80" data-cid="${c.id}" dir="auto"><span class="italic">${emptyDescLabelEsc}</span></p>`;
                return `
                <li class="campaign-list-item rounded-xl border border-white/10 bg-black/20 hover:bg-black/30 py-3 px-3 shadow-sm transition-colors"
                    data-campaign-id="${c.id}">
                    <div class="flex items-start justify-between gap-3">
                        <div class="flex-1 min-w-0 cursor-pointer campaign-select-area font-semibold text-[15px] leading-snug text-primary break-words"
                            data-cid="${c.id}" dir="${nameDir}">${safeName}</div>
                        <div class="flex items-center gap-1.5 flex-shrink-0 pt-0.5">
                            <button type="button" class="btn-cmd-primary btn-cmd-sm campaign-edit-btn"
                                data-cid="${c.id}" data-cname="${attrName}" data-cdesc="${attrDesc}" data-cdir="${attrDir}" data-has-ref="${hasRef ? '1' : ''}">${t('actions.edit')}</button>
                            <button type="button" class="btn-cmd-danger btn-cmd-sm campaign-delete-btn"
                                data-cid="${c.id}" data-cname="${attrName}">${t('actions.delete')}</button>
                        </div>
                    </div>
                    ${descBlock}
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
                        btn.getAttribute('data-cdir'),
                        btn.getAttribute('data-has-ref') === '1'
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

    function openCampaignEditModal(id, name, desc, dir, hasReferenceImage) {
        document.getElementById('campaignEditId').value = id;
        const nameInp = document.getElementById('campaignEditName');
        const descInp = document.getElementById('campaignEditDesc');
        nameInp.value = name || '';
        descInp.value = desc || '';
        if (typeof detectTextDir === 'function') {
            nameInp.dir = detectTextDir(name || '');
            descInp.dir = detectTextDir(desc || '');
        }
        const refFile = document.getElementById('campaignEditRefFile');
        const removeCb = document.getElementById('campaignEditRemoveRef');
        const removeWrap = document.getElementById('campaignEditRemoveRefWrap');
        if (refFile) refFile.value = '';
        if (removeCb) removeCb.checked = false;
        if (removeWrap) removeWrap.classList.toggle('hidden', !hasReferenceImage);
        document.getElementById('campaignEditModal').classList.remove('hidden');
    }

    function closeCampaignEditModal() {
        document.getElementById('campaignEditModal').classList.add('hidden');
        const refFile = document.getElementById('campaignEditRefFile');
        const removeCb = document.getElementById('campaignEditRemoveRef');
        if (refFile) refFile.value = '';
        if (removeCb) removeCb.checked = false;
    }

    function openCampaignReferenceModal(campaignId) {
        hideCampaignGraphTooltip();
        const modal = document.getElementById('campaignReferenceImageModal');
        const img = document.getElementById('campaignReferenceImageModalImg');
        if (!modal || !img) return;
        img.removeAttribute('src');
        img.alt = t('campaign.ref_image_modal_title') || 'Reference image';
        img.onerror = function() {
            showToast(t('toast.error_generic') || 'Error', 'error');
            closeCampaignReferenceModal();
        };
        img.src = `/api/campaigns/${campaignId}/reference-image?t=${Date.now()}`;
        modal.classList.remove('hidden');
    }

    function closeCampaignReferenceModal() {
        const modal = document.getElementById('campaignReferenceImageModal');
        const img = document.getElementById('campaignReferenceImageModalImg');
        if (modal) modal.classList.add('hidden');
        if (img) {
            img.removeAttribute('src');
            img.onerror = null;
            img.onload = null;
        }
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
    document.getElementById('campaignEditModal')?.addEventListener('click', (e) => {
        if (e.target === e.currentTarget) closeCampaignEditModal();
    });
    document.getElementById('campaignReferenceImageModalClose')?.addEventListener('click', closeCampaignReferenceModal);
    document.getElementById('campaignReferenceImageModal')?.addEventListener('click', (e) => {
        if (e.target === e.currentTarget) closeCampaignReferenceModal();
    });
    document.getElementById('campaignEditRefFile')?.addEventListener('change', function() {
        const removeCb = document.getElementById('campaignEditRemoveRef');
        if (removeCb && this.files && this.files[0]) removeCb.checked = false;
    });
    document.getElementById('campaignEditForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = document.getElementById('campaignEditId').value;
        const name = document.getElementById('campaignEditName').value.trim();
        const description = document.getElementById('campaignEditDesc').value.trim();
        const dir = (typeof detectTextDir === 'function') ? detectTextDir(description || name) : 'ltr';
        if (!name) { showToast(t('toast.campaign_name_required'), 'error'); return; }
        const refFile = document.getElementById('campaignEditRefFile');
        const removeCb = document.getElementById('campaignEditRemoveRef');
        try {
            const r = await fetch(`/api/campaigns/${id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, description, dir })
            });
            const d = await r.json().catch(() => ({}));
            if (!d.success) {
                showToast(d.message || 'Failed', 'error');
                return;
            }
            const newFile = refFile && refFile.files && refFile.files[0];
            if (newFile) {
                const fd = new FormData();
                fd.append('file', newFile);
                const ur = await fetch(`/api/campaigns/${id}/reference-image`, { method: 'POST', body: fd });
                const ud = await ur.json().catch(() => ({}));
                if (!ud.success) {
                    showToast(ud.message || t('toast.error_generic'), 'error');
                    return;
                }
            } else if (removeCb && removeCb.checked) {
                const dr = await fetch(`/api/campaigns/${id}/reference-image`, { method: 'DELETE' });
                const dd = await dr.json().catch(() => ({}));
                if (!dd.success) {
                    showToast(dd.message || t('toast.error_generic'), 'error');
                    return;
                }
            }
            showToast(d.message || 'Updated', 'success');
            closeCampaignEditModal();
            loadCampaigns();
            renderGraph(parseInt(id, 10));
        } catch (err) { showToast(t('toast.error_generic') + ': ' + err.message, 'error'); }
    });

    function setCampaignGraphActivityBanner(data) {
        const el = document.getElementById('campaignGraphActivityBanner');
        if (!el) return;
        const act = data && data.activity;
        if (!act || act.has_active_iocs) {
            el.textContent = '';
            el.classList.add('hidden');
            return;
        }
        const tFn = typeof t === 'function' ? t : function(k) { return k; };
        const linked = act.linked_ioc_count != null ? act.linked_ioc_count : 0;
        const active = act.active_ioc_count != null ? act.active_ioc_count : 0;
        const expired = act.expired_ioc_count != null ? act.expired_ioc_count : 0;
        const yara = act.yara_count != null ? act.yara_count : 0;
        let msg;
        if (linked === 0 && yara === 0) {
            msg = tFn('campaign.graph_banner_inactive_empty');
        } else if (linked === 0 && yara > 0) {
            msg = (tFn('campaign.graph_banner_inactive_yara_only') || '').replace(/\{yara\}/g, String(yara));
        } else {
            msg = (tFn('campaign.graph_banner_inactive') || '')
                .replace(/\{linked\}/g, String(linked))
                .replace(/\{active\}/g, String(active))
                .replace(/\{expired\}/g, String(expired))
                .replace(/\{yara\}/g, String(yara));
        }
        el.textContent = msg;
        el.classList.remove('hidden');
    }

    function renderGraph(campaignId) {
        const container = document.getElementById('campaign-network');
        if (!container || typeof vis === 'undefined') return;
        setCampaignGraphActivityBanner({ activity: { has_active_iocs: true } });
        if (campaignGraphTooltipDirTimer) {
            clearTimeout(campaignGraphTooltipDirTimer);
            campaignGraphTooltipDirTimer = null;
        }
        hideCampaignGraphTooltip();
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
                    setCampaignGraphActivityBanner({ activity: { has_active_iocs: true } });
                    container.innerHTML = '<div class="flex items-center justify-center h-full text-secondary">No data for this campaign</div>';
                    if (exportBtn) exportBtn.classList.add('hidden');
                    if (exportJsonBtn) exportJsonBtn.classList.add('hidden');
                    return;
                }
                setCampaignGraphActivityBanner(data);
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
                campaignNetwork.on('hoverNode', function(params) {
                    const node = nodes.get(params.node);
                    if (!node || node.title == null || node.title === '') return;
                    const dir = tooltipDirFromMajorityHebrew(String(node.title));
                    if (campaignGraphTooltipDirTimer) clearTimeout(campaignGraphTooltipDirTimer);
                    campaignGraphTooltipDirTimer = setTimeout(function() {
                        campaignGraphTooltipDirTimer = null;
                        document.querySelectorAll('div.vis-tooltip, div.vis-network-tooltip').forEach(function(tip) {
                            tip.setAttribute('dir', dir);
                        });
                    }, 130);
                });
                campaignNetwork.on('blurNode', function() {
                    if (campaignGraphTooltipDirTimer) {
                        clearTimeout(campaignGraphTooltipDirTimer);
                        campaignGraphTooltipDirTimer = null;
                    }
                });
                campaignNetwork.on('click', function(params) {
                    if (!params.nodes || params.nodes.length === 0) return;
                    const nid = params.nodes[0];
                    const sid = String(nid);
                    const node = nodes.get(nid);
                    if (!node) return;
                    if (sid.startsWith('ioc_') || sid.startsWith('yara_')) {
                        let text = node.copyValue;
                        if (text == null || text === '') {
                            const title = node.title != null ? String(node.title) : '';
                            const m = title.match(/^[^:]+:\s*(.+)$/);
                            if (m) text = m[1].split('\n')[0].trim();
                        }
                        if (text && typeof global.copyToClipboard === 'function') {
                            global.copyToClipboard(String(text));
                        }
                        return;
                    }
                    if (sid.indexOf('camp_') !== 0) return;
                    if (!node.has_reference_image) return;
                    hideCampaignGraphTooltip();
                    const graphCid = parseInt(sid.replace(/^camp_/, ''), 10);
                    if (!isNaN(graphCid)) openCampaignReferenceModal(graphCid);
                });
                if (exportBtn) exportBtn.classList.remove('hidden');
                if (exportJsonBtn) exportJsonBtn.classList.remove('hidden');
                setTimeout(() => campaignNetwork.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } }), 150);
            })
            .catch(() => {
                setCampaignGraphActivityBanner({ activity: { has_active_iocs: true } });
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

    document.getElementById('campaignCreateForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn && submitBtn.disabled) return;  // prevent double submit
        const name = document.getElementById('campaignName').value.trim();
        const description = document.getElementById('campaignDesc').value.trim();
        const dir = (typeof detectTextDir === 'function') ? detectTextDir(description || name) : 'ltr';
        if (submitBtn) submitBtn.disabled = true;
        try {
            const res = await fetch('/api/campaigns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, description: description || undefined, dir })
            });
            const data = await res.json().catch(() => ({}));
            if (data.success) {
                showToast(data.message || 'Campaign created', 'success');
                if (typeof showAchievementModal === 'function' && (data.new_badges || data.level_up || data.rank_up || data.points_earned !== undefined || data.level_info || data.new_nickname)) {
                    showAchievementModal(data);
                }
                const createRef = document.getElementById('campaignCreateRefFile');
                const newId = data.campaign && data.campaign.id;
                if (newId && createRef && createRef.files && createRef.files[0]) {
                    try {
                        const fd = new FormData();
                        fd.append('file', createRef.files[0]);
                        const ur = await fetch(`/api/campaigns/${newId}/reference-image`, { method: 'POST', body: fd });
                        const ud = await ur.json().catch(() => ({}));
                        if (!ud.success) {
                            showToast(ud.message || 'Campaign saved; reference image upload failed', 'error');
                        }
                    } catch (uploadErr) {
                        showToast((t('toast.error_generic') || 'Error') + ': ' + uploadErr.message, 'error');
                    }
                }
                document.getElementById('campaignName').value = '';
                document.getElementById('campaignDesc').value = '';
                if (createRef) createRef.value = '';
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
        const form = e.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn && submitBtn.disabled) return;
        const ioc_value = document.getElementById('linkIocValue').value.trim();
        const campaign_id = parseInt(document.getElementById('linkCampaignSelect').value, 10);
        if (!campaign_id) {
            showToast(t('toast.select_campaign'), 'error');
            return;
        }
        if (submitBtn) submitBtn.disabled = true;
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
        } finally {
            if (submitBtn) submitBtn.disabled = false;
        }
    });

    if (typeof applyAutoDir === 'function') {
        applyAutoDir(document.getElementById('campaignName'));
        applyAutoDir(document.getElementById('campaignDesc'));
        applyAutoDir(document.getElementById('campaignEditName'));
        applyAutoDir(document.getElementById('campaignEditDesc'));
    }

    global.populateCampaignDropdowns = populateCampaignDropdowns;
    global.loadUsersForAssignDropdown = loadUsersForAssignDropdown;
    global.loadCampaigns = loadCampaigns;
    global.renderGraph = renderGraph;
})(typeof window !== 'undefined' ? window : this);
