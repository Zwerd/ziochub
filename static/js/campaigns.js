/**
 * Campaign Graph tab logic (Step 10.4 - extracted from index.html).
 * Depends on globals: escapeHtml, escapeAttr, showToast, t, vis (vis-network), copyToClipboard.
 * Exposes: populateCampaignDropdowns, loadUsersForAssignDropdown, loadCampaigns, renderGraph.
 */
(function(global) {
    'use strict';

    let campaignNetwork = null;
    let currentCampaignId = null;
    /** Last successful /api/campaign-graph JSON (Vis graph in both Copy and Search modes). */
    let lastCampaignGraphData = null;
    /** 'copy' | 'search' — same graph; click behavior and Search HUD differ. */
    let campaignGraphMode = 'copy';
    let campaignSearchFocusStack = [];
    let campaignSearchCurrentIocId = null;
    let campaignSearchEscBound = false;
    /** vis DataSet refs for Search focus animations (null after destroy). */
    let campaignGraphNodesDataSet = null;
    let campaignGraphEdgesDataSet = null;
    /** Full node layout backup when entering Search focus from graph browse. */
    let campaignSearchGraphLayoutBackup = null;
    let campaignSearchGraphAnimToken = 0;
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

    function setActiveCampaignModeButtons() {
        const copyBtn = document.getElementById('btnCampaignModeCopy');
        const searchBtn = document.getElementById('btnCampaignModeSearch');
        if (!copyBtn || !searchBtn) return;
        const active = 'text-xs py-1 px-3 font-semibold bg-blue-600 text-white transition';
        const inactive = 'text-xs py-1 px-3 font-semibold bg-transparent text-secondary hover:bg-white/5 transition';
        if (campaignGraphMode === 'copy') {
            copyBtn.className = active + ' campaign-graph-mode-btn';
            searchBtn.className = inactive + ' campaign-graph-mode-btn';
        } else {
            copyBtn.className = inactive + ' campaign-graph-mode-btn';
            searchBtn.className = active + ' campaign-graph-mode-btn';
        }
    }

    function updateCampaignSearchBrowseHint() {
        const hint = document.getElementById('campaignSearchBrowseHint');
        const overlay = document.getElementById('campaignSearchFocusOverlay');
        if (!hint) return;
        const show = campaignGraphMode === 'search' &&
            currentCampaignId &&
            lastCampaignGraphData &&
            lastCampaignGraphData.success &&
            overlay &&
            overlay.classList.contains('hidden');
        hint.classList.toggle('hidden', !show);
    }

    /** Investigate overlay open: freeze Vis (no drag / pan / zoom) so graph is background only */
    function syncCampaignGraphInvestigateInteraction() {
        if (!campaignNetwork) return;
        const overlay = document.getElementById('campaignSearchFocusOverlay');
        const locked = campaignGraphMode === 'search' && overlay && !overlay.classList.contains('hidden');
        try {
            campaignNetwork.setOptions({
                interaction: {
                    hover: true,
                    tooltipDelay: 100,
                    zoomView: !locked,
                    dragView: !locked,
                    dragNodes: !locked,
                },
            });
        } catch (e) { /* ignore */ }
    }

    function setCampaignGraphUiMode(mode) {
        campaignGraphMode = mode === 'search' ? 'search' : 'copy';
        setActiveCampaignModeButtons();
        if (campaignGraphMode === 'copy') {
            exitCampaignSearchFocusToPicker();
            if (lastCampaignGraphData && currentCampaignId && !campaignNetwork) {
                buildVisNetworkFromGraphData(lastCampaignGraphData);
            }
        } else {
            bindCampaignSearchEscOnce();
            if (lastCampaignGraphData && currentCampaignId && !campaignNetwork) {
                buildVisNetworkFromGraphData(lastCampaignGraphData);
            }
        }
        updateCampaignSearchBrowseHint();
        syncCampaignGraphInvestigateInteraction();
    }

    function captureCampaignGraphLayout() {
        if (!campaignNetwork || !campaignGraphNodesDataSet) return;
        const ids = campaignGraphNodesDataSet.getIds();
        const pos = campaignNetwork.getPositions(ids);
        const backup = {};
        ids.forEach(function(id) {
            const n = campaignGraphNodesDataSet.get(id);
            const p = pos[id];
            backup[id] = {
                x: p ? p.x : 0,
                y: p ? p.y : 0,
                hidden: !!(n && n.hidden),
            };
        });
        campaignSearchGraphLayoutBackup = backup;
    }

    function restoreCampaignGraphLayoutFromSearchBackup() {
        if (!campaignSearchGraphLayoutBackup || !campaignGraphNodesDataSet) return;
        const updates = Object.keys(campaignSearchGraphLayoutBackup).map(function(id) {
            const s = campaignSearchGraphLayoutBackup[id];
            return { id: id, x: s.x, y: s.y, hidden: !!s.hidden };
        });
        campaignGraphNodesDataSet.update(updates);
        campaignSearchGraphLayoutBackup = null;
    }

    function unhideAllIocYaraNodes() {
        if (!campaignGraphNodesDataSet) return;
        const updates = [];
        campaignGraphNodesDataSet.forEach(function(node) {
            const s = String(node.id);
            if ((s.indexOf('ioc_') === 0 || s.indexOf('yara_') === 0) && node.hidden) {
                updates.push({ id: node.id, hidden: false });
            }
        });
        if (updates.length) campaignGraphNodesDataSet.update(updates);
    }

    function hideNonFocusedIocNodes(selectedNid) {
        if (!campaignGraphNodesDataSet) return;
        const updates = [];
        campaignGraphNodesDataSet.forEach(function(node) {
            const s = String(node.id);
            if ((s.indexOf('ioc_') === 0 || s.indexOf('yara_') === 0) && node.id !== selectedNid) {
                updates.push({ id: node.id, hidden: true });
            }
        });
        if (updates.length) campaignGraphNodesDataSet.update(updates);
    }

    function transitionCampaignSearchGraphFocus(newIocId, oldIocId) {
        const nNew = 'ioc_' + newIocId;
        const nOld = 'ioc_' + oldIocId;
        if (!campaignGraphNodesDataSet) return;
        const upd = [];
        if (campaignGraphNodesDataSet.get(nOld)) upd.push({ id: nOld, hidden: true });
        if (campaignGraphNodesDataSet.get(nNew)) upd.push({ id: nNew, hidden: false });
        if (upd.length) campaignGraphNodesDataSet.update(upd);
        if (campaignNetwork && campaignGraphNodesDataSet.get(nNew)) {
            try {
                campaignNetwork.focus([nNew], {
                    scale: 1.08,
                    animation: { duration: 320, easingFunction: 'easeInOutQuad' },
                });
            } catch (e) {
                try {
                    campaignNetwork.fit({ nodes: [nNew], animation: { duration: 320, easingFunction: 'easeInOutQuad' } });
                } catch (e2) { /* ignore */ }
            }
        }
    }

    function enterCampaignSearchGraphFocus(iocId) {
        if (!campaignNetwork || !campaignGraphNodesDataSet || campaignGraphMode !== 'search') return;
        const nid = 'ioc_' + iocId;
        if (!campaignGraphNodesDataSet.get(nid)) return;
        bindCampaignSearchEscOnce();
        try {
            campaignNetwork.setOptions({
                interaction: {
                    hover: true,
                    tooltipDelay: 100,
                    zoomView: false,
                    dragView: false,
                    dragNodes: false,
                },
            });
        } catch (e) { /* ignore */ }
        if (campaignSearchGraphLayoutBackup == null) {
            captureCampaignGraphLayout();
        }
        campaignSearchGraphAnimToken += 1;
        const token = campaignSearchGraphAnimToken;
        try {
            campaignNetwork.focus([nid], {
                scale: 1.08,
                animation: { duration: 380, easingFunction: 'easeInOutQuad' },
            });
        } catch (e) {
            try {
                campaignNetwork.fit({ nodes: [nid], animation: { duration: 380, easingFunction: 'easeInOutQuad' } });
            } catch (e2) { /* ignore */ }
        }
        setTimeout(function() {
            if (token !== campaignSearchGraphAnimToken) {
                syncCampaignGraphInvestigateInteraction();
                return;
            }
            hideNonFocusedIocNodes(nid);
            const overlay = document.getElementById('campaignSearchFocusOverlay');
            if (overlay) overlay.classList.remove('hidden');
            updateCampaignSearchBrowseHint();
            syncCampaignGraphInvestigateInteraction();
            loadCampaignInvestigateFocus(iocId, { resetStack: true });
        }, 395);
    }

    function exitCampaignSearchFocusToPicker() {
        campaignSearchFocusStack = [];
        campaignSearchCurrentIocId = null;
        campaignSearchGraphAnimToken += 1;
        const overlay = document.getElementById('campaignSearchFocusOverlay');
        if (overlay) overlay.classList.add('hidden');
        const bc = document.getElementById('campaignSearchBreadcrumb');
        if (bc) bc.textContent = '';
        restoreCampaignGraphLayoutFromSearchBackup();
        unhideAllIocYaraNodes();
        if (campaignNetwork) {
            try {
                campaignNetwork.fit({ animation: { duration: 350, easingFunction: 'easeInOutQuad' } });
            } catch (e) { /* ignore */ }
        }
        updateCampaignSearchBrowseHint();
        syncCampaignGraphInvestigateInteraction();
    }

    function formatOneHistoryLine(ev, iocType) {
        const labels = {
            created: (typeof t === 'function' && t('history.created')) ? t('history.created') : 'Created',
            edited: (typeof t === 'function' && t('history.edited')) ? t('history.edited') : 'Edited',
            deleted: (typeof t === 'function' && t('history.deleted')) ? t('history.deleted') : 'Deleted',
            expired: (typeof t === 'function' && t('history.expired')) ? t('history.expired') : 'Expired',
            sanity_warning: (typeof t === 'function' && t('history.sanity_warning')) ? t('history.sanity_warning') : 'Sanity warning',
            excluded: (typeof t === 'function' && t('history.excluded')) ? t('history.excluded') : 'Excluded',
            unexcluded: (typeof t === 'function' && t('history.unexcluded')) ? t('history.unexcluded') : 'Un-excluded'
        };
        const by = (ev.username || '').trim();
        const byLine = (typeof t === 'function' && t('history.by') ? t('history.by') : 'by') + ' ' + (by || '—');
        const atStr = (ev.at || '').replace('T', ' ').slice(0, 19);
        let extra = '';
        const pl = ev.payload || {};
        if (ev.event_type === 'edited' && pl.changes && pl.changes.length) {
            const fieldLabels = { comment: 'Comment', expiration: 'Expiration', ticket_id: 'Ticket', campaign: 'Campaign', tags: 'Tags', analyst: 'Analyst' };
            const parts = pl.changes.map(function(c) {
                const lab = fieldLabels[c.field] || c.field;
                return lab + ': ' + String(c.old || '—').slice(0, 80) + ' → ' + String(c.new || '—').slice(0, 80);
            });
            extra = '<div class="text-xs text-secondary mt-1 whitespace-pre-wrap">' + escapeHtml(parts.join('\n')) + '</div>';
        } else if (ev.event_type === 'deleted' && pl.reason) {
            extra = '<div class="text-xs text-secondary mt-1">' + escapeHtml(String(pl.reason).slice(0, 500)) + '</div>';
        }
        return '<div class="campaign-game-log-entry"><span class="campaign-game-log-type">' +
            escapeHtml(labels[ev.event_type] || ev.event_type) + '</span> — ' + escapeHtml(byLine) +
            ' <span class="text-secondary">' + escapeHtml(atStr) + '</span>' + extra + '</div>';
    }

    function renderCampaignInvestigateNotes(notesEl, notes) {
        if (!notesEl) return;
        const emptyLabel = (typeof t === 'function' && t('notes.empty')) ? t('notes.empty') : 'No notes yet.';
        if (!notes || !notes.length) {
            notesEl.innerHTML = '<div class="campaign-game-related-empty">' + escapeHtml(emptyLabel) + '</div>';
            return;
        }
        notesEl.innerHTML = notes.map(function(n) {
            const when = (n.created_at || '').replace('T', ' ').slice(0, 19);
            const raw = n.content != null ? String(n.content) : '';
            const dir = typeof detectTextDir === 'function' ? detectTextDir(raw) : 'auto';
            const dirAttr = dir === 'rtl' ? 'rtl' : 'ltr';
            return '<div class="campaign-game-note-card">' +
                '<div class="campaign-game-note-card__meta">' +
                '<span class="campaign-game-note-card__user">' + escapeHtml(n.username || '?') + '</span>' +
                '<span class="campaign-game-note-card__when">' + escapeHtml(when) + '</span></div>' +
                '<div class="campaign-game-note-card__body" dir="' + dirAttr + '">' + escapeHtml(raw) + '</div></div>';
        }).join('');
    }

    async function loadCampaignInvestigateFocus(iocId, opts) {
        opts = opts || {};
        const cid = currentCampaignId;
        if (!cid || !iocId) return;
        const graphTransitionFrom = opts.graphTransitionFrom;
        const previousFocusedIocId = campaignSearchCurrentIocId;

        if (opts.pushParent && previousFocusedIocId) {
            campaignSearchFocusStack.push(previousFocusedIocId);
        }
        if (opts.resetStack) {
            campaignSearchFocusStack = [];
        }
        campaignSearchCurrentIocId = iocId;

        const transitionFrom = graphTransitionFrom != null ? graphTransitionFrom : previousFocusedIocId;
        if (transitionFrom && transitionFrom !== iocId && campaignGraphMode === 'search' && campaignNetwork && campaignGraphNodesDataSet) {
            transitionCampaignSearchGraphFocus(iocId, transitionFrom);
        }

        const overlay = document.getElementById('campaignSearchFocusOverlay');
        const histEl = document.getElementById('campaignSearchHistory');
        const relatedEl = document.getElementById('campaignSearchRelated');
        const tagsEl = document.getElementById('campaignSearchTagsAbove');
        const metaEl = document.getElementById('campaignSearchMetaBlock');
        const centerType = document.getElementById('campaignSearchCenterType');
        const centerValue = document.getElementById('campaignSearchCenterValue');
        const card = document.getElementById('campaignSearchCenterCard');
        const bc = document.getElementById('campaignSearchBreadcrumb');
        const notesEl = document.getElementById('campaignSearchNotesList');
        if (overlay) overlay.classList.remove('hidden');
        updateCampaignSearchBrowseHint();
        syncCampaignGraphInvestigateInteraction();
        if (histEl) histEl.innerHTML = '<div class="campaign-game-log-entry text-secondary">' + ((typeof t === 'function' && t('campaign.search_loading')) ? t('campaign.search_loading') : 'Loading…') + '</div>';
        if (notesEl) notesEl.innerHTML = '<div class="campaign-game-log-entry text-secondary">' + ((typeof t === 'function' && t('campaign.search_loading')) ? t('campaign.search_loading') : 'Loading…') + '</div>';
        if (relatedEl) relatedEl.innerHTML = '';
        if (tagsEl) tagsEl.innerHTML = '';
        if (metaEl) metaEl.innerHTML = '';
        if (card) card.classList.remove('is-visible');
        try {
            const r = await fetch('/api/campaign-graph/' + cid + '/investigate/ioc/' + iocId, { credentials: 'same-origin' });
            const d = await r.json().catch(() => ({}));
            if (campaignSearchCurrentIocId !== iocId) return;
            if (!d.success || !d.ioc) {
                if (campaignSearchCurrentIocId === iocId) {
                    showToast(d.message || 'Failed', 'error');
                    exitCampaignSearchFocusToPicker();
                }
                return;
            }
            if (campaignSearchCurrentIocId !== iocId) return;
            const ioc = d.ioc;
            const iocType = ioc.type || '';
            if (centerType) centerType.textContent = iocType;
            if (centerValue) {
                centerValue.textContent = ioc.value || '';
                centerValue.dir = 'ltr';
            }
            if (tagsEl) {
                (ioc.tags || []).forEach(function(tag) {
                    const span = document.createElement('span');
                    span.className = 'campaign-game-tag';
                    span.textContent = tag;
                    tagsEl.appendChild(span);
                });
            }
            if (metaEl) {
                function statTile(label, value, extraClass) {
                    return '<div class="campaign-game-stat-tile' + (extraClass || '') + '" role="listitem">' +
                        '<span class="campaign-game-stat-tile__label">' + escapeHtml(label) + '</span>' +
                        '<span class="campaign-game-stat-tile__value">' + escapeHtml(String(value)) + '</span></div>';
                }
                const rows = [
                    [(typeof t === 'function' && t('search.col.user')) ? t('search.col.user') : 'Analyst', ioc.analyst || '—'],
                    [(typeof t === 'function' && t('search.col.ticket')) ? t('search.col.ticket') : 'Ticket', ioc.ticket_id || '—'],
                    [(typeof t === 'function' && t('edit.expiration')) ? t('edit.expiration') : 'Expiration', ioc.expiration || ((typeof t === 'function' && t('ttl.permanent')) ? t('ttl.permanent') : 'Permanent')],
                    [(typeof t === 'function' && t('search.col.date')) ? t('search.col.date') : 'Created', (ioc.created_at || '').replace('T', ' ').slice(0, 19) || '—'],
                ];
                if (ioc.revoked) {
                    rows.push([
                        (typeof t === 'function' && t('campaign.search_status')) ? t('campaign.search_status') : 'Status',
                        (typeof t === 'function' && t('campaign.search_revoked')) ? t('campaign.search_revoked') : 'Revoked',
                    ]);
                }
                let metaHtml = rows.map(function(row) {
                    return statTile(row[0], row[1], '');
                }).join('');
                if (ioc.comment) {
                    const cLab = (typeof t === 'function' && t('search.col.comment')) ? t('search.col.comment') : 'Comment';
                    metaHtml += '<div class="campaign-game-stat-tile campaign-game-stat-tile--wide campaign-game-stat-tile--comment" role="listitem">' +
                        '<span class="campaign-game-stat-tile__label">' + escapeHtml(cLab) + '</span>' +
                        '<span class="campaign-game-stat-tile__value">' + escapeHtml(ioc.comment) + '</span></div>';
                }
                metaHtml += '<div class="campaign-game-stat-tile campaign-game-stat-tile--wide" role="listitem">' +
                    '<button type="button" class="campaign-game-btn-copy campaign-search-copy-val">' +
                    escapeHtml((typeof t === 'function' && t('campaign.search_copy_value')) ? t('campaign.search_copy_value') : 'Copy value') +
                    '</button></div>';
                metaEl.innerHTML = metaHtml;
                const copyBtn = metaEl.querySelector('.campaign-search-copy-val');
                if (copyBtn && typeof global.copyToClipboard === 'function') {
                    copyBtn.addEventListener('click', function() {
                        global.copyToClipboard(String(ioc.value || ''));
                    });
                }
            }
            if (histEl) {
                const events = d.events || [];
                if (!events.length) {
                    histEl.innerHTML = '<div class="campaign-game-related-empty">' +
                        ((typeof t === 'function' && t('history.empty')) ? t('history.empty') : 'No history') + '</div>';
                } else {
                    histEl.innerHTML = events.map(function(ev) { return formatOneHistoryLine(ev, iocType); }).join('');
                }
            }
            var notesPayload = { success: false, notes: [] };
            try {
                const noteUrl = '/api/ioc-notes?type=' + encodeURIComponent(iocType) + '&value=' + encodeURIComponent(String(ioc.value || '').trim());
                const nr = await fetch(noteUrl, { credentials: 'same-origin' });
                notesPayload = await nr.json().catch(function() { return {}; });
            } catch (eNote) {
                notesPayload = {};
            }
            if (campaignSearchCurrentIocId !== iocId) return;
            if (notesEl) {
                if (notesPayload.success && Array.isArray(notesPayload.notes)) {
                    renderCampaignInvestigateNotes(notesEl, notesPayload.notes);
                } else {
                    const failMsg = (notesPayload && notesPayload.message)
                        ? String(notesPayload.message)
                        : ((typeof t === 'function' && t('notes.empty')) ? t('notes.empty') : 'No notes yet.');
                    notesEl.innerHTML = '<div class="campaign-game-related-empty">' + escapeHtml(failMsg) + '</div>';
                }
            }
            if (relatedEl) {
                const rel = d.related || [];
                if (!rel.length) {
                    relatedEl.innerHTML = '<div class="campaign-game-related-empty">' +
                        ((typeof t === 'function' && t('campaign.search_no_related')) ? t('campaign.search_no_related') : 'No related IOCs.') + '</div>';
                } else {
                    relatedEl.innerHTML = rel.map(function(x) {
                        let sharedHtml = '';
                        if (x.shared_tags && x.shared_tags.length) {
                            const st = ((typeof t === 'function' && t('campaign.search_shared_tags')) ? t('campaign.search_shared_tags') : 'Shared') +
                                ': ' + x.shared_tags.join(', ');
                            sharedHtml = '<span class="campaign-game-related-card__shared">' + escapeHtml(st) + '</span>';
                        }
                        return '<button type="button" class="campaign-game-related-card campaign-search-related-btn" data-related-ioc-id="' +
                            String(x.id) + '"><span class="campaign-game-related-card__type">' + escapeHtml(x.type || '') + '</span>' +
                            '<span class="campaign-game-related-card__value">' + escapeHtml(x.value || '') + '</span>' + sharedHtml + '</button>';
                    }).join('');
                    relatedEl.querySelectorAll('.campaign-search-related-btn').forEach(function(btn) {
                        btn.addEventListener('click', function() {
                            const rid = parseInt(btn.getAttribute('data-related-ioc-id'), 10);
                            if (!isNaN(rid)) loadCampaignInvestigateFocus(rid, { pushParent: true });
                        });
                    });
                }
            }
            if (bc) {
                const trail = campaignSearchFocusStack.map(function(id) { return '#' + id; }).concat(['#' + iocId]).join(' › ');
                bc.textContent = trail;
            }
            requestAnimationFrame(function() {
                if (card) card.classList.add('is-visible');
            });
        } catch (e) {
            if (campaignSearchCurrentIocId === iocId) {
                showToast((t('toast.error_generic') || 'Error') + ': ' + e.message, 'error');
                exitCampaignSearchFocusToPicker();
            }
        }
    }

    function onCampaignSearchBack() {
        if (!campaignSearchFocusStack.length) {
            exitCampaignSearchFocusToPicker();
            return;
        }
        const prevId = campaignSearchFocusStack.pop();
        const leavingId = campaignSearchCurrentIocId;
        loadCampaignInvestigateFocus(prevId, { graphTransitionFrom: leavingId });
    }

    function bindCampaignSearchEscOnce() {
        if (campaignSearchEscBound) return;
        campaignSearchEscBound = true;
        document.addEventListener('keydown', function(ev) {
            if (ev.key !== 'Escape') return;
            const tab = document.getElementById('tab-campaigns');
            if (!tab || tab.classList.contains('hidden')) return;
            if (campaignGraphMode !== 'search') return;
            const overlay = document.getElementById('campaignSearchFocusOverlay');
            if (overlay && !overlay.classList.contains('hidden')) {
                ev.preventDefault();
                onCampaignSearchBack();
            }
        });
    }

    /**
     * Size the vis canvas so node coordinates map ~1:1 to pixels (after fit), enabling scroll on #campaign-graph-scroll-wrap
     * for tall campaigns — otherwise fit() zooms out and bottom IOC thumbnails become unusably small / feel clipped.
     */
    function computeCampaignGraphCanvasPixels(nodesArr) {
        let minX = Infinity;
        let maxX = -Infinity;
        let minY = Infinity;
        let maxY = -Infinity;
        (nodesArr || []).forEach(function(n) {
            if (typeof n.x !== 'number' || typeof n.y !== 'number') return;
            minX = Math.min(minX, n.x);
            maxX = Math.max(maxX, n.x);
            minY = Math.min(minY, n.y);
            maxY = Math.max(maxY, n.y);
        });
        if (!isFinite(minX)) {
            return { width: 720, height: 420 };
        }
        const padL = 220;
        const padR = 220;
        const padT = 260;
        const padB = 160;
        const w = Math.max(640, maxX - minX + padL + padR);
        const h = Math.max(400, maxY - minY + padT + padB);
        return { width: w, height: h };
    }

    function resetCampaignNetworkContainerSizing(container) {
        if (!container) return;
        container.style.boxSizing = '';
        container.style.width = '';
        container.style.minWidth = '';
        container.style.height = '';
    }

    function buildVisNetworkFromGraphData(data) {
        const container = document.getElementById('campaign-network');
        if (!container || typeof vis === 'undefined' || !data || !data.success || !data.nodes || !data.nodes.length) return;
        if (campaignGraphTooltipDirTimer) {
            clearTimeout(campaignGraphTooltipDirTimer);
            campaignGraphTooltipDirTimer = null;
        }
        hideCampaignGraphTooltip();
        if (campaignNetwork) { campaignNetwork.destroy(); campaignNetwork = null; }
        campaignGraphNodesDataSet = null;
        campaignGraphEdgesDataSet = null;
        resetCampaignNetworkContainerSizing(container);
        const scrollWrap = document.getElementById('campaign-graph-scroll-wrap');
        if (scrollWrap) scrollWrap.scrollLeft = 0;
        if (scrollWrap) scrollWrap.scrollTop = 0;
        container.innerHTML = '';
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
        setCampaignGraphActivityBanner(data);
        const labelColor = isDark ? '#e2e8f0' : '#1e293b';
        const campaignLabelColor = isDark ? '#ffffff' : '#0f172a';
        data.nodes.forEach(function(n) {
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
        const dims = computeCampaignGraphCanvasPixels(data.nodes);
        container.style.boxSizing = 'border-box';
        container.style.width = dims.width + 'px';
        container.style.minWidth = '100%';
        container.style.height = dims.height + 'px';
        const nodes = new vis.DataSet(data.nodes);
        const edges = new vis.DataSet(data.edges || []);
        campaignNetwork = new vis.Network(container, { nodes: nodes, edges: edges }, options);
        campaignGraphNodesDataSet = nodes;
        campaignGraphEdgesDataSet = edges;
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
            if (sid.startsWith('ioc_')) {
                if (campaignGraphMode === 'search') {
                    const mi = sid.match(/^ioc_(\d+)$/);
                    if (mi) enterCampaignSearchGraphFocus(parseInt(mi[1], 10));
                    return;
                }
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
            if (sid.startsWith('yara_')) {
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
        setTimeout(function() {
            campaignNetwork.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
            updateCampaignSearchBrowseHint();
            syncCampaignGraphInvestigateInteraction();
        }, 150);
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
            const tagsShort = (typeof t === 'function' && t('campaign.tags_short')) ? t('campaign.tags_short') : 'Tags';
            const escAttr = typeof global.escapeAttr === 'function' ? global.escapeAttr : function(s) { return String(s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;'); };
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
                const tagsArr = Array.isArray(c.tags) ? c.tags : [];
                const tagsJsonAttr = escAttr(JSON.stringify(tagsArr));
                const tagsLine = tagsArr.length
                    ? `<p class="campaign-list-tags mt-1.5 text-xs text-secondary/90 campaign-select-area cursor-pointer font-mono" data-cid="${c.id}" dir="ltr">${escapeHtml(tagsShort + ': ' + tagsArr.join(', '))}</p>`
                    : '';
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
                                data-cid="${c.id}" data-cname="${attrName}" data-cdesc="${attrDesc}" data-cdir="${attrDir}" data-has-ref="${hasRef ? '1' : ''}" data-ctags="${tagsJsonAttr}">${t('actions.edit')}</button>
                            <button type="button" class="btn-cmd-danger btn-cmd-sm campaign-delete-btn"
                                data-cid="${c.id}" data-cname="${attrName}">${t('actions.delete')}</button>
                        </div>
                    </div>
                    ${tagsLine}
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
                        btn.getAttribute('data-has-ref') === '1',
                        btn.getAttribute('data-ctags') || '[]'
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

    function openCampaignEditModal(id, name, desc, dir, hasReferenceImage, tagsJsonStr) {
        document.getElementById('campaignEditId').value = id;
        const nameInp = document.getElementById('campaignEditName');
        const descInp = document.getElementById('campaignEditDesc');
        const tagsInp = document.getElementById('campaignEditTags');
        nameInp.value = name || '';
        descInp.value = desc || '';
        if (tagsInp) {
            let tags = [];
            try {
                tags = JSON.parse(tagsJsonStr || '[]');
            } catch (e1) {
                tags = [];
            }
            tagsInp.value = Array.isArray(tags) ? tags.join(', ') : '';
        }
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
                    lastCampaignGraphData = null;
                    exitCampaignSearchFocusToPicker();
                    const container = document.getElementById('campaign-network');
                    if (container) {
                        resetCampaignNetworkContainerSizing(container);
                        container.innerHTML = '';
                    }
                    if (campaignNetwork) {
                        campaignNetwork.destroy();
                        campaignNetwork = null;
                    }
                    campaignGraphNodesDataSet = null;
                    campaignGraphEdgesDataSet = null;
                    updateCampaignSearchBrowseHint();
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
                body: JSON.stringify({
                    name,
                    description,
                    dir,
                    tags: (function() {
                        const el = document.getElementById('campaignEditTags');
                        if (!el || !el.value.trim()) return [];
                        const raw = typeof normalizeTagsInputValue === 'function'
                            ? normalizeTagsInputValue(el.value)
                            : el.value.trim();
                        return raw ? raw.split(',').map(function(s) { return s.trim(); }).filter(Boolean) : [];
                    })()
                })
            });
            const d = await r.json().catch(() => ({}));
            if (!d.success) {
                if (typeof window.maybeSuggestInvalidTags === 'function' && await window.maybeSuggestInvalidTags(d)) {
                    return;
                }
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
        campaignGraphNodesDataSet = null;
        campaignGraphEdgesDataSet = null;
        resetCampaignNetworkContainerSizing(container);
        const scrollWrapPre = document.getElementById('campaign-graph-scroll-wrap');
        if (scrollWrapPre) {
            scrollWrapPre.scrollTop = 0;
            scrollWrapPre.scrollLeft = 0;
        }
        container.innerHTML = '';
        currentCampaignId = campaignId;
        lastCampaignGraphData = null;
        exitCampaignSearchFocusToPicker();
        const exportBtn = document.getElementById('exportCampaignBtn');
        const exportJsonBtn = document.getElementById('exportCampaignJsonBtn');
        fetch('/api/campaign-graph/' + campaignId)
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (!data.success || !data.nodes || data.nodes.length === 0) {
                    lastCampaignGraphData = null;
                    setCampaignGraphActivityBanner({ activity: { has_active_iocs: true } });
                    resetCampaignNetworkContainerSizing(container);
                    container.innerHTML = '<div class="flex items-center justify-center min-h-[240px] text-secondary">No data for this campaign</div>';
                    if (exportBtn) exportBtn.classList.add('hidden');
                    if (exportJsonBtn) exportJsonBtn.classList.add('hidden');
                    updateCampaignSearchBrowseHint();
                    return;
                }
                lastCampaignGraphData = data;
                buildVisNetworkFromGraphData(data);
                updateCampaignSearchBrowseHint();
            })
            .catch(function() {
                lastCampaignGraphData = null;
                setCampaignGraphActivityBanner({ activity: { has_active_iocs: true } });
                container.innerHTML = '<div class="flex items-center justify-center h-full text-secondary">Failed to load graph</div>';
                if (exportBtn) exportBtn.classList.add('hidden');
                if (exportJsonBtn) exportJsonBtn.classList.add('hidden');
                updateCampaignSearchBrowseHint();
            });
    }

    document.getElementById('btnCampaignModeCopy')?.addEventListener('click', function() {
        setCampaignGraphUiMode('copy');
    });
    document.getElementById('btnCampaignModeSearch')?.addEventListener('click', function() {
        bindCampaignSearchEscOnce();
        setCampaignGraphUiMode('search');
    });
    document.getElementById('campaignSearchBackBtn')?.addEventListener('click', onCampaignSearchBack);
    setActiveCampaignModeButtons();
    updateCampaignSearchBrowseHint();

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
                body: JSON.stringify({
                    name,
                    description: description || undefined,
                    dir,
                    tags: (function() {
                        const el = document.getElementById('campaignCreateTags');
                        if (!el || !el.value.trim()) return [];
                        const raw = typeof normalizeTagsInputValue === 'function'
                            ? normalizeTagsInputValue(el.value)
                            : el.value.trim();
                        return raw ? raw.split(',').map(function(s) { return s.trim(); }).filter(Boolean) : [];
                    })()
                })
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
                const createTags = document.getElementById('campaignCreateTags');
                if (createTags) createTags.value = '';
                if (createRef) createRef.value = '';
                loadCampaigns();
            } else {
                if (typeof window.maybeSuggestInvalidTags === 'function' && await window.maybeSuggestInvalidTags(data)) {
                    return;
                }
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
                if (cid) renderGraph(parseInt(cid, 10));
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
