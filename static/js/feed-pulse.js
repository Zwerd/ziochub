/**
 * Feed Pulse tab logic (Step 10.4 - extracted from index.html).
 * Depends on globals: escapeHtml, escapeAttr, showToast, t, copyToClipboard.
 * Exposes: loadFeedPulse.
 */
(function(global) {
    'use strict';

    let feedPulseData = null;

    async function loadFeedPulse() {
        const typeSel = document.getElementById('feedPulseType');
        const hoursSel = document.getElementById('feedPulseHours');
        const type = typeSel && typeSel.value ? typeSel.value : 'all';
        const hours = hoursSel && hoursSel.value ? parseInt(hoursSel.value, 10) : 24;
        try {
            const res = await fetch(`/api/feed-pulse?type=${encodeURIComponent(type)}&hours=${hours}`);
            const data = await res.json().catch(() => ({}));
            feedPulseData = data;
            if (!data.success) {
                showToast(data.message || 'Feed Pulse failed', 'error');
                return;
            }
            const inc = data.incoming || [];
            const out = data.outgoing || [];
            const anomalies = data.anomalies || [];

            document.getElementById('feedPulseFresh').textContent = '+' + (data.incoming_count || inc.length);
            document.getElementById('feedPulseExpired').textContent = '-' + (data.outgoing_count || out.length);
            document.getElementById('feedPulseTotal').textContent = (data.total_active || 0).toLocaleString();
            const exclusions = data.exclusions || [];
            const exclCount = data.exclusions_count ?? exclusions.length;
            document.getElementById('feedPulseExcluded').textContent = exclCount;
            document.getElementById('feedPulseExcludedCount').textContent = '(' + exclCount + ')';
            const totalAllEl = document.getElementById('feedPulseTotalAll');
            if (totalAllEl) totalAllEl.textContent = (data.total_all ?? data.total_active ?? 0).toLocaleString();

            const outBody = document.getElementById('feedPulseOutgoingBody');
            const outEmpty = document.getElementById('feedPulseOutgoingEmpty');
            const incBody = document.getElementById('feedPulseIncomingBody');
            const incEmpty = document.getElementById('feedPulseIncomingEmpty');
            const isAdmin = window.authState && window.authState.is_admin;
            const allowTitle = (typeof t === 'function' && t('feedpulse.excluded_count')) || 'Allowlisted';
            if (outBody) {
                outBody.innerHTML = out.map(o => `
                    <tr class="border-b border-white/5 hover:bg-red-900/10">
                        <td class="px-2 py-1.5 text-xs font-mono truncate max-w-[200px]" title="${escapeHtml(o.value)}">
                            <span>${escapeHtml(o.value)}</span>
                            ${o.is_allowlisted ? `<span class="ml-1 inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-slate-500/20 text-slate-200 border border-slate-400/30" title="${escapeAttr(isAdmin ? (o.allowlist_reason || allowTitle) : allowTitle)}">ALLOWLIST</span>` : ''}
                        </td>
                        <td class="px-2 py-1.5 text-xs">${escapeHtml(o.type)}</td>
                        <td class="px-2 py-1.5 text-xs">${escapeHtml(o.analyst)}</td>
                        <td class="px-2 py-1.5 text-xs">${escapeHtml(o.expiration)}</td>
                        <td class="px-2 py-1.5 text-xs text-red-300">${escapeHtml(o.reason || 'Expired')}</td>
                    </tr>`).join('');
                if (outEmpty) outEmpty.classList.toggle('hidden', out.length > 0);
            }
            document.getElementById('feedPulseOutgoingCount').textContent = '(' + out.length + ')';

            if (incBody) {
                incBody.innerHTML = inc.map(i => `
                    <tr class="border-b border-white/5 hover:bg-green-900/10">
                        <td class="px-2 py-1.5 text-xs font-mono truncate max-w-[200px]" title="${escapeHtml(i.value)}">
                            <span>${escapeHtml(i.value)}</span>
                            ${i.is_allowlisted ? `<span class="ml-1 inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-slate-500/20 text-slate-200 border border-slate-400/30" title="${escapeAttr(isAdmin ? (i.allowlist_reason || allowTitle) : allowTitle)}">ALLOWLIST</span>` : ''}
                        </td>
                        <td class="px-2 py-1.5 text-xs">${escapeHtml(i.type)}</td>
                        <td class="px-2 py-1.5 text-xs">${escapeHtml(i.analyst)}</td>
                        <td class="px-2 py-1.5 text-xs">${escapeHtml(i.campaign)}</td>
                    </tr>`).join('');
                if (incEmpty) incEmpty.classList.toggle('hidden', inc.length > 0);
            }
            document.getElementById('feedPulseIncomingCount').textContent = '(' + inc.length + ')';

            const exclBody = document.getElementById('feedPulseExcludedBody');
            const exclEmpty = document.getElementById('feedPulseExcludedEmpty');
            if (exclBody) {
                exclBody.innerHTML = exclusions.map(e => {
                    const dateStr = (e.excluded_at || '').slice(0, 10);
                    return `<tr class="border-b border-white/5 hover:bg-orange-900/10">
                        <td class="px-2 py-1.5 text-xs font-mono truncate max-w-[120px]" title="${escapeHtml(e.value)}">${escapeHtml(e.value)}</td>
                        <td class="px-2 py-1.5 text-xs">${escapeHtml(e.type)}</td>
                        <td class="px-2 py-1.5 text-xs">${escapeHtml(e.anomaly_type)}</td>
                        <td class="px-2 py-1.5 text-xs">${escapeHtml(e.excluded_by)}</td>
                        <td class="px-2 py-1.5 text-xs">${escapeHtml(dateStr)}</td>
                        <td class="px-2 py-1.5"><button type="button" class="unexclude-btn btn-cmd-neutral btn-cmd-sm text-xs" data-id="${e.id}" title="${(t('feedpulse.un_exclude') || 'Un-exclude').replace(/"/g,'&quot;')}">${t('feedpulse.un_exclude') || 'Un-exclude'}</button></td>
                    </tr>`;
                }).join('');
                if (exclEmpty) exclEmpty.classList.toggle('hidden', exclusions.length > 0);
            }

            const anomaliesArea = document.getElementById('feedPulseAnomaliesArea');
            const anomaliesList = document.getElementById('feedPulseAnomaliesList');
            if (anomaliesArea && anomaliesList) {
                if (anomalies.length > 0) {
                    anomaliesArea.classList.remove('hidden');
                    anomaliesList.innerHTML = anomalies.map(a => {
                        const attrVal = a.value ? (a.value).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;') : '';
                        const attrType = (a.ioc_type || '').replace(/"/g,'&quot;');
                        const attrAnomaly = (a.type || '').replace(/"/g,'&quot;');
                        const valBlock = a.value ? `<code class="anomaly-copy-value block mt-1 p-2 bg-black/30 rounded text-xs font-mono break-all cursor-pointer" data-value="${attrVal}" title="${(t('toast.click_to_copy') || 'Click to copy').replace(/"/g,'&quot;')}">${escapeHtml(a.value)}</code>` : '';
                        const excludeBtn = `<button type="button" class="anomaly-exclude-btn btn-cmd-neutral btn-cmd-sm mt-1 text-xs" data-value="${attrVal}" data-type="${attrType}" data-anomaly-type="${attrAnomaly}" title="${(t('feedpulse.exclude_anomaly') || 'Exclude from future scans').replace(/"/g,'&quot;')}">${t('feedpulse.exclude') || 'Exclude'}</button>`;
                        const allowBadge = a.is_allowlisted ? `<span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-500/20 text-slate-100 border border-slate-400/30" title="${escapeAttr(isAdmin ? (a.allowlist_reason || allowTitle) : allowTitle)}">ALLOWLIST</span>` : '';
                        return `<li class="flex items-start gap-2 flex-col border-b border-amber-500/20 pb-2 mb-2 last:border-0 last:pb-0 last:mb-0"><span class="flex gap-2 items-start"><span class="text-amber-400 flex-shrink-0">•</span><span class="flex-1">${escapeHtml(a.message)}${allowBadge}</span></span>${valBlock}${excludeBtn}</li>`;
                    }).join('');
                } else {
                    anomaliesArea.classList.add('hidden');
                    anomaliesList.innerHTML = '';
                }
            }
        } catch (err) {
            console.error('loadFeedPulse:', err);
            showToast(t('toast.error_generic') + ': ' + err.message, 'error');
        }
    }

    // Allowlist popup: show read-only content (admin edits in Admin → Allowlist)
    const allowlistBtn = document.getElementById('feedPulseAllowlistBtn');
    const allowlistModal = document.getElementById('feedPulseAllowlistModal');
    const allowlistContent = document.getElementById('feedPulseAllowlistContent');
    const allowlistClose = document.getElementById('feedPulseAllowlistModalClose');
    const allowlistCloseBottom = document.getElementById('feedPulseAllowlistModalCloseBottom');
    if (allowlistBtn && allowlistModal && allowlistContent) {
        function hideAllowlistModal() {
            allowlistModal.classList.add('hidden');
        }
        allowlistBtn.addEventListener('click', async function () {
            allowlistModal.classList.remove('hidden');
            allowlistContent.textContent = (typeof t === 'function' && t('feedpulse.loading') ? t('feedpulse.loading') : '') || 'Loading...';
            try {
                const res = await fetch('/api/allowlist-view');
                const data = await res.json().catch(function () { return {}; });
                if (data.success) {
                    allowlistContent.textContent = (data.content || '').trim() || ((typeof t === 'function' && t('feedpulse.allowlist_empty')) ? t('feedpulse.allowlist_empty') : '(Empty)');
                } else {
                    allowlistContent.textContent = data.message || 'Failed to load allowlist';
                }
            } catch (err) {
                allowlistContent.textContent = (err && err.message) || 'Error loading allowlist';
            }
        });
        if (allowlistClose) {
            allowlistClose.addEventListener('click', hideAllowlistModal);
        }
        if (allowlistCloseBottom) {
            allowlistCloseBottom.addEventListener('click', hideAllowlistModal);
        }
        allowlistModal.addEventListener('click', function (e) {
            if (e.target === allowlistModal) hideAllowlistModal();
        });
    }

    const connBtn = document.getElementById('feedConnectionsBtn');
    const connModal = document.getElementById('feedConnectionsModal');
    const connClose = document.getElementById('feedConnectionsModalClose');
    const connBody = document.getElementById('feedConnectionsList');
    const connEmpty = document.getElementById('feedConnectionsEmpty');
    const connLastIoc = document.getElementById('connLastIocApi');
    const connLastYara = document.getElementById('connLastYaraApi');
    const connLastDxl = document.getElementById('connLastDxl');
    const connLastIocPush = document.getElementById('connLastIocPush');
    const connIocPushToggle = document.getElementById('connIocPushDetailsToggle');
    const connIocPushWrap = document.getElementById('connIocPushDetailsWrap');
    const connIocPushBody = document.getElementById('connIocPushDetailsBody');
    const connIocPushEmpty = document.getElementById('connIocPushDetailsEmpty');
    const connIocPushRetryBtn = document.getElementById('connIocPushRetryBtn');
    const connLastIocExpirePush = document.getElementById('connLastIocExpirePush');
    const connIocExpireToggle = document.getElementById('connIocExpirePushDetailsToggle');
    const connIocExpireWrap = document.getElementById('connIocExpirePushDetailsWrap');
    const connIocExpireBody = document.getElementById('connIocExpirePushDetailsBody');
    const connIocExpireEmpty = document.getElementById('connIocExpirePushDetailsEmpty');
    const connIocExpireRetryBtn = document.getElementById('connIocExpirePushRetryBtn');
    const connLastIocManualRemovePush = document.getElementById('connLastIocManualRemovePush');
    const connIocManualToggle = document.getElementById('connIocManualRemovePushDetailsToggle');
    const connIocManualWrap = document.getElementById('connIocManualRemovePushDetailsWrap');
    const connIocManualBody = document.getElementById('connIocManualRemovePushDetailsBody');
    const connIocManualEmpty = document.getElementById('connIocManualRemovePushDetailsEmpty');
    const connIocManualRetryBtn = document.getElementById('connIocManualRemovePushRetryBtn');
    const connLastYaraAutoPush = document.getElementById('connLastYaraAutoPush');
    const connYaraAutoPushToggle = document.getElementById('connYaraAutoPushDetailsToggle');
    const connYaraAutoPushWrap = document.getElementById('connYaraAutoPushDetailsWrap');
    const connYaraAutoPushBody = document.getElementById('connYaraAutoPushDetailsBody');
    const connYaraAutoPushEmpty = document.getElementById('connYaraAutoPushDetailsEmpty');
    const connYaraAutoPushRetryBtn = document.getElementById('connYaraAutoPushRetryBtn');
    const connLastYaraAutoDelete = document.getElementById('connLastYaraAutoDelete');
    const connYaraAutoDeleteToggle = document.getElementById('connYaraAutoDeleteDetailsToggle');
    const connYaraAutoDeleteWrap = document.getElementById('connYaraAutoDeleteDetailsWrap');
    const connYaraAutoDeleteBody = document.getElementById('connYaraAutoDeleteDetailsBody');
    const connYaraAutoDeleteEmpty = document.getElementById('connYaraAutoDeleteDetailsEmpty');
    const connYaraAutoDeleteRetryBtn = document.getElementById('connYaraAutoDeleteRetryBtn');
    function hideConnModal() {
        if (connModal) connModal.classList.add('hidden');
    }
    function renderAutomationTargets(data) {
        const body = document.getElementById('connAutomationTargetsList');
        const empty = document.getElementById('connAutomationTargetsEmpty');
        if (!body) return;
        const list = (data && data.automation_targets) ? data.automation_targets : [];
        if (!list.length) {
            body.innerHTML = '';
            if (empty) empty.classList.remove('hidden');
            return;
        }
        if (empty) empty.classList.add('hidden');
        function kindLabel(k) {
            const key = 'feedpulse.connections_kind_' + k;
            return (typeof t === 'function' && t(key)) ? t(key) : k;
        }
        function statusLabel(st) {
            if (st === 'ok') return (typeof t === 'function' && t('feedpulse.connections_status_ok')) ? t('feedpulse.connections_status_ok') : 'OK';
            if (st === 'fail') return (typeof t === 'function' && t('feedpulse.connections_status_fail')) ? t('feedpulse.connections_status_fail') : 'FAIL';
            if (st === 'partial') return (typeof t === 'function' && t('feedpulse.connections_status_partial')) ? t('feedpulse.connections_status_partial') : 'PARTIAL';
            return st || '—';
        }
        function statusClass(st) {
            if (st === 'ok') return 'text-green-300';
            if (st === 'fail') return 'text-red-300';
            if (st === 'partial') return 'text-amber-300';
            return 'text-secondary';
        }
        body.innerHTML = list.map(function(row) {
            const kinds = (row.kinds || []).map(kindLabel).join(', ');
            const host = escapeHtml(row.host || '—');
            const name = escapeHtml(row.name || '—');
            const url = row.url || '';
            const urlAttr = escapeAttr(url);
            const st = row.status || '';
            const seen = escapeHtml(fmtConnTs(row.last_seen_at));
            return '<div class="px-3 py-1.5 flex flex-col gap-0.5 min-w-0 w-full max-w-full box-border" title="' + urlAttr + '">' +
                '<div class="flex justify-between items-start gap-2 min-w-0">' +
                '<span class="font-mono text-slate-300 break-words min-w-0 flex-1">' + name + '</span>' +
                '<span class="text-xs font-semibold shrink-0 text-right max-w-[40%] break-words ' + statusClass(st) + '">' + escapeHtml(statusLabel(st)) + '</span>' +
                '</div>' +
                '<div class="flex flex-col gap-0.5 min-w-0 sm:flex-row sm:justify-between sm:items-baseline sm:gap-2 text-[11px]">' +
                '<span class="text-cyan-200/90 break-all min-w-0">' + host + '</span>' +
                '<span class="text-secondary shrink-0 sm:whitespace-nowrap text-[11px] sm:text-end">' + seen + '</span>' +
                '</div>' +
                '<div class="text-[10px] text-secondary/90 break-words">' + escapeHtml(kinds) + '</div>' +
                '</div>';
        }).join('');
    }
    function fmtConnTs(iso) {
        if (!iso) return (typeof t === 'function' && t('feedpulse.connections_never')) ? t('feedpulse.connections_never') : 'Never';
        try {
            const d = new Date(iso);
            if (isNaN(d.getTime())) return iso;
            return d.toLocaleString();
        } catch (e) {
            return iso;
        }
    }
    function _renderYaraAutomationDetailsTable(parsedResults, connBodyEl, connToggle, connEmpty, connRetry) {
        const esc = (s) => escapeHtml(s == null ? '' : String(s));
        if (!connBodyEl || !connToggle) return;
        if (Array.isArray(parsedResults) && parsedResults.length) {
            connBodyEl.innerHTML = parsedResults.map(r => {
                const name = esc((r && r.name) || '');
                const url = esc((r && r.url) || '');
                const ok = !!(r && r.success);
                const status = ok ? 'OK' : 'FAIL';
                const msg = esc((r && r.message) || '');
                const statusClass = ok ? 'text-green-300' : 'text-red-300';
                return '<tr class="border-b border-white/5">' +
                    '<td class="px-2 py-1.5 font-mono">' + name + '</td>' +
                    '<td class="px-2 py-1.5 font-mono text-cyan-200/90 break-all">' + url + '</td>' +
                    '<td class="px-2 py-1.5 font-semibold ' + statusClass + '">' + status + '</td>' +
                    '<td class="px-2 py-1.5 text-secondary break-words">' + msg + '</td>' +
                    '</tr>';
            }).join('');
            connToggle.classList.remove('hidden');
            const isAdm = window.authState && window.authState.is_admin;
            const hasFail = parsedResults.some(r => r && r.success === false);
            if (isAdm && hasFail && connRetry) connRetry.classList.remove('hidden');
        } else {
            connBodyEl.innerHTML = '';
            if (connEmpty) connEmpty.classList.remove('hidden');
        }
    }

    async function openConnectionsModal() {
        if (!connModal || !connBody) return;
        connModal.classList.remove('hidden');
        renderAutomationTargets({ automation_targets: [] });
        const connAutoEmpty = document.getElementById('connAutomationTargetsEmpty');
        if (connAutoEmpty) connAutoEmpty.classList.add('hidden');
        const connAutoBody = document.getElementById('connAutomationTargetsList');
        if (connAutoBody) {
            connAutoBody.innerHTML = '<div class="px-3 py-3 text-secondary text-xs">' +
                ((typeof t === 'function' && t('feedpulse.loading')) ? t('feedpulse.loading') : 'Loading...') + '</div>';
        }
        connBody.innerHTML = '<div class="px-3 py-3 text-secondary text-xs">' +
            ((typeof t === 'function' && t('feedpulse.loading')) ? t('feedpulse.loading') : 'Loading...') + '</div>';
        if (connLastIoc) connLastIoc.textContent = '…';
        if (connLastYara) connLastYara.textContent = '…';
        if (connLastDxl) connLastDxl.textContent = '…';
        if (connLastIocPush) connLastIocPush.textContent = '…';
        if (connLastIocExpirePush) connLastIocExpirePush.textContent = '…';
        if (connLastIocManualRemovePush) connLastIocManualRemovePush.textContent = '…';
        if (connIocPushToggle) connIocPushToggle.classList.add('hidden');
        if (connIocPushRetryBtn) connIocPushRetryBtn.classList.add('hidden');
        if (connIocPushWrap) connIocPushWrap.classList.add('hidden');
        if (connIocPushBody) connIocPushBody.innerHTML = '';
        if (connIocPushEmpty) connIocPushEmpty.classList.add('hidden');
        if (connIocExpireToggle) connIocExpireToggle.classList.add('hidden');
        if (connIocExpireRetryBtn) connIocExpireRetryBtn.classList.add('hidden');
        if (connIocExpireWrap) connIocExpireWrap.classList.add('hidden');
        if (connIocExpireBody) connIocExpireBody.innerHTML = '';
        if (connIocExpireEmpty) connIocExpireEmpty.classList.add('hidden');
        if (connIocManualToggle) connIocManualToggle.classList.add('hidden');
        if (connIocManualRetryBtn) connIocManualRetryBtn.classList.add('hidden');
        if (connIocManualWrap) connIocManualWrap.classList.add('hidden');
        if (connIocManualBody) connIocManualBody.innerHTML = '';
        if (connIocManualEmpty) connIocManualEmpty.classList.add('hidden');
        if (connLastYaraAutoPush) connLastYaraAutoPush.textContent = '…';
        if (connLastYaraAutoDelete) connLastYaraAutoDelete.textContent = '…';
        if (connYaraAutoPushToggle) connYaraAutoPushToggle.classList.add('hidden');
        if (connYaraAutoPushRetryBtn) connYaraAutoPushRetryBtn.classList.add('hidden');
        if (connYaraAutoPushWrap) connYaraAutoPushWrap.classList.add('hidden');
        if (connYaraAutoPushBody) connYaraAutoPushBody.innerHTML = '';
        if (connYaraAutoPushEmpty) connYaraAutoPushEmpty.classList.add('hidden');
        if (connYaraAutoDeleteToggle) connYaraAutoDeleteToggle.classList.add('hidden');
        if (connYaraAutoDeleteRetryBtn) connYaraAutoDeleteRetryBtn.classList.add('hidden');
        if (connYaraAutoDeleteWrap) connYaraAutoDeleteWrap.classList.add('hidden');
        if (connYaraAutoDeleteBody) connYaraAutoDeleteBody.innerHTML = '';
        if (connYaraAutoDeleteEmpty) connYaraAutoDeleteEmpty.classList.add('hidden');
        try {
            const res = await fetch('/api/integration-connections');
            const data = await res.json().catch(function () { return {}; });
            if (!data.success) {
                if (connLastIoc) connLastIoc.textContent = data.message || '—';
                renderAutomationTargets({ automation_targets: [] });
                const ctb = document.getElementById('connAutomationTargetsList');
                const cte = document.getElementById('connAutomationTargetsEmpty');
                if (ctb) ctb.innerHTML = '';
                if (cte) cte.classList.remove('hidden');
                connBody.innerHTML = '';
                if (connEmpty) connEmpty.classList.remove('hidden');
                return;
            }
            renderAutomationTargets(data);
            if (connLastIoc) connLastIoc.textContent = fmtConnTs(data.last_api_ioc_ingest_at);
            if (connLastYara) connLastYara.textContent = fmtConnTs(data.last_api_yara_upload_at);
            if (connLastDxl) connLastDxl.textContent = fmtConnTs(data.last_dxl_tie_push_at);
            if (connLastIocPush) {
                // Show attempt time + quick success/fail summary when available
                let txt = fmtConnTs(data.last_ioc_push_attempt_at);
                let parsedResults = null;
                try {
                    const raw = data.last_ioc_push_results_json;
                    if (raw) {
                        const parsed = JSON.parse(raw);
                        const results = (parsed && parsed.results) ? parsed.results : [];
                        const okCount = results.filter(r => r && r.success).length;
                        const total = results.length;
                        const overall = parsed && parsed.overall_success;
                        if (total > 0) {
                            txt = (overall ? 'OK' : 'FAIL') + ` (${okCount}/${total}) ` + txt;
                            parsedResults = results;
                        }
                    }
                } catch (e) { /* ignore */ }
                connLastIocPush.textContent = txt;

                // Render details table when available
                if (connIocPushBody && connIocPushWrap && connIocPushToggle) {
                    const esc = (s) => escapeHtml(s == null ? '' : String(s));
                    if (Array.isArray(parsedResults) && parsedResults.length) {
                        connIocPushBody.innerHTML = parsedResults.map(r => {
                            const name = esc((r && r.name) || '');
                            const url = esc((r && r.url) || '');
                            const ok = !!(r && r.success);
                            const status = ok ? 'OK' : 'FAIL';
                            const msg = esc((r && r.message) || '');
                            const statusClass = ok ? 'text-green-300' : 'text-red-300';
                            return '<tr class="border-b border-white/5">' +
                                '<td class="px-2 py-1.5 font-mono">' + name + '</td>' +
                                '<td class="px-2 py-1.5 font-mono text-cyan-200/90 break-all">' + url + '</td>' +
                                '<td class="px-2 py-1.5 font-semibold ' + statusClass + '">' + status + '</td>' +
                                '<td class="px-2 py-1.5 text-secondary break-words">' + msg + '</td>' +
                                '</tr>';
                        }).join('');
                        connIocPushToggle.classList.remove('hidden');
                        // Show retry button if there are failures and user is admin
                        const isAdmin = window.authState && window.authState.is_admin;
                        const hasFail = parsedResults.some(r => r && r.success === false);
                        if (isAdmin && hasFail && connIocPushRetryBtn) connIocPushRetryBtn.classList.remove('hidden');
                    } else {
                        connIocPushBody.innerHTML = '';
                        if (connIocPushEmpty) connIocPushEmpty.classList.remove('hidden');
                    }
                }
            }

            if (connLastIocExpirePush) {
                let txt2 = fmtConnTs(data.last_ioc_expire_push_attempt_at);
                let parsed2 = null;
                try {
                    const raw2 = data.last_ioc_expire_push_results_json;
                    if (raw2) {
                        const p2 = JSON.parse(raw2);
                        const results2 = (p2 && p2.results) ? p2.results : [];
                        const okCount2 = results2.filter(r => r && r.success).length;
                        const total2 = results2.length;
                        const overall2 = p2 && p2.overall_success;
                        if (total2 > 0) {
                            txt2 = (overall2 ? 'OK' : 'FAIL') + ` (${okCount2}/${total2}) ` + txt2;
                            parsed2 = results2;
                        }
                    }
                } catch (e) { /* ignore */ }
                connLastIocExpirePush.textContent = txt2;
                if (connIocExpireBody && connIocExpireWrap && connIocExpireToggle) {
                    const esc2 = (s) => escapeHtml(s == null ? '' : String(s));
                    if (Array.isArray(parsed2) && parsed2.length) {
                        connIocExpireBody.innerHTML = parsed2.map(r => {
                            const name = esc2((r && r.name) || '');
                            const url = esc2((r && r.url) || '');
                            const ok = !!(r && r.success);
                            const status = ok ? 'OK' : 'FAIL';
                            const msg = esc2((r && r.message) || '');
                            const statusClass = ok ? 'text-green-300' : 'text-red-300';
                            return '<tr class="border-b border-white/5">' +
                                '<td class="px-2 py-1.5 font-mono">' + name + '</td>' +
                                '<td class="px-2 py-1.5 font-mono text-cyan-200/90 break-all">' + url + '</td>' +
                                '<td class="px-2 py-1.5 font-semibold ' + statusClass + '">' + status + '</td>' +
                                '<td class="px-2 py-1.5 text-secondary break-words">' + msg + '</td>' +
                                '</tr>';
                        }).join('');
                        connIocExpireToggle.classList.remove('hidden');
                        const isAdmin2 = window.authState && window.authState.is_admin;
                        const hasFail2 = parsed2.some(r => r && r.success === false);
                        if (isAdmin2 && hasFail2 && connIocExpireRetryBtn) connIocExpireRetryBtn.classList.remove('hidden');
                    } else {
                        connIocExpireBody.innerHTML = '';
                        if (connIocExpireEmpty) connIocExpireEmpty.classList.remove('hidden');
                    }
                }
            }

            if (connLastIocManualRemovePush) {
                let txt3 = fmtConnTs(data.last_ioc_manual_remove_push_attempt_at);
                let parsed3 = null;
                try {
                    const raw3 = data.last_ioc_manual_remove_push_results_json;
                    if (raw3) {
                        const p3 = JSON.parse(raw3);
                        const results3 = (p3 && p3.results) ? p3.results : [];
                        const okCount3 = results3.filter(r => r && r.success).length;
                        const total3 = results3.length;
                        const overall3 = p3 && p3.overall_success;
                        if (total3 > 0) {
                            txt3 = (overall3 ? 'OK' : 'FAIL') + ` (${okCount3}/${total3}) ` + txt3;
                            parsed3 = results3;
                        }
                    }
                } catch (e) { /* ignore */ }
                connLastIocManualRemovePush.textContent = txt3;
                if (connIocManualBody && connIocManualWrap && connIocManualToggle) {
                    const esc3 = (s) => escapeHtml(s == null ? '' : String(s));
                    if (Array.isArray(parsed3) && parsed3.length) {
                        connIocManualBody.innerHTML = parsed3.map(r => {
                            const name = esc3((r && r.name) || '');
                            const url = esc3((r && r.url) || '');
                            const ok = !!(r && r.success);
                            const status = ok ? 'OK' : 'FAIL';
                            const msg = esc3((r && r.message) || '');
                            const statusClass = ok ? 'text-green-300' : 'text-red-300';
                            return '<tr class="border-b border-white/5">' +
                                '<td class="px-2 py-1.5 font-mono">' + name + '</td>' +
                                '<td class="px-2 py-1.5 font-mono text-cyan-200/90 break-all">' + url + '</td>' +
                                '<td class="px-2 py-1.5 font-semibold ' + statusClass + '">' + status + '</td>' +
                                '<td class="px-2 py-1.5 text-secondary break-words">' + msg + '</td>' +
                                '</tr>';
                        }).join('');
                        connIocManualToggle.classList.remove('hidden');
                        const isAdmin3 = window.authState && window.authState.is_admin;
                        const hasFail3 = parsed3.some(r => r && r.success === false);
                        if (isAdmin3 && hasFail3 && connIocManualRetryBtn) connIocManualRetryBtn.classList.remove('hidden');
                    } else {
                        connIocManualBody.innerHTML = '';
                        if (connIocManualEmpty) connIocManualEmpty.classList.remove('hidden');
                    }
                }
            }

            if (connLastYaraAutoPush) {
                let txtY = fmtConnTs(data.last_yara_automation_push_attempt_at);
                let parsedY = null;
                try {
                    const rawY = data.last_yara_automation_push_results_json;
                    if (rawY) {
                        const pY = JSON.parse(rawY);
                        const resultsY = (pY && pY.results) ? pY.results : [];
                        const okCountY = resultsY.filter(r => r && r.success).length;
                        const totalY = resultsY.length;
                        const overallY = pY && pY.overall_success;
                        if (totalY > 0) {
                            txtY = (overallY ? 'OK' : 'FAIL') + ` (${okCountY}/${totalY}) ` + txtY;
                            parsedY = resultsY;
                        }
                    }
                } catch (e) { /* ignore */ }
                connLastYaraAutoPush.textContent = txtY;
                _renderYaraAutomationDetailsTable(parsedY, connYaraAutoPushBody, connYaraAutoPushToggle, connYaraAutoPushEmpty, connYaraAutoPushRetryBtn);
            }

            if (connLastYaraAutoDelete) {
                let txtZ = fmtConnTs(data.last_yara_automation_delete_attempt_at);
                let parsedZ = null;
                try {
                    const rawZ = data.last_yara_automation_delete_results_json;
                    if (rawZ) {
                        const pZ = JSON.parse(rawZ);
                        const resultsZ = (pZ && pZ.results) ? pZ.results : [];
                        const okCountZ = resultsZ.filter(r => r && r.success).length;
                        const totalZ = resultsZ.length;
                        const overallZ = pZ && pZ.overall_success;
                        if (totalZ > 0) {
                            txtZ = (overallZ ? 'OK' : 'FAIL') + ` (${okCountZ}/${totalZ}) ` + txtZ;
                            parsedZ = resultsZ;
                        }
                    }
                } catch (e) { /* ignore */ }
                connLastYaraAutoDelete.textContent = txtZ;
                _renderYaraAutomationDetailsTable(parsedZ, connYaraAutoDeleteBody, connYaraAutoDeleteToggle, connYaraAutoDeleteEmpty, connYaraAutoDeleteRetryBtn);
            }

            const rows = data.feed_access || [];
            if (connEmpty) connEmpty.classList.toggle('hidden', rows.length > 0);
            connBody.innerHTML = rows.map(function (r) {
                const ip = escapeHtml(r.client_ip || '');
                const path = escapeHtml(r.feed_path || '');
                const seen = escapeHtml(fmtConnTs(r.last_seen_at));
                return '<div class="px-3 py-1.5 flex flex-col gap-1 min-w-0 w-full max-w-full sm:flex-row sm:justify-between sm:items-start sm:gap-3">' +
                    '<div class="flex flex-col gap-0.5 min-w-0 sm:flex-1">' +
                    '<span class="font-mono text-slate-300 break-all">' + ip + '</span>' +
                    '<span class="font-mono text-cyan-200/90 break-all min-w-0">' + path + '</span></div>' +
                    '<span class="text-secondary text-[11px] shrink-0 sm:text-end sm:max-w-[40%] sm:whitespace-nowrap break-all">' + seen + '</span></div>';
            }).join('');
            if (!rows.length) {
                connBody.innerHTML = '';
            }
        } catch (err) {
            renderAutomationTargets({ automation_targets: [] });
            const ctb = document.getElementById('connAutomationTargetsList');
            const cte = document.getElementById('connAutomationTargetsEmpty');
            if (ctb) ctb.innerHTML = '';
            if (cte) cte.classList.remove('hidden');
            connBody.innerHTML = '';
            if (connEmpty) {
                connEmpty.textContent = (err && err.message) || 'Error';
                connEmpty.classList.remove('hidden');
            }
        }
    }
    if (connBtn && connModal) {
        connBtn.addEventListener('click', openConnectionsModal);
    }
    if (connClose) connClose.addEventListener('click', hideConnModal);
    if (connModal) {
        connModal.addEventListener('click', function (e) {
            if (e.target === connModal) hideConnModal();
        });
    }
    if (connIocPushToggle && connIocPushWrap) {
        connIocPushToggle.addEventListener('click', function () {
            connIocPushWrap.classList.toggle('hidden');
        });
    }
    async function _retry(kind) {
        try {
            const res = await fetch('/api/admin/ioc-push/retry', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ kind: kind })
            });
            const data = await res.json().catch(() => ({}));
            if (data && data.success) {
                if (typeof showToast === 'function') showToast('Retry completed', 'success');
                await openConnectionsModal();
            } else {
                if (typeof showToast === 'function') showToast((data && data.message) ? data.message : 'Retry failed', 'error');
            }
        } catch (e) {
            if (typeof showToast === 'function') showToast('Retry failed: ' + e.message, 'error');
        }
    }
    if (connIocPushRetryBtn) connIocPushRetryBtn.addEventListener('click', () => _retry('create'));
    if (connIocExpireToggle && connIocExpireWrap) {
        connIocExpireToggle.addEventListener('click', function () {
            connIocExpireWrap.classList.toggle('hidden');
        });
    }
    if (connIocExpireRetryBtn) connIocExpireRetryBtn.addEventListener('click', () => _retry('expire'));
    if (connIocManualToggle && connIocManualWrap) {
        connIocManualToggle.addEventListener('click', function () {
            connIocManualWrap.classList.toggle('hidden');
        });
    }
    if (connIocManualRetryBtn) connIocManualRetryBtn.addEventListener('click', () => _retry('manual_remove'));

    if (connYaraAutoPushToggle && connYaraAutoPushWrap) {
        connYaraAutoPushToggle.addEventListener('click', function () {
            connYaraAutoPushWrap.classList.toggle('hidden');
        });
    }
    if (connYaraAutoDeleteToggle && connYaraAutoDeleteWrap) {
        connYaraAutoDeleteToggle.addEventListener('click', function () {
            connYaraAutoDeleteWrap.classList.toggle('hidden');
        });
    }
    async function _retryYaraAuto(kind) {
        try {
            const res = await fetch('/api/admin/yara-automation/retry', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ kind: kind })
            });
            const data = await res.json().catch(() => ({}));
            if (data && data.success) {
                if (typeof showToast === 'function') showToast(data.message || 'Retry completed', 'success');
                await openConnectionsModal();
            } else {
                if (typeof showToast === 'function') showToast((data && data.message) ? data.message : 'Retry failed', 'error');
            }
        } catch (e) {
            if (typeof showToast === 'function') showToast('Retry failed: ' + e.message, 'error');
        }
    }
    if (connYaraAutoPushRetryBtn) connYaraAutoPushRetryBtn.addEventListener('click', () => _retryYaraAuto('push'));
    if (connYaraAutoDeleteRetryBtn) connYaraAutoDeleteRetryBtn.addEventListener('click', () => _retryYaraAuto('delete'));

    document.getElementById('feedPulseAnomaliesList')?.addEventListener('click', async (e) => {
        const copyTarget = e.target.closest('.anomaly-copy-value');
        if (copyTarget) {
            const val = copyTarget.getAttribute('data-value');
            if (val != null && typeof copyToClipboard === 'function') copyToClipboard(val);
            return;
        }
        const excludeTarget = e.target.closest('.anomaly-exclude-btn');
        if (excludeTarget) {
            const value = excludeTarget.getAttribute('data-value');
            const iocType = excludeTarget.getAttribute('data-type') || '';
            const anomalyType = excludeTarget.getAttribute('data-anomaly-type') || '';
            const analystEl = document.getElementById('iocUsername') || document.getElementById('csvUsername') || document.getElementById('txtUsername');
            const username = (analystEl && analystEl.value) ? analystEl.value.trim() : 'unknown';
            try {
                const res = await fetch('/api/sanity-exclude', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ value, type: iocType, anomaly_type: anomalyType, username })
                });
                const result = await res.json().catch(() => ({}));
                if (result.success) {
                    showToast(t('feedpulse.excluded') || 'Anomaly excluded', 'success');
                    loadFeedPulse();
                } else {
                    showToast(result.message || 'Exclude failed', 'error');
                }
            } catch (err) {
                showToast(t('toast.error_generic') + ': ' + err.message, 'error');
            }
        }
    });
    document.getElementById('feedPulseExcludedArea')?.addEventListener('click', async (e) => {
        const btn = e.target.closest('.unexclude-btn');
        if (!btn) return;
        const id = btn.getAttribute('data-id');
        if (!id) return;
        try {
            const res = await fetch('/api/sanity-exclude', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: parseInt(id, 10) })
            });
            const result = await res.json().catch(() => ({}));
            if (result.success) {
                showToast(t('feedpulse.unexcluded') || 'Exclusion removed', 'success');
                loadFeedPulse();
            } else {
                showToast(result.message || 'Un-exclude failed', 'error');
            }
        } catch (err) {
            showToast(t('toast.error_generic') + ': ' + err.message, 'error');
        }
    });
    document.getElementById('feedPulseType')?.addEventListener('change', loadFeedPulse);
    document.getElementById('feedPulseHours')?.addEventListener('change', loadFeedPulse);
    document.getElementById('feedPulseExportBtn')?.addEventListener('click', () => {
        if (!feedPulseData || !feedPulseData.success) {
            showToast(t('feedpulse.no_data_export') || 'No data to export', 'error');
            return;
        }
        const rows = [];
        rows.push(['Feed Pulse Report', '', '', '']);
        rows.push(['Generated', new Date().toISOString(), '', '']);
        rows.push(['Hours', feedPulseData.hours || 24, '', '']);
        rows.push(['Total Active', feedPulseData.total_active || 0, 'Total All IOCs', feedPulseData.total_all ?? feedPulseData.total_active ?? 0]);
        rows.push(['Incoming', feedPulseData.incoming_count || 0, 'Outgoing', feedPulseData.outgoing_count || 0]);
        rows.push([], ['INCOMING']);
        (feedPulseData.incoming || []).forEach(i => rows.push([i.value, i.type, i.analyst, i.campaign]));
        rows.push([], ['OUTGOING']);
        (feedPulseData.outgoing || []).forEach(o => rows.push([o.value, o.type, o.analyst, o.expiration, o.reason || 'Expired']));
        if ((feedPulseData.anomalies || []).length) {
            rows.push([], ['ANOMALIES']);
            (feedPulseData.anomalies || []).forEach(a => rows.push([a.value, a.message]));
        }
        if ((feedPulseData.exclusions || []).length) {
            rows.push([], ['EXCLUDED']);
            (feedPulseData.exclusions || []).forEach(e => rows.push([e.value, e.type, e.anomaly_type, e.excluded_by, e.excluded_at]));
        }
        const csv = rows.map(r => r.map(c => '"' + String(c).replace(/"/g, '""') + '"').join(',')).join('\n');
        const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'feed-pulse-' + new Date().toISOString().slice(0, 10) + '.csv';
        a.click();
        URL.revokeObjectURL(a.href);
        showToast(t('feedpulse.exported') || 'Report exported', 'success');
    });

    global.loadFeedPulse = loadFeedPulse;
})(typeof window !== 'undefined' ? window : this);
