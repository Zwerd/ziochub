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
    const connPushUnifiedBody = document.getElementById('connPushUnifiedBody');
    const connPushUnifiedEmpty = document.getElementById('connPushUnifiedEmpty');
    function hideFeedConnectionsModal() {
        if (connModal) connModal.classList.add('hidden');
    }
    function hidePullStateModal() {
        const pm = document.getElementById('feedPullStateModal');
        if (pm) pm.classList.add('hidden');
    }
    function hidePushStateModal() {
        const pm = document.getElementById('feedPushStateModal');
        if (pm) pm.classList.add('hidden');
    }
    async function fetchIntegrationConnectionsJson() {
        const res = await fetch('/api/integration-connections');
        return await res.json().catch(function () { return {}; });
    }
    function renderPushUnified(data) {
        if (!connPushUnifiedBody) return;
        const vendor = (data && data.push_state) ? data.push_state : [];
        const autoTargets = (data && data.automation_targets) ? data.automation_targets : [];

        function statusLabel(st) {
            if (st === true) return 'OK';
            if (st === false) return 'FAIL';
            if (st === 'ok') return 'OK';
            if (st === 'fail') return 'FAIL';
            if (st === 'partial') return 'PARTIAL';
            return '—';
        }
        function statusClass(st) {
            if (st === true || st === 'ok') return 'text-green-300 font-semibold';
            if (st === false || st === 'fail') return 'text-red-300 font-semibold';
            if (st === 'partial') return 'text-amber-300 font-semibold';
            return 'text-secondary';
        }
        function transferredText(count, kind) {
            if (count == null || count === '') return kind ? ('— (' + kind + ')') : '—';
            return String(count) + (kind ? (' (' + kind + ')') : '');
        }

        const rows = [];

        // Vendor integrations: one row per system+kind, using last_attempt_* when available.
        vendor.forEach(function (r) {
            const system = r.display_name || '—';
            const systemType = 'Vendor integration';
            const addr = (r.address || '').trim() || '—';
            const kind = (r.data_kind || '').trim() || 'IOC';
            const at = r.last_attempt_at || r.last_push_at || null;
            const ok = (r.last_attempt_ok !== undefined) ? r.last_attempt_ok : null;
            const msg = (r.last_attempt_message || '').trim();
            const count = (r.last_attempt_count !== undefined) ? r.last_attempt_count : null;
            rows.push({
                system: system,
                system_type: systemType,
                address: addr,
                transferred: transferredText(count, kind),
                at: at,
                status: ok,
                reason: msg || '',
            });
        });

        // Automation targets: already aggregated per URL
        autoTargets.forEach(function (r) {
            const system = r.name || '—';
            const systemType = 'HTTP automation';
            const addr = (r.url || '').trim() || '—';
            const kinds = (r.kinds || []).join(', ');
            rows.push({
                system: system,
                system_type: systemType,
                address: addr,
                transferred: kinds ? ('— (' + kinds + ')') : '—',
                at: r.last_seen_at || null,
                status: r.status || '',
                reason: '',
            });
        });

        // Sort by timestamp desc
        rows.sort(function (a, b) {
            const ta = a.at ? Date.parse(a.at) : 0;
            const tb = b.at ? Date.parse(b.at) : 0;
            return tb - ta;
        });

        if (!rows.length) {
            connPushUnifiedBody.innerHTML = '';
            if (connPushUnifiedEmpty) connPushUnifiedEmpty.classList.remove('hidden');
            return;
        }
        if (connPushUnifiedEmpty) connPushUnifiedEmpty.classList.add('hidden');

        connPushUnifiedBody.innerHTML = rows.map(function (r) {
            const stLbl = statusLabel(r.status);
            const stCls = statusClass(r.status);
            return '<tr class="hover:bg-white/5">' +
                '<td class="px-2 py-1.5 text-slate-200 break-words">' + escapeHtml(r.system) + '</td>' +
                '<td class="px-2 py-1.5 text-cyan-200/90 break-words">' + escapeHtml(r.system_type) + '</td>' +
                '<td class="px-2 py-1.5 text-slate-200 font-mono text-[11px] break-all">' + escapeHtml(r.address) + '</td>' +
                '<td class="px-2 py-1.5 text-slate-200">' + escapeHtml(r.transferred) + '</td>' +
                '<td class="px-2 py-1.5 text-secondary whitespace-nowrap">' + escapeHtml(fmtConnTs(r.at)) + '</td>' +
                '<td class="px-2 py-1.5 ' + stCls + '">' + escapeHtml(stLbl) + '</td>' +
                '<td class="px-2 py-1.5 text-secondary break-words">' + escapeHtml(r.reason || '') + '</td>' +
                '</tr>';
        }).join('');
    }
    function renderPullState(data) {
        var body = document.getElementById('connPullStateList');
        var empty = document.getElementById('connPullStateEmpty');
        if (!body) return;
        var list = (data && data.pull_state) ? data.pull_state : [];
        function statusLabel(st) {
            if (st === 'ok') return (typeof t === 'function' && t('feedpulse.connections_status_ok')) ? t('feedpulse.connections_status_ok') : 'OK';
            if (st === 'fail') return (typeof t === 'function' && t('feedpulse.connections_status_fail')) ? t('feedpulse.connections_status_fail') : 'FAIL';
            if (st === 'disabled') return (typeof t === 'function' && t('feedpulse.connections_status_disabled')) ? t('feedpulse.connections_status_disabled') : 'Disabled';
            if (st === 'not_configured') return (typeof t === 'function' && t('feedpulse.connections_status_not_configured')) ? t('feedpulse.connections_status_not_configured') : 'Not configured';
            if (st === 'unknown') return (typeof t === 'function' && t('feedpulse.connections_status_unknown')) ? t('feedpulse.connections_status_unknown') : 'Unknown';
            return st || '—';
        }
        function statusClass(st) {
            if (st === 'ok') return 'text-green-300';
            if (st === 'fail') return 'text-red-300';
            if (st === 'disabled' || st === 'not_configured') return 'text-slate-400';
            return 'text-amber-300';
        }
        if (!list.length) {
            body.innerHTML = '';
            if (empty) empty.classList.remove('hidden');
            return;
        }
        if (empty) empty.classList.add('hidden');
        body.innerHTML = list.map(function (row) {
            var name = escapeHtml(row.name || '—');
            var addrRaw = (row.address || '').trim();
            var addrDisp = escapeHtml(addrRaw || row.host || '—');
            var seen = escapeHtml(fmtConnTs(row.last_pull_at));
            var st = row.status || '';
            var stLbl = escapeHtml(statusLabel(st));
            var stCls = statusClass(st);
            var urlAttr = escapeAttr(addrRaw || '');
            return '<div class="px-3 py-1.5 flex flex-col gap-0.5 min-w-0 w-full max-w-full box-border" title="' + urlAttr + '">' +
                '<div class="flex justify-between items-start gap-2 min-w-0">' +
                '<span class="font-mono text-slate-300 break-words min-w-0 flex-1">' + name + '</span>' +
                '<span class="text-xs font-semibold shrink-0 text-right max-w-[40%] break-words ' + stCls + '">' + stLbl + '</span>' +
                '</div>' +
                '<div class="flex flex-col gap-0.5 min-w-0 sm:flex-row sm:justify-between sm:items-baseline sm:gap-2 text-[11px]">' +
                '<span class="text-cyan-200/90 break-all min-w-0">' + addrDisp + '</span>' +
                '<span class="text-secondary shrink-0 sm:whitespace-nowrap text-[11px] sm:text-end">' + seen + '</span>' +
                '</div>' +
                '</div>';
        }).join('');
    }
    function renderVendorPushState(data) {
        var body = document.getElementById('connVendorPushStateList');
        var empty = document.getElementById('connVendorPushStateEmpty');
        if (!body) return;
        var list = (data && data.push_state) ? data.push_state : [];
        function kindLabel(k) {
            var key = 'feedpulse.push_state_kind_' + String(k || '').toLowerCase();
            var lbl = (typeof t === 'function' && t(key)) ? t(key) : '';
            return lbl || String(k || '—');
        }
        function lastLbl() {
            return (typeof t === 'function' && t('feedpulse.push_state_last_connection')) ? t('feedpulse.push_state_last_connection') : 'Last connection';
        }
        if (!list.length) {
            body.innerHTML = '';
            if (empty) empty.classList.remove('hidden');
            return;
        }
        if (empty) empty.classList.add('hidden');
        body.innerHTML = list.map(function (row) {
            var name = escapeHtml(row.display_name || '—');
            var addr = escapeHtml((row.address || '').trim() || '—');
            var host = (row.host || '').trim();
            var ip = (row.host_ip || '').trim();
            var hostPart = escapeHtml(host || '—');
            var ipPart = ip ? escapeHtml(ip) : '';
            var hostIpLine = hostPart + (ipPart ? ' · ' + ipPart : '');
            var kind = escapeHtml(kindLabel(row.data_kind));
            var seen = escapeHtml(fmtConnTs(row.last_push_at));
            var addrAttr = escapeAttr((row.address || '').trim());
            return '<div class="px-3 py-1.5 flex flex-col gap-1 min-w-0 w-full max-w-full box-border" title="' + addrAttr + '">' +
                '<div class="flex justify-between items-start gap-2 min-w-0">' +
                '<span class="font-semibold text-slate-200 break-words min-w-0 flex-1">' + name + '</span>' +
                '<span class="text-[10px] uppercase tracking-wide text-cyan-300 shrink-0 font-semibold">' + kind + '</span>' +
                '</div>' +
                '<div class="text-[11px] text-cyan-200/85 break-all">' + addr + '</div>' +
                '<div class="flex flex-col gap-0.5 sm:flex-row sm:justify-between sm:items-baseline sm:gap-2 text-[11px]">' +
                '<span class="text-slate-400 break-all min-w-0">' + hostIpLine + '</span>' +
                '<span class="text-secondary shrink-0 sm:text-end"><span class="text-secondary/80">' + escapeHtml(lastLbl()) + ': </span>' + seen + '</span>' +
                '</div>' +
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

    function resetPushModalLoadingState() {
        if (connPushUnifiedBody) {
            connPushUnifiedBody.innerHTML = '<tr><td colspan="7" class="px-3 py-3 text-secondary text-xs">' +
                ((typeof t === 'function' && t('feedpulse.loading')) ? t('feedpulse.loading') : 'Loading...') + '</td></tr>';
        }
        if (connPushUnifiedEmpty) connPushUnifiedEmpty.classList.add('hidden');
    }

    function clearPushModalOnApiError(message) {
        if (connPushUnifiedBody) connPushUnifiedBody.innerHTML = '';
        if (connPushUnifiedEmpty) connPushUnifiedEmpty.classList.remove('hidden');
        if (typeof showToast === 'function' && message) showToast(message, 'error');
    }

    function applyOutboundPushFromApi(data) {
        renderPushUnified(data);
    }

    async function openFeedConnectionsModal() {
        if (!connModal || !connBody) return;
        connModal.classList.remove('hidden');
        connBody.innerHTML = '<tr><td colspan="5" class="px-3 py-3 text-secondary text-xs">' +
            ((typeof t === 'function' && t('feedpulse.loading')) ? t('feedpulse.loading') : 'Loading...') + '</td></tr>';
        if (connEmpty) {
            connEmpty.textContent = '';
            connEmpty.classList.add('hidden');
        }
        try {
            const data = await fetchIntegrationConnectionsJson();
            if (!data.success) {
                connBody.innerHTML = '';
                if (connEmpty) {
                    connEmpty.textContent = data.message || '—';
                    connEmpty.classList.remove('hidden');
                }
                return;
            }
            const rows = (data.feed_clients || []);
            if (connEmpty) connEmpty.classList.toggle('hidden', rows.length > 0);
            connBody.innerHTML = rows.map(function (r) {
                const name = escapeHtml(r.product_name || '—');
                const ptype = escapeHtml(r.product_type || '—');
                const kind = escapeHtml(r.value_kind || '—');
                const uri = escapeHtml(r.uri || '');
                const seen = escapeHtml(fmtConnTs(r.last_connection_at));
                return '<tr class="hover:bg-white/5">' +
                    '<td class="px-2 py-1.5 text-slate-300 break-all">' + name + '</td>' +
                    '<td class="px-2 py-1.5 text-cyan-200/90 break-words">' + ptype + '</td>' +
                    '<td class="px-2 py-1.5 text-slate-200">' + kind + '</td>' +
                    '<td class="px-2 py-1.5 text-slate-200 font-mono text-[11px] break-all">' + uri + '</td>' +
                    '<td class="px-2 py-1.5 text-secondary whitespace-nowrap">' + seen + '</td>' +
                    '</tr>';
            }).join('');
            if (!rows.length) {
                connBody.innerHTML = '';
            }
        } catch (err) {
            connBody.innerHTML = '';
            if (connEmpty) {
                connEmpty.textContent = (err && err.message) || 'Error';
                connEmpty.classList.remove('hidden');
            }
        }
    }

    async function openPullStateModal() {
        const pullModal = document.getElementById('feedPullStateModal');
        const pl = document.getElementById('connPullStateList');
        const ple = document.getElementById('connPullStateEmpty');
        if (!pullModal || !pl) return;
        pullModal.classList.remove('hidden');
        if (ple) ple.classList.add('hidden');
        pl.innerHTML = '<div class="px-3 py-3 text-secondary text-xs">' +
            ((typeof t === 'function' && t('feedpulse.loading')) ? t('feedpulse.loading') : 'Loading...') + '</div>';
        try {
            const data = await fetchIntegrationConnectionsJson();
            if (!data.success) {
                renderPullState({ pull_state: [] });
                pl.innerHTML = '';
                if (ple) ple.classList.remove('hidden');
                if (typeof showToast === 'function' && data.message) showToast(data.message, 'error');
                return;
            }
            renderPullState(data);
        } catch (err) {
            renderPullState({ pull_state: [] });
            pl.innerHTML = '';
            if (ple) ple.classList.remove('hidden');
            if (typeof showToast === 'function') showToast((err && err.message) || 'Error', 'error');
        }
    }

    async function openPushStateModal() {
        const pushModal = document.getElementById('feedPushStateModal');
        if (!pushModal) return;
        pushModal.classList.remove('hidden');
        resetPushModalLoadingState();
        try {
            const data = await fetchIntegrationConnectionsJson();
            if (!data.success) {
                clearPushModalOnApiError(data.message || 'Failed to load push state');
                return;
            }
            applyOutboundPushFromApi(data);
        } catch (err) {
            clearPushModalOnApiError((err && err.message) || 'Error');
        }
    }

    const pullStateBtn = document.getElementById('feedPullStateBtn');
    const pushStateBtn = document.getElementById('feedPushStateBtn');
    const pullStateClose = document.getElementById('feedPullStateModalClose');
    const pushStateClose = document.getElementById('feedPushStateModalClose');
    const pullStateModal = document.getElementById('feedPullStateModal');
    const pushStateModal = document.getElementById('feedPushStateModal');

    if (connBtn && connModal) {
        connBtn.addEventListener('click', openFeedConnectionsModal);
    }
    if (connClose) connClose.addEventListener('click', hideFeedConnectionsModal);
    if (connModal) {
        connModal.addEventListener('click', function (e) {
            if (e.target === connModal) hideFeedConnectionsModal();
        });
    }
    if (pullStateBtn && pullStateModal) {
        pullStateBtn.addEventListener('click', openPullStateModal);
    }
    if (pullStateClose) pullStateClose.addEventListener('click', hidePullStateModal);
    if (pullStateModal) {
        pullStateModal.addEventListener('click', function (e) {
            if (e.target === pullStateModal) hidePullStateModal();
        });
    }
    if (pushStateBtn && pushStateModal) {
        pushStateBtn.addEventListener('click', openPushStateModal);
    }
    if (pushStateClose) pushStateClose.addEventListener('click', hidePushStateModal);
    if (pushStateModal) {
        pushStateModal.addEventListener('click', function (e) {
            if (e.target === pushStateModal) hidePushStateModal();
        });
    }
    // Retry buttons were removed from the simplified unified Push State table.

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
