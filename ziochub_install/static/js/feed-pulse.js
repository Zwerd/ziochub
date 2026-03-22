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

    document.getElementById('feedPulseRefreshBtn')?.addEventListener('click', loadFeedPulse);

    // Allowlist popup: show read-only content (admin edits in Admin → Allowlist)
    const allowlistBtn = document.getElementById('feedPulseAllowlistBtn');
    const allowlistModal = document.getElementById('feedPulseAllowlistModal');
    const allowlistContent = document.getElementById('feedPulseAllowlistContent');
    const allowlistClose = document.getElementById('feedPulseAllowlistModalClose');
    if (allowlistBtn && allowlistModal && allowlistContent) {
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
            allowlistClose.addEventListener('click', function () { allowlistModal.classList.add('hidden'); });
        }
        allowlistModal.addEventListener('click', function (e) {
            if (e.target === allowlistModal) allowlistModal.classList.add('hidden');
        });
    }
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
