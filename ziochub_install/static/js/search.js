/**
 * Search & Investigate tab logic (Step 10.4 - extracted from index.html).
 * Depends on globals: escapeHtml, escapeAttr, showToast, t, getIocTypeIcon, copyToClipboard,
 *                     switchTab, loadStats, loadLiveFeed, loadFeedPulse, loadUsersForAssignDropdown,
 *                     openYaraMetaEditModal, translations, currentLang.
 * Exposes: performSearch, openEditModal, openDeleteIocModal, revokeIOC, openIocHistoryModal,
 *          getExpirationBadge, highlightMatch, detectTextDir.
 */
(function(global) {
    'use strict';

    var rtlByScriptEnabled = (document.body && document.body.getAttribute('data-search-comment-rtl')) === '1';

    /**
     * If setting is on: return 'rtl' when text has more Hebrew/Arabic letters than other letters, else 'ltr'. Else return 'auto'.
     */
    function detectTextDir(text) {
        if (!text || typeof text !== 'string') return 'auto';
        if (!rtlByScriptEnabled) return 'auto';
        var rtl = 0, ltr = 0, c, code;
        for (var i = 0; i < text.length; i++) {
            c = text[i];
            code = c.charCodeAt(0);
            if (code >= 0x0590 && code <= 0x05FF) rtl++;      // Hebrew
            else if (code >= 0x0600 && code <= 0x06FF) rtl++; // Arabic
            else if ((code >= 0x0041 && code <= 0x005A) || (code >= 0x0061 && code <= 0x007A)) ltr++; // Latin A-Za-z
            else if (code >= 0x0400 && code <= 0x04FF) ltr++; // Cyrillic
        }
        if (rtl === 0 && ltr === 0) return 'auto';
        return rtl > ltr ? 'rtl' : 'ltr';
    }
    global.detectTextDir = detectTextDir;

    const searchInput = document.getElementById('searchInput');
    const searchButton = document.getElementById('searchButton');
    const searchResults = document.getElementById('searchResults');
    const searchNoResults = document.getElementById('searchNoResults');
    const resultsTableBody = document.getElementById('resultsTableBody');
    const resultCount = document.getElementById('resultCount');

    /** Decode ``searchBrowseSelect`` value: ``c|us`` = country, ``a|domain`` = aggregate browse. */
    function parseBrowseSelect(raw) {
        var out = { country: '', aggregate: '' };
        if (!raw || typeof raw !== 'string') return out;
        if (raw.indexOf('c|') === 0) {
            out.country = raw.slice(2).trim().toLowerCase();
            return out;
        }
        if (raw.indexOf('a|') === 0) {
            out.aggregate = raw.slice(2).trim().toLowerCase();
            return out;
        }
        return out;
    }

    /**
     * One ``<select>``: flat list of browse targets — countries (IP) and IOC-type aggregates —
     * sorted by identifier count descending (e.g. domain (203), url (103), United States (76), …).
     * Still exposed as ``loadSearchCountryCodes`` for the tab switcher.
     */
    function loadSearchBrowseSelect() {
        var sel = document.getElementById('searchBrowseSelect');
        if (!sel) return;
        var prev = sel.value || '';
        var tr = (global.translations && global.translations[global.currentLang || 'en']) || {};
        var s = tr.search || {};
        var noneLabel = s.browse_none || '\u2014 None \u2014';

        var aggOrder = [
            { key: 'domain', labelKey: 'agg_domain' },
            { key: 'email', labelKey: 'agg_email' },
            { key: 'url', labelKey: 'agg_url' },
            { key: 'yara', labelKey: 'agg_yara' },
            { key: 'campaign', labelKey: 'agg_campaign' },
            { key: 'hash_md5', labelKey: 'agg_md5' },
            { key: 'hash_sha1', labelKey: 'agg_sha1' },
            { key: 'hash_sha256', labelKey: 'agg_sha256' },
            { key: 'hash_sha512', labelKey: 'agg_sha512' },
            { key: 'hash_other', labelKey: 'agg_other' }
        ];

        Promise.all([
            fetch('/api/ip-country-codes').then(function (r) { return r.json(); }).catch(function () { return {}; }),
            fetch('/api/search/browse-filters').then(function (r) { return r.json(); }).catch(function () { return {}; })
        ]).then(function (pair) {
            var cdata = pair[0];
            var bdata = pair[1];
            while (sel.firstChild) {
                sel.removeChild(sel.firstChild);
            }
            var anyOpt = document.createElement('option');
            anyOpt.value = '';
            anyOpt.setAttribute('data-i18n', 'search.browse_none');
            anyOpt.textContent = noneLabel;
            sel.appendChild(anyOpt);

            var regionNames = null;
            try {
                var lang = document.documentElement.getAttribute('lang') || (global.currentLang || 'en');
                regionNames = new Intl.DisplayNames([lang, 'en'], { type: 'region' });
            } catch (e2) { /* ignore */ }

            var items = [];

            if (cdata && cdata.success && Array.isArray(cdata.countries)) {
                cdata.countries.forEach(function (row) {
                    var code = (row.code || '').toLowerCase();
                    if (!code || code.length !== 2) return;
                    var cnt = parseInt(row.count, 10);
                    if (!isFinite(cnt) || cnt <= 0) return;
                    var upper = code.toUpperCase();
                    var lbl = upper;
                    if (regionNames) {
                        try {
                            lbl = regionNames.of(upper);
                        } catch (e3) {
                            lbl = upper;
                        }
                    }
                    lbl += ' (' + cnt + ')';
                    items.push({ value: 'c|' + code, text: lbl, count: cnt });
                });
            }

            var agg = (bdata && bdata.success && bdata.aggregates) ? bdata.aggregates : null;
            if (agg && typeof agg === 'object') {
                aggOrder.forEach(function (row) {
                    var n = parseInt(agg[row.key], 10);
                    if (!isFinite(n) || n <= 0) return;
                    var name = (s[row.labelKey] != null && s[row.labelKey] !== '') ? s[row.labelKey] : row.key;
                    items.push({ value: 'a|' + row.key, text: name + ' (' + n + ')', count: n });
                });
            }

            items.sort(function (a, b) {
                if (b.count !== a.count) return b.count - a.count;
                return a.text.localeCompare(b.text, undefined, { sensitivity: 'base' });
            });

            items.forEach(function (it) {
                var opt = document.createElement('option');
                opt.value = it.value;
                opt.textContent = it.text;
                sel.appendChild(opt);
            });

            if (prev) {
                for (var i = 0; i < sel.options.length; i++) {
                    if (sel.options[i].value === prev) {
                        sel.selectedIndex = i;
                        break;
                    }
                }
            }
        }).catch(function () { /* keep first option */ });
    }

    function performSearch() {
        const query = searchInput.value.trim();
        const filter = document.getElementById('searchFilter').value || 'all';
        var browseRaw = '';
        var browseEl = document.getElementById('searchBrowseSelect');
        if (browseEl) browseRaw = browseEl.value || '';
        var br = parseBrowseSelect(browseRaw);
        var countryCode = (br.country || '').trim().toLowerCase();
        var browseAgg = (br.aggregate || '').trim().toLowerCase();
        // Empty search with "All Groups" + "All Columns" should list everything (paginated).

        let url = `/api/search?q=${encodeURIComponent(query)}&filter=${encodeURIComponent(filter)}`;
        if (countryCode) {
            url += '&country_code=' + encodeURIComponent(countryCode);
        }
        if (browseAgg) {
            url += '&browse_aggregate=' + encodeURIComponent(browseAgg);
        }
        if (!query && (countryCode || browseAgg)) {
            url += '&per_page=1000';
        }

        fetch(url)
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    if (result.results && result.results.length > 0) {
                        displaySearchResults(result.results, result.total);
                    } else {
                        showNoResults();
                    }
                } else {
                    showToast(result.message || 'Search failed', 'error');
                }
            })
            .catch(error => {
                showToast(t('toast.error_search') + ': ' + error.message, 'error');
            });
    }

    if (searchButton && searchInput) {
        searchButton.addEventListener('click', performSearch);
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') performSearch();
        });
    } else {
        console.error('Search elements not found:', { searchButton, searchInput });
    }

    function getExpirationBadge(expirationStatus, expiresOn, isExpired) {
        if (expirationStatus === 'Deleted') {
            return `<span class="badge bg-slate-600 text-slate-200">${typeof t === 'function' && t('search.col.deleted') ? t('search.col.deleted') : 'Deleted'}</span>`;
        }
        if (expirationStatus === 'Permanent') {
            return `<span class="badge badge-permanent">🔴 ${t('ttl.permanent')}</span>`;
        } else if (isExpired) {
            return `<span class="badge badge-expired">🟢 ${t('search.col.expired') || 'Expired'}</span>`;
        } else {
            return `<span class="badge badge-expires">🟡 ${escapeHtml(expirationStatus)}</span>`;
        }
    }

    let _searchAllResults = [];
    let _searchPage = 1;
    let _searchSortBy = null;
    let _searchSortDir = 'asc';

    function _getSortValue(result, key) {
        const v = result[key];
        if (key === 'tags') return Array.isArray(v) ? v.join(',') : (v || '');
        if (key === 'date' && v) return v;
        return (v != null && v !== '') ? String(v).toLowerCase() : '';
    }

    function _sortSearchResults() {
        if (!_searchSortBy || !_searchAllResults.length) return;
        const dir = _searchSortDir === 'asc' ? 1 : -1;
        _searchAllResults.sort((a, b) => {
            const va = _getSortValue(a, _searchSortBy);
            const vb = _getSortValue(b, _searchSortBy);
            if (va < vb) return -1 * dir;
            if (va > vb) return 1 * dir;
            return 0;
        });
    }

    function _updateSearchSortArrows() {
        document.querySelectorAll('.search-sortable').forEach(function(th) {
            const arrow = th.querySelector('.search-sort-arrow');
            if (!arrow) return;
            const key = th.getAttribute('data-sort');
            if (key === _searchSortBy) {
                arrow.textContent = _searchSortDir === 'asc' ? '\u25B2' : '\u25BC';
            } else {
                arrow.textContent = '';
            }
        });
    }

    function _getPageSize() {
        const sel = document.getElementById('searchPageSize');
        return sel ? parseInt(sel.value, 10) : 50;
    }

    function _renderSearchPage() {
        _sortSearchResults();
        const pageSize = _getPageSize();
        const totalPages = Math.max(1, Math.ceil(_searchAllResults.length / pageSize));
        if (_searchPage > totalPages) _searchPage = totalPages;
        const start = (_searchPage - 1) * pageSize;
        const pageResults = _searchAllResults.slice(start, start + pageSize);
        const query = (searchInput && searchInput.value) ? searchInput.value.trim() : '';
        resultsTableBody.innerHTML = '';
        pageResults.forEach((result, index) => {
            _renderSearchRow(result, query);
        });
        _bindSearchRowActions();
        const prevBtn = document.getElementById('searchPrevPage');
        const nextBtn = document.getElementById('searchNextPage');
        const info = document.getElementById('searchPageInfo');
        if (prevBtn) prevBtn.disabled = _searchPage <= 1;
        if (nextBtn) nextBtn.disabled = _searchPage >= totalPages;
        if (info) info.textContent = `${_searchPage} / ${totalPages}`;
    }

    document.getElementById('searchPrevPage')?.addEventListener('click', () => { _searchPage--; _renderSearchPage(); });
    document.getElementById('searchNextPage')?.addEventListener('click', () => { _searchPage++; _renderSearchPage(); });
    document.getElementById('searchPageSize')?.addEventListener('change', () => { _searchPage = 1; _renderSearchPage(); });

    function displaySearchResults(results, totalFromApi) {
        searchResults.classList.remove('hidden');
        searchNoResults.classList.add('hidden');
        const n = (totalFromApi != null && totalFromApi !== '') ? Number(totalFromApi) : results.length;
        resultCount.textContent = Number.isFinite(n) ? n : results.length;
        _searchAllResults = results;
        _searchPage = 1;
        _renderSearchPage();
        _updateSearchSortArrows();
    }

    document.querySelectorAll('.search-sortable').forEach(function(th) {
        th.addEventListener('click', function() {
            const key = th.getAttribute('data-sort');
            if (!key) return;
            if (_searchSortBy === key) _searchSortDir = _searchSortDir === 'asc' ? 'desc' : 'asc';
            else { _searchSortBy = key; _searchSortDir = 'asc'; }
            _sortSearchResults();
            _renderSearchPage();
            _updateSearchSortArrows();
        });
    });

    function _renderSearchRow(result, query) {
        const isYara = result.file_type === 'YARA';
        const isCampaign = result.file_type === 'Campaign';
        const row = document.createElement('tr');
        row.className = 'border border-white/10';
        row.dataset.iocValue = result.ioc;
        row.dataset.iocType = result.file_type;
        row.dataset.comment = result.comment || '';
        row.dataset.expiration = result.expiration || 'NEVER';
        row.dataset.campaign = result.campaign_name != null ? result.campaign_name : '';
        row.dataset.ticketId = result.ref || '';
        row.dataset.tags = Array.isArray(result.tags) ? result.tags.join(',') : (result.tags || '');
        row.dataset.analyst = result.user || '';
        row.dataset.isYara = isYara ? '1' : '0';
        row.dataset.campaignId = (result.campaign_id != null && result.campaign_id !== '') ? String(result.campaign_id) : '';

        const expirationBadge = getExpirationBadge(
            result.expiration_status || 'Unknown',
            result.expires_on,
            result.is_expired
        );

        const icon = getIocTypeIcon(result.file_type, result.ioc, result.country_code);
        const iocDisplay = highlightMatch(result.ioc || '', query);
        const userDisplay = highlightMatch(result.user || 'N/A', query);
        const commentDisplay = highlightMatch(result.comment || 'N/A', query);
        const iocAttr = escapeAttr(result.ioc || '');
        const typeCellClass = isYara
            ? 'border border-white/10 px-4 py-2 font-mono text-sm text-amber-400'
            : (isCampaign ? 'border border-white/10 px-4 py-2 font-mono text-sm text-rose-300' : 'border border-white/10 px-4 py-2 font-mono text-sm');
        const isDeleted = result.status === 'Deleted';
        const graphBtnLabel = (typeof t === 'function' && t('tab.campaign')) ? t('tab.campaign') : 'Campaign Graph';
        const actionsCell = isCampaign
            ? `<td class="border border-white/10 px-3 py-2">
                <div class="flex items-center gap-1.5 flex-wrap">
                    <button type="button" class="btn-cmd-primary btn-cmd-sm" data-action="open-campaign-graph" title="${escapeAttr(graphBtnLabel)}">${escapeHtml(graphBtnLabel)}</button>
                </div>
               </td>`
            : isYara
            ? `<td class="border border-white/10 px-3 py-2">
                <div class="flex items-center gap-1.5 flex-wrap">
                    <button type="button" class="btn-cmd-primary btn-cmd-sm" data-action="edit-yara-meta" title="${t('actions.edit_metadata')}">${t('actions.edit')}</button>
                    <button type="button" class="btn-cmd-neutral btn-cmd-sm" data-action="history" title="${typeof t === 'function' && t('actions.history') ? t('actions.history') : 'History'}">${typeof t === 'function' && t('actions.history') ? t('actions.history') : 'History'}</button>
                    <button type="button" class="btn-cmd-neutral btn-cmd-sm" data-action="view-yara" title="${t('actions.go_to_yara')}">${t('actions.view')}</button>
                </div>
               </td>`
            : isDeleted
            ? `<td class="border border-white/10 px-3 py-2">
                <div class="flex items-center gap-1.5">
                    <button type="button" class="btn-cmd-neutral btn-cmd-sm" data-action="history" title="${typeof t === 'function' && t('actions.history') ? t('actions.history') : 'History'}">${typeof t === 'function' && t('actions.history') ? t('actions.history') : 'History'}</button>
                    <button type="button" class="btn-cmd-primary btn-cmd-sm" data-action="add-note" title="${typeof t === 'function' && t('actions.note') ? t('actions.note') : 'Note'}">${typeof t === 'function' && t('actions.note') ? t('actions.note') : 'Note'}</button>
                </div>
               </td>`
            : `<td class="border border-white/10 px-3 py-2">
                <div class="flex items-center gap-1.5">
                    <button type="button" class="btn-cmd-primary btn-cmd-sm" data-action="edit">${t('actions.edit')}</button>
                    <button type="button" class="btn-cmd-primary btn-cmd-sm" data-action="add-note" title="${typeof t === 'function' && t('actions.note') ? t('actions.note') : 'Note'}">${typeof t === 'function' && t('actions.note') ? t('actions.note') : 'Note'}</button>
                    <button type="button" class="btn-cmd-neutral btn-cmd-sm" data-action="history" title="${typeof t === 'function' && t('actions.history') ? t('actions.history') : 'History'}">${typeof t === 'function' && t('actions.history') ? t('actions.history') : 'History'}</button>
                    <button type="button" class="btn-cmd-danger btn-cmd-sm" data-action="delete">${t('actions.delete')}</button>
                </div>
               </td>`;

        const ticketDisplay = escapeHtml(result.ref || '');
        const campaignDisplay = escapeHtml(result.campaign_name || '');
        const tagsArr = Array.isArray(result.tags) ? result.tags : [];
        const tagsDisplay = tagsArr.length ? tagsArr.map(t => '<span class="inline-block bg-white/10 text-xs px-2 py-0.5 rounded mr-1">' + escapeHtml(String(t)) + '</span>').join('') : '<span class="text-secondary">-</span>';

        row.innerHTML = `
            <td class="${typeCellClass}">${icon} ${result.file_type}</td>
            <td class="border border-white/10 px-4 py-2 font-mono" title="${iocAttr}"><span class="inline-flex items-center gap-1">${iocDisplay} <button type="button" class="copy-ioc-btn btn-cmd-neutral btn-cmd-sm ml-1 flex-shrink-0" onclick="copyToClipboard(this.getAttribute('data-ioc'))" data-ioc="${iocAttr}" title="${t('actions.copy')}" aria-label="${t('actions.copy')}">${t('actions.copy')}</button></span></td>
            <td class="border border-white/10 px-4 py-2 text-sm">${result.date || 'N/A'}</td>
            <td class="border border-white/10 px-4 py-2 text-sm" title="${escapeAttr(result.user || '')}">${userDisplay}</td>
            <td class="border border-white/10 px-4 py-2 text-sm font-mono" title="${escapeAttr(result.ref || '')}">${ticketDisplay || '<span class="text-secondary">-</span>'}</td>
            <td class="border border-white/10 px-4 py-2 text-sm" title="${escapeAttr(result.comment || '')}" dir="${typeof detectTextDir==='function'?detectTextDir(result.comment||''):'auto'}">${commentDisplay}</td>
            <td class="border border-white/10 px-4 py-2 text-sm">${tagsDisplay}</td>
            <td class="border border-white/10 px-4 py-2 text-sm" title="${escapeAttr(result.campaign_name || '')}">${campaignDisplay || '<span class="text-secondary">-</span>'}</td>
            <td class="border border-white/10 px-4 py-2">${expirationBadge}</td>
            ${actionsCell}
        `;

        resultsTableBody.appendChild(row);
    }

    function _bindSearchRowActions() {
        resultsTableBody.querySelectorAll('[data-action="edit"]').forEach(btn => {
            btn.addEventListener('click', function() {
                const row = this.closest('tr');
                openEditModal(
                    row.dataset.iocValue,
                    row.dataset.iocType,
                    row.dataset.comment,
                    row.dataset.expiration,
                    row.dataset.campaign || '',
                    row.dataset.ticketId || '',
                    row.dataset.tags || '',
                    row.dataset.analyst || ''
                );
            });
        });
        resultsTableBody.querySelectorAll('[data-action="delete"]').forEach(btn => {
            btn.addEventListener('click', function() {
                const row = this.closest('tr');
                openDeleteIocModal(row.dataset.iocValue, row.dataset.iocType);
            });
        });
        resultsTableBody.querySelectorAll('[data-action="history"]').forEach(btn => {
            btn.addEventListener('click', function() {
                const row = this.closest('tr');
                openIocHistoryModal(row.dataset.iocType, row.dataset.iocValue);
            });
        });
        resultsTableBody.querySelectorAll('[data-action="add-note"]').forEach(btn => {
            btn.addEventListener('click', function() {
                const row = this.closest('tr');
                openAddNoteModal(row.dataset.iocType, row.dataset.iocValue);
            });
        });
        resultsTableBody.querySelectorAll('[data-action="view-yara"]').forEach(btn => {
            btn.addEventListener('click', function() {
                if (typeof switchTab === 'function') switchTab('yara');
            });
        });
        resultsTableBody.querySelectorAll('[data-action="edit-yara-meta"]').forEach(btn => {
            btn.addEventListener('click', function() {
                const row = this.closest('tr');
                if (typeof openYaraMetaEditModal === 'function') {
                    openYaraMetaEditModal(
                        row.dataset.iocValue,
                        row.dataset.ticketId || '',
                        row.dataset.comment || '',
                        row.dataset.campaign || ''
                    );
                }
            });
        });
        resultsTableBody.querySelectorAll('[data-action="open-campaign-graph"]').forEach(btn => {
            btn.addEventListener('click', function() {
                const row = this.closest('tr');
                const cid = row.dataset.campaignId;
                const idNum = cid ? parseInt(cid, 10) : NaN;
                if (typeof global.switchTab === 'function') {
                    global.switchTab('campaigns');
                }
                if (!isNaN(idNum) && typeof global.renderGraph === 'function') {
                    setTimeout(function() { global.renderGraph(idNum); }, 150);
                }
            });
        });
    }

    function showNoResults() {
        searchResults.classList.add('hidden');
        searchNoResults.classList.remove('hidden');
    }

    function highlightMatch(text, query) {
        if (!query || !text) return escapeHtml(text || '');
        const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const re = new RegExp('(' + escaped + ')', 'gi');
        const parts = String(text).split(re);
        return parts.map((part, i) => i % 2 === 1
            ? '<span class="bg-yellow-500/40 text-white rounded px-1">' + escapeHtml(part) + '</span>'
            : escapeHtml(part)).join('');
    }

    // Delete IOC modal and revoke
    const deleteIocModal = document.getElementById('deleteIocModal');
    const deleteIocReason = document.getElementById('deleteIocReason');
    const deleteIocReasonError = document.getElementById('deleteIocReasonError');

    function openDeleteIocModal(value, type) {
        document.getElementById('deleteIocValue').value = value || '';
        document.getElementById('deleteIocType').value = type || '';
        if (deleteIocReason) { deleteIocReason.value = ''; deleteIocReason.removeAttribute('dir'); deleteIocReason.setAttribute('dir', 'ltr'); }
        if (deleteIocReasonError) { deleteIocReasonError.textContent = ''; deleteIocReasonError.classList.add('hidden'); }
        if (deleteIocModal) deleteIocModal.classList.remove('hidden');
    }
    if (deleteIocReason && typeof window.detectDir === 'function') {
        deleteIocReason.addEventListener('input', function () {
            this.setAttribute('dir', window.detectDir(this.value));
        });
        deleteIocReason.addEventListener('keyup', function () {
            this.setAttribute('dir', window.detectDir(this.value));
        });
    }

    document.getElementById('deleteIocCancel')?.addEventListener('click', () => {
        if (deleteIocModal) deleteIocModal.classList.add('hidden');
    });
    deleteIocModal?.addEventListener('click', (e) => {
        if (e.target === deleteIocModal) deleteIocModal.classList.add('hidden');
    });

    document.getElementById('deleteIocSubmit')?.addEventListener('click', async () => {
        const value = document.getElementById('deleteIocValue')?.value?.trim();
        const type = document.getElementById('deleteIocType')?.value?.trim();
        const reason = (deleteIocReason?.value || '').trim();
        if (!reason) {
            if (deleteIocReasonError) {
                deleteIocReasonError.textContent = (typeof t === 'function' && t('delete_modal.reason_required')) ? t('delete_modal.reason_required') : 'Please provide a reason for deletion.';
                deleteIocReasonError.classList.remove('hidden');
            }
            return;
        }
        if (deleteIocReasonError) { deleteIocReasonError.textContent = ''; deleteIocReasonError.classList.add('hidden'); }
        await revokeIOC(value, type, reason);
        if (deleteIocModal) deleteIocModal.classList.add('hidden');
    });

    async function revokeIOC(value, type, reason) {
        try {
            const response = await fetch('/api/revoke', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ value: value, type: type, reason: reason || '' })
            });
            let result;
            try {
                const text = await response.text();
                result = JSON.parse(text);
            } catch (parseErr) {
                // Server returned HTML or invalid JSON (e.g. redirect, 500 error page)
                if (response.status === 401 || response.status === 403) {
                    result = { success: false, message: 'Session expired or access denied. Please refresh and log in again.', require_login: true };
                } else {
                    result = { success: false, message: 'Server error (status ' + response.status + '). Please refresh and try again. If it persists, check server logs.' };
                }
            }
            if (result.require_password_change) {
                showToast(result.message || 'Password change required', 'error');
                window.location.href = '/change-password';
                return;
            }
            if (result.require_login) {
                showToast(result.message || 'Please log in again', 'error');
                window.location.href = '/login';
                return;
            }
            if (result.success) {
                showToast(result.message, 'success');
                // On revoke, only show achievement popup when something positive happened (no "0 points" popup)
                if (typeof showAchievementModal === 'function' && (result.new_badges || result.level_up || result.rank_up || result.new_nickname || (result.points_earned !== undefined && result.points_earned > 0))) {
                    showAchievementModal(result);
                }
                performSearch();
                if (typeof loadStats === 'function') loadStats();
                if (typeof loadLiveFeed === 'function') loadLiveFeed();
                const feedPulseTab = document.getElementById('feed-pulse');
                if (feedPulseTab && !feedPulseTab.classList.contains('hidden') && typeof loadFeedPulse === 'function') {
                    loadFeedPulse();
                }
            } else {
                showToast(result.message, 'error');
            }
        } catch (error) {
            showToast((typeof t === 'function' && t('toast.error_revoke')) ? t('toast.error_revoke') + ': ' + error.message : 'Failed to revoke: ' + error.message, 'error');
        }
    }

    // Edit Modal
    const editModal = document.getElementById('editModal');
    const editForm = document.getElementById('editForm');
    const cancelEdit = document.getElementById('cancelEdit');

    async function openEditModal(iocValue, iocType, comment, expiration, campaignName, ticketId, tagsStr, analystStr) {
        if (typeof loadUsersForAssignDropdown === 'function') await loadUsersForAssignDropdown();
        document.getElementById('editIocValue').value = iocValue;
        document.getElementById('editIocType').value = iocType;
        document.getElementById('editIocDisplay').value = `${iocType}: ${iocValue}`;
        const editCommentEl = document.getElementById('editComment');
        editCommentEl.value = comment;
        if (typeof detectTextDir === 'function') editCommentEl.dir = detectTextDir(comment);
        let expDisplay = expiration === 'NEVER' ? t('ttl.permanent') : expiration;
        document.getElementById('editExpiration').value = expDisplay;
        document.getElementById('editTicketId').value = ticketId || '';
        const editTagsEl = document.getElementById('editTags');
        if (editTagsEl) editTagsEl.value = tagsStr || '';
        const editCampaignSelect = document.getElementById('editCampaignSelect');
        if (editCampaignSelect) {
            editCampaignSelect.value = (campaignName != null && campaignName !== '') ? campaignName : '';
        }
        const editAssignTo = document.getElementById('editAssignTo');
        if (editAssignTo) {
            const want = (analystStr || '').trim().toLowerCase();
            let found = false;
            for (let i = 0; i < editAssignTo.options.length; i++) {
                if ((editAssignTo.options[i].value || '').toLowerCase() === want) {
                    editAssignTo.selectedIndex = i;
                    found = true;
                    break;
                }
            }
            if (!found) editAssignTo.selectedIndex = 0;
        }
        editModal.classList.remove('hidden');
    }

    if (cancelEdit) {
        cancelEdit.addEventListener('click', () => {
            editModal.classList.add('hidden');
        });
    }

    if (editModal) {
        editModal.addEventListener('click', (e) => {
            if (e.target === editModal) {
                editModal.classList.add('hidden');
            }
        });
    }

    if (editForm) {
        editForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const iocValue = document.getElementById('editIocValue').value;
            const iocType = document.getElementById('editIocType').value;
            const comment = document.getElementById('editComment').value;
            let expiration = document.getElementById('editExpiration').value.trim();
            const editCampaignSelect = document.getElementById('editCampaignSelect');
            const campaign_name = editCampaignSelect && editCampaignSelect.value ? editCampaignSelect.value : '';

            if (expiration.toLowerCase() === 'permanent' || expiration === t('ttl.permanent')) {
                expiration = 'Permanent';
            }

            const ticketId = document.getElementById('editTicketId').value.trim();
            const editTagsEl = document.getElementById('editTags');
            const tagsStr = editTagsEl
                ? (typeof normalizeTagsInputValue === 'function'
                    ? normalizeTagsInputValue(editTagsEl.value)
                    : editTagsEl.value.trim())
                : '';
            const editAssignTo = document.getElementById('editAssignTo');
            const assignToVal = editAssignTo && editAssignTo.value ? editAssignTo.value.trim() : '';
            const payload = {
                value: iocValue,
                type: iocType,
                comment: comment,
                expiration: expiration,
                ticket_id: ticketId
            };
            if (campaign_name !== undefined) payload.campaign_name = campaign_name;
            if (tagsStr) payload.tags = tagsStr.split(',').map(s => s.trim()).filter(Boolean);
            if (assignToVal) payload.analyst = assignToVal;

            try {
                const response = await fetch('/api/edit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const result = await response.json();

                if (result.success) {
                    showToast(result.message, 'success');
                    if (typeof showAchievementModal === 'function' && (result.new_badges || result.level_up || result.rank_up || result.points_earned !== undefined || result.level_info || result.new_nickname)) {
                        showAchievementModal(result);
                    }
                    editModal.classList.add('hidden');
                    performSearch();
                    if (typeof loadStats === 'function') loadStats();
                    if (typeof loadLiveFeed === 'function') loadLiveFeed();
                } else {
                    if (result && Array.isArray(result.invalid_tags) && result.invalid_tags.length && result.suggest_allowed && typeof window.appConfirm === 'function') {
                        try {
                            const list = result.invalid_tags.slice(0, 10).join(', ') + (result.invalid_tags.length > 10 ? '…' : '');
                            const ok = await window.appConfirm({
                                title: (typeof t === 'function' && t('tags.suggest_title')) ? t('tags.suggest_title') : 'Suggest new tag(s)?',
                                message: ((typeof t === 'function' && t('tags.suggest_message')) ? t('tags.suggest_message') : 'These tags are not allowed yet:') + '\n\n' + list,
                                okText: (typeof t === 'function' && t('tags.suggest_ok')) ? t('tags.suggest_ok') : 'Suggest',
                                cancelText: (typeof t === 'function' && t('tags.suggest_cancel')) ? t('tags.suggest_cancel') : 'Cancel'
                            });
                            if (ok) {
                                const r2 = await fetch('/api/tags/suggest', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ tags: result.invalid_tags })
                                });
                                const d2 = await r2.json().catch(() => ({}));
                                if (d2 && d2.success) showToast((typeof t === 'function' && t('tags.suggested')) ? t('tags.suggested') : 'Suggestion submitted to admin for approval.', 'success');
                                else showToast((d2 && d2.message) ? d2.message : 'Failed to suggest tags', 'error');
                                return;
                            }
                        } catch (e) { /* ignore */ }
                    }
                    showToast(result.message, 'error');
                }
            } catch (error) {
                showToast(t('toast.error_update') + ': ' + error.message, 'error');
            }
        });
    }

    // IOC History modal
    const iocHistoryModal = document.getElementById('iocHistoryModal');
    const iocHistoryTitle = document.getElementById('iocHistoryTitle');
    const iocHistoryList = document.getElementById('iocHistoryList');
    const iocHistoryClose = document.getElementById('iocHistoryClose');
    const iocNotesList = document.getElementById('iocNotesList');
    const iocHistoryNotesSection = document.getElementById('iocHistoryNotesSection');

    // Add Note modal
    const addNoteModal = document.getElementById('addNoteModal');
    const addNoteIocLabel = document.getElementById('addNoteIocLabel');
    const addNoteContent = document.getElementById('addNoteContent');
    const addNoteSubmitBtn = document.getElementById('addNoteSubmitBtn');
    const addNoteCancel = document.getElementById('addNoteCancel');

    let _noteIocType = '';
    let _noteIocValue = '';

    function _renderNoteHtml(note) {
        const dateStr = note.created_at ? new Date(note.created_at).toLocaleString() : '';
        const by = note.username ? escapeHtml(note.username) : '-';
        return '<div class="border border-amber-400/20 rounded px-3 py-2 bg-amber-950/20">'
            + '<div class="flex justify-between items-center mb-1">'
            + '<span class="font-semibold text-amber-200 text-xs">' + by + '</span>'
            + '<span class="text-secondary text-xs">' + dateStr + '</span>'
            + '</div>'
            + '<div class="text-white/90 whitespace-pre-wrap break-words" dir="' + (typeof detectTextDir==='function'?detectTextDir(note.content):'auto') + '">' + escapeHtml(note.content) + '</div>'
            + '</div>';
    }

    async function _loadNotes(iocType, iocValue) {
        if (!iocNotesList) return;
        const noNotesText = (typeof t === 'function' && t('notes.empty')) ? t('notes.empty') : 'No notes yet.';
        iocNotesList.innerHTML = '<div class="text-secondary text-xs">' + escapeHtml(noNotesText) + '</div>';
        try {
            const r = await fetch('/api/ioc-notes?type=' + encodeURIComponent(iocType) + '&value=' + encodeURIComponent(iocValue));
            const j = await r.json();
            if (!j.success) return;
            const notes = j.notes || [];
            if (notes.length === 0) {
                if (iocHistoryNotesSection) iocHistoryNotesSection.classList.add('hidden');
                return;
            }
            if (iocHistoryNotesSection) iocHistoryNotesSection.classList.remove('hidden');
            iocNotesList.innerHTML = notes.map(_renderNoteHtml).join('');
            iocNotesList.scrollTop = iocNotesList.scrollHeight;
        } catch (_) { /* silent */ }
    }

    async function openIocHistoryModal(iocType, iocValue) {
        if (!iocHistoryModal || !iocHistoryList) return;
        const titleText = (typeof t === 'function' && t('actions.history')) ? t('actions.history') : 'History';
        iocHistoryTitle.textContent = titleText + ' - ' + (iocType || '') + ': ' + (iocValue || '');
        iocHistoryList.innerHTML = '<div class="text-secondary">Loading...</div>';
        if (iocHistoryNotesSection) iocHistoryNotesSection.classList.add('hidden');
        iocHistoryModal.classList.remove('hidden');

        _loadNotes(iocType, iocValue);

        try {
            const r = await fetch('/api/ioc-history?type=' + encodeURIComponent(iocType || '') + '&value=' + encodeURIComponent(iocValue || ''));
            const j = await r.json();
            if (!j.success) {
                iocHistoryList.innerHTML = '<div class="text-red-400">' + escapeHtml(j.message || 'Failed to load history') + '</div>';
                return;
            }
            const events = j.events || [];
            if (events.length === 0) {
                iocHistoryList.innerHTML = '<div class="text-secondary">' + (typeof t === 'function' && t('history.empty') ? t('history.empty') : 'No history recorded for this IOC.') + '</div>';
                return;
            }
            const labels = {
                created: (typeof t === 'function' && t('history.created')) ? t('history.created') : 'Created',
                edited: (typeof t === 'function' && t('history.edited')) ? t('history.edited') : 'Edited',
                deleted: (typeof t === 'function' && t('history.deleted')) ? t('history.deleted') : 'Deleted',
                expired: (typeof t === 'function' && t('history.expired')) ? t('history.expired') : 'Expired',
                excluded: (typeof t === 'function' && t('history.excluded')) ? t('history.excluded') : 'Excluded',
                unexcluded: (typeof t === 'function' && t('history.unexcluded')) ? t('history.unexcluded') : 'Un-excluded'
            };
            iocHistoryList.innerHTML = events.map(ev => {
                const atStr = ev.at ? new Date(ev.at).toLocaleString() : '';
                const by = ev.username ? escapeHtml(ev.username) : '-';
                let byLine = (typeof t === 'function' && t('history.by') ? t('history.by') : 'by') + ' ' + by;
                if (ev.event_type === 'created' && ev.payload && ev.payload.entered_by != null && ev.payload.assigned_to != null) {
                    const enteredByLabel = (typeof t === 'function' && t('history.entered_by')) ? t('history.entered_by') : 'Entered by';
                    const assignedToLabel = (typeof t === 'function' && t('history.assigned_to')) ? t('history.assigned_to') : 'assigned to';
                    byLine = escapeHtml(enteredByLabel) + ' <span class="font-medium">' + escapeHtml(String(ev.payload.entered_by || '')) + '</span>, ' + escapeHtml(assignedToLabel) + ' <span class="font-medium">' + escapeHtml(String(ev.payload.assigned_to || '')) + '</span>';
                }
                let extra = '';
                if (ev.event_type === 'created' && ev.payload && ev.payload.expiration_date) {
                    extra = ' <span class="text-secondary">(expires: ' + escapeHtml(String(ev.payload.expiration_date).slice(0, 10)) + ')</span>';
                }
                if (ev.event_type === 'created' && iocType === 'YARA' && ev.payload) {
                    const p = ev.payload;
                    const ticketL = (typeof t === 'function' && t('history.field_ticket_id')) ? t('history.field_ticket_id') : 'Ticket ID';
                    const campL = (typeof t === 'function' && t('history.field_campaign')) ? t('history.field_campaign') : 'Campaign';
                    const descL = (typeof t === 'function' && t('history.field_comment')) ? t('history.field_comment') : 'Description';
                    const statusL = (typeof t === 'function' && t('history.yara_status')) ? t('history.yara_status') : 'Rule status';
                    const metaBits = [];
                    if (p.ticket_id) metaBits.push('<span class="text-secondary">' + escapeHtml(ticketL) + ':</span> ' + escapeHtml(String(p.ticket_id)));
                    if (p.campaign) metaBits.push('<span class="text-secondary">' + escapeHtml(campL) + ':</span> ' + escapeHtml(String(p.campaign)));
                    if (p.rule_status) metaBits.push('<span class="text-secondary">' + escapeHtml(statusL) + ':</span> ' + escapeHtml(String(p.rule_status)));
                    if (p.comment) {
                        const cdir = (typeof detectTextDir === 'function') ? detectTextDir(String(p.comment)) : 'auto';
                        metaBits.push('<span class="text-secondary">' + escapeHtml(descL) + ':</span> <span dir="' + cdir + '">' + escapeHtml(String(p.comment)) + '</span>');
                    }
                    if (metaBits.length) {
                        extra += ' <div class="mt-2 space-y-1 text-sm text-cyan-100/85">' + metaBits.join('<br>') + '</div>';
                    }
                }
                if (ev.event_type === 'deleted' && ev.payload && ev.payload.reason) {
                    const reasonLabel = (typeof t === 'function' && t('history.deleted_reason')) ? t('history.deleted_reason') : 'Reason';
                    extra += ' <div class="mt-2 text-amber-200/90"><span class="font-semibold">' + escapeHtml(reasonLabel) + ':</span> ' + escapeHtml(ev.payload.reason) + '</div>';
                }
                if (ev.event_type === 'deleted' && iocType === 'YARA' && ev.payload) {
                    const p = ev.payload;
                    const oup = (typeof t === 'function' && t('history.yara_original_uploader')) ? t('history.yara_original_uploader') : 'Original uploader';
                    const dl = (typeof t === 'function' && t('history.field_comment')) ? t('history.field_comment') : 'Description';
                    if (p.original_analyst) {
                        extra += '<div class="mt-1 text-sm text-cyan-200/75"><span class="font-semibold">' + escapeHtml(oup) + ':</span> ' + escapeHtml(String(p.original_analyst)) + '</div>';
                    }
                    if (p.original_comment) {
                        const cdir = (typeof detectTextDir === 'function') ? detectTextDir(String(p.original_comment)) : 'auto';
                        extra += '<div class="mt-1 text-sm text-cyan-100/80"><span class="text-secondary">' + escapeHtml(dl) + ':</span> <span dir="' + cdir + '">' + escapeHtml(String(p.original_comment)) + '</span></div>';
                    }
                }
                if ((ev.event_type === 'excluded' || ev.event_type === 'unexcluded') && ev.payload && ev.payload.anomaly_type) {
                    extra += ' <span class="text-secondary">(anomaly: ' + escapeHtml(ev.payload.anomaly_type) + ')</span>';
                }
                if (ev.event_type === 'edited' && ev.payload && ev.payload.reason && (!ev.payload.changes || !ev.payload.changes.length)) {
                    const rl = (typeof t === 'function' && t('history.yara_edit_reason')) ? t('history.yara_edit_reason') : 'Change reason';
                    const dirReason = (typeof detectTextDir === 'function') ? detectTextDir(String(ev.payload.reason)) : 'auto';
                    extra += ' <div class="mt-2 text-cyan-100/90"><span class="font-semibold">' + escapeHtml(rl) + ':</span> <span class="whitespace-pre-wrap" dir="' + dirReason + '">' + escapeHtml(String(ev.payload.reason)) + '</span></div>';
                }
                if (ev.event_type === 'edited' && ev.payload && ev.payload.changes && ev.payload.changes.length) {
                    const fieldLabels = { comment: (typeof t === 'function' && t('history.field_comment')) ? t('history.field_comment') : 'Comment', expiration: (typeof t === 'function' && t('history.field_expiration')) ? t('history.field_expiration') : 'Expiration', ticket_id: (typeof t === 'function' && t('history.field_ticket_id')) ? t('history.field_ticket_id') : 'Ticket ID', campaign: (typeof t === 'function' && t('history.field_campaign')) ? t('history.field_campaign') : 'Campaign', tags: (typeof t === 'function' && t('history.field_tags')) ? t('history.field_tags') : 'Tags', analyst: (typeof t === 'function' && t('history.field_analyst')) ? t('history.field_analyst') : 'Assigned to' };
                    const arrow = (typeof t === 'function' && t('history.to')) ? t('history.to') : '→';
                    extra += ' <div class="mt-2 space-y-1 text-sm">' + ev.payload.changes.map(function(c) {
                        const label = fieldLabels[c.field] || c.field;
                        const dirAttr = (c.field === 'comment' && typeof detectTextDir === 'function') ? ' dir="' + detectTextDir(String(c.new)) + '"' : '';
                        return '<div class="text-cyan-200/90"' + dirAttr + '><span class="font-semibold">' + escapeHtml(label) + ':</span> <span class="text-secondary line-through">' + escapeHtml(String(c.old)) + '</span> ' + escapeHtml(arrow) + ' <span class="text-green-200/90">' + escapeHtml(String(c.new)) + '</span></div>';
                    }).join('') + '</div>';
                }
                return '<div class="border border-white/10 rounded px-3 py-2 bg-tertiary/50"><span class="font-semibold">' + (labels[ev.event_type] || ev.event_type) + '</span> - ' + byLine + ' <span class="text-secondary">' + atStr + '</span>' + extra + '</div>';
            }).join('');
        } catch (e) {
            iocHistoryList.innerHTML = '<div class="text-red-400">' + escapeHtml(e.message || 'Error loading history') + '</div>';
        }
    }

    function openAddNoteModal(iocType, iocValue) {
        if (!addNoteModal) return;
        _noteIocType = iocType || '';
        _noteIocValue = iocValue || '';
        if (addNoteIocLabel) addNoteIocLabel.textContent = _noteIocType + ': ' + _noteIocValue;
        if (addNoteContent) addNoteContent.value = '';
        addNoteModal.classList.remove('hidden');
        if (addNoteContent) addNoteContent.focus();
    }

    async function _submitNote() {
        if (!addNoteContent || !_noteIocType || !_noteIocValue) return;
        const content = addNoteContent.value.trim();
        if (!content) return;
        if (addNoteSubmitBtn) addNoteSubmitBtn.disabled = true;
        try {
            const r = await fetch('/api/ioc-notes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: _noteIocType, value: _noteIocValue, content: content })
            });
            const j = await r.json();
            if (j.success) {
                addNoteModal.classList.add('hidden');
                showToast((typeof t === 'function' && t('notes.added')) ? t('notes.added') : 'Note added', 'success');
                if (typeof showAchievementModal === 'function' && (j.new_badges || j.level_up || j.rank_up || j.points_earned !== undefined || j.level_info || j.new_nickname)) {
                    showAchievementModal(j);
                }
            } else {
                showToast((j.message || 'Failed to add note'), 'error');
            }
        } catch (e) {
            showToast(e.message || 'Error', 'error');
        } finally {
            if (addNoteSubmitBtn) addNoteSubmitBtn.disabled = false;
        }
    }

    if (addNoteSubmitBtn) addNoteSubmitBtn.addEventListener('click', _submitNote);
    if (addNoteCancel) addNoteCancel.addEventListener('click', () => { if (addNoteModal) addNoteModal.classList.add('hidden'); });
    if (addNoteModal) addNoteModal.addEventListener('click', (e) => { if (e.target === addNoteModal) addNoteModal.classList.add('hidden'); });

    if (iocHistoryClose) iocHistoryClose.addEventListener('click', () => { if (iocHistoryModal) iocHistoryModal.classList.add('hidden'); });
    if (iocHistoryModal) iocHistoryModal.addEventListener('click', (e) => { if (e.target === iocHistoryModal) iocHistoryModal.classList.add('hidden'); });

    // Auto-detect RTL/LTR for Edit modal comment field and Add Note textarea
    if (typeof applyAutoDir === 'function') {
        applyAutoDir(document.getElementById('editComment'));
        applyAutoDir(document.getElementById('addNoteContent'));
    }

    global.performSearch = performSearch;
    global.loadSearchCountryCodes = loadSearchBrowseSelect;
    global.loadSearchBrowseSelect = loadSearchBrowseSelect;
    global.openEditModal = openEditModal;
    global.openDeleteIocModal = openDeleteIocModal;
    global.revokeIOC = revokeIOC;
    global.openIocHistoryModal = openIocHistoryModal;
    global.openAddNoteModal = openAddNoteModal;
    global.getExpirationBadge = getExpirationBadge;
    global.highlightMatch = highlightMatch;
})(typeof window !== 'undefined' ? window : this);
