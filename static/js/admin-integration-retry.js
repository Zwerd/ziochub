/**
 * Shared retry queue UI for Integrations push panels (data-retry-vendor on .integ-retry-panel).
 */
window.integRetryFields = function(prefix) {
    var en = document.getElementById(prefix + '_retry_enabled');
    var iv = document.getElementById(prefix + '_retry_interval_minutes');
    var mx = document.getElementById(prefix + '_retry_max_attempts');
    var o = {};
    if (en) o[prefix + '_retry_enabled'] = en.value || 'true';
    if (iv) o[prefix + '_retry_interval_minutes'] = iv.value || '15';
    if (mx) o[prefix + '_retry_max_attempts'] = mx.value || '3';
    return o;
};

(function() {
    function renderQueue(panel, data) {
        var summaryEl = panel.querySelector('.integ-retry-queue-summary');
        var listEl = panel.querySelector('.integ-retry-queue-list');
        if (!summaryEl) return;
        if (!data || !data.success) {
            summaryEl.textContent = (data && data.message) ? data.message : 'Could not load retry queue.';
            if (listEl) {
                listEl.classList.add('hidden');
                listEl.textContent = '';
            }
            return;
        }
        var d = data.data || data;
        var count = d.count || 0;
        summaryEl.textContent = count
            ? (count + ' queued failure(s); auto-retry every ' + (d.interval_minutes || '?') + ' min'
                + ', max ' + (d.max_attempts || '3') + ' attempts'
                + (d.enabled ? '' : ' (auto-retry disabled)'))
            : 'No queued failures.';
        if (!listEl) return;
        var items = d.items || [];
        if (!items.length) {
            listEl.classList.add('hidden');
            listEl.textContent = '';
            return;
        }
        listEl.classList.remove('hidden');
        listEl.textContent = items.map(function(it) {
            var head = it.filename
                ? ((it.kind || 'push') + ' ' + (it.filename || ''))
                : ((it.action || '?') + ' ' + (it.type || '') + ' ' + (it.value || ''));
            var maxA = d.max_attempts || 3;
            return [
                head,
                '  attempts=' + (it.attempts || 0) + '/' + maxA + ' next=' + (it.next_retry_at || '-'),
                '  err: ' + (it.last_error || '')
            ].join('\n');
        }).join('\n\n');
    }

    async function refreshQueue(panel) {
        var vendor = panel.getAttribute('data-retry-vendor');
        if (!vendor) return;
        try {
            var res = await fetch('/api/admin/integration-retry-queue?vendor=' + encodeURIComponent(vendor), {
                credentials: 'same-origin',
                headers: { 'Accept': 'application/json' }
            });
            var data = await res.json();
            renderQueue(panel, data);
        } catch (e) {
            renderQueue(panel, { success: false, message: 'Network error loading queue.' });
        }
    }

    async function runRetry(panel) {
        var vendor = panel.getAttribute('data-retry-vendor');
        if (!vendor) return;
        var btn = panel.querySelector('.integ-retry-run-btn');
        if (btn) btn.disabled = true;
        try {
            var res = await fetch('/api/admin/integration-retry', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                body: JSON.stringify({ vendor: vendor, force: false })
            });
            var data = await res.json();
            var summaryEl = panel.querySelector('.integ-retry-queue-summary');
            if (summaryEl && data.message) {
                summaryEl.textContent = data.message;
            }
            await refreshQueue(panel);
        } catch (e) {
            var summaryEl = panel.querySelector('.integ-retry-queue-summary');
            if (summaryEl) summaryEl.textContent = 'Network error during retry.';
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    function initPanel(panel) {
        var refreshBtn = panel.querySelector('.integ-retry-refresh-btn');
        var runBtn = panel.querySelector('.integ-retry-run-btn');
        if (refreshBtn) refreshBtn.addEventListener('click', function() { refreshQueue(panel); });
        if (runBtn) runBtn.addEventListener('click', function() { runRetry(panel); });
        refreshQueue(panel);
    }

    document.querySelectorAll('.integ-retry-panel[data-retry-vendor]').forEach(initPanel);
})();
