/**
 * Shared JS helpers (Step 8 — extracted from index.html).
 * Exposed on window so inline script and other modules can use them.
 */
(function(global) {
    'use strict';

    function escapeHtml(text) {
        if (text == null || text === '') return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function escapeAttr(text) {
        if (text == null || text === '') return '';
        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/"/g, '&quot;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    async function copyToClipboard(text) {
        if (text == null || text === '') return;
        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(text);
                if (typeof global.showToast === 'function' && typeof global.t === 'function') {
                    global.showToast(global.t('toast.copied'), 'success');
                }
                return;
            }
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.select();
            try {
                document.execCommand('copy');
                if (typeof global.showToast === 'function' && typeof global.t === 'function') {
                    global.showToast(global.t('toast.copied'), 'success');
                }
            } catch (e) {
                if (typeof global.showToast === 'function' && typeof global.t === 'function') {
                    global.showToast(global.t('toast.copy_failed'), 'error');
                }
            }
            document.body.removeChild(ta);
        } catch (err) {
            if (typeof global.showToast === 'function' && typeof global.t === 'function') {
                global.showToast(global.t('toast.copy_failed'), 'error');
            }
        }
    }

    global.escapeHtml = escapeHtml;
    global.escapeAttr = escapeAttr;
    global.copyToClipboard = copyToClipboard;
})(typeof window !== 'undefined' ? window : this);
