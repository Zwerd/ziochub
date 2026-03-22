/**
 * Shared JS helpers (Step 8 - extracted from index.html).
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

    /**
     * Detect text direction from the first letter in the string.
     * Returns 'rtl' if the first letter is Hebrew/Arabic, otherwise 'ltr'.
     */
    function detectTextDir(text) {
        if (!text) return 'ltr';
        const m = text.match(/[a-zA-Z\u0590-\u05FF\u0600-\u06FF\u0700-\u074F]/);
        if (!m) return 'ltr';
        const cp = m[0].codePointAt(0);
        return (cp >= 0x0590 && cp <= 0x074F) ? 'rtl' : 'ltr';
    }

    /**
     * Apply auto-dir detection on an input/textarea element.
     * Sets dir attribute live as the user types.
     */
    function applyAutoDir(el) {
        if (!el) return;
        function update() { el.dir = detectTextDir(el.value); }
        el.addEventListener('input', update);
        update();
    }

    /**
     * Apply auto-dir to multiple elements by ID.
     */
    function initAutoDirFields(ids) {
        ids.forEach(function(id) { applyAutoDir(document.getElementById(id)); });
    }

    global.escapeHtml = escapeHtml;
    global.escapeAttr = escapeAttr;
    global.copyToClipboard = copyToClipboard;
    global.detectTextDir = detectTextDir;
    global.applyAutoDir = applyAutoDir;
    global.initAutoDirFields = initAutoDirFields;
})(typeof window !== 'undefined' ? window : this);
