/**
 * Shared API client (Step 9 - ARCHITECTURE_GAPS_AND_STEPS.md).
 * apiFetch: centralizes fetch, response.ok check, JSON parse, result.success check, and showToast on error.
 * Exposed on window for use from index.html and other scripts.
 */
(function(global) {
    'use strict';

    /**
     * Call API and return parsed JSON. On HTTP error or result.success === false, shows toast and returns null or result.
     * @param {string} url - Request URL
     * @param {RequestInit} [options] - fetch options (method, headers, body, etc.)
     * @returns {Promise<object|null>} - Parsed JSON result, or null on network/HTTP error
     */
    async function apiFetch(url, options) {
        const opts = { credentials: 'same-origin', ...options };
        try {
            const response = await fetch(url, opts);
            let result = null;
            try {
                const text = await response.text();
                if (text) result = JSON.parse(text);
            } catch (e) {
                if (!response.ok && typeof global.showToast === 'function') {
                    global.showToast(response.status === 500 ? 'Server error' : 'Request failed', 'error');
                }
                return null;
            }
            if (!response.ok) {
                if (typeof global.showToast === 'function') {
                    global.showToast((result && result.message) ? result.message : 'Request failed', 'error');
                }
                return null;
            }
            if (result && result.success === false) {
                if (typeof global.showToast === 'function') {
                    global.showToast(result.message || 'Error', 'error');
                }
                return result;
            }
            return result;
        } catch (err) {
            if (typeof global.showToast === 'function') {
                global.showToast(err && err.message ? err.message : 'Network error', 'error');
            }
            console.error('apiFetch error:', err);
            return null;
        }
    }

    global.apiFetch = apiFetch;
})(typeof window !== 'undefined' ? window : this);
