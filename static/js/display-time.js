/**
 * Display UTC ISO timestamps in the configured site timezone (default Asia/Jerusalem).
 * DB and APIs remain UTC; use only when rendering in the browser.
 */
(function (global) {
    'use strict';

    var TZ = global.ZIOCHUB_DISPLAY_TZ || 'UTC';

    var _dtfFull = null;
    var _dtfDate = null;

    function dtfFull() {
        if (!_dtfFull) {
            _dtfFull = new Intl.DateTimeFormat('en-GB', {
                timeZone: TZ,
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
            });
        }
        return _dtfFull;
    }

    function dtfDateOnly() {
        if (!_dtfDate) {
            _dtfDate = new Intl.DateTimeFormat('en-GB', {
                timeZone: TZ,
                year: 'numeric',
                month: '2-digit',
                day: '2-digit'
            });
        }
        return _dtfDate;
    }

    /** Normalize API/DB string to a Date interpreted as UTC. */
    function parseUtcDate(iso) {
        if (iso == null || iso === '') return null;
        var s = String(iso).trim();
        if (!s) return null;
        if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(s) && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(s)) {
            s = s.replace(' ', 'T') + 'Z';
        }
        var d = new Date(s);
        return isNaN(d.getTime()) ? null : d;
    }

    function formatUtcToLocal(iso) {
        var d = parseUtcDate(iso);
        if (!d) return iso == null ? '' : String(iso);
        return dtfFull().format(d);
    }

    function formatUtcToLocalDate(iso) {
        var d = parseUtcDate(iso);
        if (!d) return iso == null ? '' : String(iso);
        return dtfDateOnly().format(d);
    }

    global.formatUtcToLocal = formatUtcToLocal;
    global.formatUtcToLocalDate = formatUtcToLocalDate;
    global.ziochubParseUtcDate = parseUtcDate;
})(typeof window !== 'undefined' ? window : globalThis);
