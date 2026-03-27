/**
 * IOC tags: autocomplete from GET /api/tags?q= (prefix match on existing tags).
 * Dropdown uses fixed positioning so it is not clipped inside modals.
 * Blur + submit paths: lowercase / dedupe via normalizeTagsInputValue.
 */
(function (global) {
    'use strict';

    var DEBOUNCE_MS = 180;
    var MAX_SUGGEST = 20;
    var _docClickBound = false;

    function debounce(fn, ms) {
        var t;
        return function () {
            var self = this;
            var args = arguments;
            clearTimeout(t);
            t = setTimeout(function () { fn.apply(self, args); }, ms);
        };
    }

    function getSegmentBounds(input) {
        var v = input.value;
        var caret = input.selectionStart != null ? input.selectionStart : v.length;
        var head = v.slice(0, caret);
        var i = head.lastIndexOf(',');
        var start = i === -1 ? 0 : i + 1;
        var rest = v.slice(start);
        var nextComma = rest.indexOf(',');
        var end = nextComma === -1 ? v.length : start + nextComma;
        return { start: start, end: end, token: v.slice(start, end).trim() };
    }

    function normalizeTagsInputValue(raw) {
        var parts = raw.split(',').map(function (s) { return s.trim().toLowerCase(); }).filter(Boolean);
        var seen = {};
        var out = [];
        for (var i = 0; i < parts.length; i++) {
            if (!seen[parts[i]]) {
                seen[parts[i]] = true;
                out.push(parts[i]);
            }
        }
        return out.join(', ');
    }

    function hideDropdown(ul) {
        if (!ul) return;
        ul.classList.add('hidden');
        ul.innerHTML = '';
    }

    function positionDropdown(ul, input) {
        if (!ul || !input) return;
        var r = input.getBoundingClientRect();
        ul.style.position = 'fixed';
        ul.style.left = r.left + 'px';
        ul.style.top = (r.bottom + 4) + 'px';
        ul.style.minWidth = Math.max(r.width, 200) + 'px';
        ul.style.maxWidth = 'min(100vw - 16px, 420px)';
        ul.style.zIndex = '30000';
    }

    function bindDocClickOnce() {
        if (_docClickBound) return;
        _docClickBound = true;
        document.addEventListener('click', function (e) {
            document.querySelectorAll('.tag-autocomplete-dd').forEach(function (ul) {
                if (ul.classList.contains('hidden')) return;
                var inp = ul._tagInput;
                if (inp && (inp === e.target || inp.contains(e.target))) return;
                if (ul.contains(e.target)) return;
                hideDropdown(ul);
            });
        });
        window.addEventListener('scroll', function () {
            document.querySelectorAll('.tag-autocomplete-dd:not(.hidden)').forEach(function (ul) {
                if (ul._tagInput) positionDropdown(ul, ul._tagInput);
            });
        }, true);
        window.addEventListener('resize', function () {
            document.querySelectorAll('.tag-autocomplete-dd:not(.hidden)').forEach(function (ul) {
                if (ul._tagInput) positionDropdown(ul, ul._tagInput);
            });
        });
    }

    function attach(input) {
        if (!input || input.getAttribute('data-tags-autocomplete') === '1') return;
        input.setAttribute('data-tags-autocomplete', '1');
        bindDocClickOnce();

        var wrap = input.parentElement;
        if (!wrap || !wrap.classList.contains('tag-autocomplete-wrap')) {
            wrap = document.createElement('div');
            wrap.className = 'tag-autocomplete-wrap relative w-full';
            input.parentNode.insertBefore(wrap, input);
            wrap.appendChild(input);
        }

        var ul = document.createElement('ul');
        ul.className = 'tag-autocomplete-dd hidden max-h-48 overflow-y-auto rounded border border-white/15 bg-[#0f172a] shadow-xl text-sm';
        ul.setAttribute('role', 'listbox');
        ul._tagInput = input;
        document.body.appendChild(ul);
        input._tagDropdownUl = ul;

        function runFetch() {
            var b = getSegmentBounds(input);
            var q = b.token.toLowerCase();
            if (!q) {
                hideDropdown(ul);
                return;
            }
            fetch('/api/tags?q=' + encodeURIComponent(q), { credentials: 'same-origin', headers: { Accept: 'application/json' } })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (!data || !data.success || !Array.isArray(data.tags)) {
                        hideDropdown(ul);
                        return;
                    }
                    var list = data.tags.filter(function (t) { return t && String(t).trim(); }).slice(0, MAX_SUGGEST);
                    if (!list.length) {
                        hideDropdown(ul);
                        return;
                    }
                    ul.innerHTML = '';
                    list.forEach(function (tag) {
                        var li = document.createElement('li');
                        li.className = 'cursor-pointer px-3 py-1.5 hover:bg-white/10 text-primary';
                        li.setAttribute('role', 'option');
                        li.textContent = tag;
                        li.addEventListener('mousedown', function (e) {
                            e.preventDefault();
                            var v = input.value;
                            var bb = getSegmentBounds(input);
                            var before = v.slice(0, bb.start);
                            var after = v.slice(bb.end);
                            var newVal = before + tag + ', ' + after.replace(/^\s*,?\s*/, '');
                            input.value = newVal;
                            var pos = before.length + String(tag).length + 2;
                            input.focus();
                            try {
                                input.setSelectionRange(pos, pos);
                            } catch (err) { /* ignore */ }
                            hideDropdown(ul);
                        });
                        ul.appendChild(li);
                    });
                    positionDropdown(ul, input);
                    ul.classList.remove('hidden');
                })
                .catch(function () { hideDropdown(ul); });
        }

        var fetchSuggestions = debounce(runFetch, DEBOUNCE_MS);

        input.addEventListener('input', fetchSuggestions);
        input.addEventListener('focus', function () {
            var b = getSegmentBounds(input);
            if (b.token.length) runFetch();
        });
        input.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') hideDropdown(ul);
        });
        input.addEventListener('blur', function () {
            setTimeout(function () {
                hideDropdown(ul);
                input.value = normalizeTagsInputValue(input.value);
            }, 200);
        });
    }

    function initTagAutocomplete(ids) {
        if (!Array.isArray(ids)) return;
        ids.forEach(function (id) {
            var el = document.getElementById(id);
            if (el) attach(el);
        });
    }

    global.initTagAutocomplete = initTagAutocomplete;
    global.normalizeTagsInputValue = normalizeTagsInputValue;
})(typeof window !== 'undefined' ? window : this);
