(function() {
    function tabBtnClass(on) {
        return on ? ['active', 'bg-cyan-600', 'text-white'] : ['bg-tertiary', 'text-primary'];
    }
    function setBtnActive(btn, on) {
        btn.classList.remove('active', 'bg-cyan-600', 'text-white', 'bg-tertiary', 'text-primary');
        tabBtnClass(on).forEach(function(c) { btn.classList.add(c); });
    }
    function showTopTab(name) {
        document.querySelectorAll('.integ-top-pane').forEach(function(p) { p.classList.add('hidden'); });
        var pane = document.getElementById('integ-tab-' + name);
        if (pane) pane.classList.remove('hidden');
        if (name === 'push-ioc') activatePushIocSub('cortex-xdr');
        if (name === 'push-yara') activatePushYaraSub('trellix-ex-nx');
        if (name === 'import') activateImportSub('misp');
    }
    function activatePushIocSub(tab) {
        var root = document.getElementById('integ-tab-push-ioc');
        if (!root) return;
        root.querySelectorAll('.push-ioc-sub-btn').forEach(function(b) {
            setBtnActive(b, b.getAttribute('data-tab') === tab);
        });
        root.querySelectorAll('.settings-tab-pane').forEach(function(p) { p.classList.add('hidden'); });
        var pane = document.getElementById('settings-tab-' + tab);
        if (pane) pane.classList.remove('hidden');
    }
    function activatePushYaraSub(tab) {
        var root = document.getElementById('integ-tab-push-yara');
        if (!root) return;
        root.querySelectorAll('.push-yara-sub-btn').forEach(function(b) {
            setBtnActive(b, b.getAttribute('data-tab') === tab);
        });
        root.querySelectorAll('.settings-tab-pane').forEach(function(p) { p.classList.add('hidden'); });
        var pane = document.getElementById('settings-tab-' + tab);
        if (pane) pane.classList.remove('hidden');
    }
    function activateImportSub(name) {
        var root = document.getElementById('integ-tab-import');
        if (!root) return;
        root.querySelectorAll('.import-sub-tab-btn').forEach(function(b) {
            setBtnActive(b, b.getAttribute('data-import-sub') === name);
        });
        root.querySelectorAll('.import-sub-pane').forEach(function(p) { p.classList.add('hidden'); });
        var pane = document.getElementById('import-sub-' + name);
        if (pane) pane.classList.remove('hidden');
    }
    document.querySelectorAll('.integ-top-tab-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var tab = this.getAttribute('data-integ-tab');
            document.querySelectorAll('.integ-top-tab-btn').forEach(function(b) {
                setBtnActive(b, b.getAttribute('data-integ-tab') === tab);
            });
            showTopTab(tab);
            if (history.replaceState) {
                history.replaceState(null, '', '?tab=' + encodeURIComponent(tab));
            }
        });
    });
    document.querySelectorAll('#integ-tab-push-ioc .push-ioc-sub-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            activatePushIocSub(this.getAttribute('data-tab'));
        });
    });
    document.querySelectorAll('#integ-tab-push-yara .push-yara-sub-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            activatePushYaraSub(this.getAttribute('data-tab'));
        });
    });
    document.querySelectorAll('#integ-tab-import .import-sub-tab-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            activateImportSub(this.getAttribute('data-import-sub'));
        });
    });
    var params = new URLSearchParams(window.location.search);
    var rawTab = params.get('tab') || 'overview';
    var sub = params.get('sub');
    var tab = rawTab;
    var pushIocSubTabs = ['cortex-xdr', 'google-secops', 'netskope', 'cisco-esa', 'ioc-push', 'misp-push', 'opendxl'];
    var pushYaraSubTabs = ['trellix-ex-nx', 'yara-push'];
    var importSubTabs = ['misp', 'taxii'];
    if (pushIocSubTabs.indexOf(rawTab) >= 0) {
        tab = 'push-ioc';
        if (!sub) sub = rawTab;
    } else if (pushYaraSubTabs.indexOf(rawTab) >= 0) {
        tab = 'push-yara';
        if (!sub) sub = rawTab;
    } else if (importSubTabs.indexOf(rawTab) >= 0) {
        tab = 'import';
        if (!sub) sub = rawTab;
    } else {
        var legacy = { 'feeds': 'export', 'ioc-push': 'push-ioc', 'yara-push': 'push-yara', 'opendxl': 'push-ioc', 'trellix-ex-nx': 'push-yara' };
        if (legacy[rawTab]) tab = legacy[rawTab];
    }
    var topBtn = document.querySelector('.integ-top-tab-btn[data-integ-tab="' + tab + '"]');
    if (topBtn) topBtn.click();
    else showTopTab('overview');
    if (sub && tab === 'push-ioc') activatePushIocSub(sub);
    if (sub && tab === 'push-yara') activatePushYaraSub(sub);
    if (sub && tab === 'import') activateImportSub(sub);
})();
