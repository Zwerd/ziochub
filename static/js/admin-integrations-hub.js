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
    var tab = params.get('tab') || 'overview';
    var legacy = { 'misp': 'import', 'taxii': 'import', 'feeds': 'export', 'ioc-push': 'push-ioc', 'yara-push': 'push-yara', 'opendxl': 'push-ioc', 'trellix-ex-nx': 'push-yara', 'cisco-esa': 'push-ioc', 'cortex-xdr': 'push-ioc', 'google-secops': 'push-ioc' };
    if (legacy[tab]) tab = legacy[tab];
    var topBtn = document.querySelector('.integ-top-tab-btn[data-integ-tab="' + tab + '"]');
    if (topBtn) topBtn.click();
    else showTopTab('overview');
    var sub = params.get('sub');
    if (sub && tab === 'push-ioc') activatePushIocSub(sub);
    if (sub && tab === 'push-yara') activatePushYaraSub(sub);
})();
