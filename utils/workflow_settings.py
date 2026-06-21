"""Admin-configurable analyst workflow: YARA/IOC approval gates and UI toggles."""


def _truthy(val) -> bool:
    return str(val or '').strip().lower() in ('true', '1', 'yes', 'on')


def _sync_usernames(get_setting) -> frozenset[str]:
    names = set()
    for key in ('misp_sync_user', 'taxii_sync_user'):
        v = (get_setting(key, '') or '').strip().lower()
        if v:
            names.add(v)
    return frozenset(names)


def yara_analyst_requires_approval(user, get_setting) -> bool:
    """True when analyst YARA must go through admin approval before feeds/push."""
    if user and getattr(user, 'is_admin', False):
        return False
    return not _truthy(get_setting('yara_analyst_auto_publish', 'false'))


def ioc_analyst_requires_approval(user, get_setting, *, analyst_username: str | None = None) -> bool:
    """True when analyst IOC must be approved before feeds/vendor push."""
    if user and getattr(user, 'is_admin', False):
        return False
    uname = (analyst_username or getattr(user, 'username', '') or '').strip().lower()
    if uname and uname in _sync_usernames(get_setting):
        return False
    return not _truthy(get_setting('ioc_analyst_auto_publish', 'false'))


def champs_tab_enabled(get_setting) -> bool:
    return _truthy(get_setting('champs_tab_enabled', 'true'))


def ui_workflow_flags(user, get_setting) -> dict:
    """Frontend hints for current user (tab visibility, approval messaging)."""
    return {
        'champs_tab_enabled': champs_tab_enabled(get_setting),
        'yara_approval_required': yara_analyst_requires_approval(user, get_setting) if user else True,
        'ioc_approval_required': ioc_analyst_requires_approval(user, get_setting) if user else True,
        'yara_analyst_auto_publish': _truthy(get_setting('yara_analyst_auto_publish', 'false')),
        'ioc_analyst_auto_publish': _truthy(get_setting('ioc_analyst_auto_publish', 'false')),
    }
