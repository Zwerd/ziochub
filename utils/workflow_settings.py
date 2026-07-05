"""Admin-configurable analyst workflow: YARA/IOC approval gates and UI toggles."""

from utils.ioc_import_mode import DEFAULT_ANALYST_IOC_MODE, normalize_ioc_import_mode


def _truthy(val) -> bool:
    return str(val or '').strip().lower() in ('true', '1', 'yes', 'on')


def yara_analyst_requires_approval(user, get_setting) -> bool:
    """True when analyst YARA must go through admin approval before feeds/push."""
    if user and getattr(user, 'is_admin', False):
        return False
    return not _truthy(get_setting('yara_analyst_auto_publish', 'false'))


def ioc_analyst_submission_mode(get_setting) -> str:
    """
    Analyst IOC submission policy: auto | pending | block.
    Reads ioc_analyst_submission_mode; falls back to legacy ioc_analyst_auto_publish boolean.
    """
    explicit = (get_setting('ioc_analyst_submission_mode', '') or '').strip()
    if explicit:
        return normalize_ioc_import_mode(explicit, DEFAULT_ANALYST_IOC_MODE)
    if _truthy(get_setting('ioc_analyst_auto_publish', 'true')):
        return 'auto'
    return 'pending'


def ioc_analyst_submissions_blocked(get_setting) -> bool:
    """True when analyst IOC submissions are rejected (not stored)."""
    return ioc_analyst_submission_mode(get_setting) == 'block'


def ioc_analyst_requires_approval(user, get_setting, *, analyst_username: str | None = None) -> bool:
    """True when analyst IOC must be approved before feeds/vendor push."""
    if user and getattr(user, 'is_admin', False):
        return False
    return ioc_analyst_submission_mode(get_setting) == 'pending'


def champs_tab_enabled(get_setting) -> bool:
    return _truthy(get_setting('champs_tab_enabled', 'true'))


def ui_workflow_flags(user, get_setting) -> dict:
    """Frontend hints for current user (tab visibility, approval messaging)."""
    mode = ioc_analyst_submission_mode(get_setting)
    return {
        'champs_tab_enabled': champs_tab_enabled(get_setting),
        'yara_approval_required': yara_analyst_requires_approval(user, get_setting) if user else True,
        'ioc_approval_required': (
            ioc_analyst_requires_approval(user, get_setting) if user else mode == 'pending'
        ),
        'ioc_submissions_blocked': ioc_analyst_submissions_blocked(get_setting),
        'ioc_analyst_submission_mode': mode,
        'yara_analyst_auto_publish': _truthy(get_setting('yara_analyst_auto_publish', 'false')),
        'ioc_analyst_auto_publish': mode == 'auto',
    }
