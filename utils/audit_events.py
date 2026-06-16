"""
Central CEF audit helpers and action catalog (Tier 1 / Tier 2 policy).
"""
from __future__ import annotations

import uuid
from typing import Any

# Default CEF severity per action (0–10). Used when audit_log_event severity is omitted.
ACTION_SEVERITY: dict[str, int] = {
    'login_fail': 7,
    'login': 5,
    'logout': 5,
    'password_change': 6,
    'IOC_CREATE': 5,
    'IOC_CREATE_FAIL': 6,
    'IOC_INGEST': 5,
    'IOC_INGEST_FAIL': 6,
    'IOC_EDIT': 5,
    'IOC_DELETE': 6,
    'IOC_NOTE_ADD': 4,
    'IOC_STAGING_SUBMIT': 5,
    'IOC_STAGING_FAIL': 6,
    'BULK_CSV': 5,
    'BULK_CSV_FAIL': 6,
    'BULK_TXT': 5,
    'BULK_TXT_FAIL': 6,
    'IOC_EXPORT': 3,
    'YARA_UPLOAD': 5,
    'YARA_UPLOAD_FAIL': 6,
    'YARA_APPROVE': 5,
    'YARA_REJECT': 6,
    'YARA_DELETE': 6,
    'tag_suggest': 4,
    'tag_suggest_fail': 6,
    'misp_sync': 5,
    'misp_sync_auto': 5,
    'taxii_sync': 5,
    'taxii_sync_auto': 5,
    'misp_push_ok': 5,
    'misp_push_fail': 6,
    'integration_retry_auto': 5,
    'champs_team_goal_set': 5,
    'champs_ticker_update': 4,
    'admin_settings_update': 6,
}

# Action catalog for Admin → Logs reference (act= signature in CEF).
AUDIT_ACTION_CATALOG: list[dict[str, str]] = [
    # Auth
    {'action': 'login', 'category': 'Auth', 'description': 'Successful login'},
    {'action': 'login_fail', 'category': 'Auth', 'description': 'Failed login (Tier 1)', 'tier': '1'},
    {'action': 'logout', 'category': 'Auth', 'description': 'User logout'},
    {'action': 'password_change', 'category': 'Auth', 'description': 'Password changed (incl. forced)'},
    {'action': 'profile_update', 'category': 'Auth', 'description': 'Profile updated'},
    {'action': 'avatar_upload', 'category': 'Auth', 'description': 'User avatar uploaded'},
    {'action': 'avatar_delete', 'category': 'Auth', 'description': 'User avatar removed'},
    # IOC
    {'action': 'IOC_CREATE', 'category': 'IOC', 'description': 'Single IOC submitted (UI)'},
    {'action': 'IOC_CREATE_FAIL', 'category': 'IOC', 'description': 'Single IOC submit rejected (Tier 1)', 'tier': '1'},
    {'action': 'IOC_INGEST', 'category': 'IOC', 'description': 'IOC ingested via API (/api/v1/ioc)'},
    {'action': 'IOC_INGEST_FAIL', 'category': 'IOC', 'description': 'API ingest rejected (Tier 1)', 'tier': '1'},
    {'action': 'IOC_EDIT', 'category': 'IOC', 'description': 'IOC metadata edited'},
    {'action': 'IOC_DELETE', 'category': 'IOC', 'description': 'IOC revoked (soft delete)'},
    {'action': 'IOC_NOTE_ADD', 'category': 'IOC', 'description': 'Note added to IOC'},
    {'action': 'IOC_STAGING_SUBMIT', 'category': 'IOC', 'description': 'Staging batch submitted'},
    {'action': 'IOC_STAGING_FAIL', 'category': 'IOC', 'description': 'Staging batch rejected (Tier 1)', 'tier': '1'},
    {'action': 'IOC_EXPORT', 'category': 'IOC', 'description': 'IOC export downloaded (Tier 2)', 'tier': '2'},
    {'action': 'BULK_CSV', 'category': 'IOC', 'description': 'Bulk CSV upload processed'},
    {'action': 'BULK_CSV_FAIL', 'category': 'IOC', 'description': 'Bulk CSV upload failed (Tier 1)', 'tier': '1'},
    {'action': 'BULK_TXT', 'category': 'IOC', 'description': 'Bulk TXT upload processed'},
    {'action': 'BULK_TXT_FAIL', 'category': 'IOC', 'description': 'Bulk TXT upload failed (Tier 1)', 'tier': '1'},
    # YARA
    {'action': 'YARA_UPLOAD', 'category': 'YARA', 'description': 'YARA rule uploaded (pending)'},
    {'action': 'YARA_UPLOAD_FAIL', 'category': 'YARA', 'description': 'YARA upload rejected (Tier 1)', 'tier': '1'},
    {'action': 'YARA_APPROVE', 'category': 'YARA', 'description': 'YARA rule approved'},
    {'action': 'YARA_REJECT', 'category': 'YARA', 'description': 'YARA rule rejected'},
    {'action': 'YARA_UPDATE', 'category': 'YARA', 'description': 'YARA rule content updated'},
    {'action': 'YARA_DELETE', 'category': 'YARA', 'description': 'YARA rule deleted'},
    {'action': 'YARA_RESUBMIT', 'category': 'YARA', 'description': 'Rejected YARA resubmitted'},
    {'action': 'YARA_EDIT_META', 'category': 'YARA', 'description': 'YARA ticket/comment/campaign edited'},
    # Tags
    {'action': 'tag_suggest', 'category': 'Tags', 'description': 'Tag suggestion submitted'},
    {'action': 'tag_suggest_fail', 'category': 'Tags', 'description': 'Tag suggestion rejected (Tier 1)', 'tier': '1'},
    {'action': 'admin_tags_approve', 'category': 'Tags', 'description': 'Admin approved tag suggestion(s)'},
    {'action': 'admin_tags_reject', 'category': 'Tags', 'description': 'Admin rejected tag suggestion(s)'},
    # Campaigns
    {'action': 'CAMPAIGN_CREATE', 'category': 'Campaigns', 'description': 'Campaign created'},
    {'action': 'CAMPAIGN_UPDATE', 'category': 'Campaigns', 'description': 'Campaign updated'},
    {'action': 'CAMPAIGN_DELETE', 'category': 'Campaigns', 'description': 'Campaign deleted'},
    # Sync (automatic)
    {'action': 'misp_sync', 'category': 'Sync', 'description': 'Manual MISP pull (admin)'},
    {'action': 'misp_sync_auto', 'category': 'Sync', 'description': 'Automatic MISP pull (timer)'},
    {'action': 'misp_push_ok', 'category': 'Sync', 'description': 'IOC pushed outbound to MISP'},
    {'action': 'misp_push_fail', 'category': 'Sync', 'description': 'MISP outbound push failed (Tier 1)', 'tier': '1'},
    {'action': 'taxii_sync', 'category': 'Sync', 'description': 'Manual TAXII pull (admin)'},
    {'action': 'taxii_sync_auto', 'category': 'Sync', 'description': 'Automatic TAXII pull (timer)'},
    # Automation push
    {'action': 'integration_retry_auto', 'category': 'Automation', 'description': 'Automatic integration retry tick (scheduler)'},
    {'action': 'admin_integration_retry', 'category': 'Automation', 'description': 'Manual integration retry (admin)'},
    {'action': 'ioc_push_skip', 'category': 'Automation', 'description': 'IOC HTTP push skipped (no target/template)'},
    {'action': 'yara_push_skip', 'category': 'Automation', 'description': 'YARA push skipped (disabled/missing URL)'},
    {'action': 'yara_delete_ok', 'category': 'Automation', 'description': 'YARA deleted from remote target'},
    {'action': 'yara_delete_fail', 'category': 'Automation', 'description': 'YARA delete on remote target failed'},
    {'action': 'yara_delete_skip', 'category': 'Automation', 'description': 'YARA delete skipped'},
    {'action': 'esa_dict_add_ok', 'category': 'Automation', 'description': 'ESA dictionary word(s) added'},
    {'action': 'esa_dict_add_fail', 'category': 'Automation', 'description': 'ESA dictionary add failed'},
    {'action': 'esa_dict_remove_ok', 'category': 'Automation', 'description': 'ESA dictionary word(s) removed'},
    {'action': 'esa_dict_remove_fail', 'category': 'Automation', 'description': 'ESA dictionary remove failed'},
    {'action': 'yara_push_ok', 'category': 'Automation', 'description': 'YARA pushed to target'},
    {'action': 'yara_push_fail', 'category': 'Automation', 'description': 'YARA push to target failed'},
    {'action': 'ioc_push_ok', 'category': 'Automation', 'description': 'IOC pushed to HTTP target'},
    {'action': 'ioc_push_fail', 'category': 'Automation', 'description': 'IOC push to target failed'},
    {'action': 'DXL_TIE_PUSH', 'category': 'Automation', 'description': 'Hash pushed to OpenDXL TIE'},
    {'action': 'DXL_TIE_PUSH_FAIL', 'category': 'Automation', 'description': 'OpenDXL TIE push failed'},
    # Admin
    {'action': 'admin_settings_update', 'category': 'Admin', 'description': 'Admin settings changed'},
    {'action': 'admin_user_create', 'category': 'Admin', 'description': 'User created'},
    {'action': 'admin_user_update', 'category': 'Admin', 'description': 'User updated'},
    {'action': 'admin_user_toggle', 'category': 'Admin', 'description': 'User enabled/disabled'},
    {'action': 'admin_allowlist_save', 'category': 'Admin', 'description': 'Allowlist saved'},
    {'action': 'admin_downstream_create', 'category': 'Admin', 'description': 'Distribution system created'},
    # Champs (admin mutations)
    {'action': 'champs_team_goal_set', 'category': 'Champs', 'description': 'Team goal created/updated (admin)'},
    {'action': 'champs_ticker_update', 'category': 'Champs', 'description': 'Ticker messages updated (admin)'},
]


def new_audit_batch_id() -> str:
    """Short correlation id for bulk/staging operations (Phase 3)."""
    return uuid.uuid4().hex[:12]


def format_audit_detail(**fields) -> str:
    """Build key=value detail string for CEF msg= field."""
    parts: list[str] = []
    for key, val in fields.items():
        if val is None or val == '':
            continue
        text = str(val).replace('"', "'").replace('\n', ' ').replace('\r', ' ')
        if key == 'reason':
            parts.append(f'reason="{text[:200]}"')
        else:
            parts.append(f'{key}={text[:500]}')
    return ' '.join(parts)


def audit_log_event(
    action: str,
    outcome: str = 'success',
    *,
    severity: int | None = None,
    username: str | None = None,
    **fields,
) -> None:
    """
    Standard CEF audit entry. outcome: success | fail.
    Tier 1 failures default to severity 6; success defaults to 5.
    """
    import app as app_module

    detail = format_audit_detail(**fields)
    is_fail = outcome.lower() in ('fail', 'failure', 'denied', 'error')
    if is_fail or action.endswith('_fail'):
        default_sev = ACTION_SEVERITY.get(action, 6)
        sev = severity if severity is not None else default_sev
        if action == 'login_fail' and severity is None:
            sev = 7
        app_module.audit_log_fail(action, detail, severity=sev, username=username)
    else:
        default_sev = ACTION_SEVERITY.get(action, 5)
        sev = severity if severity is not None else default_sev
        app_module.audit_log(action, detail, severity=sev, username=username)


def audit_sync_result(action: str, result: dict[str, Any], *, username: str | None = None) -> None:
    """CEF audit for MISP/TAXII sync jobs (manual or automatic)."""
    if result.get('skipped') is True:
        return
    skipped_count = result.get('duplicates_skipped', result.get('skipped', 0))
    if isinstance(skipped_count, bool):
        skipped_count = 0
    if result.get('success'):
        audit_log_event(
            action,
            'success',
            username=username,
            added=result.get('added', 0),
            skipped=skipped_count,
            fetched=result.get('fetched', 0),
            invalid=result.get('invalid', 0),
            errors=result.get('errors', 0),
        )
    else:
        audit_log_event(
            action,
            'fail',
            username=username,
            reason=str(result.get('error') or 'unknown')[:200],
        )


def audit_integration_retry_tick(summaries: dict[str, dict[str, Any]]) -> None:
    """CEF audit for automatic integration retry scheduler (one entry per vendor with work)."""
    for vendor, summary in (summaries or {}).items():
        processed = int(summary.get('processed') or 0)
        if processed <= 0:
            continue
        succeeded = int(summary.get('succeeded') or 0)
        failed = int(summary.get('failed') or 0)
        outcome = 'fail' if failed > 0 and succeeded == 0 else 'success'
        audit_log_event(
            'integration_retry_auto',
            outcome,
            vendor=vendor,
            processed=processed,
            ok=succeeded,
            fail=failed,
            abandoned=int(summary.get('abandoned') or 0),
            remaining=int(summary.get('remaining') or 0),
        )


def line_matches_audit_filters(
    line: str,
    *,
    action: str = '',
    user: str = '',
    q: str = '',
) -> bool:
    """Filter a raw CEF log line by action signature, username, or free-text query."""
    low = line.lower()
    act = (action or '').strip()
    if act:
        act_low = act.lower()
        if f'|{act}|' not in line and f' act={act_low} ' not in low and f' act={act_low}|' not in low:
            return False
    usr = (user or '').strip().lower()
    if usr:
        if (
            f'suser={usr}' not in low
            and f'user={usr}' not in low
            and f' by={usr}' not in low
            and f' analyst={usr}' not in low
        ):
            return False
    query = (q or '').strip().lower()
    if query and query not in low:
        return False
    return True
