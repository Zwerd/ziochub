"""
Admin routes: API (url_prefix='/api/admin') and HTML pages (url_prefix='/admin').
Uses lazy imports from app for shared helpers to avoid circular imports.
"""
import logging
import os

from flask import Blueprint, request, jsonify, url_for, redirect, render_template
from flask_login import current_user
from sqlalchemy.exc import IntegrityError

from sqlalchemy.exc import OperationalError

from extensions import db
from models import User, UserProfile, SystemSetting, IOC
from utils.auth import hash_password
from utils.decorators import admin_required, admin_required_page
from utils.allowlist import clear_allowlist_cache
from routes.auth import _save_avatar, AVATARS_DIR, ALLOWED_AVATAR_EXT
from utils.tags import parse_allowed_tags_setting, normalize_tags_from_input


# --- Admin API blueprint ---
bp = Blueprint('admin_api', __name__, url_prefix='/api/admin')

# --- Admin HTML pages blueprint ---
pages_bp = Blueprint('admin_pages', __name__, url_prefix='/admin')

# Scoring methods for Champs (used by admin scoring page)
SCORING_METHODS = [
    {'id': '1', 'name': 'Weighted + Streak', 'description': 'IOC: 2 pts (3 if linked to campaign). YARA: 10-50 pts by rule quality. Expired deletion: 1 pt. Bonus: 10% for 3+ consecutive days of activity.'},
    {'id': '2', 'name': 'Flat', 'description': '1 point per IOC regardless of type or campaign. Fixed points per YARA rule. Simple total with no bonuses.'},
    {'id': '3', 'name': 'By Type', 'description': 'Different points per IOC type: e.g. IP=3, Domain=2, Hash=4, URL=2, Email=2. YARA in a fixed range. Reflects perceived value or difficulty of each type.'},
    {'id': '4', 'name': 'Campaign Focus', 'description': 'Little or no points for IOCs without a campaign. Full points only for campaign-linked IOCs and YARA. Encourages structured, campaign-driven work.'},
    {'id': '5', 'name': 'Time Decay', 'description': 'Recent activity counts full; older activity is discounted (e.g. last 7 days 100%, 8-30 days 50%, 31-90 days 25%). Emphasizes current contribution.'},
    {'id': '6', 'name': 'Quality', 'description': 'Base points plus bonus for comment, tags, campaign, ticket ID, and TTL. Rewards rich metadata and curation over bulk submission.'},
    {'id': '7', 'name': 'Goal-Based', 'description': 'Points (or contribution share) count mainly when contributing to an active team goal. Aligns scoring with current team targets.'},
    {'id': '8', 'name': 'Smart (Effort)', 'description': 'Rewards genuine effort over bulk ingestion. IOCs: single submit = 2 pts base, bulk (CSV/TXT/Paste) = 1 pt base. +1 for meaningful comment (unique per batch; duplicated comments ignored). +1 for campaign link. Range: 1-4 pts/IOC. YARA: 10 base pts on upload; full quality score (10-50) unlocks only after admin approval. Badges decay fast (1-7 days of inactivity).'},
]


def _from_app(*names):
    """Lazy import from app to avoid circular import."""
    import app as _app
    return tuple(getattr(_app, n) for n in names)


# ---------------------------------------------------------------------------
# Tags governance (Allowed tags + suggestions queue)
# Stored in system_settings:
# - allowed_tags (JSON list)
# - tags_restricted_enabled (true/false)
# - tags_allow_suggest (true/false)
# - tag_suggestions (JSON list of {id, tag, suggested_by, suggested_at})
# ---------------------------------------------------------------------------


def _load_tag_suggestions(_get_setting) -> list[dict]:
    import json
    raw = (_get_setting('tag_suggestions', '[]') or '[]').strip()
    try:
        data = json.loads(raw) if raw else []
    except Exception:
        data = []
    return data if isinstance(data, list) else []


def _save_tag_suggestions(_set_setting, items: list[dict]) -> None:
    import json
    _set_setting('tag_suggestions', json.dumps(items or [], ensure_ascii=False))


@bp.route('/inbox', methods=['GET'])
@admin_required
def admin_inbox():
    """Admin inbox snapshot: pending YARA approvals + pending tag suggestions."""
    _api_ok, _api_error, _get_setting = _from_app('_api_ok', '_api_error', '_get_setting')
    try:
        from models import YaraRule
        from sqlalchemy import func
        # YARA pending
        yara_pending_count = YaraRule.query.filter_by(status='pending').count()
        yara_pending_rows = (
            YaraRule.query.filter_by(status='pending')
            .order_by(YaraRule.uploaded_at.desc())
            .limit(20)
            .all()
        )
        yara_pending = [{
            'filename': r.filename,
            'original_filename': getattr(r, 'original_filename', None) or None,
            'display_name': (getattr(r, 'original_filename', None) or r.filename),
            'analyst': r.analyst or '',
            'uploaded_at': r.uploaded_at.isoformat() if r.uploaded_at else '',
            'ticket_id': r.ticket_id or '',
            'comment': (r.comment or '')[:200],
        } for r in yara_pending_rows]

        # Tags suggestions
        suggestions = _load_tag_suggestions(_get_setting)
        suggestions_sorted = sorted(suggestions, key=lambda x: (x.get('suggested_at') or ''), reverse=True)
        tag_suggestions_count = len(suggestions_sorted)
        tag_suggestions = suggestions_sorted[:20]

        total = int(yara_pending_count) + int(tag_suggestions_count)
        return _api_ok(data={
            'total_pending': total,
            'yara_pending_count': yara_pending_count,
            'yara_pending': yara_pending,
            'tag_suggestions_count': tag_suggestions_count,
            'tag_suggestions': tag_suggestions,
        })
    except Exception as e:
        logging.exception('admin_inbox failed')
        return _api_error(str(e), 500)


@bp.route('/ioc-push/retry', methods=['POST'])
@admin_required
def admin_ioc_push_retry():
    """
    Retry failed IOC push targets for the last recorded event.
    Body: { kind: "create" | "expire" | "manual_remove" }
    """
    _api_ok, _api_error, _get_setting = _from_app('_api_ok', '_api_error', '_get_setting')
    try:
        data = request.get_json(silent=True) or {}
        kind = (data.get('kind') or 'create').strip().lower()
        if kind not in ('create', 'expire', 'manual_remove'):
            return jsonify({'success': False, 'message': 'Invalid kind'}), 400
        from app import audit_log
        from utils.ioc_push_retry import (
            InvalidStoredContextError,
            NoMatchingTargetsError,
            NoRecordedContextError,
            retry_last_failed_ioc_push,
        )

        try:
            payload, msg = retry_last_failed_ioc_push(kind=kind, get_setting=_get_setting, audit_log_fn=audit_log)
            # Keep same response shape as before
            return _api_ok(data=payload, message=msg)
        except NoRecordedContextError as e:
            return jsonify({'success': False, 'message': str(e)}), 404
        except NoMatchingTargetsError as e:
            return jsonify({'success': False, 'message': str(e)}), 404
        except InvalidStoredContextError as e:
            return jsonify({'success': False, 'message': str(e)}), 500
    except Exception as e:
        logging.exception('admin_ioc_push_retry failed')
        return _api_error(str(e), 500)


@bp.route('/yara-automation/retry', methods=['POST'])
@admin_required
def admin_yara_automation_retry():
    """
    Retry failed YARA automation targets from the last recorded attempt.
    Body: { kind: "push" | "delete" } — push = POST after approve; delete = remote delete after rule removal.
    """
    _api_ok, _api_error, _get_setting = _from_app('_api_ok', '_api_error', '_get_setting')
    try:
        data = request.get_json(silent=True) or {}
        kind = (data.get('kind') or 'push').strip().lower()
        if kind not in ('push', 'delete'):
            return jsonify({'success': False, 'message': 'Invalid kind'}), 400
        from app import audit_log
        import app as _app_mod
        data_yara = _app_mod.app.config.get('DATA_YARA') or ''
        from utils.yara_automation_retry import (
            InvalidStoredContextError,
            NoMatchingTargetsError,
            NoRecordedContextError,
            retry_last_failed_yara_automation,
        )

        try:
            payload, msg = retry_last_failed_yara_automation(
                kind=kind,
                get_setting=_get_setting,
                data_yara_dir=data_yara,
                audit_log_fn=audit_log,
            )
            return _api_ok(data=payload, message=msg)
        except NoRecordedContextError as e:
            return jsonify({'success': False, 'message': str(e)}), 404
        except NoMatchingTargetsError as e:
            return jsonify({'success': False, 'message': str(e)}), 404
        except InvalidStoredContextError as e:
            return jsonify({'success': False, 'message': str(e)}), 500
    except Exception as e:
        logging.exception('admin_yara_automation_retry failed')
        return _api_error(str(e), 500)


@bp.route('/tags', methods=['GET'])
@admin_required
def admin_tags_get():
    """Get current tags governance configuration (allowed tags + flags)."""
    _api_ok, _get_setting = _from_app('_api_ok', '_get_setting')
    allowed = parse_allowed_tags_setting(_get_setting('allowed_tags', '[]'))
    restricted = (_get_setting('tags_restricted_enabled', 'false') or 'false').lower() == 'true'
    allow_suggest = (_get_setting('tags_allow_suggest', 'true') or 'true').lower() == 'true'
    return _api_ok(data={
        'allowed_tags': allowed,
        'tags_restricted_enabled': restricted,
        'tags_allow_suggest': allow_suggest,
    })


@bp.route('/tags/suggestions', methods=['GET'])
@admin_required
def admin_tags_suggestions_list():
    """List pending tag suggestions (for approval workflow)."""
    _api_ok, _get_setting = _from_app('_api_ok', '_get_setting')
    items = _load_tag_suggestions(_get_setting)
    # newest first
    items = sorted(items, key=lambda x: (x.get('suggested_at') or ''), reverse=True)
    return _api_ok(data={'suggestions': items[:500]})


@bp.route('/tags/suggestions/approve', methods=['POST'])
@admin_required
def admin_tags_suggestions_approve():
    """Approve one or more suggested tags: add to allowed_tags and remove from queue."""
    _api_ok, _api_error, _get_setting, _set_setting, audit_log = _from_app('_api_ok', '_api_error', '_get_setting', '_set_setting', 'audit_log')
    import json
    try:
        data = request.get_json() or {}
        ids = data.get('ids') or []
        if isinstance(ids, str):
            ids = [ids]
        if not isinstance(ids, list) or not ids:
            return jsonify({'success': False, 'message': 'Missing ids'}), 400
        ids = [str(x).strip() for x in ids if str(x).strip()]
        if not ids:
            return jsonify({'success': False, 'message': 'Missing ids'}), 400

        allowed = parse_allowed_tags_setting(_get_setting('allowed_tags', '[]'))
        allowed_set = set(allowed)
        suggestions = _load_tag_suggestions(_get_setting)
        keep = []
        approved = []
        for item in suggestions:
            if str(item.get('id') or '').strip() in ids:
                tag = (item.get('tag') or '').strip()
                if tag:
                    tag_norm = normalize_tags_from_input([tag])[0] if normalize_tags_from_input([tag]) else ''
                    if tag_norm and tag_norm not in allowed_set:
                        allowed.append(tag_norm)
                        allowed_set.add(tag_norm)
                    approved.append(tag_norm or tag)
            else:
                keep.append(item)
        _set_setting('allowed_tags', json.dumps(allowed, ensure_ascii=False))
        _save_tag_suggestions(_set_setting, keep)
        audit_log('admin_tags_approve', f'by={current_user.username} count={len(approved)}')
        return _api_ok(data={'approved': approved, 'allowed_tags': allowed}, message='Approved')
    except Exception as e:
        logging.exception('admin_tags_suggestions_approve failed')
        return _api_error(str(e), 500)


@bp.route('/tags/suggestions/reject', methods=['POST'])
@admin_required
def admin_tags_suggestions_reject():
    """Reject one or more suggested tags: remove from queue."""
    _api_ok, _api_error, _get_setting, _set_setting, audit_log = _from_app('_api_ok', '_api_error', '_get_setting', '_set_setting', 'audit_log')
    try:
        data = request.get_json() or {}
        ids = data.get('ids') or []
        if isinstance(ids, str):
            ids = [ids]
        if not isinstance(ids, list) or not ids:
            return jsonify({'success': False, 'message': 'Missing ids'}), 400
        ids = {str(x).strip() for x in ids if str(x).strip()}
        if not ids:
            return jsonify({'success': False, 'message': 'Missing ids'}), 400
        suggestions = _load_tag_suggestions(_get_setting)
        keep = [item for item in suggestions if str(item.get('id') or '').strip() not in ids]
        _save_tag_suggestions(_set_setting, keep)
        audit_log('admin_tags_reject', f'by={current_user.username} count={len(ids)}')
        return _api_ok(message='Rejected')
    except Exception as e:
        logging.exception('admin_tags_suggestions_reject failed')
        return _api_error(str(e), 500)


# --- Certificate ---

@bp.route('/certificate/status', methods=['GET'])
@admin_required
def certificate_status():
    """Return current certificate status (present, expiry)."""
    _certificate_status, = _from_app('_certificate_status')
    return jsonify({'success': True, 'certificate': _certificate_status()})


@bp.route('/certificate', methods=['POST'])
@admin_required
def certificate_save():
    """Save SSL certificate and private key (PEM)."""
    _api_error, _certificate_status, audit_log = _from_app('_api_error', '_certificate_status', 'audit_log')
    try:
        data = request.get_json() or {}
        cert_pem = (data.get('cert_pem') or '').strip()
        key_pem = (data.get('key_pem') or '').strip()
        ca_pem = (data.get('ca_pem') or '').strip()
        if not cert_pem or not key_pem:
            return jsonify({'success': False, 'message': 'Certificate and private key are required.'}), 400
        if '-----BEGIN' not in cert_pem or '-----END' not in cert_pem:
            return jsonify({'success': False, 'message': 'Invalid certificate PEM (expect -----BEGIN CERTIFICATE----- / -----END CERTIFICATE-----).'}), 400
        if '-----BEGIN' not in key_pem or '-----END' not in key_pem:
            return jsonify({'success': False, 'message': 'Invalid private key PEM (expect -----BEGIN ... PRIVATE KEY----- / -----END ... PRIVATE KEY-----).'}), 400
        SSL_DIR, SSL_CERT_FILE, SSL_KEY_FILE, SSL_CA_FILE = _from_app('SSL_DIR', 'SSL_CERT_FILE', 'SSL_KEY_FILE', 'SSL_CA_FILE')
        os.makedirs(SSL_DIR, exist_ok=True)
        with open(SSL_CERT_FILE, 'w', encoding='utf-8', newline='\n') as f:
            f.write(cert_pem)
        with open(SSL_KEY_FILE, 'w', encoding='utf-8', newline='\n') as f:
            f.write(key_pem)
        try:
            os.chmod(SSL_KEY_FILE, 0o600)
        except OSError:
            pass
        if ca_pem and ('-----BEGIN' in ca_pem and '-----END' in ca_pem):
            with open(SSL_CA_FILE, 'w', encoding='utf-8', newline='\n') as f:
                f.write(ca_pem)
        elif os.path.isfile(SSL_CA_FILE):
            try:
                os.remove(SSL_CA_FILE)
            except OSError:
                pass
        audit_log('admin_certificate_save', f'by={current_user.username}')
        return jsonify({
            'success': True,
            'message': 'Certificate saved. Restart the application (or reverse proxy) with HTTPS to use it.',
            'certificate': _certificate_status()
        })
    except Exception as e:
        logging.exception('api_admin_certificate_save failed')
        return _api_error(str(e), 500)


# --- Scoring method ---

@bp.route('/scoring-method', methods=['GET'])
@admin_required
def get_scoring_method():
    """Get current Champs scoring method (1-8)."""
    _api_ok, _get_setting = _from_app('_api_ok', '_get_setting')
    method = _get_setting('champs_scoring_method', '1')
    return _api_ok(data={'method': method})


@bp.route('/scoring-method', methods=['POST'])
@admin_required
def save_scoring_method():
    """Save Champs scoring method (1-8)."""
    _api_ok, _api_error, _set_setting, audit_log = _from_app('_api_ok', '_api_error', '_set_setting', 'audit_log')
    try:
        data = request.get_json() or {}
        method = str(data.get('method', '1')).strip()
        if method not in ('1', '2', '3', '4', '5', '6', '7', '8'):
            return jsonify({'success': False, 'message': 'Invalid method. Use 1-8.'}), 400
        _set_setting('champs_scoring_method', method)
        audit_log('admin_scoring_method_update', f'method={method} by={current_user.username}')
        return _api_ok(message='Scoring method saved.')
    except Exception as e:
        logging.exception('api_admin_save_scoring_method failed')
        return _api_error(str(e), 500)


# --- Settings ---

_SETTINGS_DEFAULTS = {
    # Session / security
    # Minutes of inactivity before auto-logoff. "0" means never.
    'session_inactivity_timeout_minutes': '15',
    'auth_mode': 'local_only',
    'ldap_enabled': 'false',
    'ldap_url': '',
    'ldap_base_dn': '',
    'ldap_bind_dn': '',
    'ldap_bind_password': '',
    'ldap_servers': '[]',  # JSON array of {url, base_dn, bind_dn, bind_password}; auth tries in order
    'ldap_user_filter': '(sAMAccountName=%(user)s)',
    'misp_enabled': 'false',
    'misp_url': '',
    'misp_api_key': '',
    'misp_verify_ssl': 'false',
    'misp_last_days': '30',
    'misp_filter_tags': '',
    'misp_filter_types': '',
    'misp_published_only': 'true',
    'misp_default_ttl': 'permanent',
    'misp_sync_user': 'misp_sync',
    'misp_pull_interval': '60',
    'misp_last_sync': '',
    'misp_last_sync_result': '',
    'misp_exclude_from_champs': 'true',
    'syslog_udp_enabled': 'false',
    'syslog_udp_host': '',
    'syslog_udp_port': '514',
    'dxl_enabled': 'false',
    'dxl_config_path': '',
    'automation_fireeye_enabled': 'false',
    'automation_fireeye_appliances': '[]',
    'automation_fireeye_ignore_ssl': 'false',
    'automation_trellix_nx_enabled': 'false',
    'automation_trellix_nx_targets': '[]',
    # Trellix Email Security (EX): multiple targets (JSON); legacy flat keys still read when this is empty
    'trellix_ex_targets': '[]',
    'trellix_ex_enabled': 'false',
    'trellix_ex_base_url': '',
    'trellix_ex_login_path': '/login/login',
    'trellix_ex_upload_path': '/ex/yara_rules_ng/upload_yara',
    'trellix_ex_username': '',
    'trellix_ex_password': '',
    'trellix_ex_manual_cookie': '',
    'trellix_ex_verify_ssl': 'true',
    'trellix_ex_f_type': 'common',
    'trellix_ex_content_type': 'base',
    'trellix_ex_csrf_param': '',
    'trellix_ex_csrf_token': '',
    'sanity_check_mode': 'block_non_admin',
    'search_comment_rtl_by_script': 'true',  # In search results: if comment has more Hebrew/Arabic than other text, show RTL
    # Tags governance (admin-controlled taxonomy)
    # - allowed_tags: JSON array of tags (lowercase recommended)
    # - tags_restricted_enabled: when true, API rejects tags not in allowed_tags
    'allowed_tags': '[]',
    'tags_restricted_enabled': 'false',
    'tags_allow_suggest': 'true',
    'feeds_public_enabled': 'true',
    'feed_cache_enabled': 'true',
    'feed_cache_ttl_seconds': '300',
    'ioc_push_enabled': 'false',
    'ioc_push_ignore_ssl': 'false',
    'ioc_push_targets': '[]',
    # Cisco ESA-dictionary sync (API shape fixed in code; admin only sets URL, credentials, mappings)
    'esa_enabled': 'false',
    'esa_base_url': '',
    'esa_username': '',
    'esa_passphrase': '',
    'esa_verify_ssl': 'true',
    'esa_skip_misp_sync': 'true',
    'esa_cleanup_on_expire': 'true',
    'esa_mappings': '[]',
    'esa_deployment_mode': 'standalone',
    'esa_group_name': '',
    'esa_host_name': '',
    # Vendor IOC outbound (Integrations)
    'cortex_xdr_enabled': 'false',
    'cortex_xdr_base_url': '',
    'cortex_xdr_api_key_id': '',
    'cortex_xdr_api_key': '',
    'cortex_xdr_verify_ssl': 'true',
    'cortex_xdr_hash_blocklist_enabled': 'true',
    'cortex_xdr_display_name': '',
    'google_secops_enabled': 'false',
    'google_secops_base_url': '',
    'google_secops_chronicle_api_base': '',
    'google_secops_project_number': '',
    'google_secops_location': '',
    'google_secops_instance_id': '',
    'google_secops_customer_id': '',
    'google_secops_data_table_id': '',
    'google_secops_credentials_json': '',
    'google_secops_verify_ssl': 'true',
    'google_secops_display_name': '',
}


def _normalize_ioc_push_targets_for_save(val) -> str:
    """Validate Admin JSON for IOC push targets; return serialized JSON string."""
    import json
    from utils.ioc_push import MAX_BODY_TEMPLATE_CHARS

    if val is None:
        return '[]'
    if isinstance(val, str):
        try:
            val = json.loads(val.strip() or '[]')
        except (TypeError, ValueError) as e:
            raise ValueError(f'ioc_push_targets: invalid JSON ({e})') from e
    if not isinstance(val, list):
        raise ValueError('ioc_push_targets must be a JSON array')
    allowed_auth = frozenset(('none', 'basic', 'api_key'))
    out = []
    for item in val:
        if not isinstance(item, dict):
            continue
        tmpl = item.get('body_template')
        tmpl = tmpl if isinstance(tmpl, str) else ''
        if len(tmpl) > MAX_BODY_TEMPLATE_CHARS:
            raise ValueError(f"Target '{item.get('name', '')}': body_template too long")
        auth_type = str(item.get('auth_type') or 'none').strip().lower()
        if auth_type not in allowed_auth:
            auth_type = 'none'
        en = item.get('enabled', True)
        if isinstance(en, str):
            enabled = en.strip().lower() in ('true', '1', 'yes')
        else:
            enabled = bool(en)
        vs = item.get('verify_ssl')
        verify_ssl_json = None
        if vs is not None:
            if isinstance(vs, str):
                verify_ssl_json = vs.strip().lower() in ('true', '1', 'yes')
            else:
                verify_ssl_json = bool(vs)
        out.append({
            'name': str(item.get('name') or '').strip(),
            'enabled': enabled,
            'url': str(item.get('url') or '').strip(),
            'method': 'POST',
            'auth_type': auth_type,
            'username': str(item.get('username') or '').strip(),
            'password': str(item.get('password') or '').strip(),
            'api_key': str(item.get('api_key') or '').strip(),
            'api_key_header': str(item.get('api_key_header') or 'X-API-Key').strip() or 'X-API-Key',
            'body_template': tmpl,
            'content_type': str(item.get('content_type') or 'application/json').strip() or 'application/json',
            'verify_ssl': verify_ssl_json,
        })
    return json.dumps(out, ensure_ascii=False)


def _normalize_esa_mappings(val) -> str:
    """Validate esa_mappings: JSON array of {dictionary_name, ioc_type} with ioc_type in Email|Domain|IP|URL."""
    import json
    from utils.cisco_esa import ESA_IOC_TYPES, canonical_esa_ioc_type

    allowed = frozenset(ESA_IOC_TYPES)
    if val is None:
        return '[]'
    if isinstance(val, str):
        try:
            val = json.loads(val.strip() or '[]')
        except (TypeError, ValueError) as e:
            raise ValueError(f'esa_mappings: invalid JSON ({e})') from e
    if not isinstance(val, list):
        raise ValueError('esa_mappings must be a JSON array')
    out: list[dict] = []
    for item in val:
        if not isinstance(item, dict):
            continue
        name = (item.get('dictionary_name') or item.get('name') or '').strip()
        ct = canonical_esa_ioc_type(item.get('ioc_type'))
        if not name or not ct or ct not in allowed:
            continue
        out.append({'dictionary_name': name, 'ioc_type': ct})
    return json.dumps(out, ensure_ascii=False)


def _trellix_ex_targets_json_for_form(get_setting_fn) -> str:
    """JSON array for Integrations UI; migrates legacy flat EX keys into one row when JSON is empty."""
    import json

    raw = (get_setting_fn('trellix_ex_targets', '') or '').strip()
    rows: list[dict] = []
    if raw and raw != '[]':
        try:
            rows = json.loads(raw)
        except Exception:
            rows = []
    if not isinstance(rows, list):
        rows = []
    rows = [r for r in rows if isinstance(r, dict)]
    if not rows:
        base = (get_setting_fn('trellix_ex_base_url', '') or '').strip()
        if base:
            rows = [{
                'name': 'Trellix EX',
                'base_url': base,
                'login_path': (get_setting_fn('trellix_ex_login_path', '') or '/login/login').strip(),
                'upload_path': (get_setting_fn('trellix_ex_upload_path', '') or '/ex/yara_rules_ng/upload_yara').strip(),
                'username': (get_setting_fn('trellix_ex_username', '') or '').strip(),
                'password': (get_setting_fn('trellix_ex_password', '') or ''),
                'manual_cookie': (get_setting_fn('trellix_ex_manual_cookie', '') or '').strip(),
                'verify_ssl': (get_setting_fn('trellix_ex_verify_ssl', 'true') or 'true').lower() in ('true', '1', 'yes'),
                'f_type': (get_setting_fn('trellix_ex_f_type', 'common') or 'common').strip(),
                'content_type': (get_setting_fn('trellix_ex_content_type', 'base') or 'base').strip(),
                'csrf_param': (get_setting_fn('trellix_ex_csrf_param', '') or '').strip(),
                'csrf_token': (get_setting_fn('trellix_ex_csrf_token', '') or '').strip(),
            }]
    return json.dumps(rows, ensure_ascii=False)


def _normalize_trellix_ex_targets_for_save(val, _get_setting) -> str:
    import json

    MAX_TARGETS = 32
    MAX_URL = 2048

    def _old_list() -> list:
        try:
            o = json.loads(_get_setting('trellix_ex_targets', '[]') or '[]')
            return o if isinstance(o, list) else []
        except Exception:
            return []

    old = [x for x in _old_list() if isinstance(x, dict)]
    legacy_pw = (_get_setting('trellix_ex_password', '') or '').strip()

    if val is None:
        return '[]'
    if isinstance(val, str):
        try:
            val = json.loads(val.strip() or '[]')
        except Exception as e:
            raise ValueError('trellix_ex_targets: invalid JSON') from e
    if not isinstance(val, list):
        raise ValueError('trellix_ex_targets must be a list')
    if len(val) > MAX_TARGETS:
        raise ValueError(f'trellix_ex_targets: at most {MAX_TARGETS} targets allowed')
    out: list[dict] = []
    for i, item in enumerate(val):
        if not isinstance(item, dict):
            continue
        base = str(item.get('base_url') or '').strip()[:MAX_URL]
        if not base:
            continue
        name = str(item.get('name') or '').strip()[:256] or 'Trellix EX'
        lp = str(item.get('login_path') or '').strip()[:512]
        up = str(item.get('upload_path') or '').strip()[:512]
        user = str(item.get('username') or '').strip()[:512]
        pwd = str(item.get('password') or '')
        if not pwd.strip() and i < len(old):
            pwd = str(old[i].get('password') or '')
        if not pwd.strip() and i == 0 and legacy_pw:
            pwd = legacy_pw
        mc = str(item.get('manual_cookie') or '').strip()[:8000]
        vs = item.get('verify_ssl', True)
        if isinstance(vs, str):
            verify_ssl = vs.strip().lower() in ('true', '1', 'yes')
        else:
            verify_ssl = bool(vs)
        ft = str(item.get('f_type') or '').strip()[:64] or 'common'
        ct = str(item.get('content_type') or '').strip()[:64] or 'base'
        csrf_p = str(item.get('csrf_param') or '').strip()[:128]
        csrf_t = str(item.get('csrf_token') or '').strip()[:8192]
        del_p = str(item.get('delete_path') or '').strip()[:512]
        edm = str(item.get('ex_delete_name_mode') or 'same').strip().lower()
        if edm not in ('same', 'yar_txt'):
            edm = 'same'
        row_out: dict = {
            'name': name,
            'base_url': base.rstrip('/'),
            'login_path': lp,
            'upload_path': up,
            'username': user,
            'password': pwd,
            'manual_cookie': mc,
            'verify_ssl': verify_ssl,
            'f_type': ft,
            'content_type': ct,
        }
        if csrf_p:
            row_out['csrf_param'] = csrf_p
        if csrf_t:
            row_out['csrf_token'] = csrf_t
        if del_p:
            row_out['delete_path'] = del_p
        if edm != 'same':
            row_out['ex_delete_name_mode'] = edm
        out.append(row_out)
    return json.dumps(out, ensure_ascii=False)


def _esa_mapping_rows_for_ui(raw_mappings: str) -> list[dict]:
    """One UI row per mapping; empty starter row if none."""
    from utils.cisco_esa import parse_mappings

    rows = parse_mappings(raw_mappings or '[]')
    ui = [{'dictionary_name': r['dictionary_name'], 'ioc_type': r['ioc_type']} for r in rows]
    if not ui:
        ui = [{'dictionary_name': '', 'ioc_type': 'Email'}]
    return ui


def _validate_esa_deployment_settings(_get_setting) -> None:
    """Require group_name / host_name when mode needs them (Cisco API Guide)."""
    mode = (_get_setting('esa_deployment_mode', 'standalone') or 'standalone').strip().lower()
    if mode == 'group' and not (_get_setting('esa_group_name', '') or '').strip():
        raise ValueError('ESA: Group mode requires a group name (see Cisco API cluster levels).')
    if mode == 'machine' and not (_get_setting('esa_host_name', '') or '').strip():
        raise ValueError('ESA: Machine mode requires a host name.')


@bp.route('/settings', methods=['GET'])
@admin_required
def get_settings():
    """Get all system settings (JSON API)."""
    _api_ok, _ensure_system_settings_table = _from_app('_api_ok', '_ensure_system_settings_table')
    settings = dict(_SETTINGS_DEFAULTS)
    try:
        rows = SystemSetting.query.all()
        for r in rows:
            settings[r.key] = (r.value or '') if r.value is not None else ''
    except OperationalError:
        try:
            _ensure_system_settings_table()
            rows = SystemSetting.query.all()
            for r in rows:
                settings[r.key] = (r.value or '') if r.value is not None else ''
        except Exception:
            pass
    for k, v in _SETTINGS_DEFAULTS.items():
        if k not in settings:
            settings[k] = v
    # Backward compat: if ldap_servers empty but single ldap_url set, expose as one server in list
    import json as _json
    try:
        raw_servers = (settings.get('ldap_servers') or '').strip()
        if (not raw_servers or raw_servers == '[]') and (settings.get('ldap_url') or '').strip():
            settings['ldap_servers'] = _json.dumps([{
                'url': settings.get('ldap_url', ''),
                'base_dn': settings.get('ldap_base_dn', ''),
                'bind_dn': settings.get('ldap_bind_dn', ''),
                'bind_password': settings.get('ldap_bind_password', ''),
            }])
    except Exception:
        pass
    return _api_ok(data={'settings': settings})


# MISP keys (fallback when misp_settings module is missing, e.g. old install)
_MISP_SAVE_KEYS_FALLBACK = (
    'misp_enabled', 'misp_url', 'misp_api_key', 'misp_verify_ssl', 'misp_last_days',
    'misp_filter_tags', 'misp_filter_types', 'misp_published_only', 'misp_default_ttl',
    'misp_sync_user', 'misp_pull_interval', 'misp_exclude_from_champs',
    'misp_push_enabled', 'misp_push_include_comment', 'misp_push_default_event_id',
)
_MISP_SYNC_KEYS_FALLBACK = (
    'misp_url', 'misp_api_key', 'misp_verify_ssl', 'misp_last_days',
    'misp_filter_tags', 'misp_filter_types', 'misp_published_only', 'misp_default_ttl', 'misp_sync_user',
)


@bp.route('/settings', methods=['POST'])
@admin_required
def save_settings():
    """Save system settings (JSON API)."""
    _api_ok, _api_error, _set_setting, _get_setting, audit_log = _from_app('_api_ok', '_api_error', '_set_setting', '_get_setting', 'audit_log')
    try:
        data = request.get_json() or {}
        try:
            from misp_settings import MISP_SAVE_KEYS
            misp_keys = MISP_SAVE_KEYS
        except ImportError:
            misp_keys = _MISP_SAVE_KEYS_FALLBACK
        syslog_keys = ('syslog_udp_enabled', 'syslog_udp_host', 'syslog_udp_port')
        ldap_keys = ('auth_mode', 'ldap_enabled', 'ldap_url', 'ldap_base_dn', 'ldap_bind_dn', 'ldap_bind_password', 'ldap_servers', 'ldap_user_filter')
        session_keys = ('session_inactivity_timeout_minutes',)
        dxl_keys = ('dxl_enabled', 'dxl_config_path')
        automation_keys = (
            'automation_fireeye_enabled',
            'automation_fireeye_appliances',
            'automation_fireeye_ignore_ssl',
            'automation_trellix_nx_enabled',
            'automation_trellix_nx_targets',
            'trellix_ex_targets',
        )
        trellix_ex_keys = ('trellix_ex_enabled',)
        sanity_keys = ('sanity_check_mode',)
        feed_keys = ('feeds_public_enabled', 'feed_cache_enabled', 'feed_cache_ttl_seconds')
        search_keys = ('search_comment_rtl_by_script',)
        tags_keys = ('allowed_tags', 'tags_restricted_enabled', 'tags_allow_suggest')
        ioc_push_keys = ('ioc_push_enabled', 'ioc_push_ignore_ssl', 'ioc_push_targets')
        esa_keys = (
            'esa_enabled', 'esa_base_url', 'esa_username', 'esa_passphrase', 'esa_verify_ssl',
            'esa_skip_misp_sync', 'esa_cleanup_on_expire', 'esa_mappings',
            'esa_deployment_mode', 'esa_group_name', 'esa_host_name',
        )
        vendor_ioc_keys = (
            'cortex_xdr_enabled',
            'cortex_xdr_display_name',
            'cortex_xdr_base_url',
            'cortex_xdr_api_key_id',
            'cortex_xdr_api_key',
            'cortex_xdr_verify_ssl',
            'cortex_xdr_hash_blocklist_enabled',
            'google_secops_enabled',
            'google_secops_display_name',
            'google_secops_base_url',
            'google_secops_chronicle_api_base',
            'google_secops_project_number',
            'google_secops_location',
            'google_secops_instance_id',
            'google_secops_customer_id',
            'google_secops_data_table_id',
            'google_secops_credentials_json',
            'google_secops_verify_ssl',
        )
        sections = []
        for key in (
            session_keys + ldap_keys + misp_keys + syslog_keys + dxl_keys + automation_keys + trellix_ex_keys
            + sanity_keys + feed_keys + search_keys + tags_keys + ioc_push_keys + esa_keys + vendor_ioc_keys
        ):
            if key in data:
                val = data[key]
                if key == 'session_inactivity_timeout_minutes':
                    try:
                        n = int(str(val).strip())
                    except ValueError:
                        n = 15
                    # 0 = never; clamp to sane range otherwise
                    if n < 0:
                        n = 0
                    if n > 1440:
                        n = 1440
                    _set_setting(key, str(n))
                    if 'Session' not in sections:
                        sections.append('Session')
                    continue
                if key == 'cortex_xdr_api_key':
                    if isinstance(val, str) and val.strip():
                        _set_setting('cortex_xdr_api_key', val.strip())
                        if 'Vendor IOC' not in sections:
                            sections.append('Vendor IOC')
                    continue
                if key == 'trellix_ex_targets':
                    try:
                        _set_setting(key, _normalize_trellix_ex_targets_for_save(val, _get_setting))
                    except ValueError as vex:
                        return jsonify({'success': False, 'message': str(vex)}), 400
                elif key in ('automation_fireeye_appliances', 'automation_trellix_nx_targets'):
                    import json
                    _set_setting(key, json.dumps(val) if isinstance(val, (list, dict)) else str(val).strip())
                elif key == 'ldap_servers':
                    import json
                    _set_setting(key, json.dumps(val) if isinstance(val, (list, dict)) else str(val).strip())
                elif key == 'feed_cache_ttl_seconds':
                    from utils.feed_cache import FEED_CACHE_TTL_DEFAULT, FEED_CACHE_TTL_PRESETS
                    try:
                        n = int(str(val).strip())
                    except ValueError:
                        n = FEED_CACHE_TTL_DEFAULT
                    if n not in FEED_CACHE_TTL_PRESETS:
                        n = FEED_CACHE_TTL_DEFAULT
                    _set_setting(key, str(n))
                elif key == 'feed_cache_enabled':
                    _set_setting(key, 'true' if str(val).lower() in ('true', '1', 'yes') else 'false')
                elif key == 'ioc_push_targets':
                    _set_setting(key, _normalize_ioc_push_targets_for_save(val))
                elif key == 'esa_mappings':
                    _set_setting(key, _normalize_esa_mappings(val))
                elif key == 'esa_deployment_mode':
                    from utils.cisco_esa import ESA_DEPLOYMENT_MODES
                    m = str(val).strip().lower()
                    if m not in ESA_DEPLOYMENT_MODES:
                        m = 'standalone'
                    _set_setting(key, m)
                elif key in ('esa_group_name', 'esa_host_name'):
                    _set_setting(key, str(val).strip())
                elif key in trellix_ex_keys:
                    if key == 'trellix_ex_enabled':
                        _set_setting(key, 'true' if str(val).lower() in ('true', '1', 'yes') else 'false')
                    else:
                        _set_setting(key, str(val).strip())
                elif key in vendor_ioc_keys:
                    if key in (
                        'cortex_xdr_enabled',
                        'cortex_xdr_verify_ssl',
                        'cortex_xdr_hash_blocklist_enabled',
                        'google_secops_enabled',
                        'google_secops_verify_ssl',
                    ):
                        _set_setting(key, 'true' if str(val).lower() in ('true', '1', 'yes') else 'false')
                    elif key == 'google_secops_credentials_json':
                        _set_setting(key, str(val) if val is not None else '')
                    else:
                        _set_setting(key, str(val).strip())
                elif key in esa_keys:
                    if key in ('esa_verify_ssl', 'esa_skip_misp_sync', 'esa_cleanup_on_expire'):
                        _set_setting(key, 'true' if str(val).lower() in ('true', '1', 'yes') else 'false')
                    else:
                        _set_setting(key, str(val).strip())
                elif key == 'allowed_tags':
                    # Accept list/dict/string; store JSON list normalized to lowercase (comma-separated allowed too)
                    import json
                    from utils.tags import normalize_tags_from_input
                    if isinstance(val, (list, tuple)):
                        allowed = normalize_tags_from_input(list(val))
                    elif isinstance(val, str):
                        v = val.strip()
                        if v.startswith('['):
                            try:
                                allowed = normalize_tags_from_input(json.loads(v))
                            except Exception:
                                allowed = normalize_tags_from_input(v)
                        else:
                            allowed = normalize_tags_from_input(v.replace('\n', ','))
                    else:
                        allowed = []
                    _set_setting(key, json.dumps(allowed, ensure_ascii=False))
                elif key in ('tags_restricted_enabled', 'tags_allow_suggest'):
                    _set_setting(key, 'true' if str(val).lower() in ('true', '1', 'yes') else 'false')
                else:
                    _set_setting(key, str(val).strip())
                if key in ldap_keys and 'LDAP' not in sections:
                    sections.append('LDAP')
                elif key in session_keys and 'Session' not in sections:
                    sections.append('Session')
                elif key in misp_keys and 'MISP' not in sections:
                    sections.append('MISP')
                elif key in syslog_keys and 'Syslog' not in sections:
                    sections.append('Syslog')
                elif key in dxl_keys and 'DXL' not in sections:
                    sections.append('DXL')
                elif key in automation_keys and 'YARA push' not in sections:
                    sections.append('YARA push')
                elif (key in trellix_ex_keys or key == 'trellix_ex_targets') and 'Trellix EX' not in sections:
                    sections.append('Trellix EX')
                elif key in vendor_ioc_keys and 'Vendor IOC' not in sections:
                    sections.append('Vendor IOC')
                elif key in sanity_keys and 'Sanity' not in sections:
                    sections.append('Sanity')
                elif key in feed_keys and 'Feeds' not in sections:
                    sections.append('Feeds')
                elif key in search_keys and 'Search' not in sections:
                    sections.append('Search')
                elif key in tags_keys and 'Tags' not in sections:
                    sections.append('Tags')
                elif key in ioc_push_keys and 'IOC push' not in sections:
                    sections.append('IOC push')
                elif key in esa_keys and 'ESA' not in sections:
                    sections.append('ESA')
        if any(k in data for k in esa_keys):
            _validate_esa_deployment_settings(_get_setting)
        if any(k in data for k in ('feeds_public_enabled', 'feed_cache_enabled', 'feed_cache_ttl_seconds')):
            try:
                from utils.feed_cache import clear_all_feed_cache
                clear_all_feed_cache()
            except Exception:
                pass
        try:
            from utils.cef_logger import refresh_cef_udp_target
            udp_enabled = _get_setting('syslog_udp_enabled', 'false').lower() == 'true'
            udp_host = _get_setting('syslog_udp_host', '').strip() if udp_enabled else ''
            udp_port = int(_get_setting('syslog_udp_port', '514') or '514')
            refresh_cef_udp_target(udp_host, udp_port)
        except Exception:
            pass
        detail = ','.join(sections) if sections else 'settings'
        audit_log('admin_settings_update', f'{detail} by={current_user.username}')
        return _api_ok(message='Settings saved')
    except Exception as e:
        logging.exception('api_admin_save_settings failed')
        return _api_error(str(e), 500)


@bp.route('/automation-test', methods=['POST'])
@admin_required
def automation_test():
    """POST minimal YARA to configured targets-verifies same path as approval-time push (Admin → YARA push)."""
    audit_log, _api_error = _from_app('audit_log', '_api_error')
    try:
        data = request.get_json() or {}
        appliances = data.get('appliances')
        if appliances is None:
            return jsonify({'success': False, 'message': 'Missing appliances array.'}), 400
        if not isinstance(appliances, list):
            return jsonify({'success': False, 'message': 'appliances must be a list.'}), 400
        if len(appliances) == 0:
            return jsonify({
                'success': True,
                'overall_success': False,
                'results': [],
                'message': 'Add at least one target (name, base URL, path) before testing.',
            })
        from utils.yara_http_push import test_yara_push_connections
        ignore_ssl = data.get('ignore_ssl')
        if ignore_ssl is None:
            _get_setting, = _from_app('_get_setting')
            verify_ssl = _get_setting('automation_fireeye_ignore_ssl', 'false').lower() != 'true'
        else:
            verify_ssl = not (str(ignore_ssl).lower() in ('true', '1', 'yes'))
        result = test_yara_push_connections(appliances, verify_ssl=verify_ssl)
        audit_log(
            'admin_automation_test',
            f'by={current_user.username} targets={len(appliances)} overall={result.get("overall_success")}',
        )
        return jsonify({
            'success': True,
            'overall_success': result.get('overall_success'),
            'results': result.get('results', []),
        })
    except Exception as e:
        logging.exception('api_admin_automation_test failed')
        return _api_error(str(e), 500)


@bp.route('/ioc-push-test', methods=['POST'])
@admin_required
def ioc_push_test():
    """POST sample IOC JSON to targets from request body (same rendering as live IOC push)."""
    audit_log, _api_error = _from_app('audit_log', '_api_error')
    try:
        data = request.get_json() or {}
        targets = data.get('targets')
        if targets is None:
            return jsonify({'success': False, 'message': 'Missing targets array.'}), 400
        if not isinstance(targets, list):
            return jsonify({'success': False, 'message': 'targets must be a list.'}), 400
        if len(targets) == 0:
            return jsonify({
                'success': True,
                'overall_success': False,
                'results': [],
                'message': 'Add at least one target with URL and body template before testing.',
            })
        ignore_ssl = data.get('ignore_ssl')
        if ignore_ssl is None:
            _get_setting, = _from_app('_get_setting')
            verify_ssl = _get_setting('ioc_push_ignore_ssl', 'false').lower() != 'true'
        else:
            verify_ssl = not (str(ignore_ssl).lower() in ('true', '1', 'yes'))
        from utils.ioc_push import test_ioc_push_targets
        result = test_ioc_push_targets(targets, verify_ssl_override=verify_ssl)
        audit_log(
            'admin_ioc_push_test',
            f'by={current_user.username} targets={len(targets)} overall={result.get("overall_success")}',
        )
        return jsonify({
            'success': True,
            'overall_success': result.get('overall_success'),
            'results': result.get('results', []),
        })
    except Exception as e:
        logging.exception('api_admin_ioc_push_test failed')
        return _api_error(str(e), 500)


@bp.route('/esa/test', methods=['POST'])
@admin_required
def esa_test():
    """Verify ESA login (Base64 credentials) and GET config/dictionaries with jwttoken header."""
    audit_log, _api_error = _from_app('audit_log', '_api_error')
    try:
        from utils.cisco_esa import esa_test_connection, esa_settings_dict
        result = esa_test_connection(esa_settings_dict())
        audit_log('admin_esa_test', f'by={current_user.username} ok={result.get("success")}')
        return jsonify({'success': True, **result})
    except Exception as e:
        logging.exception('api_admin_esa_test failed')
        return _api_error(str(e), 500)


@bp.route('/cortex-xdr/test', methods=['POST'])
@admin_required
def cortex_xdr_test():
    """POST Cortex XDR public_api probe using saved Integrations settings."""
    audit_log, _api_error = _from_app('audit_log', '_api_error')
    try:
        from utils.cortex_xdr import cortex_xdr_settings_dict, cortex_xdr_test_connection

        data = request.get_json(silent=True) or {}
        ignore_ssl = data.get('ignore_ssl')
        settings = cortex_xdr_settings_dict()
        if ignore_ssl is not None:
            verify_ssl = not (str(ignore_ssl).lower() in ('true', '1', 'yes'))
        else:
            verify_ssl = (settings.get('cortex_xdr_verify_ssl', 'true') or 'true').lower() in ('true', '1', 'yes')

        result = cortex_xdr_test_connection(settings, verify_ssl=verify_ssl)
        audit_log('admin_cortex_xdr_test', f'by={current_user.username} ok={result.get("success")}')
        return jsonify({'success': True, **result})
    except Exception as e:
        logging.exception('api_admin_cortex_xdr_test failed')
        return _api_error(str(e), 500)


@bp.route('/google-secops/test', methods=['POST'])
@admin_required
def google_secops_test():
    """OAuth token + optional GET to saved Google SecOps base URL."""
    audit_log, _api_error = _from_app('audit_log', '_api_error')
    try:
        from utils.google_secops import google_secops_settings_dict, google_secops_test_connection

        data = request.get_json(silent=True) or {}
        ignore_ssl = data.get('ignore_ssl')
        settings = google_secops_settings_dict()
        if ignore_ssl is not None:
            verify_ssl = not (str(ignore_ssl).lower() in ('true', '1', 'yes'))
        else:
            verify_ssl = (settings.get('google_secops_verify_ssl', 'true') or 'true').lower() in ('true', '1', 'yes')

        result = google_secops_test_connection(settings, verify_ssl=verify_ssl)
        audit_log('admin_google_secops_test', f'by={current_user.username} ok={result.get("success")}')
        return jsonify({'success': True, **result})
    except Exception as e:
        logging.exception('api_admin_google_secops_test failed')
        return _api_error(str(e), 500)


@bp.route('/trellix-ex/test', methods=['POST'])
@admin_required
def trellix_ex_test():
    """POST minimal YARA to Trellix EX (login + multipart upload) using saved Integrations settings."""
    audit_log, _api_error = _from_app('audit_log', '_api_error')
    try:
        _get_setting, = _from_app('_get_setting')
        from utils.trellix_ex import test_trellix_ex_connection, trellix_ex_enabled

        if not trellix_ex_enabled(_get_setting):
            return jsonify({
                'success': True,
                'overall_success': False,
                'results': [],
                'message': 'Trellix EX is disabled. Enable it, save, then test.',
            })

        data = request.get_json(silent=True) or {}
        ignore_ssl = data.get('ignore_ssl')
        if ignore_ssl is not None and str(ignore_ssl).lower() in ('true', '1', 'yes'):
            verify_ssl = False
        else:
            # Per-target verify_ssl from trellix_ex_targets JSON (or legacy normalized row).
            verify_ssl = None

        result = test_trellix_ex_connection(_get_setting, verify_ssl=verify_ssl)
        audit_log(
            'admin_trellix_ex_test',
            f'by={current_user.username} ok={result.get("overall_success")}',
        )
        # Force 200 so browsers/proxies never surface rare 2xx (e.g. 203) without a JSON body the UI can parse.
        return jsonify(result), 200
    except Exception as e:
        logging.exception('api_admin_trellix_ex_test failed')
        return _api_error(str(e), 500)


def _rewrite_dxl_config_certs_section(content: str, certs_dir: str) -> str:
    """Rewrite [Certs] section in dxlclient.config to use certs_dir paths. Leaves [Brokers] etc. unchanged."""
    certs_dir = os.path.abspath(certs_dir)
    broker_crt = os.path.join(certs_dir, 'brokercerts.crt').replace('\\', '/')
    client_crt = os.path.join(certs_dir, 'client.crt').replace('\\', '/')
    client_key = os.path.join(certs_dir, 'client.key').replace('\\', '/')
    lines = content.replace('\r\n', '\n').split('\n')
    out = []
    in_certs = False
    for line in lines:
        if line.strip().lower() == '[certs]':
            in_certs = True
            out.append(line)
            out.append(f'BrokerCertChain={broker_crt}')
            out.append(f'CertFile={client_crt}')
            out.append(f'PrivateKey={client_key}')
            continue
        if in_certs and line.strip().lower().startswith(('brokercertchain=', 'certfile=', 'privatekey=')):
            continue
        if in_certs and line.strip().startswith('[') and 'certs' not in line.strip().lower():
            in_certs = False
        out.append(line)
    return '\n'.join(out)


@bp.route('/dxl/upload', methods=['POST'])
@admin_required
def dxl_upload():
    """Upload ePO DXL files one by one. Saves to fixed directory and sets dxl_config_path."""
    _api_ok, _api_error, _set_setting, audit_log = _from_app('_api_ok', '_api_error', '_set_setting', 'audit_log')
    DXL_DIR, = _from_app('DXL_DIR')
    try:
        config_file = request.files.get('config_file')
        broker_certs = request.files.get('broker_certs')
        client_cert = request.files.get('client_cert')
        client_key = request.files.get('client_key')
        if not any((config_file and config_file.filename), (broker_certs and broker_certs.filename), (client_cert and client_cert.filename), (client_key and client_key.filename)):
            return _api_error('Upload at least one file: config file, broker certs, client cert, or client key.'), 400
        os.makedirs(DXL_DIR, exist_ok=True)
        config_path = os.path.join(DXL_DIR, 'dxlclient.config')
        broker_path = os.path.join(DXL_DIR, 'brokercerts.crt')
        client_crt_path = os.path.join(DXL_DIR, 'client.crt')
        client_key_path = os.path.join(DXL_DIR, 'client.key')
        if config_file and config_file.filename:
            content = config_file.read()
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='replace')
            content = _rewrite_dxl_config_certs_section(content, DXL_DIR)
            with open(config_path, 'w', encoding='utf-8', newline='\n') as f:
                f.write(content)
        if broker_certs and broker_certs.filename:
            broker_certs.save(broker_path)
        if client_cert and client_cert.filename:
            client_cert.save(client_crt_path)
        if client_key and client_key.filename:
            client_key.save(client_key_path)
            try:
                os.chmod(client_key_path, 0o600)
            except OSError:
                pass
        abs_config = os.path.abspath(config_path)
        if config_file and config_file.filename:
            _set_setting('dxl_config_path', abs_config)
            audit_log('admin_dxl_upload', f'by={current_user.username} path={abs_config}')
            return _api_ok(message='Files saved. Config path updated.', data={'dxl_config_path': abs_config})
        audit_log('admin_dxl_upload', f'by={current_user.username} certs_only')
        return _api_ok(message='Certificate files saved. Upload the config file to set the path.', data={'dxl_config_path': _from_app('_get_setting')[0]('dxl_config_path', '')})
    except Exception as e:
        logging.exception('admin dxl_upload failed')
        return _api_error(str(e), 500)


@bp.route('/dxl/test', methods=['POST'])
@admin_required
def dxl_test():
    """Run DXL connection test step-by-step; return list of steps for Admin UI."""
    _api_ok, _api_error = _from_app('_api_ok', '_api_error')
    try:
        from utils.dxl_tie import test_dxl_connection_steps
        data = request.get_json() or {}
        config_path = (data.get('dxl_config_path') or '').strip()
        steps = test_dxl_connection_steps(config_path)
        success = all(s.get('status') == 'ok' for s in steps)
        return _api_ok(data={'success': success, 'steps': steps})
    except Exception as e:
        logging.exception('admin dxl_test failed')
        return _api_error(str(e), 500)


@bp.route('/ldap/test', methods=['POST'])
@admin_required
def ldap_test():
    """Run LDAP connection test for one or multiple servers; return steps per server for Admin UI."""
    _api_ok, _api_error = _from_app('_api_ok', '_api_error')
    try:
        from utils.ldap_auth import test_ldap_connection_steps
        import json as _json
        data = request.get_json() or {}
        servers = data.get('ldap_servers')
        if isinstance(servers, list) and len(servers) > 0:
            results = []
            all_ok = True
            for i, s in enumerate(servers):
                url = (s.get('url') or '').strip()
                base_dn = (s.get('base_dn') or '').strip()
                bind_dn = (s.get('bind_dn') or '').strip()
                bind_password = s.get('bind_password') or ''
                steps = test_ldap_connection_steps(url, base_dn, bind_dn, bind_password)
                ok = all(st.get('status') == 'ok' for st in steps)
                if not ok:
                    all_ok = False
                results.append({'url': url or '(empty)', 'steps': steps, 'success': ok})
            return _api_ok(data={'success': all_ok, 'servers': results})
        # Single server (legacy)
        ldap_url = (data.get('ldap_url') or '').strip()
        base_dn = (data.get('ldap_base_dn') or '').strip()
        bind_dn = (data.get('ldap_bind_dn') or '').strip()
        bind_password = data.get('ldap_bind_password') or ''
        steps = test_ldap_connection_steps(ldap_url, base_dn, bind_dn, bind_password)
        success = all(s.get('status') == 'ok' for s in steps)
        return _api_ok(data={'success': success, 'steps': steps})
    except Exception as e:
        logging.exception('admin ldap_test failed')
        return _api_error(str(e), 500)


@bp.route('/logs/tail')
@admin_required
def logs_tail():
    """Return last N lines of CEF audit log (default 50)."""
    _api_ok, _api_error, get_audit_log_path = _from_app('_api_ok', '_api_error', 'get_audit_log_path')
    try:
        lines = min(int(request.args.get('lines', 50)), 500)
        log_path = get_audit_log_path()
        if not os.path.isfile(log_path):
            return _api_ok(data={'lines': [], 'path': log_path, 'message': 'Log file not found or empty.'})
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            all_lines = f.readlines()
        last = all_lines[-lines:] if len(all_lines) >= lines else all_lines
        return _api_ok(data={'lines': [ln.rstrip('\n\r') for ln in last], 'path': log_path})
    except Exception as e:
        logging.exception('admin logs_tail failed')
        return _api_error(str(e), 500)


# --- Users ---

def _avatar_url(profile):
    """Return avatar URL or None (used in list)."""
    if profile and profile.avatar_path:
        return url_for('static', filename=profile.avatar_path)
    return None


@bp.route('/users', methods=['GET'])
@admin_required
def list_users():
    """List all users (username, source, is_admin, last login, avatar_url)."""
    _api_ok = _from_app('_api_ok')[0]
    users = User.query.order_by(User.username).all()
    result = []
    for u in users:
        profile = UserProfile.query.filter_by(user_id=u.id).first()
        result.append({
            'id': u.id,
            'username': u.username,
            'source': u.source,
            'is_admin': u.is_admin,
            'is_active': u.is_active,
            'must_change_password': getattr(u, 'must_change_password', False),
            'display_name': (profile and profile.display_name) or u.username,
            'avatar_url': _avatar_url(profile),
            'last_login_at': u.last_login_at.isoformat() if u.last_login_at else None,
            'created_at': u.created_at.isoformat() if u.created_at else None,
        })
    return _api_ok(data={'users': result})


@bp.route('/users', methods=['POST'])
@admin_required
def create_user():
    """Create a local user (admin only)."""
    _api_ok, _api_error, _commit_with_retry, audit_log = _from_app('_api_ok', '_api_error', '_commit_with_retry', 'audit_log')
    try:
        data = request.get_json() or {}
        username = (data.get('username') or '').strip().lower()
        password = data.get('password') or ''
        display_name = (data.get('display_name') or '').strip() or username
        is_admin = bool(data.get('is_admin', False))
        if not username:
            return jsonify({'success': False, 'message': 'Username is required'}), 400
        if len(username) < 2:
            return jsonify({'success': False, 'message': 'Username must be at least 2 characters'}), 400
        if not password or len(password) < 4:
            return jsonify({'success': False, 'message': 'Password must be at least 4 characters'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 409
        must_change = bool(data.get('must_change_password', False))
        user = User(
            username=username,
            password_hash=hash_password(password),
            source='local',
            is_admin=is_admin,
            is_active=True,
            must_change_password=must_change,
        )
        db.session.add(user)
        _commit_with_retry()
        profile = UserProfile(user_id=user.id, display_name=display_name)
        db.session.add(profile)
        _commit_with_retry()
        audit_log('admin_user_create', f'username={username} by={current_user.username}')
        return _api_ok(message=f'User {username} created', data={'id': user.id})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Username already exists'}), 409
    except Exception as e:
        logging.exception('api_admin_create_user failed')
        return _api_error(str(e), 500)


@bp.route('/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    """Update a user (admin only). Local: full edit. LDAP: is_admin and display_name only."""
    _api_error, _commit_with_retry, audit_log = _from_app('_api_error', '_commit_with_retry', 'audit_log')
    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        if user.source == 'system':
            return jsonify({'success': False, 'message': 'System users (e.g. MISP sync) cannot be edited'}), 400
        data = request.get_json() or {}
        is_ldap = user.source == 'ldap'

        if 'display_name' in data:
            profile = UserProfile.query.filter_by(user_id=user.id).first()
            display_name = (data.get('display_name') or '').strip()
            if profile:
                profile.display_name = display_name or user.username
            else:
                db.session.add(UserProfile(user_id=user.id, display_name=display_name or user.username))
        if 'is_admin' in data:
            user.is_admin = bool(data['is_admin'])

        if not is_ldap:
            if 'password' in data and data['password']:
                pwd = str(data['password'])
                if len(pwd) < 4:
                    return jsonify({'success': False, 'message': 'Password must be at least 4 characters'}), 400
                user.password_hash = hash_password(pwd)
            if 'must_change_password' in data:
                user.must_change_password = bool(data['must_change_password'])

        _commit_with_retry()
        audit_log('admin_user_update', f'user_id={user_id} by={current_user.username}')
        return jsonify({'success': True, 'message': f'User {user.username} updated'})
    except Exception as e:
        logging.exception('api_admin_update_user failed')
        return _api_error(str(e), 500)


@bp.route('/users/<int:user_id>/avatar', methods=['POST'])
@admin_required
def user_avatar_upload(user_id):
    """Upload profile picture for a user (admin only)."""
    _api_ok, _api_error, _commit_with_retry, audit_log = _from_app(
        '_api_ok', '_api_error', '_commit_with_retry', 'audit_log'
    )
    try:
        user = db.session.get(User, user_id)
        if not user:
            return _api_error('User not found', 404)
        if 'file' not in request.files and 'avatar' not in request.files:
            return _api_error('No file provided', 400)
        file = request.files.get('file') or request.files.get('avatar')
        rel_path, err = _save_avatar(file, user_id, ALLOWED_AVATAR_EXT, AVATARS_DIR)
        if err:
            return _api_error(err, 400)
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        if not profile:
            profile = UserProfile(user_id=user_id, display_name=user.username)
            db.session.add(profile)
        profile.avatar_path = rel_path
        _commit_with_retry()
        audit_log('admin_avatar_upload', f'user_id={user_id} username={user.username} by={current_user.username}')
        return _api_ok(data={'avatar_url': url_for('static', filename=rel_path)}, message='Profile picture updated')
    except Exception as e:
        logging.exception('api_admin_user_avatar_upload failed')
        return _api_error(str(e), 500)


@bp.route('/users/<int:user_id>/avatar', methods=['DELETE'])
@admin_required
def user_avatar_delete(user_id):
    """Remove profile picture of a user (admin only)."""
    _api_ok, _api_error, _commit_with_retry, audit_log = _from_app('_api_ok', '_api_error', '_commit_with_retry', 'audit_log')
    try:
        user = db.session.get(User, user_id)
        if not user:
            return _api_error('User not found', 404)
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        if not profile or not profile.avatar_path:
            return _api_ok(data={'avatar_url': None}, message='No avatar to remove')
        old_path = profile.avatar_path
        profile.avatar_path = None
        _commit_with_retry()
        if old_path and old_path.startswith('avatars/'):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            filepath = os.path.join(base_dir, 'static', old_path)
            if os.path.isfile(filepath):
                try:
                    os.remove(filepath)
                except OSError:
                    pass
        audit_log('admin_avatar_delete', f'user_id={user_id} username={user.username} by={current_user.username}')
        return _api_ok(data={'avatar_url': None}, message='Profile picture removed')
    except Exception as e:
        logging.exception('admin user_avatar_delete failed')
        return _api_error(str(e), 500)


@bp.route('/users/<int:user_id>/toggle-active', methods=['POST'])
@admin_required
def toggle_user_active(user_id):
    """Activate or deactivate a user (admin only)."""
    _api_error, _commit_with_retry, audit_log, invalidate_champs_leaderboard_cache = _from_app(
        '_api_error', '_commit_with_retry', 'audit_log', 'invalidate_champs_leaderboard_cache'
    )
    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        if user.id == current_user.id:
            return jsonify({'success': False, 'message': 'You cannot deactivate yourself'}), 400
        user.is_active = not user.is_active
        _commit_with_retry()
        status = 'activated' if user.is_active else 'deactivated'
        audit_log('admin_user_toggle', f'user_id={user_id} status={status} by={current_user.username}')
        try:
            invalidate_champs_leaderboard_cache(user_id=user_id)
        except Exception:
            pass
        return jsonify({'success': True, 'message': f'User {user.username} {status}', 'is_active': user.is_active})
    except Exception as e:
        logging.exception('api_admin_toggle_user_active failed')
        return _api_error(str(e), 500)


# --- Allowlist management (admin only) ---

@bp.route('/allowlist', methods=['GET'])
@admin_required
def allowlist_get():
    """Return raw allowlist file content."""
    _api_ok, _api_error = _from_app('_api_ok', '_api_error')
    ALLOWLIST_FILE, = _from_app('ALLOWLIST_FILE')
    try:
        raw = ''
        try:
            with open(ALLOWLIST_FILE, 'r', encoding='utf-8', errors='replace') as f:
                raw = f.read()
        except OSError:
            raw = ''
        return _api_ok(data={'raw': raw})
    except Exception as e:
        logging.exception('admin allowlist_get failed')
        return _api_error(str(e), 500)


@bp.route('/allowlist', methods=['POST'])
@admin_required
def allowlist_save():
    """Replace allowlist file content with provided raw text."""
    _api_ok, _api_error, audit_log = _from_app('_api_ok', '_api_error', 'audit_log')
    ALLOWLIST_FILE, = _from_app('ALLOWLIST_FILE')
    try:
        data = request.get_json() or {}
        raw = data.get('raw')
        if raw is None:
            return _api_error('raw is required', 400)
        if not isinstance(raw, str):
            return _api_error('raw must be a string', 400)
        if len(raw) > 500_000:
            return _api_error('Allowlist too large (max 500KB)', 400)
        # Normalize line endings; keep comments as-is
        raw_norm = raw.replace('\r\n', '\n').replace('\r', '\n')
        os.makedirs(os.path.dirname(ALLOWLIST_FILE), exist_ok=True)
        with open(ALLOWLIST_FILE, 'w', encoding='utf-8', newline='\n') as f:
            f.write(raw_norm.strip() + '\n' if raw_norm.strip() else '')
        clear_allowlist_cache(ALLOWLIST_FILE)
        audit_log('admin_allowlist_save', f'by={current_user.username}')
        return _api_ok(message='Allowlist saved')
    except Exception as e:
        logging.exception('admin allowlist_save failed')
        return _api_error(str(e), 500)


@bp.route('/allowlist/reload', methods=['POST'])
@admin_required
def allowlist_reload():
    """Clear allowlist cache so next check reloads from disk."""
    _api_ok, _api_error, audit_log = _from_app('_api_ok', '_api_error', 'audit_log')
    ALLOWLIST_FILE, = _from_app('ALLOWLIST_FILE')
    try:
        clear_allowlist_cache(ALLOWLIST_FILE)
        audit_log('admin_allowlist_reload', f'by={current_user.username}')
        return _api_ok(message='Allowlist reloaded')
    except Exception as e:
        logging.exception('admin allowlist_reload failed')
        return _api_error(str(e), 500)


# --- MISP Integration ---

@bp.route('/misp/test', methods=['POST'])
@admin_required
def misp_test():
    """Test MISP connectivity step-by-step; return steps for Admin UI live log."""
    _api_ok, _api_error, _get_setting = _from_app('_api_ok', '_api_error', '_get_setting')
    try:
        data = request.get_json() or {}
        url = (data.get('misp_url') or _get_setting('misp_url', '')).strip()
        api_key = (data.get('misp_api_key') or _get_setting('misp_api_key', '')).strip()
        verify_ssl = (data.get('misp_verify_ssl') or _get_setting('misp_verify_ssl', 'false')).lower() == 'true'

        from utils.misp_sync import test_connection_steps
        steps = test_connection_steps(url, api_key, verify_ssl)
        success = all(s.get('status') == 'ok' for s in steps)
        return _api_ok(data={'success': success, 'steps': steps})
    except Exception as e:
        logging.exception('admin misp_test failed')
        return _api_error(str(e), 500)


@bp.route('/misp/sync', methods=['POST'])
@admin_required
def misp_sync_now():
    """Run MISP sync manually (admin only)."""
    _api_ok, _api_error, _get_setting, _set_setting, audit_log = _from_app(
        '_api_ok', '_api_error', '_get_setting', '_set_setting', 'audit_log'
    )
    try:
        try:
            from misp_settings import MISP_SYNC_KEYS
            sync_keys = MISP_SYNC_KEYS
        except ImportError:
            sync_keys = _MISP_SYNC_KEYS_FALLBACK
        settings = {key: _get_setting(key, '') for key in sync_keys}

        from utils.misp_sync import run_sync
        log_lines = []
        result = run_sync(settings, log_lines=log_lines)

        import json
        from datetime import datetime, timezone
        now_str = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        _set_setting('misp_last_sync', now_str)
        _set_setting('misp_last_sync_result', json.dumps(result)[:1000])

        audit_log('misp_sync', f"manual by={current_user.username} added={result.get('added', 0)} skipped={result.get('skipped', 0)}")

        if result.get('success'):
            inv = result.get('invalid', 0)
            inv_msg = f", {inv} invalid" if inv else ''
            return _api_ok(
                message=f"Sync complete: {result.get('added', 0)} added, {result.get('skipped', 0)} duplicates skipped{inv_msg}",
                data={**result, 'steps': log_lines}
            )
        return jsonify({'success': False, 'message': result.get('error', 'Sync failed'), 'data': {**result, 'steps': log_lines}}), 400
    except Exception as e:
        logging.exception('admin misp_sync_now failed')
        return _api_error(str(e), 500)


@bp.route('/backfill-ioc-aggregate-fields', methods=['POST'])
@admin_required
def backfill_ioc_aggregate_fields():
    """
    Backfill country_code, tld, email_domain for existing IOCs that have them null.
    Fixes Live Stats (Top Countries, Top TLDs, Top Email Domains) for MISP-imported or legacy data.
    """
    _api_ok, _api_error, audit_log, _commit_with_retry = _from_app(
        '_api_ok', '_api_error', 'audit_log', '_commit_with_retry'
    )
    try:
        from utils.ioc_aggregate_fields import compute_ioc_aggregate_fields

        geoip_reader = None
        try:
            from app import geoip_reader as _gr
            geoip_reader = _gr
        except ImportError:
            pass

        # IOCs missing aggregate fields: IP without country_code, Domain/URL without tld, Email without email_domain
        need_fill = IOC.query.filter(
            db.or_(
                db.and_(IOC.type == 'IP', IOC.country_code.is_(None)),
                db.and_(IOC.type == 'Domain', IOC.tld.is_(None)),
                db.and_(IOC.type == 'URL', IOC.tld.is_(None)),
                db.and_(IOC.type == 'Email', IOC.email_domain.is_(None)),
            )
        ).all()

        updated = 0
        for row in need_fill:
            agg = compute_ioc_aggregate_fields(row.type, row.value or '', geoip_reader)
            changed = False
            if row.type == 'IP' and agg.get('country_code') is not None:
                row.country_code = agg['country_code']
                changed = True
            if row.type in ('Domain', 'URL') and agg.get('tld') is not None:
                row.tld = agg['tld']
                changed = True
            if row.type == 'Email' and agg.get('email_domain') is not None:
                row.email_domain = agg['email_domain']
                changed = True
            if changed:
                updated += 1

        if updated > 0:
            _commit_with_retry()
        audit_log('backfill_ioc_aggregate', f'updated={updated} total_candidates={len(need_fill)} by={current_user.username}')
        return _api_ok(
            message=f'Backfill complete: {updated} IOCs updated (of {len(need_fill)} needing aggregate fields).',
            data={'updated': updated, 'candidates': len(need_fill)},
        )
    except Exception as e:
        logging.exception('admin backfill_ioc_aggregate_fields failed')
        return _api_error(str(e), 500)


# --- Admin HTML pages ---

@pages_bp.route('/')
@admin_required_page
def admin_index():
    """Admin dashboard - redirect to users list."""
    return redirect(url_for('admin_pages.admin_users'))


def _misp_settings_fallback(get_setting_fn):
    """Fallback MISP settings when misp_settings module is missing (e.g. old install)."""
    defaults = {
        'misp_enabled': 'false', 'misp_url': '', 'misp_api_key': '', 'misp_verify_ssl': 'false',
        'misp_last_days': '30', 'misp_filter_tags': '', 'misp_filter_types': '',
        'misp_published_only': 'true', 'misp_default_ttl': 'permanent', 'misp_sync_user': 'misp_sync',
        'misp_pull_interval': '60', 'misp_exclude_from_champs': 'true',
        'misp_push_enabled': 'false', 'misp_push_include_comment': 'true', 'misp_push_default_event_id': '',
        'misp_last_sync': '', 'misp_last_sync_result': '',
    }
    return {k: str((get_setting_fn(k, v) if callable(get_setting_fn) else get_setting_fn.get(k, v)) or v).strip() or v for k, v in defaults.items()}


def _get_ldap_servers_for_form(get_setting_fn):
    """Return list of LDAP server dicts for settings form; migrate from single server if needed."""
    import json as _json
    try:
        raw = (get_setting_fn('ldap_servers', '') or '').strip()
        if raw and raw != '[]':
            return _json.loads(raw)
        if (get_setting_fn('ldap_url', '') or '').strip():
            return [{
                'url': get_setting_fn('ldap_url', ''),
                'base_dn': get_setting_fn('ldap_base_dn', ''),
                'bind_dn': get_setting_fn('ldap_bind_dn', ''),
                'bind_password': get_setting_fn('ldap_bind_password', ''),
            }]
    except Exception:
        pass
    return []


def _build_admin_settings_form_context():
    """Shared dict for admin Settings and Integrations pages (forms read system_settings)."""
    _get_setting, = _from_app('_get_setting')
    try:
        from misp_settings import get_settings_for_form
        misp_settings_dict = get_settings_for_form(_get_setting)
    except ImportError:
        misp_settings_dict = _misp_settings_fallback(_get_setting)
    ldap_servers = _get_ldap_servers_for_form(_get_setting)
    try:
        from utils.feed_cache import FEED_CACHE_TTL_DEFAULT, normalize_feed_cache_ttl_seconds
        _ttl_raw = int(_get_setting('feed_cache_ttl_seconds', '300') or '300')
    except ValueError:
        _ttl_raw = FEED_CACHE_TTL_DEFAULT
    _feed_ttl = str(normalize_feed_cache_ttl_seconds(_ttl_raw))
    return {
        'session_inactivity_timeout_minutes': _get_setting('session_inactivity_timeout_minutes', '15'),
        'auth_mode': _get_setting('auth_mode', 'local_only'),
        'feeds_public_enabled': _get_setting('feeds_public_enabled', 'true'),
        'feed_cache_enabled': _get_setting('feed_cache_enabled', 'true'),
        'feed_cache_ttl_seconds': _feed_ttl,
        'ldap_enabled': _get_setting('ldap_enabled', 'false'),
        'ldap_url': _get_setting('ldap_url', ''),
        'ldap_base_dn': _get_setting('ldap_base_dn', ''),
        'ldap_bind_dn': _get_setting('ldap_bind_dn', ''),
        'ldap_bind_password': _get_setting('ldap_bind_password', ''),
        'ldap_servers': ldap_servers,
        'ldap_user_filter': _get_setting('ldap_user_filter', '(sAMAccountName=%(user)s)'),
        **misp_settings_dict,
        'syslog_udp_enabled': _get_setting('syslog_udp_enabled', 'false'),
        'syslog_udp_host': _get_setting('syslog_udp_host', ''),
        'syslog_udp_port': _get_setting('syslog_udp_port', '514'),
        'dxl_enabled': _get_setting('dxl_enabled', 'false'),
        'dxl_config_path': _get_setting('dxl_config_path', ''),
        'automation_fireeye_enabled': _get_setting('automation_fireeye_enabled', 'false'),
        'automation_fireeye_appliances': _get_setting('automation_fireeye_appliances', '[]'),
        'automation_fireeye_ignore_ssl': _get_setting('automation_fireeye_ignore_ssl', 'false'),
        'automation_trellix_nx_enabled': _get_setting('automation_trellix_nx_enabled', 'false'),
        'automation_trellix_nx_targets': _get_setting('automation_trellix_nx_targets', '[]'),
        'trellix_ex_enabled': _get_setting('trellix_ex_enabled', 'false'),
        'trellix_ex_targets': _trellix_ex_targets_json_for_form(_get_setting),
        'trellix_ex_base_url': _get_setting('trellix_ex_base_url', ''),
        'trellix_ex_login_path': _get_setting('trellix_ex_login_path', '/login/login'),
        'trellix_ex_upload_path': _get_setting('trellix_ex_upload_path', '/ex/yara_rules_ng/upload_yara'),
        'trellix_ex_username': _get_setting('trellix_ex_username', ''),
        'trellix_ex_password': _get_setting('trellix_ex_password', ''),
        'trellix_ex_manual_cookie': _get_setting('trellix_ex_manual_cookie', ''),
        'trellix_ex_verify_ssl': _get_setting('trellix_ex_verify_ssl', 'true'),
        'trellix_ex_f_type': _get_setting('trellix_ex_f_type', 'common'),
        'trellix_ex_content_type': _get_setting('trellix_ex_content_type', 'base'),
        'trellix_ex_csrf_param': _get_setting('trellix_ex_csrf_param', ''),
        'trellix_ex_csrf_token': _get_setting('trellix_ex_csrf_token', ''),
        'ioc_push_enabled': _get_setting('ioc_push_enabled', 'false'),
        'ioc_push_ignore_ssl': _get_setting('ioc_push_ignore_ssl', 'false'),
        'ioc_push_targets': _get_setting('ioc_push_targets', '[]'),
        'search_comment_rtl_by_script': _get_setting('search_comment_rtl_by_script', 'true'),
        'esa_enabled': _get_setting('esa_enabled', 'false'),
        'esa_base_url': _get_setting('esa_base_url', ''),
        'esa_username': _get_setting('esa_username', ''),
        'esa_passphrase': _get_setting('esa_passphrase', ''),
        'esa_verify_ssl': _get_setting('esa_verify_ssl', 'true'),
        'esa_skip_misp_sync': _get_setting('esa_skip_misp_sync', 'true'),
        'esa_cleanup_on_expire': _get_setting('esa_cleanup_on_expire', 'true'),
        'esa_mappings': _get_setting('esa_mappings', '[]'),
        'esa_mapping_rows': _esa_mapping_rows_for_ui(_get_setting('esa_mappings', '[]')),
        'esa_deployment_mode': _get_setting('esa_deployment_mode', 'standalone'),
        'esa_group_name': _get_setting('esa_group_name', ''),
        'esa_host_name': _get_setting('esa_host_name', ''),
        'cortex_xdr_enabled': _get_setting('cortex_xdr_enabled', 'false'),
        'cortex_xdr_display_name': _get_setting('cortex_xdr_display_name', ''),
        'cortex_xdr_base_url': _get_setting('cortex_xdr_base_url', ''),
        'cortex_xdr_api_key_id': _get_setting('cortex_xdr_api_key_id', ''),
        'cortex_xdr_api_key': _get_setting('cortex_xdr_api_key', ''),
        'cortex_xdr_verify_ssl': _get_setting('cortex_xdr_verify_ssl', 'true'),
        'cortex_xdr_hash_blocklist_enabled': _get_setting('cortex_xdr_hash_blocklist_enabled', 'true'),
        'google_secops_enabled': _get_setting('google_secops_enabled', 'false'),
        'google_secops_display_name': _get_setting('google_secops_display_name', ''),
        'google_secops_base_url': _get_setting('google_secops_base_url', ''),
        'google_secops_chronicle_api_base': _get_setting('google_secops_chronicle_api_base', ''),
        'google_secops_project_number': _get_setting('google_secops_project_number', ''),
        'google_secops_location': _get_setting('google_secops_location', ''),
        'google_secops_instance_id': _get_setting('google_secops_instance_id', ''),
        'google_secops_customer_id': _get_setting('google_secops_customer_id', ''),
        'google_secops_data_table_id': _get_setting('google_secops_data_table_id', ''),
        'google_secops_credentials_json': _get_setting('google_secops_credentials_json', ''),
        'google_secops_verify_ssl': _get_setting('google_secops_verify_ssl', 'true'),
    }


@pages_bp.route('/settings')
@admin_required_page
def admin_settings():
    """Admin settings: feeds, TAXII, cache, search, tags, LDAP, MISP, Syslog."""
    try:
        return render_template('admin/settings.html', settings=_build_admin_settings_form_context())
    except Exception:
        logging.exception('admin_settings page failed')
        from flask import abort
        abort(500)


@pages_bp.route('/integrations')
@admin_required_page
def admin_integrations():
    """Built-in vendor integrations: Trellix EX/NX, Cisco ESA (OpenDXL under Automations)."""
    try:
        return render_template('admin/integrations.html', settings=_build_admin_settings_form_context())
    except Exception:
        logging.exception('admin_integrations page failed')
        from flask import abort
        abort(500)


@pages_bp.route('/automations')
@admin_required_page
def admin_automations():
    """Outbound automations: IOC push, YARA push, OpenDXL (DXL fabric)."""
    try:
        return render_template('admin/automations.html', settings=_build_admin_settings_form_context())
    except Exception:
        logging.exception('admin_automations page failed')
        from flask import abort
        abort(500)


@pages_bp.route('/sanity')
@admin_required_page
def admin_sanity():
    """Admin Sanity Check page - behaviour for critical anomalies (block/warn)."""
    _get_setting, = _from_app('_get_setting')
    mode = _get_setting('sanity_check_mode', 'block_non_admin').strip().lower()
    if mode not in ('block_all', 'block_non_admin', 'warn_all'):
        mode = 'block_non_admin'
    return render_template('admin/sanity.html', sanity_check_mode=mode)


@pages_bp.route('/allowlist')
@admin_required_page
def admin_allowlist():
    """Admin allowlist management page (known-good / critical assets)."""
    return render_template('admin/allowlist.html')


@pages_bp.route('/users')
@admin_required_page
def admin_users():
    """Admin users list page."""
    return render_template('admin/users.html')


@pages_bp.route('/scoring')
@admin_required_page
def admin_scoring():
    """Admin scoring method selection page (Champs)."""
    _get_setting, = _from_app('_get_setting')
    current = _get_setting('champs_scoring_method', '1')
    return render_template('admin/scoring.html', scoring_methods=SCORING_METHODS, current=current)


@pages_bp.route('/certificate')
@admin_required_page
def admin_certificate():
    """Admin SSL/TLS certificate settings - upload cert signed by local CA for HTTPS (prevent MITM)."""
    _certificate_status, = _from_app('_certificate_status')
    status = _certificate_status()
    return render_template('admin/certificate.html', cert_status=status)


@pages_bp.route('/logs')
@admin_required_page
def admin_logs():
    """Admin audit log viewer (CEF log, last 50 lines)."""
    return render_template('admin/logs.html')
