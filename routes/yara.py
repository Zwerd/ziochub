"""
YARA API routes: upload, list, delete, view, update, edit-yara-meta.
Register with url_prefix='/api'.
Uses lazy imports from app for shared helpers to avoid circular imports.
"""
import json
import logging
import os
import shutil
import threading
from datetime import datetime

from flask import Blueprint, request, jsonify, current_app
from flask_login import current_user
from sqlalchemy.exc import IntegrityError

from sqlalchemy import func
from extensions import db
from models import YaraRule, Campaign, User, iso_utc
from utils.yara_utils import (
    yara_safe_path,
    validate_yara_syntax,
    yara_content_sha256,
    sanitize_yara_filename,
)
from utils.decorators import login_required, admin_required
from utils.refanger import sanitize_comment
from utils.validation_messages import (
    MSG_CONTENT_REQUIRED,
    MSG_FILENAME_REQUIRED,
    MSG_YARA_DELETE_REASON_REQUIRED,
    MSG_YARA_DUPLICATE_CONTENT_UPDATE,
    MSG_YARA_DUPLICATE_CONTENT_UPLOAD,
    MSG_YARA_EDIT_REASON_REQUIRED,
    MSG_FILE_NOT_FOUND,
    MSG_INVALID_FILENAME,
    MSG_INVALID_TYPE,
    MSG_JSON_BODY_REQUIRED,
    MSG_YARA_COMPILER_UNAVAILABLE,
    MSG_YARA_FILENAME_INVALID,
    MSG_YARA_FILENAME_NORMALIZED,
    MSG_YARA_SOURCE_EMPTY,
    MSG_YARA_SOURCE_TOO_LARGE,
)
from utils.champs import compute_yara_quality_points


bp = Blueprint('yara_api', __name__, url_prefix='/api')


def _from_app(*names):
    import app as _app
    return tuple(getattr(_app, n) for n in names)


def _record_yara_distribution_push(filename: str, result: dict | None, api_source: str) -> None:
    try:
        from utils.downstream import record_yara_push_target_results
        record_yara_push_target_results(
            filename,
            (result or {}).get('results', []),
            api_source=api_source,
        )
    except Exception:
        logging.debug('record_yara_push_target_results failed', exc_info=True)


def _mark_yara_distribution_delete(filename: str, result: dict | None, api_source: str) -> None:
    try:
        from utils.downstream import mark_yara_push_target_results_removed
        mark_yara_push_target_results_removed(
            filename,
            (result or {}).get('results', []),
            api_source=api_source,
        )
    except Exception:
        logging.debug('mark_yara_push_target_results_removed failed', exc_info=True)


def _mark_yara_removed_from_hub(filename: str) -> None:
    try:
        from utils.downstream import mark_yara_removed_from_hub
        mark_yara_removed_from_hub(filename)
    except Exception:
        logging.debug('mark_yara_removed_from_hub failed', exc_info=True)


def _data_yara():
    return current_app.config.get('DATA_YARA') or ''


def _data_yara_pending():
    return current_app.config.get('DATA_YARA_PENDING') or ''


def _data_yara_rejected():
    return current_app.config.get('DATA_YARA_REJECTED') or ''


def _yara_safe_path(filename):
    return yara_safe_path(filename, _data_yara())


def _yara_safe_path_pending(filename):
    return yara_safe_path(filename, _data_yara_pending())


def _yara_safe_path_rejected(filename):
    return yara_safe_path(filename, _data_yara_rejected())


def _move_yara_file(src: str, dst: str) -> None:
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.isfile(dst):
        os.remove(dst)
    shutil.move(src, dst)


def _yara_upload_fail_audit(audit_log_fn, code: str, reason: str, *, filename: str = '', analyst: str = ''):
    """CEF audit for rejected YARA uploads (Tier 1 failure)."""
    from utils.audit_events import audit_log_event
    fn = (filename or '').strip()
    if fn:
        safe, _ = sanitize_yara_filename(os.path.basename(fn))
        fn = safe or os.path.basename(fn)
    audit_log_event(
        'YARA_UPLOAD_FAIL',
        'fail',
        username=(analyst or getattr(current_user, 'username', None) or None),
        code=code,
        reason=reason,
        file=(fn or '')[:120],
    )


def _reject_invalid_yara_syntax(content: str):
    """
    Same rules as POST /api/yara/validate-syntax: libyara compile must succeed.
    Returns Flask (response, status) tuple if invalid, or None if OK.
    """
    ok, err = validate_yara_syntax(content)
    if ok:
        return None
    if err == 'empty':
        return jsonify({'success': False, 'message': MSG_YARA_SOURCE_EMPTY}), 400
    if err == 'too_large':
        return jsonify({'success': False, 'message': MSG_YARA_SOURCE_TOO_LARGE}), 400
    if isinstance(err, str) and err.startswith('library_unavailable'):
        detail = err[len('library_unavailable'):].lstrip(':').strip()
        msg = MSG_YARA_COMPILER_UNAVAILABLE
        if detail:
            msg = f'{msg} ({detail})'
        return jsonify({'success': False, 'message': msg, 'code': 'no_compiler'}), 400
    if isinstance(err, str) and err.startswith('library_load_failed:'):
        detail = err.split(':', 1)[1].strip()
        msg = MSG_YARA_COMPILER_UNAVAILABLE
        if detail:
            msg = f'{msg} ({detail})'
        return jsonify({'success': False, 'message': msg, 'code': 'no_compiler'}), 400
    return jsonify({'success': False, 'message': err or 'Invalid YARA syntax'}), 400


def _find_existing_yara_with_same_content(content: str, exclude_filename: str | None = None) -> str | None:
    """
    Return basename of an existing rule with identical body (DB by content_sha256, else scan disk).
    exclude_filename: when editing, ignore the file being updated.
    """
    h = yara_content_sha256(content)
    q = YaraRule.query.filter(YaraRule.content_sha256 == h)
    if exclude_filename:
        q = q.filter(YaraRule.filename != exclude_filename)
    row = q.first()
    if row:
        return row.filename
    excl = {exclude_filename} if exclude_filename else set()
    for base in (_data_yara(), _data_yara_pending(), _data_yara_rejected()):
        if not base or not os.path.isdir(base):
            continue
        for name in os.listdir(base):
            if not name.lower().endswith('.yar'):
                continue
            if name in excl:
                continue
            path = os.path.join(base, name)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    other = f.read()
            except OSError:
                continue
            if yara_content_sha256(other) == h:
                return name
    return None


def _schedule_yara_outbound_push(rule, content: str, _get_setting, audit_log) -> bool:
    """Push approved YARA to configured automation targets (background thread). Returns True if push scheduled."""
    fireeye_pending = False
    try:
        from utils.trellix_ex import trellix_ex_enabled as _trellix_ex_on
        from utils.trellix_cms import trellix_cms_enabled as _trellix_cms_on
        from utils.trellix_nx import trellix_nx_wmps_enabled as _nx_wmps_on
        from utils.yara_push_targets import (
            merged_yara_automation_appliances,
            yara_http_push_verify_ssl,
            yara_session_push_verify_ssl,
        )

        fe_on = _get_setting('automation_fireeye_enabled', 'false').lower() == 'true'
        tx_on = _trellix_ex_on(_get_setting)
        cms_on = _trellix_cms_on(_get_setting)
        nx_wmps_on = _nx_wmps_on(_get_setting)
        appliances = []
        if fe_on:
            appliances = merged_yara_automation_appliances(_get_setting)
            if not isinstance(appliances, list):
                appliances = []
        has_fe_targets = fe_on and len(appliances) > 0
        if has_fe_targets or tx_on or cms_on or nx_wmps_on:
            from utils.yara_http_push import push_yara_to_appliances, set_fireeye_status

            app_obj = current_app._get_current_object()
            verify_fe = yara_http_push_verify_ssl(_get_setting)
            verify_session = yara_session_push_verify_ssl(_get_setting)
            rule_filename = rule.filename
            set_fireeye_status(rule_filename, 'pending', '')

            def _yara_outbound_upload():
                with app_obj.app_context():
                    try:
                        combined_results = []
                        overall = True
                        from utils.yara_retry_enqueue import enqueue_yara_vendor_failure

                        if has_fe_targets:
                            result_fe = push_yara_to_appliances(
                                content, rule_filename, appliances, audit_log, verify_ssl=verify_fe
                            )
                            combined_results.extend(result_fe.get('results', []))
                            overall = overall and bool(result_fe.get('overall_success'))
                            _record_yara_distribution_push(rule_filename, result_fe, 'yara_http')
                            enqueue_yara_vendor_failure(
                                'yara_http', rule_filename, result_fe, get_setting=_get_setting,
                            )
                        if tx_on:
                            from utils.trellix_ex import push_yara_trellix_ex
                            result_tx = push_yara_trellix_ex(
                                content, rule_filename, _get_setting, audit_log, verify_ssl=verify_session,
                            )
                            combined_results.extend(result_tx.get('results', []))
                            overall = overall and bool(result_tx.get('overall_success'))
                            _record_yara_distribution_push(rule_filename, result_tx, 'yara_trellix_ex')
                            enqueue_yara_vendor_failure(
                                'trellix_ex', rule_filename, result_tx, get_setting=_get_setting,
                            )
                        if cms_on:
                            from utils.trellix_cms import push_yara_trellix_cms
                            result_cms = push_yara_trellix_cms(
                                content, rule_filename, _get_setting, audit_log, verify_ssl=verify_session,
                            )
                            combined_results.extend(result_cms.get('results', []))
                            overall = overall and bool(result_cms.get('overall_success'))
                            _record_yara_distribution_push(rule_filename, result_cms, 'yara_trellix_cms')
                            enqueue_yara_vendor_failure(
                                'trellix_cms', rule_filename, result_cms, get_setting=_get_setting,
                            )
                        if nx_wmps_on:
                            from utils.trellix_nx import push_yara_nx_wmps
                            result_nxw = push_yara_nx_wmps(
                                content, rule_filename, _get_setting, audit_log, verify_ssl=verify_session,
                            )
                            combined_results.extend(result_nxw.get('results', []))
                            overall = overall and bool(result_nxw.get('overall_success'))
                            _record_yara_distribution_push(rule_filename, result_nxw, 'yara_trellix_nx')
                            enqueue_yara_vendor_failure(
                                'trellix_nx', rule_filename, result_nxw, get_setting=_get_setting,
                            )
                        result = {'overall_success': overall, 'results': combined_results}
                        try:
                            from utils.integration_telemetry import record_yara_automation_results
                            record_yara_automation_results(
                                result, kind='push', context={'filename': rule_filename}
                            )
                        except Exception:
                            logging.debug('record_yara_automation_results failed', exc_info=True)
                        if result['overall_success']:
                            set_fireeye_status(rule_filename, 'success', 'All automation targets updated.')
                        else:
                            msgs = '; '.join(
                                r.get('name', '') + ': ' + (r.get('message') or '')
                                for r in result.get('results', [])
                            )
                            set_fireeye_status(rule_filename, 'error', msgs or 'Push failed')
                    except Exception as e:
                        logging.exception('YARA outbound push failed for %s', rule_filename)
                        try:
                            set_fireeye_status(rule_filename, 'error', str(e))
                        except Exception:
                            pass
                        audit_log('yara_push_fail', f'file={rule_filename} error={e}')

            threading.Thread(target=_yara_outbound_upload, daemon=True).start()
            fireeye_pending = True
    except Exception as e:
        logging.warning('YARA outbound automation setup failed: %s', e)
    return fireeye_pending


@bp.route('/upload-yara', methods=['POST'])
@login_required
def upload_yara():
    try:
        audit_log, = _from_app('audit_log')
        analyst_name = (current_user.username or '').lower()
        _auto_ticket_id, = _from_app('_auto_ticket_id')
        if 'file' not in request.files:
            _yara_upload_fail_audit(audit_log, 'no_file', 'No file provided', analyst=analyst_name)
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        file = request.files['file']
        ticket_id = (request.form.get('ticket_id') or '').strip() or _auto_ticket_id(current_user.id)
        campaign_name = (request.form.get('campaign_name') or '').strip() or None
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id
        if file.filename == '':
            _yara_upload_fail_audit(audit_log, 'no_file_selected', 'No file selected', analyst=analyst_name)
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        if not file.filename.lower().endswith('.yar'):
            _yara_upload_fail_audit(
                audit_log, 'invalid_type', 'Invalid file type. Only .yar files are allowed',
                filename=file.filename, analyst=analyst_name,
            )
            return jsonify({'success': False, 'message': 'Invalid file type. Only .yar files are allowed'}), 400
        file_content = file.read().decode('utf-8', errors='replace')
        syntax_reject = _reject_invalid_yara_syntax(file_content)
        if syntax_reject is not None:
            resp, _status = syntax_reject
            try:
                payload = resp.get_json(silent=True) or {}
            except Exception:
                payload = {}
            _yara_upload_fail_audit(
                audit_log,
                payload.get('code') or 'syntax_invalid',
                payload.get('message') or 'Invalid YARA syntax',
                filename=file.filename,
                analyst=analyst_name,
            )
            return syntax_reject
        dup_name = _find_existing_yara_with_same_content(file_content)
        if dup_name:
            msg = MSG_YARA_DUPLICATE_CONTENT_UPLOAD.format(filename=dup_name)
            _yara_upload_fail_audit(
                audit_log, 'duplicate_content', msg, filename=file.filename, analyst=analyst_name,
            )
            return jsonify({
                'success': False,
                'message': msg,
                'code': 'duplicate_content',
                'existing_filename': dup_name,
            }), 409
        raw_base = os.path.basename(file.filename or '').strip()
        safe_filename, was_normalized = sanitize_yara_filename(raw_base)
        if not safe_filename:
            _yara_upload_fail_audit(
                audit_log, 'invalid_filename', MSG_YARA_FILENAME_INVALID,
                filename=file.filename, analyst=analyst_name,
            )
            return jsonify({'success': False, 'message': MSG_YARA_FILENAME_INVALID}), 400
        original_filename = safe_filename
        data_yara = _data_yara()
        data_pending = _data_yara_pending()
        filepath_approved = os.path.join(data_yara, safe_filename)
        filepath_pending = os.path.join(data_pending, safe_filename)
        filepath_rejected = os.path.join(_data_yara_rejected(), safe_filename)
        username = analyst_name
        if os.path.exists(filepath_approved) or os.path.exists(filepath_pending) or os.path.exists(filepath_rejected):
            _yara_upload_fail_audit(
                audit_log, 'name_exists', 'Rule name already exists',
                filename=safe_filename, analyst=analyst_name,
            )
            return jsonify({'success': False, 'message': 'Rule name already exists'}), 409
        existing_rule = YaraRule.query.filter_by(filename=safe_filename).first()
        if existing_rule:
            if (existing_rule.status or '').lower() == 'rejected' and (existing_rule.analyst or '').lower() == username:
                reject_msg = f'Rule "{safe_filename}" was rejected. Open Status → Rejected and use Edit & Resubmit.'
                _yara_upload_fail_audit(
                    audit_log, 'rejected_resubmit', reject_msg,
                    filename=safe_filename, analyst=analyst_name,
                )
                return jsonify({
                    'success': False,
                    'message': reject_msg,
                    'code': 'rejected_resubmit',
                    'filename': safe_filename,
                }), 409
            _yara_upload_fail_audit(
                audit_log, 'name_exists', 'Rule name already exists',
                filename=safe_filename, analyst=analyst_name,
            )
            return jsonify({'success': False, 'message': 'Rule name already exists'}), 409
        _get_setting = _from_app('_get_setting')[0]
        from utils.workflow_settings import yara_analyst_requires_approval
        needs_approval = yara_analyst_requires_approval(current_user, _get_setting)
        comment = (request.form.get('comment') or '').strip() or 'Uploaded YARA Rule'
        quality_pts = compute_yara_quality_points(file_content)
        content_hash = yara_content_sha256(file_content)
        _commit_with_retry, _api_error, _log_champs_event = _from_app('_commit_with_retry', '_api_error', '_log_champs_event')
        save_path = filepath_pending if needs_approval else filepath_approved
        rule_status = 'pending' if needs_approval else 'approved'
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(file_content)
        try:
            db.session.add(YaraRule(
                filename=safe_filename,
                original_filename=original_filename,
                analyst=username,
                ticket_id=ticket_id or None,
                comment=comment,
                campaign_id=campaign_id,
                quality_points=quality_pts,
                status=rule_status,
                content_sha256=content_hash,
            ))
            _commit_with_retry()
        except IntegrityError:
            db.session.rollback()
            if os.path.exists(save_path):
                try:
                    os.remove(save_path)
                except OSError:
                    pass
            _yara_upload_fail_audit(
                audit_log, 'name_exists', 'Rule name already exists',
                filename=safe_filename, analyst=analyst_name,
            )
            return _api_error('Rule name already exists', 409)
        except (ValueError, OSError) as e:
            db.session.rollback()
            if os.path.exists(save_path):
                try:
                    os.remove(save_path)
                except OSError:
                    pass
            _yara_upload_fail_audit(
                audit_log, 'db_error', str(e), filename=safe_filename, analyst=analyst_name,
            )
            return _api_error(f'Database or file error: {str(e)}', 500)
        cmt = (comment or '')[:60]
        audit_log(
            'YARA_UPLOAD',
            f'file={safe_filename} analyst={username} status={rule_status} comment="{cmt}"',
        )
        _log_champs_event('yara_upload', user_id=current_user.id, payload={'filename': safe_filename})
        refresh_champ_score_for_user = _from_app('refresh_champ_score_for_user')[0]
        refresh_champ_score_for_user(current_user.id)
        fireeye_pending = False
        if not needs_approval:
            rule_row = YaraRule.query.filter_by(filename=safe_filename).first()
            if rule_row:
                fireeye_pending = _schedule_yara_outbound_push(rule_row, file_content, _get_setting, audit_log)
        try:
            from utils.integration_telemetry import record_api_yara_upload
            record_api_yara_upload()
        except Exception:
            pass
        if needs_approval:
            message = f'YARA rule uploaded and pending approval: {safe_filename}'
        else:
            message = f'YARA rule published: {safe_filename}'
        if was_normalized:
            message = MSG_YARA_FILENAME_NORMALIZED.format(filename=safe_filename) + ' ' + message
        if ticket_id:
            message += f' (Ticket: {ticket_id})'
        return jsonify({
            'success': True,
            'message': message,
            'filename': safe_filename,
            'normalized': was_normalized,
            'pending_approval': needs_approval,
            'fireeye_pending': fireeye_pending,
        })
    except (UnicodeDecodeError, OSError) as e:
        _api_error, = _from_app('_api_error')
        try:
            audit_log, = _from_app('audit_log')
            _yara_upload_fail_audit(
                audit_log, 'io_error', str(e),
                filename=(request.files.get('file').filename if request.files.get('file') else ''),
                analyst=(current_user.username or '').lower(),
            )
        except Exception:
            pass
        return _api_error(f'File read or write error: {str(e)}', 500)
    except Exception as e:
        logging.exception('upload_yara failed')
        _api_error, = _from_app('_api_error')
        try:
            audit_log, = _from_app('audit_log')
            _yara_upload_fail_audit(
                audit_log, 'unexpected', str(e),
                filename=(request.files.get('file').filename if request.files.get('file') else ''),
                analyst=(current_user.username or '').lower(),
            )
        except Exception:
            pass
        return _api_error('An unexpected error occurred', 500)


@bp.route('/yara/validate-syntax', methods=['POST'])
@login_required
def yara_validate_syntax():
    """Compile YARA source in memory (libyara); returns whether syntax is valid and compiler message if not."""
    if not request.is_json:
        return jsonify({'success': False, 'message': MSG_JSON_BODY_REQUIRED}), 400
    data = request.get_json(silent=True) or {}
    source = data.get('source')
    if source is not None and not isinstance(source, str):
        return jsonify({'success': False, 'message': MSG_INVALID_TYPE}), 400
    ok, err = validate_yara_syntax(source)
    if ok:
        return jsonify({'success': True, 'valid': True})
    if err == 'empty':
        return jsonify({'success': False, 'message': MSG_YARA_SOURCE_EMPTY}), 400
    if err == 'too_large':
        return jsonify({'success': False, 'message': MSG_YARA_SOURCE_TOO_LARGE}), 400
    if isinstance(err, str) and err.startswith('library_unavailable'):
        detail = err[len('library_unavailable'):].lstrip(':').strip()
        msg = MSG_YARA_COMPILER_UNAVAILABLE
        if detail:
            msg = f'{msg} ({detail})'
        return jsonify({
            'success': True,
            'valid': False,
            'message': msg,
            'code': 'no_compiler',
            'detail': detail or None,
        })
    if isinstance(err, str) and err.startswith('library_load_failed:'):
        detail = err.split(':', 1)[1].strip()
        msg = MSG_YARA_COMPILER_UNAVAILABLE
        if detail:
            msg = f'{msg} ({detail})'
        return jsonify({
            'success': True,
            'valid': False,
            'message': msg,
            'code': 'no_compiler',
        })
    return jsonify({'success': True, 'valid': False, 'message': err})


@bp.route('/list-yara', methods=['GET'])
@login_required
def list_yara():
    """Approved YARA rules only (data/YARA + DB status approved). Includes can_edit/can_delete for UI."""
    try:
        files = []
        data_yara = _data_yara()
        if not os.path.isdir(data_yara):
            return jsonify({'success': True, 'files': []})
        is_admin = bool(getattr(current_user, 'is_admin', False))
        uname_lower = (current_user.username or '').strip().lower()
        for name in sorted(os.listdir(data_yara)):
            if not name.lower().endswith('.yar'):
                continue
            filepath = os.path.join(data_yara, name)
            if not os.path.isfile(filepath):
                continue
            meta = YaraRule.query.filter_by(filename=name).first()
            status = (meta.status if meta else 'approved') or 'approved'
            if status.lower() != 'approved':
                continue
            size_bytes = os.path.getsize(filepath)
            mtime = os.path.getmtime(filepath)
            size_kb = round(size_bytes / 1024, 2)
            if meta and meta.uploaded_at:
                upload_date = meta.uploaded_at.strftime('%Y-%m-%d %H:%M')
            else:
                upload_date = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')
            display_name = name
            analyst_lower = (meta.analyst if meta else '').strip().lower()
            if is_admin:
                can_edit = True
                can_delete = True
            elif meta and analyst_lower and analyst_lower == uname_lower:
                can_edit = True
                can_delete = True
            else:
                can_edit = False
                can_delete = False
            files.append({
                'filename': name,
                'original_filename': name,
                'display_name': display_name,
                'size_kb': size_kb,
                'upload_date': upload_date,
                'user': meta.analyst if meta else None,
                'ticket_id': meta.ticket_id if meta else None,
                'comment': meta.comment if meta else None,
                'status': 'approved',
                'can_edit': can_edit,
                'can_delete': can_delete,
            })
        return jsonify({'success': True, 'files': files})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/delete-yara', methods=['DELETE'])
@login_required
def delete_yara():
    _commit_with_retry, audit_log, refresh_champ_score_for_user, _log_ioc_history = _from_app(
        '_commit_with_retry', 'audit_log', 'refresh_champ_score_for_user', '_log_ioc_history'
    )
    _log_champs_event = _from_app('_log_champs_event')[0]
    try:
        data = request.get_json() or {}
        filename = (data.get('filename') or '').strip()
        reason = (data.get('reason') or '').strip()
        if not filename:
            return jsonify({'success': False, 'message': MSG_FILENAME_REQUIRED}), 400
        safe, filepath = _yara_safe_path(filename)
        if safe is None:
            return jsonify({'success': False, 'message': MSG_INVALID_FILENAME}), 400
        if not os.path.isfile(filepath):
            return jsonify({'success': False, 'message': MSG_FILE_NOT_FOUND}), 404
        rule = YaraRule.query.filter_by(filename=safe).first()
        is_admin = getattr(current_user, 'is_admin', False)
        if is_admin and not reason:
            return jsonify({'success': False, 'message': MSG_YARA_DELETE_REASON_REQUIRED}), 400
        owner_id = None
        if rule:
            analyst_lower = (rule.analyst or '').strip().lower()
            if not is_admin and analyst_lower != current_user.username.lower():
                return jsonify({'success': False, 'message': 'Only the rule owner or an admin can delete this rule'}), 403
            if analyst_lower:
                owner = User.query.filter(func.lower(User.username) == analyst_lower).first()
                if owner:
                    owner_id = owner.id
        else:
            if not is_admin:
                return jsonify({'success': False, 'message': 'Only an admin can delete this rule'}), 403
        hist_payload = {
            'reason': reason if is_admin else (reason or ''),
            'original_analyst': (rule.analyst or '') if rule else '',
            'original_comment': (rule.comment or '') if rule else '',
            'ticket_id': (rule.ticket_id or '') if rule else '',
            'original_uploaded_at': iso_utc(rule.uploaded_at) if rule else None,
            'deleted_by_admin': is_admin,
        }
        _log_ioc_history('YARA', safe, 'deleted', current_user.username, hist_payload)
        os.remove(filepath)
        YaraRule.query.filter_by(filename=safe).delete()
        _commit_with_retry()
        _mark_yara_removed_from_hub(safe)
        _audit_del = f'file={safe} analyst={current_user.username}'
        if reason:
            _audit_del += f' reason={reason[:120]!r}'
        audit_log('YARA_DELETE', _audit_del)
        try:
            _log_champs_event(
                'yara_deletion',
                user_id=current_user.id,
                payload={
                    'filename': safe,
                    'status': (rule.status if rule else 'unknown'),
                    'deleted_by_admin': is_admin,
                },
            )
            _commit_with_retry()
        except Exception as e:
            logging.warning('YARA delete: champs yara_deletion event failed: %s', e)
            db.session.rollback()
        try:
            refresh_champ_score_for_user(current_user.id)
        except Exception as e:
            logging.warning('YARA delete: refresh_champ_score for deleter failed: %s', e)
        if owner_id is not None and owner_id != current_user.id:
            try:
                refresh_champ_score_for_user(owner_id)
            except Exception as e:
                logging.warning('YARA delete: refresh_champ_score for owner failed: %s', e)
        _get_setting = _from_app('_get_setting')[0]
        fe_on = _get_setting('automation_fireeye_enabled', 'false').lower() == 'true'
        try:
            from utils.trellix_ex import delete_yara_trellix_ex, trellix_ex_enabled as _trellix_ex_on_delete
            tx_on = _trellix_ex_on_delete(_get_setting)
        except Exception:
            tx_on = False
        try:
            from utils.trellix_cms import delete_yara_trellix_cms, trellix_cms_enabled as _trellix_cms_on_delete
            cms_on = _trellix_cms_on_delete(_get_setting)
        except Exception:
            cms_on = False
        try:
            from utils.trellix_nx import delete_yara_nx_wmps, trellix_nx_wmps_enabled as _nx_wmps_on_delete

            nx_wmps_on = _nx_wmps_on_delete(_get_setting)
        except Exception:
            nx_wmps_on = False
        appliances = []
        if fe_on:
            try:
                from utils.yara_push_targets import merged_yara_automation_appliances
                appliances = merged_yara_automation_appliances(_get_setting)
                if not isinstance(appliances, list):
                    appliances = []
            except Exception as e:
                logging.warning('YARA delete: appliance list failed: %s', e)
                appliances = []
        has_fe = fe_on and bool(appliances)
        if has_fe or tx_on or cms_on or nx_wmps_on:
            from utils.yara_http_push import delete_yara_from_appliances
            app_obj = current_app._get_current_object()
            from utils.yara_push_targets import yara_http_push_verify_ssl, yara_session_push_verify_ssl

            verify_fe = yara_http_push_verify_ssl(_get_setting)
            verify_session = yara_session_push_verify_ssl(_get_setting)

            def _auto_delete():
                with app_obj.app_context():
                    try:
                        combined_results: list = []
                        overall = True
                        if has_fe:
                            result_fe = delete_yara_from_appliances(safe, appliances, audit_log, verify_ssl=verify_fe)
                            combined_results.extend(result_fe.get('results', []))
                            overall = overall and bool(result_fe.get('overall_success'))
                            _mark_yara_distribution_delete(safe, result_fe, 'yara_http')
                        if tx_on:
                            result_tx = delete_yara_trellix_ex(
                                safe, _get_setting, audit_log, verify_ssl=verify_session
                            )
                            combined_results.extend(result_tx.get('results', []))
                            overall = overall and bool(result_tx.get('overall_success'))
                            _mark_yara_distribution_delete(safe, result_tx, 'yara_trellix_ex')
                        if cms_on:
                            result_cms = delete_yara_trellix_cms(
                                safe, _get_setting, audit_log, verify_ssl=verify_session
                            )
                            combined_results.extend(result_cms.get('results', []))
                            overall = overall and bool(result_cms.get('overall_success'))
                            _mark_yara_distribution_delete(safe, result_cms, 'yara_trellix_cms')
                        if nx_wmps_on:
                            result_nxw = delete_yara_nx_wmps(
                                safe, _get_setting, audit_log, verify_ssl=verify_session
                            )
                            combined_results.extend(result_nxw.get('results', []))
                            overall = overall and bool(result_nxw.get('overall_success'))
                            _mark_yara_distribution_delete(safe, result_nxw, 'yara_trellix_nx')
                        result = {'overall_success': overall, 'results': combined_results}
                        try:
                            from utils.integration_telemetry import record_yara_automation_results

                            record_yara_automation_results(result, kind='delete', context={'filename': safe})
                        except Exception:
                            logging.debug('record_yara_automation_results delete failed', exc_info=True)
                    except Exception as e:
                        logging.exception('Automation YARA delete failed for %s', safe)
                        try:
                            from utils.integration_telemetry import record_yara_automation_results

                            record_yara_automation_results(
                                {
                                    'overall_success': False,
                                    'results': [{'name': '—', 'url': '', 'success': False, 'message': str(e)}],
                                },
                                kind='delete',
                                context={'filename': safe},
                            )
                        except Exception:
                            pass
                        audit_log('yara_automation_delete_fail', f'file={safe} error={e}')

            threading.Thread(target=_auto_delete, daemon=True).start()
        return jsonify({'success': True, 'message': f'Deleted {safe}'})
    except OSError as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/view-yara/<path:filename>', methods=['GET'])
def view_yara(filename):
    try:
        safe, filepath_approved = _yara_safe_path(filename)
        if safe is None:
            return jsonify({'success': False, 'message': MSG_INVALID_FILENAME}), 400
        filepath = filepath_approved
        if not os.path.isfile(filepath):
            _, filepath_pending = _yara_safe_path_pending(filename)
            if os.path.isfile(filepath_pending):
                filepath = filepath_pending
            else:
                return jsonify({'success': False, 'message': MSG_FILE_NOT_FOUND}), 404
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        return jsonify({'success': True, 'filename': safe, 'content': content})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/update-yara', methods=['POST'])
@login_required
def update_yara():
    _commit_with_retry, audit_log, _log_ioc_history = _from_app('_commit_with_retry', 'audit_log', '_log_ioc_history')
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'JSON body required'}), 400
        filename = (data.get('filename') or '').strip()
        content = data.get('content')
        reason = (data.get('reason') or '').strip()
        if not filename:
            return jsonify({'success': False, 'message': MSG_FILENAME_REQUIRED}), 400
        if content is None:
            return jsonify({'success': False, 'message': 'Content is required'}), 400
        safe, filepath_approved = _yara_safe_path(filename)
        if safe is None:
            return jsonify({'success': False, 'message': MSG_INVALID_FILENAME}), 400
        _, filepath_pending = _yara_safe_path_pending(filename)
        content_str = content if isinstance(content, str) else ''
        syntax_reject = _reject_invalid_yara_syntax(content_str)
        if syntax_reject is not None:
            return syntax_reject
        new_h = yara_content_sha256(content_str)
        dup_other = _find_existing_yara_with_same_content(content_str, exclude_filename=safe)
        if dup_other:
            return jsonify({
                'success': False,
                'message': MSG_YARA_DUPLICATE_CONTENT_UPDATE.format(filename=dup_other),
                'code': 'duplicate_content',
                'existing_filename': dup_other,
            }), 409
        old_content = ''
        if os.path.isfile(filepath_approved):
            with open(filepath_approved, 'r', encoding='utf-8', errors='replace') as f:
                old_content = f.read()
        elif os.path.isfile(filepath_pending):
            with open(filepath_pending, 'r', encoding='utf-8', errors='replace') as f:
                old_content = f.read()
        content_changed = old_content != content_str
        if content_changed and not reason:
            return jsonify({'success': False, 'message': MSG_YARA_EDIT_REASON_REQUIRED}), 400
        row = YaraRule.query.filter_by(filename=safe).first()
        is_admin = getattr(current_user, 'is_admin', False)
        uname_lower = (current_user.username or '').strip().lower()
        if not is_admin:
            if not row:
                return jsonify({'success': False, 'message': 'Only an admin can edit this rule'}), 403
            analyst_lower = (row.analyst or '').strip().lower()
            if analyst_lower != uname_lower:
                return jsonify({'success': False, 'message': 'Only the rule owner or an admin can edit this rule'}), 403
        if not content_changed:
            return jsonify({'success': True, 'message': f'No changes to apply for {safe}'})

        def _ensure_row_for_update() -> YaraRule:
            nonlocal row
            if row:
                return row
            row = YaraRule(
                filename=safe,
                original_filename=safe,
                analyst='unknown',
                ticket_id=None,
                comment='Recovered from approved file on edit',
                status='approved',
                content_sha256=new_h,
            )
            db.session.add(row)
            return row

        # Approved on disk: any content change → pending (analyst or admin).
        if os.path.isfile(filepath_approved):
            with open(filepath_pending, 'w', encoding='utf-8') as f:
                f.write(content_str)
            try:
                os.remove(filepath_approved)
            except OSError:
                pass
            r = _ensure_row_for_update()
            r.quality_points = compute_yara_quality_points(content_str)
            r.status = 'pending'
            r.content_sha256 = new_h
            _log_ioc_history('YARA', safe, 'edited', current_user.username, {'reason': reason[:4000]})
            _commit_with_retry()
            audit_log('YARA_UPDATE', f'file={safe} analyst={current_user.username} status=pending (re-approval required)')
            return jsonify({
                'success': True,
                'message': f'Updated {safe}. Rule moved to pending for admin approval.',
                'moved_to_pending': True,
            })
        if os.path.isfile(filepath_pending):
            with open(filepath_pending, 'w', encoding='utf-8') as f:
                f.write(content_str)
            r = _ensure_row_for_update() if is_admin or row else row
            if r:
                r.quality_points = compute_yara_quality_points(content_str)
                r.content_sha256 = new_h
                if (r.status or '').lower() == 'approved':
                    r.status = 'pending'
                    _log_ioc_history('YARA', safe, 'edited', current_user.username, {'reason': reason[:4000]})
                    _commit_with_retry()
                    audit_log('YARA_UPDATE', f'file={safe} analyst={current_user.username} status=pending (re-approval required)')
                    return jsonify({
                        'success': True,
                        'message': f'Updated {safe}. Rule moved to pending for admin approval.',
                        'moved_to_pending': True,
                    })
            if content_changed:
                _log_ioc_history('YARA', safe, 'edited', current_user.username, {'reason': reason[:4000]})
            _commit_with_retry()
            audit_log('YARA_UPDATE', f'file={safe} analyst={current_user.username}')
            return jsonify({'success': True, 'message': f'Updated {safe}', 'moved_to_pending': False})
        return jsonify({'success': False, 'message': MSG_FILE_NOT_FOUND}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/edit-yara-meta', methods=['POST'])
@login_required
def edit_yara_meta():
    _commit_with_retry, audit_log = _from_app('_commit_with_retry', 'audit_log')
    try:
        data = request.get_json()
        filename = (data.get('filename') or '').strip()
        if not filename:
            return jsonify({'success': False, 'message': 'Filename is required'}), 400
        safe, _ = _yara_safe_path(filename)
        if safe is None:
            return jsonify({'success': False, 'message': MSG_INVALID_FILENAME}), 400
        rule = YaraRule.query.filter_by(filename=safe).first()
        if not rule:
            return jsonify({'success': False, 'message': 'YARA rule not found'}), 404
        is_admin = getattr(current_user, 'is_admin', False)
        if not is_admin:
            analyst_lower = (rule.analyst or '').strip().lower()
            if analyst_lower != current_user.username.lower():
                return jsonify({'success': False, 'message': 'Only the rule owner or an admin can edit this rule'}), 403
        moved_to_pending = False
        if not is_admin and (rule.status or '').lower() == 'approved':
            path_approved = os.path.join(_data_yara(), safe)
            path_pending = os.path.join(_data_yara_pending(), safe)
            if os.path.isfile(path_approved):
                with open(path_approved, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                with open(path_pending, 'w', encoding='utf-8') as f:
                    f.write(content)
                try:
                    os.remove(path_approved)
                except OSError:
                    pass
                rule.status = 'pending'
                moved_to_pending = True
        new_ticket_id = data.get('ticket_id')
        if new_ticket_id is not None:
            _auto_ticket_id, = _from_app('_auto_ticket_id')
            rule.ticket_id = (new_ticket_id.strip() if new_ticket_id else '') or _auto_ticket_id(current_user.id)
        new_comment = data.get('comment')
        if new_comment is not None:
            rule.comment = sanitize_comment(new_comment) or None
        campaign_name_raw = data.get('campaign_name')
        if campaign_name_raw is not None:
            campaign_name = (campaign_name_raw.strip() if isinstance(campaign_name_raw, str) else '') or None
            if campaign_name is None or campaign_name == '' or campaign_name.lower() == 'none':
                rule.campaign_id = None
            else:
                camp = Campaign.query.filter_by(name=campaign_name).first()
                if camp:
                    rule.campaign_id = camp.id
                else:
                    return jsonify({'success': False, 'message': f'Campaign "{campaign_name}" not found'}), 400
        _commit_with_retry()
        changes = []
        if new_ticket_id is not None:
            changes.append('ticket_id')
        if new_comment is not None:
            changes.append('comment')
        if campaign_name_raw is not None:
            changes.append('campaign')
        audit_log('YARA_EDIT_META', f'file={filename} changes={",".join(changes) or "none"}')
        msg = f'YARA rule "{filename}" updated successfully'
        if moved_to_pending:
            msg += ' Rule moved to pending for admin approval.'
        return jsonify({'success': True, 'message': msg, 'moved_to_pending': moved_to_pending})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# --- Pending approval workflow ---

@bp.route('/yara/my-pending', methods=['GET'])
@login_required
def list_my_pending():
    """List current user's YARA rules with status=pending (analyst sees their own uploads)."""
    try:
        username = current_user.username.lower()
        rules = YaraRule.query.filter_by(status='pending', analyst=username).order_by(YaraRule.uploaded_at.desc()).all()
        data_pending = _data_yara_pending()
        files = []
        for r in rules:
            filepath = os.path.join(data_pending, r.filename)
            if os.path.isfile(filepath):
                files.append({
                    'filename': r.filename,
                    'original_filename': r.filename,
                    'display_name': r.filename,
                    'upload_date': r.uploaded_at.strftime('%Y-%m-%d %H:%M') if r.uploaded_at else None,
                    'comment': r.comment,
                    'ticket_id': r.ticket_id,
                })
        return jsonify({'success': True, 'files': files})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/yara/pending', methods=['GET'])
@admin_required
def list_yara_pending():
    """List YARA rules with status=pending (admin only)."""
    try:
        rules = YaraRule.query.filter_by(status='pending').order_by(YaraRule.uploaded_at.desc()).all()
        data_pending = _data_yara_pending()
        files = []
        for r in rules:
            filepath = os.path.join(data_pending, r.filename)
            if os.path.isfile(filepath):
                files.append({
                    'filename': r.filename,
                    'original_filename': r.filename,
                    'display_name': r.filename,
                    'upload_date': r.uploaded_at.strftime('%Y-%m-%d %H:%M') if r.uploaded_at else None,
                    'user': r.analyst,
                    'ticket_id': r.ticket_id,
                    'comment': r.comment,
                })
        return jsonify({'success': True, 'files': files})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/yara/pending-content/<path:filename>', methods=['GET'])
@login_required
def view_yara_pending_content(filename):
    """Return raw content of a pending YARA file. Allowed for admin or the rule owner (analyst)."""
    safe, filepath = _yara_safe_path_pending(filename)
    if safe is None:
        return jsonify({'success': False, 'message': MSG_INVALID_FILENAME}), 400
    if not os.path.isfile(filepath):
        return jsonify({'success': False, 'message': MSG_FILE_NOT_FOUND}), 404
    rule = YaraRule.query.filter_by(filename=safe, status='pending').first()
    if not rule:
        return jsonify({'success': False, 'message': 'Not a pending rule'}), 404
    # Admin or the uploader (analyst) may view
    if not getattr(current_user, 'is_admin', False) and rule.analyst != current_user.username.lower():
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        return jsonify({'success': True, 'filename': safe, 'content': content})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/yara/approve', methods=['POST'])
@admin_required
def approve_yara():
    """Move pending rule to approved dir and set status=approved (admin only)."""
    _commit_with_retry, audit_log, refresh_champ_score_for_user = _from_app('_commit_with_retry', 'audit_log', 'refresh_champ_score_for_user')
    try:
        data = request.get_json() or {}
        filename = (data.get('filename') or '').strip()
        if not filename:
            return jsonify({'success': False, 'message': MSG_FILENAME_REQUIRED}), 400
        safe_pending, path_pending = _yara_safe_path_pending(filename)
        if safe_pending is None:
            return jsonify({'success': False, 'message': MSG_INVALID_FILENAME}), 400
        rule = YaraRule.query.filter_by(filename=safe_pending, status='pending').first()
        if not rule:
            rule = YaraRule.query.filter(YaraRule.status == 'pending', func.lower(YaraRule.filename) == safe_pending.lower()).first()
        if not rule:
            return jsonify({'success': False, 'message': 'Rule not found or not pending'}), 404
        path_pending = os.path.join(_data_yara_pending(), rule.filename)
        if not os.path.isfile(path_pending):
            return jsonify({'success': False, 'message': MSG_FILE_NOT_FOUND}), 404
        path_approved = os.path.join(_data_yara(), rule.filename)
        if os.path.exists(path_approved):
            return jsonify({'success': False, 'message': 'Rule name already exists in approved'}), 409
        with open(path_pending, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        with open(path_approved, 'w', encoding='utf-8') as f:
            f.write(content)
        try:
            os.remove(path_pending)
        except OSError:
            pass
        rule.status = 'approved'
        if not getattr(rule, 'content_sha256', None):
            rule.content_sha256 = yara_content_sha256(content)
        _commit_with_retry()
        audit_log('YARA_APPROVE', f'file={rule.filename}')
        # Refresh Champs score for the rule owner (analyst) so they get full YARA points
        analyst_username = (rule.analyst or '').strip()
        if analyst_username:
            owner = User.query.filter(func.lower(User.username) == analyst_username.lower()).first()
            if owner:
                try:
                    refresh_champ_score_for_user(owner.id)
                except Exception as e:
                    logging.warning('YARA approve: refresh_champ_score for analyst %s failed: %s', analyst_username, e)
                try:
                    from utils.user_notifications import notify_yara_outcome
                    notify_yara_outcome(owner.id, rule, 'approved')
                    _commit_with_retry()
                except Exception as e:
                    logging.warning('YARA approve: notify analyst %s failed: %s', analyst_username, e)
                    db.session.rollback()

        # Outbound YARA automation
        _get_setting = _from_app('_get_setting')[0]
        fireeye_pending = _schedule_yara_outbound_push(rule, content, _get_setting, audit_log)

        return jsonify({
            'success': True,
            'message': f'Approved: {rule.filename}',
            'fireeye_pending': fireeye_pending,
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/yara/fireeye-status', methods=['GET'])
@login_required
def fireeye_status():
    """Return FireEye push status for a filename (for UI polling after approve)."""
    filename = (request.args.get('filename') or '').strip()
    if not filename:
        return jsonify({'success': False, 'message': 'filename required'}), 400
    safe, _ = _yara_safe_path(filename)
    if safe is None:
        return jsonify({'success': False, 'message': 'invalid filename'}), 400
    from utils.yara_http_push import get_fireeye_status
    info = get_fireeye_status(safe, clear_after_read=True)
    return jsonify({'success': True, 'data': info})


def _yara_rejected_row_dict(r: YaraRule) -> dict:
    return {
        'filename': r.filename,
        'original_filename': r.filename,
        'display_name': r.filename,
        'upload_date': r.uploaded_at.strftime('%Y-%m-%d %H:%M') if r.uploaded_at else None,
        'rejected_at': iso_utc(r.rejected_at) if r.rejected_at else None,
        'rejected_by': r.rejected_by,
        'rejection_reason': r.rejection_reason,
        'seen': r.rejection_seen_at is not None,
        'comment': r.comment,
        'ticket_id': r.ticket_id,
        'campaign_id': r.campaign_id,
    }


@bp.route('/yara/my-rejected', methods=['GET'])
@login_required
def list_my_rejected():
    """List current user's rejected YARA rules (soft reject — resubmit allowed)."""
    try:
        username = current_user.username.lower()
        rules = (
            YaraRule.query.filter_by(status='rejected', analyst=username)
            .order_by(YaraRule.rejected_at.desc(), YaraRule.uploaded_at.desc())
            .all()
        )
        data_rejected = _data_yara_rejected()
        files = []
        unseen = 0
        for r in rules:
            filepath = os.path.join(data_rejected, r.filename)
            if not os.path.isfile(filepath):
                continue
            if r.rejection_seen_at is None:
                unseen += 1
            files.append(_yara_rejected_row_dict(r))
        return jsonify({'success': True, 'files': files, 'unseen_count': unseen})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/yara/rejected-content/<path:filename>', methods=['GET'])
@login_required
def view_yara_rejected_content(filename):
    """Return raw content of a rejected YARA file (admin or rule owner)."""
    safe, filepath = _yara_safe_path_rejected(filename)
    if safe is None:
        return jsonify({'success': False, 'message': MSG_INVALID_FILENAME}), 400
    if not os.path.isfile(filepath):
        return jsonify({'success': False, 'message': MSG_FILE_NOT_FOUND}), 404
    rule = YaraRule.query.filter_by(filename=safe, status='rejected').first()
    if not rule:
        return jsonify({'success': False, 'message': 'Not a rejected rule'}), 404
    if not getattr(current_user, 'is_admin', False) and rule.analyst != current_user.username.lower():
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        return jsonify({
            'success': True,
            'filename': safe,
            'content': content,
            'rejection_reason': rule.rejection_reason,
            'rejected_by': rule.rejected_by,
            'rejected_at': iso_utc(rule.rejected_at) if rule.rejected_at else None,
            'comment': rule.comment,
            'ticket_id': rule.ticket_id,
            'campaign_id': rule.campaign_id,
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/yara/mark-rejection-seen', methods=['POST'])
@login_required
def mark_yara_rejection_seen():
    """Mark rejected rule(s) as seen by the analyst (clears notification badge)."""
    _commit_with_retry, = _from_app('_commit_with_retry')
    try:
        data = request.get_json() or {}
        mark_all = bool(data.get('all'))
        filename = (data.get('filename') or '').strip()
        username = current_user.username.lower()
        now = datetime.utcnow()
        q = YaraRule.query.filter_by(status='rejected', analyst=username).filter(
            YaraRule.rejection_seen_at.is_(None)
        )
        if not mark_all:
            if not filename:
                return jsonify({'success': False, 'message': MSG_FILENAME_REQUIRED}), 400
            safe, _ = _yara_safe_path_rejected(filename)
            if safe is None:
                return jsonify({'success': False, 'message': MSG_INVALID_FILENAME}), 400
            q = q.filter_by(filename=safe)
        updated = 0
        for rule in q.all():
            rule.rejection_seen_at = now
            updated += 1
        if updated:
            _commit_with_retry()
        return jsonify({'success': True, 'updated': updated})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/yara/resubmit', methods=['POST'])
@login_required
def resubmit_yara():
    """Move a rejected rule back to pending (optionally with updated content/metadata)."""
    _commit_with_retry, audit_log, _log_champs_event = _from_app(
        '_commit_with_retry', 'audit_log', '_log_champs_event'
    )
    try:
        data = request.get_json() or {}
        if not data:
            return jsonify({'success': False, 'message': MSG_JSON_BODY_REQUIRED}), 400
        filename = (data.get('filename') or '').strip()
        if not filename:
            return jsonify({'success': False, 'message': MSG_FILENAME_REQUIRED}), 400
        safe, path_rejected = _yara_safe_path_rejected(filename)
        if safe is None:
            return jsonify({'success': False, 'message': MSG_INVALID_FILENAME}), 400
        rule = YaraRule.query.filter_by(filename=safe, status='rejected').first()
        if not rule:
            return jsonify({'success': False, 'message': 'Rule not found or not rejected'}), 404
        if rule.analyst != current_user.username.lower():
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        if not os.path.isfile(path_rejected):
            return jsonify({'success': False, 'message': MSG_FILE_NOT_FOUND}), 404

        content = data.get('content')
        if content is None:
            with open(path_rejected, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        else:
            content = str(content)
        syntax_reject = _reject_invalid_yara_syntax(content)
        if syntax_reject is not None:
            return syntax_reject
        dup_name = _find_existing_yara_with_same_content(content, exclude_filename=safe)
        if dup_name:
            msg = MSG_YARA_DUPLICATE_CONTENT_UPLOAD.format(filename=dup_name)
            return jsonify({
                'success': False,
                'message': msg,
                'code': 'duplicate_content',
                'existing_filename': dup_name,
            }), 409

        path_pending = os.path.join(_data_yara_pending(), safe)
        if os.path.isfile(path_pending):
            return jsonify({'success': False, 'message': 'A pending rule with this name already exists'}), 409
        _move_yara_file(path_rejected, path_pending)
        with open(path_pending, 'w', encoding='utf-8') as f:
            f.write(content)

        if 'comment' in data:
            rule.comment = (data.get('comment') or '').strip() or rule.comment
        if 'ticket_id' in data:
            rule.ticket_id = (data.get('ticket_id') or '').strip() or None
        campaign_name = (data.get('campaign_name') or '').strip()
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            rule.campaign_id = c.id if c else None
        elif data.get('campaign_name') == '':
            rule.campaign_id = None

        rule.status = 'pending'
        rule.rejected_at = None
        rule.rejected_by = None
        rule.rejection_reason = None
        rule.rejection_seen_at = None
        rule.uploaded_at = datetime.utcnow()
        rule.quality_points = compute_yara_quality_points(content)
        rule.content_sha256 = yara_content_sha256(content)
        _commit_with_retry()
        audit_log('YARA_RESUBMIT', f'file={safe} analyst={rule.analyst}')
        _log_champs_event('yara_resubmit', user_id=current_user.id, payload={'filename': safe})
        try:
            from utils.user_notifications import dismiss_yara_outcome_notification
            dismiss_yara_outcome_notification(current_user.id, safe, 'rejected')
            _commit_with_retry()
        except Exception as e:
            logging.warning('YARA resubmit: dismiss rejection notification failed: %s', e)
            db.session.rollback()
        return jsonify({
            'success': True,
            'message': f'Rule "{safe}" resubmitted and is pending admin approval.',
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/yara/reject', methods=['POST'])
@admin_required
def reject_yara():
    """Soft-reject pending rule: keep DB row + file in YARA_rejected for analyst resubmit."""
    _commit_with_retry, audit_log, _log_champs_event = _from_app(
        '_commit_with_retry', 'audit_log', '_log_champs_event'
    )
    try:
        data = request.get_json() or {}
        filename = (data.get('filename') or '').strip()
        if not filename:
            return jsonify({'success': False, 'message': MSG_FILENAME_REQUIRED}), 400
        reason = sanitize_comment((data.get('reason') or '').strip()) or None
        safe, path_pending = _yara_safe_path_pending(filename)
        if safe is None:
            return jsonify({'success': False, 'message': MSG_INVALID_FILENAME}), 400
        rule = YaraRule.query.filter_by(filename=safe, status='pending').first()
        if not rule:
            return jsonify({'success': False, 'message': 'Rule not found or not pending'}), 404
        if not os.path.isfile(path_pending):
            return jsonify({'success': False, 'message': MSG_FILE_NOT_FOUND}), 404
        path_rejected = os.path.join(_data_yara_rejected(), rule.filename)
        _move_yara_file(path_pending, path_rejected)
        rule.status = 'rejected'
        rule.rejected_at = datetime.utcnow()
        rule.rejected_by = (current_user.username or '').strip().lower() or None
        rule.rejection_reason = reason
        rule.rejection_seen_at = None
        _commit_with_retry()
        _mark_yara_removed_from_hub(safe)
        audit_log('YARA_REJECT', f'file={safe} by={rule.rejected_by} reason="{ (reason or "")[:120] }"')
        analyst_username = (rule.analyst or '').strip()
        if analyst_username:
            owner = User.query.filter(func.lower(User.username) == analyst_username.lower()).first()
            if owner:
                _log_champs_event(
                    'yara_rejected',
                    user_id=owner.id,
                    payload={
                        'filename': safe,
                        'rejected_by': rule.rejected_by,
                        'reason': reason,
                    },
                )
                try:
                    from utils.user_notifications import notify_yara_outcome
                    notify_yara_outcome(
                        owner.id,
                        rule,
                        'rejected',
                        reason=reason,
                        rejected_by=rule.rejected_by,
                    )
                    _commit_with_retry()
                except Exception as e:
                    logging.warning('YARA reject: notify analyst %s failed: %s', analyst_username, e)
                    db.session.rollback()
        return jsonify({
            'success': True,
            'message': f'Rejected: {safe}. The analyst can edit and resubmit from Status → Rejected.',
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
