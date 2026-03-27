"""
YARA API routes: upload, list, delete, view, update, edit-yara-meta.
Register with url_prefix='/api'.
Uses lazy imports from app for shared helpers to avoid circular imports.
"""
import json
import logging
import os
import re
import threading
from datetime import datetime

from flask import Blueprint, request, jsonify, current_app
from flask_login import current_user
from sqlalchemy.exc import IntegrityError

from sqlalchemy import func
from extensions import db
from models import YaraRule, Campaign, User
from utils.yara_utils import yara_safe_path, validate_yara_syntax
from utils.decorators import login_required, admin_required
from utils.refanger import sanitize_comment
from utils.validation_messages import (
    MSG_CONTENT_REQUIRED,
    MSG_FILENAME_REQUIRED,
    MSG_YARA_DELETE_REASON_REQUIRED,
    MSG_YARA_EDIT_REASON_REQUIRED,
    MSG_FILE_NOT_FOUND,
    MSG_INVALID_FILENAME,
    MSG_INVALID_TYPE,
    MSG_JSON_BODY_REQUIRED,
    MSG_YARA_COMPILER_UNAVAILABLE,
    MSG_YARA_SOURCE_EMPTY,
    MSG_YARA_SOURCE_TOO_LARGE,
)
from utils.champs import compute_yara_quality_points


bp = Blueprint('yara_api', __name__, url_prefix='/api')


def _from_app(*names):
    import app as _app
    return tuple(getattr(_app, n) for n in names)


def _data_yara():
    return current_app.config.get('DATA_YARA') or ''


def _data_yara_pending():
    return current_app.config.get('DATA_YARA_PENDING') or ''


def _yara_safe_path(filename):
    return yara_safe_path(filename, _data_yara())


def _yara_safe_path_pending(filename):
    return yara_safe_path(filename, _data_yara_pending())


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


@bp.route('/upload-yara', methods=['POST'])
@login_required
def upload_yara():
    try:
        _auto_ticket_id, = _from_app('_auto_ticket_id')
        if 'file' not in request.files:
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
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        if not file.filename.lower().endswith('.yar'):
            return jsonify({'success': False, 'message': 'Invalid file type. Only .yar files are allowed'}), 400
        safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', file.filename)
        if not safe_filename:
            safe_filename = 'rule.yar'
        if ticket_id:
            base_name, ext = os.path.splitext(safe_filename)
            safe_filename = f"{base_name}_T{ticket_id}{ext}"
        data_yara = _data_yara()
        data_pending = _data_yara_pending()
        filepath_approved = os.path.join(data_yara, safe_filename)
        filepath_pending = os.path.join(data_pending, safe_filename)
        if os.path.exists(filepath_approved) or os.path.exists(filepath_pending):
            return jsonify({'success': False, 'message': 'Rule name already exists'}), 409
        if YaraRule.query.filter_by(filename=safe_filename).first():
            return jsonify({'success': False, 'message': 'Rule name already exists'}), 409
        file_content = file.read().decode('utf-8', errors='replace')
        syntax_reject = _reject_invalid_yara_syntax(file_content)
        if syntax_reject is not None:
            return syntax_reject
        with open(filepath_pending, 'w', encoding='utf-8') as f:
            f.write(file_content)
        username = current_user.username.lower()
        comment = (request.form.get('comment') or '').strip() or 'Uploaded YARA Rule'
        quality_pts = compute_yara_quality_points(file_content)
        _commit_with_retry, _api_error, audit_log, _log_champs_event = _from_app('_commit_with_retry', '_api_error', 'audit_log', '_log_champs_event')
        try:
            db.session.add(YaraRule(
                filename=safe_filename,
                analyst=username,
                ticket_id=ticket_id or None,
                comment=comment,
                campaign_id=campaign_id,
                quality_points=quality_pts,
                status='pending'
            ))
            _commit_with_retry()
        except IntegrityError:
            db.session.rollback()
            if os.path.exists(filepath_pending):
                try:
                    os.remove(filepath_pending)
                except OSError:
                    pass
            return _api_error('Rule name already exists', 409)
        except (ValueError, OSError) as e:
            db.session.rollback()
            if os.path.exists(filepath_pending):
                try:
                    os.remove(filepath_pending)
                except OSError:
                    pass
            return _api_error(f'Database or file error: {str(e)}', 500)
        cmt = (comment or '')[:60]
        audit_log('YARA_UPLOAD', f'file={safe_filename} analyst={username} status=pending comment="{cmt}"')
        _log_champs_event('yara_upload', user_id=current_user.id, payload={'filename': safe_filename})
        refresh_champ_score_for_user = _from_app('refresh_champ_score_for_user')[0]
        refresh_champ_score_for_user(current_user.id)
        message = f'YARA rule uploaded and pending approval: {safe_filename}'
        if ticket_id:
            message += f' (Ticket: {ticket_id})'
        return jsonify({'success': True, 'message': message})
    except (UnicodeDecodeError, OSError) as e:
        _api_error, = _from_app('_api_error')
        return _api_error(f'File read or write error: {str(e)}', 500)
    except Exception as e:
        logging.exception('upload_yara failed')
        _api_error, = _from_app('_api_error')
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
def list_yara():
    try:
        files = []
        data_yara = _data_yara()
        if not os.path.isdir(data_yara):
            return jsonify({'success': True, 'files': []})
        for name in sorted(os.listdir(data_yara)):
            if not name.lower().endswith('.yar'):
                continue
            filepath = os.path.join(data_yara, name)
            if not os.path.isfile(filepath):
                continue
            size_bytes = os.path.getsize(filepath)
            mtime = os.path.getmtime(filepath)
            size_kb = round(size_bytes / 1024, 2)
            meta = YaraRule.query.filter_by(filename=name).first()
            if meta and meta.uploaded_at:
                upload_date = meta.uploaded_at.strftime('%Y-%m-%d %H:%M')
            else:
                upload_date = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')
            files.append({
                'filename': name,
                'size_kb': size_kb,
                'upload_date': upload_date,
                'user': meta.analyst if meta else None,
                'ticket_id': meta.ticket_id if meta else None,
                'comment': meta.comment if meta else None
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
            'original_uploaded_at': rule.uploaded_at.isoformat() if rule and rule.uploaded_at else None,
            'deleted_by_admin': is_admin,
        }
        _log_ioc_history('YARA', safe, 'deleted', current_user.username, hist_payload)
        os.remove(filepath)
        YaraRule.query.filter_by(filename=safe).delete()
        _commit_with_retry()
        _audit_del = f'file={safe} analyst={current_user.username}'
        if reason:
            _audit_del += f' reason={reason[:120]!r}'
        audit_log('YARA_DELETE', _audit_del)
        if owner_id is not None:
            try:
                refresh_champ_score_for_user(owner_id)
            except Exception as e:
                logging.warning('YARA delete: refresh_champ_score for owner failed: %s', e)
        _get_setting = _from_app('_get_setting')[0]
        if _get_setting('automation_fireeye_enabled', 'false').lower() == 'true':
            try:
                raw = _get_setting('automation_fireeye_appliances', '[]') or '[]'
                appliances = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(appliances, list) and appliances:
                    from utils.fireeye_push import delete_yara_from_appliances
                    app_obj = current_app._get_current_object()
                    verify_ssl = _get_setting('automation_fireeye_ignore_ssl', 'false').lower() != 'true'

                    def _auto_delete():
                        with app_obj.app_context():
                            try:
                                delete_yara_from_appliances(safe, appliances, audit_log, verify_ssl=verify_ssl)
                            except Exception as e:
                                logging.exception('Automation YARA delete failed for %s', safe)
                                audit_log('yara_automation_delete_fail', f'file={safe} error={e}')

                    threading.Thread(target=_auto_delete, daemon=True).start()
            except Exception as e:
                logging.warning('YARA delete: automation setup failed: %s', e)
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
        if not is_admin:
            if not row:
                return jsonify({'success': False, 'message': 'Only an admin can edit this rule'}), 403
            analyst_lower = (row.analyst or '').strip().lower()
            if analyst_lower != current_user.username.lower():
                return jsonify({'success': False, 'message': 'Only the rule owner or an admin can edit this rule'}), 403
        if os.path.isfile(filepath_approved):
            if not is_admin and row and getattr(row, 'status', None) == 'approved':
                with open(filepath_pending, 'w', encoding='utf-8') as f:
                    f.write(content_str)
                try:
                    os.remove(filepath_approved)
                except OSError:
                    pass
                if row:
                    row.quality_points = compute_yara_quality_points(content_str)
                    row.status = 'pending'
                if content_changed:
                    _log_ioc_history('YARA', safe, 'edited', current_user.username, {'reason': reason[:4000]})
                _commit_with_retry()
                audit_log('YARA_UPDATE', f'file={safe} analyst={current_user.username} status=pending (re-approval required)')
                return jsonify({'success': True, 'message': f'Updated {safe}. Rule moved to pending for admin approval.', 'moved_to_pending': True})
            with open(filepath_approved, 'w', encoding='utf-8') as f:
                f.write(content_str)
        elif os.path.isfile(filepath_pending):
            with open(filepath_pending, 'w', encoding='utf-8') as f:
                f.write(content_str)
        else:
            return jsonify({'success': False, 'message': MSG_FILE_NOT_FOUND}), 404
        quality_pts = compute_yara_quality_points(content_str)
        if row:
            row.quality_points = quality_pts
        if content_changed:
            _log_ioc_history('YARA', safe, 'edited', current_user.username, {'reason': reason[:4000]})
        _commit_with_retry()
        audit_log('YARA_UPDATE', f'file={safe} analyst={current_user.username}')
        return jsonify({'success': True, 'message': f'Updated {safe}'})
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
        if not is_admin and getattr(rule, 'status', None) == 'approved':
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
        moved = not is_admin and getattr(rule, 'status', None) == 'pending'
        if moved:
            msg += ' Rule moved to pending for admin approval.'
        return jsonify({'success': True, 'message': msg, 'moved_to_pending': moved})
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

        # FireEye automation: push to appliances in background
        fireeye_pending = False
        _get_setting = _from_app('_get_setting')[0]
        if _get_setting('automation_fireeye_enabled', 'false').lower() == 'true':
            try:
                raw = _get_setting('automation_fireeye_appliances', '[]') or '[]'
                appliances = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(appliances, list) and appliances:
                    from utils.fireeye_push import push_yara_to_appliances, set_fireeye_status
                    app_obj = current_app._get_current_object()
                    verify_ssl = _get_setting('automation_fireeye_ignore_ssl', 'false').lower() != 'true'
                    set_fireeye_status(rule.filename, 'pending', '')

                    def _fireeye_upload():
                        with app_obj.app_context():
                            try:
                                result = push_yara_to_appliances(
                                    content, rule.filename, appliances, audit_log, verify_ssl=verify_ssl
                                )
                                if result['overall_success']:
                                    set_fireeye_status(rule.filename, 'success', 'All appliances updated.')
                                else:
                                    msgs = '; '.join(
                                        r.get('name', '') + ': ' + (r.get('message') or '')
                                        for r in result.get('results', [])
                                    )
                                    set_fireeye_status(rule.filename, 'error', msgs or 'Push failed')
                            except Exception as e:
                                logging.exception('FireEye push failed for %s', rule.filename)
                                set_fireeye_status(rule.filename, 'error', str(e))
                                audit_log('yara_push_fail', f'file={rule.filename} error={e}')

                    t = threading.Thread(target=_fireeye_upload, daemon=True)
                    t.start()
                    fireeye_pending = True
            except Exception as e:
                logging.warning('FireEye automation setup failed: %s', e)

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
    from utils.fireeye_push import get_fireeye_status
    info = get_fireeye_status(safe, clear_after_read=True)
    return jsonify({'success': True, 'data': info})


@bp.route('/yara/reject', methods=['POST'])
@admin_required
def reject_yara():
    """Remove pending rule file and delete DB row (admin only)."""
    _commit_with_retry, audit_log = _from_app('_commit_with_retry', 'audit_log')
    try:
        data = request.get_json() or {}
        filename = (data.get('filename') or '').strip()
        if not filename:
            return jsonify({'success': False, 'message': MSG_FILENAME_REQUIRED}), 400
        safe, path_pending = _yara_safe_path_pending(filename)
        if safe is None:
            return jsonify({'success': False, 'message': MSG_INVALID_FILENAME}), 400
        rule = YaraRule.query.filter_by(filename=safe, status='pending').first()
        if not rule:
            return jsonify({'success': False, 'message': 'Rule not found or not pending'}), 404
        if os.path.isfile(path_pending):
            try:
                os.remove(path_pending)
            except OSError:
                pass
        db.session.delete(rule)
        _commit_with_retry()
        audit_log('YARA_REJECT', f'file={safe}')
        return jsonify({'success': True, 'message': f'Rejected: {safe}'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
