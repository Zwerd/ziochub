"""
Campaigns, Playbook, and Campaign Graph API routes.
Register with url_prefix='/api'.
Uses lazy imports from app for shared helpers to avoid circular imports.
"""
import base64
import json
import logging
import os
import io
import csv
from datetime import datetime

from flask import Blueprint, request, jsonify, Response, current_app
from flask_login import current_user
from sqlalchemy.exc import IntegrityError

from extensions import db
from models import Campaign, IOC, YaraRule
from utils.decorators import login_required


bp = Blueprint('campaigns_api', __name__, url_prefix='/api')


def _from_app(*names):
    import app as _app
    return tuple(getattr(_app, n) for n in names)


def _playbook_file():
    f, = _from_app('PLAYBOOK_CUSTOM_FILE')
    return f


def _playbook_load():
    """Load custom playbook items from JSON file. Returns list (order preserved)."""
    path = _playbook_file()
    if not os.path.isfile(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _playbook_save(custom_list):
    """Save custom playbook items to JSON file. Order is global (all users see it)."""
    path = _playbook_file()
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(custom_list, f, ensure_ascii=False, indent=2)
        f.flush()
        try:
            os.fsync(f.fileno())
        except (OSError, AttributeError):
            pass
    logging.info('Playbook order saved to %s (%d items)', path, len(custom_list))


# --- Campaign list / create / link / update / delete ---

@bp.route('/campaigns', methods=['GET'])
def list_campaigns():
    """List all campaigns (for future UI)."""
    try:
        campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
        return jsonify({
            'success': True,
            'campaigns': [
                {'id': c.id, 'name': c.name, 'description': c.description, 'dir': getattr(c, 'dir', None) or 'ltr', 'created_at': c.created_at.isoformat() if c.created_at else None}
                for c in campaigns
            ],
            'count': len(campaigns)
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/campaigns', methods=['POST'])
@login_required
def create_campaign():
    """Create a new campaign."""
    (
        _commit_with_retry, audit_log, _log_champs_event,
        _capture_champs_before, _detect_champs_changes, refresh_champ_score_for_user,
    ) = _from_app(
        '_commit_with_retry', 'audit_log', '_log_champs_event',
        '_capture_champs_before', '_detect_champs_changes', 'refresh_champ_score_for_user',
    )
    try:
        data = request.get_json() or {}
        name = (data.get('name') or '').strip()
        description = (data.get('description') or '').strip() or None
        dir_val = (data.get('dir') or 'ltr').strip().lower()
        if dir_val not in ('ltr', 'rtl'):
            dir_val = 'ltr'
        if not name:
            return jsonify({'success': False, 'message': 'Campaign name is required'}), 400

        champs_before = _capture_champs_before(current_user.id, (current_user.username or '').lower()) if current_user and current_user.is_authenticated else None

        created_by = current_user.id if current_user and current_user.is_authenticated else None
        db.session.add(Campaign(name=name, description=description, dir=dir_val, created_by=created_by))
        _commit_with_retry()
        audit_log('CAMPAIGN_CREATE', f'name={name}')
        c = Campaign.query.filter_by(name=name).first()

        try:
            _log_champs_event('campaign_create', user_id=current_user.id if current_user and current_user.is_authenticated else None, payload={'campaign_id': c.id, 'name': name[:100]})
        except Exception:
            pass
        try:
            refresh_champ_score_for_user(current_user.id)
        except Exception as e:
            logging.warning('create_campaign: refresh_champ_score failed (campaign saved): %s', e)

        response = {
            'success': True,
            'message': 'Campaign created',
            'campaign': {'id': c.id, 'name': c.name, 'description': c.description, 'dir': c.dir or 'ltr', 'created_at': c.created_at.isoformat() if c.created_at else None}
        }
        if champs_before and current_user and current_user.is_authenticated:
            try:
                response.update(_detect_champs_changes(champs_before, current_user.id, (current_user.username or '').lower()))
            except Exception as e:
                logging.warning('create_campaign: champs change detection failed (campaign saved): %s', e)
        return jsonify(response), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Campaign name already exists'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/campaigns/link', methods=['POST'])
@login_required
def link_ioc_to_campaign():
    """Link an existing IOC to a campaign by value. Expects {ioc_value, campaign_id}."""
    from utils.validation_messages import MSG_IOC_NOT_FOUND
    (
        _commit_with_retry, audit_log, _log_ioc_history, _log_champs_event,
        _capture_champs_before, _detect_champs_changes, refresh_champ_score_for_user,
    ) = _from_app(
        '_commit_with_retry', 'audit_log', '_log_ioc_history', '_log_champs_event',
        '_capture_champs_before', '_detect_champs_changes', 'refresh_champ_score_for_user',
    )
    try:
        data = request.get_json() or {}
        ioc_value = (data.get('ioc_value') or '').strip()
        campaign_id = data.get('campaign_id')
        if not ioc_value:
            return jsonify({'success': False, 'message': 'ioc_value is required'}), 400
        if campaign_id is None:
            return jsonify({'success': False, 'message': 'campaign_id is required'}), 400
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404
        ioc = IOC.query.filter(IOC.value == ioc_value).first()
        if not ioc:
            return jsonify({'success': False, 'message': MSG_IOC_NOT_FOUND}), 404

        champs_before = _capture_champs_before(current_user.id, (current_user.username or '').lower()) if current_user and current_user.is_authenticated else None

        had_campaign = bool(ioc.campaign_id)
        old_campaign_id = ioc.campaign_id
        old_campaign_name = ''
        if old_campaign_id:
            old_camp = db.session.get(Campaign, old_campaign_id)
            old_campaign_name = (old_camp.name if old_camp else '')
        ioc.campaign_id = campaign_id
        if old_campaign_id != campaign_id:
            edit_changes = [{'field': 'campaign', 'old': old_campaign_name or '\u2014', 'new': campaign.name}]
            _log_ioc_history(ioc.type, ioc_value, 'edited',
                             current_user.username if current_user and current_user.is_authenticated else None,
                             {'changes': edit_changes})
        _commit_with_retry()
        audit_log('IOC_CAMPAIGN_LINK', f'ioc_value={ioc_value[:80]} campaign={campaign.name} type={ioc.type}')
        # Champs Smart Effort: reward first-time campaign linking as a separate effort event
        try:
            _log_champs_event(
                'ioc_campaign_link',
                user_id=current_user.id if current_user and current_user.is_authenticated else None,
                payload={
                    'ioc_id': ioc.id,
                    'value': ioc_value[:100],
                    'type': ioc.type,
                    'campaign_id': campaign_id,
                    'had_campaign': had_campaign,
                },
            )
        except Exception:
            pass
        try:
            refresh_champ_score_for_user(current_user.id)
        except Exception as e:
            logging.warning('link_ioc_to_campaign: refresh_champ_score failed (link saved): %s', e)

        response = {
            'success': True,
            'message': f'IOC linked to campaign "{campaign.name}"',
            'ioc_id': ioc.id,
            'campaign_id': campaign_id,
        }
        if champs_before and current_user and current_user.is_authenticated:
            try:
                response.update(_detect_champs_changes(champs_before, current_user.id, (current_user.username or '').lower()))
            except Exception as e:
                logging.warning('link_ioc_to_campaign: champs change detection failed (link saved): %s', e)
        return jsonify(response)
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/campaigns/<int:campaign_id>', methods=['PUT'])
@login_required
def update_campaign(campaign_id):
    """Update campaign name and/or description."""
    _commit_with_retry, audit_log = _from_app('_commit_with_retry', 'audit_log')
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404
        data = request.get_json() or {}
        name = (data.get('name') or '').strip()
        if name:
            campaign.name = name
        description = data.get('description')
        if description is not None:
            campaign.description = description.strip() or None
        dir_val = data.get('dir')
        if dir_val is not None:
            dir_val = (dir_val or 'ltr').strip().lower()
            if dir_val in ('ltr', 'rtl'):
                campaign.dir = dir_val
        _commit_with_retry()
        audit_log('CAMPAIGN_UPDATE', f'id={campaign_id} name={campaign.name}')
        return jsonify({
            'success': True,
            'message': f'Campaign "{campaign.name}" updated',
            'campaign': {'id': campaign.id, 'name': campaign.name, 'description': campaign.description, 'dir': campaign.dir or 'ltr'}
        })
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Campaign name already exists'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/campaigns/<int:campaign_id>', methods=['DELETE'])
@login_required
def delete_campaign(campaign_id):
    """Delete a campaign after unlinking all associated IOCs and YARA rules."""
    _commit_with_retry, audit_log = _from_app('_commit_with_retry', 'audit_log')
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404
        IOC.query.filter(IOC.campaign_id == campaign_id).update({'campaign_id': None})
        YaraRule.query.filter(YaraRule.campaign_id == campaign_id).update({'campaign_id': None})
        campaign_name = campaign.name
        db.session.delete(campaign)
        _commit_with_retry()
        audit_log('CAMPAIGN_DELETE', f'id={campaign_id} name={campaign_name}')
        return jsonify({'success': True, 'message': f'Campaign "{campaign_name}" deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# --- Playbook ---

@bp.route('/playbook', methods=['GET'])
def get_playbook_custom():
    """Return custom Hunter's Playbook items (sites, groups, workflows) for persistence."""
    _api_error, = _from_app('_api_error')
    try:
        custom = _playbook_load()
        return jsonify({'success': True, 'custom': custom})
    except Exception as e:
        return _api_error(str(e), 500)


@bp.route('/playbook', methods=['POST'])
@login_required
def save_playbook_item():
    """Create or update one custom playbook item. Body: { item: { type, id, name, ... } }."""
    _api_error, audit_log = _from_app('_api_error', 'audit_log')
    try:
        data = request.get_json() or {}
        item = data.get('item')
        if not item or not isinstance(item, dict):
            return jsonify({'success': False, 'message': 'item object is required'}), 400
        item_id = (item.get('id') or '').strip()
        if not item_id:
            return jsonify({'success': False, 'message': 'item.id is required'}), 400
        custom = _playbook_load()
        idx = next((i for i, c in enumerate(custom) if c.get('id') == item_id), -1)
        if idx >= 0:
            custom[idx] = item
        else:
            custom.insert(0, item)
        _playbook_save(custom)
        audit_log('PLAYBOOK_SAVE', f'id={item_id} type={item.get("type", "site")}')
        return jsonify({'success': True, 'custom': custom})
    except Exception as e:
        return _api_error(str(e), 500)


@bp.route('/playbook/reorder', methods=['POST'])
@login_required
def reorder_playbook_items():
    """Reorder custom playbook items (global for all users). Body: { ids: [ id1, id2, ... ] }."""
    _api_error, audit_log = _from_app('_api_error', 'audit_log')
    try:
        data = request.get_json() or {}
        ids = data.get('ids')
        if not isinstance(ids, list):
            return jsonify({'success': False, 'message': 'ids array is required'}), 400
        custom = _playbook_load()
        id_to_item = {c.get('id'): c for c in custom if c.get('id')}
        ordered = [id_to_item[i] for i in ids if i in id_to_item]
        for c in custom:
            if c.get('id') not in ids:
                ordered.append(c)
        _playbook_save(ordered)
        audit_log('PLAYBOOK_REORDER', f'count={len(ordered)} by={current_user.username}')
        logging.info('Playbook reorder: ids=%s', ids)
        return jsonify({'success': True, 'custom': ordered})
    except Exception as e:
        logging.exception('Playbook reorder failed')
        return _api_error(str(e), 500)


@bp.route('/playbook/<path:item_id>', methods=['DELETE'])
@login_required
def delete_playbook_item(item_id):
    """Remove a custom playbook item by id."""
    _api_error, audit_log = _from_app('_api_error', 'audit_log')
    try:
        item_id = (item_id or '').strip()
        if not item_id:
            return jsonify({'success': False, 'message': 'id is required'}), 400
        custom = _playbook_load()
        new_custom = [c for c in custom if c.get('id') != item_id]
        if len(new_custom) == len(custom):
            return jsonify({'success': False, 'message': 'Item not found'}), 404
        _playbook_save(new_custom)
        audit_log('PLAYBOOK_DELETE', f'id={item_id}')
        return jsonify({'success': True, 'custom': new_custom})
    except Exception as e:
        return _api_error(str(e), 500)


# --- Export ---

@bp.route('/campaigns/<int:campaign_id>/export', methods=['GET'])
def export_campaign_csv(campaign_id):
    """Export all IOCs and YARA rules for a campaign as a CSV download."""
    get_country_code, = _from_app('get_country_code')
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404

        iocs = IOC.query.filter(IOC.campaign_id == campaign_id).all()
        yara_rules = YaraRule.query.filter(YaraRule.campaign_id == campaign_id).all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Type', 'Value', 'Country', 'Analyst', 'Ticket ID', 'Comment', 'Created', 'Expiration'])

        for ioc in iocs:
            country = ''
            if ioc.type == 'IP':
                country = get_country_code(ioc.value) or ''
            writer.writerow([
                ioc.type,
                ioc.value,
                country.upper() if country else '',
                ioc.analyst or '',
                ioc.ticket_id or '',
                ioc.comment or '',
                ioc.created_at.strftime('%Y-%m-%d %H:%M:%S') if ioc.created_at else '',
                ioc.expiration_date.strftime('%Y-%m-%d %H:%M:%S') if ioc.expiration_date else 'Permanent',
            ])

        for rule in yara_rules:
            writer.writerow([
                'YARA',
                rule.filename,
                '',
                rule.analyst or '',
                rule.ticket_id or '',
                rule.comment or '',
                rule.uploaded_at.strftime('%Y-%m-%d %H:%M:%S') if rule.uploaded_at else '',
                '',
            ])

        csv_content = output.getvalue()
        output.close()
        safe_name = ''.join(c if c.isalnum() or c in '-_ ' else '_' for c in campaign.name).strip()
        filename = f'campaign_{safe_name}_{campaign.id}.csv'

        return Response(
            csv_content,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/campaigns/<int:campaign_id>/export-json', methods=['GET'])
def export_campaign_json(campaign_id):
    """Export all IOCs and YARA rules for a campaign as a JSON download."""
    get_country_code, = _from_app('get_country_code')
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404

        iocs = IOC.query.filter(IOC.campaign_id == campaign_id).all()
        yara_rules = YaraRule.query.filter(YaraRule.campaign_id == campaign_id).all()

        payload = {
            'campaign': {
                'id': campaign.id,
                'name': campaign.name,
                'description': campaign.description or '',
            },
            'exported_at': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
            'iocs': [],
            'yara_rules': [],
        }

        for ioc in iocs:
            country = ''
            if ioc.type == 'IP':
                country = (get_country_code(ioc.value) or '').upper()
            payload['iocs'].append({
                'type': ioc.type,
                'value': ioc.value,
                'country': country,
                'analyst': ioc.analyst or '',
                'ticket_id': ioc.ticket_id or '',
                'comment': ioc.comment or '',
                'created_at': ioc.created_at.strftime('%Y-%m-%d %H:%M:%S') if ioc.created_at else '',
                'expiration': ioc.expiration_date.strftime('%Y-%m-%d %H:%M:%S') if ioc.expiration_date else 'Permanent',
            })

        for rule in yara_rules:
            payload['yara_rules'].append({
                'filename': rule.filename,
                'analyst': rule.analyst or '',
                'ticket_id': rule.ticket_id or '',
                'comment': rule.comment or '',
                'uploaded_at': rule.uploaded_at.strftime('%Y-%m-%d %H:%M:%S') if rule.uploaded_at else '',
            })

        safe_name = ''.join(c if c.isalnum() or c in '-_ ' else '_' for c in campaign.name).strip()
        filename = f'campaign_{safe_name}_{campaign.id}.json'
        content = json.dumps(payload, ensure_ascii=False, indent=2)
        return Response(
            content,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# --- Campaign graph (Vis.js) ---

_IOC_TYPE_COLORS = {
    'IP': '#00d4ff',
    'Domain': '#a78bfa',
    'Hash': '#f43f5e',
    'Email': '#22c55e',
    'URL': '#f59e0b',
    'YARA': '#eab308',
}


def _emoji_svg_data_uri(emoji, bg_color='#3b82f6'):
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">'
        f'<circle cx="32" cy="32" r="32" fill="{bg_color}"/>'
        f'<text x="32" y="44" text-anchor="middle" font-size="32">{emoji}</text>'
        f'</svg>'
    )
    b64 = base64.b64encode(svg.encode('utf-8')).decode('ascii')
    return f'data:image/svg+xml;base64,{b64}'


_EMOJI_SVGS = {
    'campaign': _emoji_svg_data_uri('🎯', '#ef4444'),
    'IP':       _emoji_svg_data_uri('🛡️', '#0891b2'),
    'Domain':   _emoji_svg_data_uri('🌐', '#7c3aed'),
    'URL':      _emoji_svg_data_uri('🔗', '#d97706'),
    'Email':    _emoji_svg_data_uri('📧', '#16a34a'),
    'Hash':     _emoji_svg_data_uri('☣️', '#e11d48'),
    'YARA':     _emoji_svg_data_uri('📜', '#ca8a04'),
}

_COLUMN_X = {
    'IP':     -500,
    'Domain': -250,
    'URL':       0,
    'Email':   250,
    'Hash':    500,
    'YARA':    500,
}

_COLUMN_HEADERS = {
    'IP':     ('IP Addresses',  '#00d4ff'),
    'Domain': ('Domains',       '#a78bfa'),
    'URL':    ('URLs',          '#f59e0b'),
    'Email':  ('Emails',        '#22c55e'),
    'Hash':   ('Hashes / YARA', '#f43f5e'),
}


@bp.route('/campaign-graph/<int:campaign_id>', methods=['GET'])
def campaign_graph(campaign_id):
    """Return Orchestra-layout Vis.js graph: Campaign at top, IOC columns below with fixed x/y."""
    get_country_code, = _from_app('get_country_code')
    try:
        campaign = db.session.get(Campaign, campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404

        camp_node_id = f'camp_{campaign.id}'
        camp_label = campaign.name[:30] + ('…' if len(campaign.name) > 30 else '')
        nodes = [{
            'id': camp_node_id,
            'label': f'<b>{camp_label}</b>',
            'title': (campaign.name + ('\n' + (campaign.description or ''))) if campaign.description else campaign.name,
            'shape': 'circularImage',
            'image': _EMOJI_SVGS['campaign'],
            'size': 40,
            'x': 0, 'y': 0,
            'fixed': {'x': True, 'y': True},
            'borderWidth': 3,
            'color': {'border': '#ef4444', 'highlight': {'border': '#f87171'}},
            'font': {
                'multi': 'html',
                'vadjust': -140,
                'size': 24,
                'color': '#ffffff',
                'face': 'Segoe UI, sans-serif',
                'bold': {'color': '#ffffff', 'size': 24, 'face': 'Segoe UI, sans-serif'},
            },
        }]
        edges = []

        for col_type, (col_label, col_color) in _COLUMN_HEADERS.items():
            col_x = _COLUMN_X.get(col_type, 0)
            nodes.append({
                'id': f'header_{col_type}',
                'label': col_label,
                'x': col_x, 'y': 85,
                'fixed': {'x': True, 'y': True},
                'shape': 'text',
                'font': {'size': 13, 'color': col_color, 'face': 'Inter, Segoe UI, sans-serif',
                         'bold': {'color': col_color, 'size': 13}},
            })

        col_y = {}
        iocs = IOC.query.filter(IOC.campaign_id == campaign_id).all()
        for ioc in iocs:
            ioc_type = ioc.type or 'Hash'
            col_x = _COLUMN_X.get(ioc_type, 400)
            node_color = _IOC_TYPE_COLORS.get(ioc_type, '#94a3b8')
            truncated = (ioc.value[:24] + '…') if len(ioc.value) > 24 else ioc.value
            y_key = ioc_type
            if y_key not in col_y:
                col_y[y_key] = 150
            node_y = col_y[y_key]
            col_y[y_key] += 80
            node = {
                'id': f'ioc_{ioc.id}',
                'label': truncated,
                'title': f"{ioc_type}: {ioc.value}",
                'shape': 'circularImage',
                'size': 22,
                'x': col_x, 'y': node_y,
                'fixed': {'x': True, 'y': True},
                'borderWidth': 2,
                'color': {'border': node_color, 'highlight': {'border': '#ffffff'}},
                'font': {'color': '#e2e8f0', 'size': 14, 'face': 'Consolas, monospace', 'bold': True, 'vadjust': 0},
            }
            if ioc_type == 'IP':
                cc = get_country_code(ioc.value)
                node['image'] = f'/static/flags/1x1/{cc}.svg' if cc else _EMOJI_SVGS['IP']
            else:
                node['image'] = _EMOJI_SVGS.get(ioc_type, _EMOJI_SVGS['Hash'])
            nodes.append(node)
            edges.append({
                'from': camp_node_id,
                'to': f'ioc_{ioc.id}',
                'color': {'color': node_color, 'opacity': 0.5},
                'width': 1.5,
            })

        yara_rules = YaraRule.query.filter(YaraRule.campaign_id == campaign_id).all()
        y_key_yara = 'YARA'
        for rule in yara_rules:
            if y_key_yara not in col_y:
                col_y[y_key_yara] = col_y.get('Hash', 150)
            node_y = col_y[y_key_yara]
            col_y[y_key_yara] += 80
            nodes.append({
                'id': f'yara_{rule.id}',
                'label': rule.filename[:20] + ('…' if len(rule.filename) > 20 else ''),
                'title': f"YARA: {rule.filename}\n{rule.comment or ''}",
                'shape': 'circularImage',
                'image': _EMOJI_SVGS['YARA'],
                'size': 22,
                'x': 500, 'y': node_y,
                'fixed': {'x': True, 'y': True},
                'borderWidth': 2,
                'color': {'border': '#eab308', 'highlight': {'border': '#fde68a'}},
                'font': {'color': '#e2e8f0', 'size': 14, 'face': 'Consolas, monospace', 'bold': True, 'vadjust': 0},
            })
            edges.append({
                'from': camp_node_id,
                'to': f'yara_{rule.id}',
                'color': {'color': '#fbbf24', 'opacity': 0.5},
                'width': 1.5,
            })

        return jsonify({
            'success': True,
            'nodes': nodes,
            'edges': edges,
            'campaign': {'id': campaign.id, 'name': campaign.name, 'description': campaign.description}
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
