"""
Downstream distribution tracking: admin registry, feed/TAXII correlation, API push events.
"""
from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy.exc import IntegrityError

from extensions import db
from models import DownstreamSystem, FeedSourceLastSeen, IOC, IocDownstreamEvent, _utcnow, iso_utc

logger = logging.getLogger(__name__)

# Vendor icons: drop official logos into static/img/vendors/ as {vendor_id}.svg|.png|.webp
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_VENDORS_ICON_DIR = _PROJECT_ROOT / 'static' / 'img' / 'vendors'
_ICON_EXTENSIONS = ('.svg', '.png', '.webp', '.jpg', '.jpeg')
_icon_url_cache: dict[str, str] = {}

# Vendor catalog for Admin UI + Search icons (alphabetical; generic last).
# Icon files: static/img/vendors/{id}.svg|.png|.webp
VENDOR_CATALOG: list[dict[str, str]] = [
    {'id': 'akamai', 'label': 'Akamai'},
    {'id': 'anomali', 'label': 'Anomali'},
    {'id': 'armis', 'label': 'Armis'},
    {'id': 'carbon_black', 'label': 'VMware Carbon Black'},
    {'id': 'cato', 'label': 'Cato Networks'},
    {'id': 'checkpoint', 'label': 'Check Point'},
    {'id': 'cisco', 'label': 'Cisco'},
    {'id': 'claroty', 'label': 'Claroty'},
    {'id': 'crowdstrike', 'label': 'CrowdStrike'},
    {'id': 'cortex', 'label': 'Cortex XDR'},
    {'id': 'cyberark', 'label': 'CyberArk'},
    {'id': 'cybereason', 'label': 'Cybereason'},
    {'id': 'darktrace', 'label': 'Darktrace'},
    {'id': 'elastic', 'label': 'Elastic'},
    {'id': 'exabeam', 'label': 'Exabeam'},
    {'id': 'f5', 'label': 'F5 Networks'},
    {'id': 'forescout', 'label': 'Forescout'},
    {'id': 'fortinet', 'label': 'Fortinet'},
    {'id': 'google', 'label': 'Google'},
    {'id': 'google_secops', 'label': 'Google SecOps'},
    {'id': 'hunters', 'label': 'Hunters'},
    {'id': 'ibm', 'label': 'IBM'},
    {'id': 'imperva', 'label': 'Imperva'},
    {'id': 'logz_io', 'label': 'Logz.io'},
    {'id': 'mandiant', 'label': 'Mandiant'},
    {'id': 'mcafee', 'label': 'OpenDXL / Trellix TIE'},
    {'id': 'microsoft', 'label': 'Microsoft'},
    {'id': 'misp', 'label': 'MISP'},
    {'id': 'palo_alto', 'label': 'Palo Alto Networks'},
    {'id': 'radware', 'label': 'Radware'},
    {'id': 'rapid7', 'label': 'Rapid7'},
    {'id': 'recorded_future', 'label': 'Recorded Future'},
    {'id': 'securonix', 'label': 'Securonix'},
    {'id': 'sentinelone', 'label': 'SentinelOne'},
    {'id': 'shodan', 'label': 'Shodan'},
    {'id': 'sophos', 'label': 'Sophos'},
    {'id': 'splunk', 'label': 'Splunk'},
    {'id': 'symantec', 'label': 'Symantec'},
    {'id': 'threatconnect', 'label': 'ThreatConnect'},
    {'id': 'threatquotient', 'label': 'ThreatQuotient'},
    {'id': 'trend_micro', 'label': 'Trend Micro'},
    {'id': 'trellix', 'label': 'Trellix'},
    {'id': 'varonis', 'label': 'Varonis'},
    {'id': 'virustotal', 'label': 'VirusTotal'},
    {'id': 'generic', 'label': 'Other / Generic'},
]

_VENDOR_IDS = {v['id'] for v in VENDOR_CATALOG}
CUSTOM_VENDOR_ID = 'custom'
_ALLOWED_UPLOAD_EXT = {'.svg', '.png', '.webp', '.jpg', '.jpeg'}
_MAX_ICON_BYTES = 512 * 1024
_CUSTOM_ICON_DIR = _VENDORS_ICON_DIR / 'custom'

_CHANNEL_FEED = 'feed'
_CHANNEL_TAXII = 'taxii'
_CHANNEL_API = 'api'

_REMOVE_ACTIONS = frozenset({
    'remove', 'delete', 'revoke', 'expire_remove', 'delete_remove',
})

_CORRELATE_BATCH = 500


def vendor_label(vendor_id: str) -> str:
    vid = (vendor_id or '').strip()
    for v in VENDOR_CATALOG:
        if v['id'] == vid:
            return v['label']
    return vid or 'Unknown'


def clear_vendor_icon_cache() -> None:
    """Clear resolved icon URL cache (after replacing files under static/img/vendors/)."""
    _icon_url_cache.clear()


def _resolve_vendor_icon_url(vendor_id: str) -> str:
    """Return /static URL for the first matching icon file (svg → png → webp → jpg)."""
    vid = (vendor_id or 'generic').strip().lower() or 'generic'
    cached = _icon_url_cache.get(vid)
    if cached:
        return cached

    if _VENDORS_ICON_DIR.is_dir():
        for ext in _ICON_EXTENSIONS:
            path = _VENDORS_ICON_DIR / f'{vid}{ext}'
            if path.is_file():
                url = f'/static/img/vendors/{vid}{ext}'
                _icon_url_cache[vid] = url
                return url

    if vid != 'generic':
        url = _resolve_vendor_icon_url('generic')
        _icon_url_cache[vid] = url
        return url

    fallback = '/static/img/vendors/generic.svg'
    _icon_url_cache['generic'] = fallback
    return fallback


def vendor_icon_url(vendor_id: str) -> str:
    vid = (vendor_id or 'generic').strip() or 'generic'
    if vid not in _VENDOR_IDS:
        vid = 'generic'
    return _resolve_vendor_icon_url(vid)


def vendor_catalog_for_api() -> list[dict[str, str]]:
    """Vendor list with resolved icon_url for Admin UI."""
    return [
        {**v, 'icon_url': vendor_icon_url(v['id'])}
        for v in VENDOR_CATALOG
    ]


def custom_icon_url(relpath: str) -> str:
    rel = (relpath or '').strip().replace('\\', '/').lstrip('/')
    if not rel or '..' in rel.split('/'):
        return vendor_icon_url('generic')
    return f'/static/img/vendors/{rel}'


def system_icon_url(row: DownstreamSystem) -> str:
    if getattr(row, 'is_custom_vendor', False) and (row.custom_icon_path or '').strip():
        return custom_icon_url(row.custom_icon_path)
    return vendor_icon_url(row.vendor_id)


def system_vendor_label(row: DownstreamSystem) -> str:
    if getattr(row, 'is_custom_vendor', False) and (row.custom_vendor_label or '').strip():
        return row.custom_vendor_label.strip()
    return vendor_label(row.vendor_id)


def system_event_vendor_id(row: DownstreamSystem) -> str:
    if getattr(row, 'is_custom_vendor', False):
        return CUSTOM_VENDOR_ID
    return row.vendor_id


def _delete_icon_file(relpath: str | None) -> None:
    rel = (relpath or '').strip().replace('\\', '/').lstrip('/')
    if not rel or '..' in rel.split('/'):
        return
    try:
        path = (_VENDORS_ICON_DIR / rel).resolve()
        if not str(path).startswith(str(_VENDORS_ICON_DIR.resolve())):
            return
        if path.is_file():
            path.unlink()
    except Exception:
        logger.debug('delete downstream icon failed', exc_info=True)


def save_downstream_custom_icon(system_id: int, file_storage) -> str:
    """Save uploaded icon; return relative path under static/img/vendors/."""
    if file_storage is None or not getattr(file_storage, 'filename', None):
        raise ValueError('Icon image is required for a custom vendor')
    ext = Path(file_storage.filename).suffix.lower()
    if ext not in _ALLOWED_UPLOAD_EXT:
        raise ValueError('Icon must be SVG, PNG, WebP, or JPG')
    try:
        file_storage.stream.seek(0, 2)
        size = file_storage.stream.tell()
        file_storage.stream.seek(0)
    except Exception:
        size = 0
    if size > _MAX_ICON_BYTES:
        raise ValueError('Icon file too large (max 512 KB)')
    _CUSTOM_ICON_DIR.mkdir(parents=True, exist_ok=True)
    import secrets
    fname = f'ds_{int(system_id)}_{secrets.token_hex(8)}{ext}'
    dest = _CUSTOM_ICON_DIR / fname
    file_storage.save(dest)
    return f'custom/{fname}'


def parse_downstream_payload(req) -> dict[str, Any]:
    """Parse JSON or multipart form for downstream system create/update."""
    ct = (getattr(req, 'content_type', None) or '').lower()
    if 'multipart/form-data' in ct:
        form = req.form
        icon = req.files.get('icon') if hasattr(req, 'files') else None
        use_custom = str(form.get('use_custom_vendor', '')).strip().lower() in ('1', 'true', 'yes', 'on')
        enabled_raw = form.get('enabled', 'true')
        enabled = str(enabled_raw).strip().lower() in ('1', 'true', 'yes', 'on')
        return {
            'name': form.get('name'),
            'vendor_id': form.get('vendor_id'),
            'client_ip': form.get('client_ip'),
            'enabled': enabled,
            'use_custom_vendor': use_custom,
            'custom_vendor_label': form.get('custom_vendor_label'),
            'icon': icon if icon and getattr(icon, 'filename', None) else None,
        }
    data = req.get_json(silent=True) if hasattr(req, 'get_json') else {}
    if not isinstance(data, dict):
        data = {}
    return {
        'name': data.get('name'),
        'vendor_id': data.get('vendor_id'),
        'client_ip': data.get('client_ip'),
        'enabled': data.get('enabled', True),
        'use_custom_vendor': bool(data.get('use_custom_vendor')),
        'custom_vendor_label': data.get('custom_vendor_label'),
        'icon': None,
    }


def validate_client_ip(raw: str) -> tuple[bool, str]:
    s = (raw or '').strip()
    if not s:
        return False, 'IP address is required'
    try:
        ipaddress.ip_address(s)
        return True, s
    except ValueError:
        return False, 'Invalid IP address'


def normalize_vendor_id(raw: str) -> str | None:
    vid = (raw or '').strip().lower()
    if vid in _VENDOR_IDS:
        return vid
    return None


def downstream_system_to_dict(row: DownstreamSystem) -> dict[str, Any]:
    return {
        'id': row.id,
        'name': row.name,
        'vendor_id': row.vendor_id,
        'vendor_label': system_vendor_label(row),
        'is_custom_vendor': bool(getattr(row, 'is_custom_vendor', False)),
        'custom_vendor_label': row.custom_vendor_label or '',
        'client_ip': row.client_ip,
        'enabled': bool(row.enabled),
        'icon_url': system_icon_url(row),
        'last_feed_correlated_at': iso_utc(row.last_feed_correlated_at),
        'last_taxii_correlated_at': iso_utc(row.last_taxii_correlated_at),
        'created_at': iso_utc(row.created_at),
        'updated_at': iso_utc(row.updated_at),
    }


def list_downstream_systems() -> list[dict[str, Any]]:
    rows = DownstreamSystem.query.order_by(DownstreamSystem.name.asc()).all()
    return [downstream_system_to_dict(r) for r in rows]


def build_feed_client_lookup_by_ip() -> dict[str, dict[str, Any]]:
    """Map client IP → vendor icon/label and display name(s) from enabled downstream systems."""
    grouped: dict[str, list[DownstreamSystem]] = defaultdict(list)
    rows = (
        DownstreamSystem.query
        .filter_by(enabled=True)
        .order_by(DownstreamSystem.name.asc())
        .all()
    )
    for row in rows:
        ip = (row.client_ip or '').strip()
        if ip:
            grouped[ip].append(row)

    out: dict[str, dict[str, Any]] = {}
    for ip, systems in grouped.items():
        if len(systems) == 1:
            r = systems[0]
            out[ip] = {
                'registered': True,
                'system_name': r.name,
                'vendor_label': system_vendor_label(r),
                'vendor_icon_url': system_icon_url(r),
            }
            continue
        out[ip] = {
            'registered': True,
            'system_name': ' / '.join(s.name for s in systems),
            'vendor_label': ' / '.join(sorted({system_vendor_label(s) for s in systems})),
            'vendor_icon_url': system_icon_url(systems[0]),
        }
    return out


# Admin → Integrations vendor APIs (Feed Pulse push_state icons)
_INTEGRATION_VENDOR_MAP: dict[str, str] = {
    'cortex_xdr': 'cortex',
    'google_secops': 'google_secops',
    'cisco_esa': 'cisco',
    'misp_push': 'misp',
    'misp_pull': 'misp',
    'opendxl': 'mcafee',
    'trellix': 'trellix',
    'fireeye_yara': 'trellix',
    'trellix_nx': 'trellix',
    'trellix_ex': 'trellix',
    'trellix_cms': 'trellix',
}

INTEGRATION_SYSTEM_LABELS: dict[str, str] = {
    'cortex_xdr': 'Vendor integration',
    'google_secops': 'Vendor integration',
    'cisco_esa': 'Vendor integration',
    'misp_push': 'Vendor integration',
    'misp_pull': 'Inbound pull',
    'opendxl': 'Vendor integration',
    'fireeye_yara': 'FireEye / Trellix YARA',
    'trellix_nx': 'Trellix NX YARA',
    'trellix_ex': 'Trellix Email Security YARA',
    'trellix_cms': 'Trellix CMS YARA',
}

INTEGRATION_VENDOR_LABELS: dict[str, str] = {
    'cortex_xdr': 'Cortex XDR',
    'google_secops': 'Google SecOps',
    'cisco_esa': 'Cisco ESA',
    'misp_push': 'MISP',
    'misp_pull': 'MISP',
    'opendxl': 'OpenDXL / Trellix TIE',
    'trellix': 'Trellix',
    'trellix_ex': 'Trellix',
    'trellix_cms': 'Trellix',
    'trellix_nx': 'Trellix',
    'fireeye_yara': 'Trellix',
}


def integration_icon_url(integration_id: str) -> str:
    """Icon for Admin → Integrations products (e.g. google_secops.png before catalog alias)."""
    iid = (integration_id or '').strip().lower()
    if not iid:
        return vendor_icon_url('generic')
    cache_key = f'integration:{iid}'
    cached = _icon_url_cache.get(cache_key)
    if cached:
        return cached
    if _VENDORS_ICON_DIR.is_dir():
        for ext in _ICON_EXTENSIONS:
            path = _VENDORS_ICON_DIR / f'{iid}{ext}'
            if path.is_file():
                url = f'/static/img/vendors/{iid}{ext}'
                _icon_url_cache[cache_key] = url
                return url
    vid = _INTEGRATION_VENDOR_MAP.get(iid, iid)
    url = vendor_icon_url(vid)
    _icon_url_cache[cache_key] = url
    return url


def integration_icons_for_admin() -> dict[str, str]:
    """Resolved icon URLs for Integrations sub-tabs (Push IOC / Push YARA / Import)."""
    ids = (
        'cortex_xdr', 'google_secops', 'cisco_esa', 'misp_push', 'misp_pull', 'opendxl',
        'trellix', 'trellix_ex', 'trellix_cms', 'trellix_nx',
    )
    return {iid: integration_icon_url(iid) for iid in ids}


def vendor_meta_for_integration(integration_id: str) -> dict[str, str]:
    """Vendor icon/label for configured outbound API integrations."""
    iid = (integration_id or '').strip()
    vid = _INTEGRATION_VENDOR_MAP.get(iid, 'generic')
    return {
        'integration_id': iid,
        'vendor_id': vid,
        'vendor_label': INTEGRATION_VENDOR_LABELS.get(iid) or vendor_label(vid),
        'vendor_icon_url': integration_icon_url(iid),
        'integration_label': INTEGRATION_SYSTEM_LABELS.get(iid, 'HTTP automation'),
    }


def resolve_push_vendor_by_host(
    host: str,
    lookup: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Match HTTP push target to downstream registry when host is a literal IP."""
    ip = (host or '').strip()
    generic = vendor_icon_url('generic')
    if not ip:
        return {'registered': False, 'vendor_label': '', 'vendor_icon_url': generic}
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {'registered': False, 'vendor_label': '', 'vendor_icon_url': generic}
    info = (lookup or build_feed_client_lookup_by_ip()).get(ip)
    if info:
        return {
            'registered': True,
            'vendor_label': info['vendor_label'],
            'vendor_icon_url': info['vendor_icon_url'],
        }
    return {'registered': False, 'vendor_label': '', 'vendor_icon_url': generic}


def create_downstream_system(
    *,
    name: str,
    vendor_id: str,
    client_ip: str,
    enabled: bool = True,
    use_custom_vendor: bool = False,
    custom_vendor_label: str | None = None,
    icon_file=None,
) -> DownstreamSystem:
    nm = (name or '').strip()
    if not nm:
        raise ValueError('Name is required')
    ok, ip_or_err = validate_client_ip(client_ip)
    if not ok:
        raise ValueError(ip_or_err)
    now = _utcnow()
    use_custom = bool(use_custom_vendor)
    if use_custom:
        custom_label = (custom_vendor_label or '').strip()
        if not custom_label:
            raise ValueError('Custom vendor name is required')
        row = DownstreamSystem(
            name=nm,
            vendor_id='generic',
            client_ip=ip_or_err,
            enabled=bool(enabled),
            is_custom_vendor=True,
            custom_vendor_label=custom_label,
            last_feed_correlated_at=now,
            last_taxii_correlated_at=now,
            created_at=now,
            updated_at=now,
        )
        db.session.add(row)
        db.session.flush()
        if icon_file:
            row.custom_icon_path = save_downstream_custom_icon(row.id, icon_file)
        else:
            raise ValueError('Icon image is required for a custom vendor')
        db.session.commit()
        return row

    vid = normalize_vendor_id(vendor_id)
    if not vid:
        raise ValueError('Invalid vendor')
    row = DownstreamSystem(
        name=nm,
        vendor_id=vid,
        client_ip=ip_or_err,
        enabled=bool(enabled),
        is_custom_vendor=False,
        custom_vendor_label=None,
        custom_icon_path=None,
        last_feed_correlated_at=now,
        last_taxii_correlated_at=now,
        created_at=now,
        updated_at=now,
    )
    db.session.add(row)
    db.session.commit()
    return row


def update_downstream_system(
    system_id: int,
    *,
    name: str | None = None,
    vendor_id: str | None = None,
    client_ip: str | None = None,
    enabled: bool | None = None,
    use_custom_vendor: bool | None = None,
    custom_vendor_label: str | None = None,
    icon_file=None,
) -> DownstreamSystem:
    row = DownstreamSystem.query.get(system_id)
    if not row:
        raise LookupError('System not found')
    if name is not None:
        nm = (name or '').strip()
        if not nm:
            raise ValueError('Name is required')
        row.name = nm
    if client_ip is not None:
        ok, ip_or_err = validate_client_ip(client_ip)
        if not ok:
            raise ValueError(ip_or_err)
        row.client_ip = ip_or_err
    if enabled is not None:
        row.enabled = bool(enabled)

    if use_custom_vendor is not None:
        if use_custom_vendor:
            custom_label = (custom_vendor_label or row.custom_vendor_label or '').strip()
            if not custom_label:
                raise ValueError('Custom vendor name is required')
            row.is_custom_vendor = True
            row.custom_vendor_label = custom_label
            row.vendor_id = 'generic'
            if icon_file:
                old_path = row.custom_icon_path
                row.custom_icon_path = save_downstream_custom_icon(row.id, icon_file)
                if old_path and old_path != row.custom_icon_path:
                    _delete_icon_file(old_path)
            elif not (row.custom_icon_path or '').strip():
                raise ValueError('Icon image is required for a custom vendor')
        else:
            if (row.custom_icon_path or '').strip():
                _delete_icon_file(row.custom_icon_path)
            row.is_custom_vendor = False
            row.custom_vendor_label = None
            row.custom_icon_path = None
            if vendor_id is not None:
                vid = normalize_vendor_id(vendor_id)
                if not vid:
                    raise ValueError('Invalid vendor')
                row.vendor_id = vid
    elif vendor_id is not None and not row.is_custom_vendor:
        vid = normalize_vendor_id(vendor_id)
        if not vid:
            raise ValueError('Invalid vendor')
        row.vendor_id = vid
    elif icon_file and row.is_custom_vendor:
        old_path = row.custom_icon_path
        row.custom_icon_path = save_downstream_custom_icon(row.id, icon_file)
        if old_path and old_path != row.custom_icon_path:
            _delete_icon_file(old_path)

    row.updated_at = _utcnow()
    db.session.commit()
    return row


def delete_downstream_system(system_id: int) -> None:
    row = DownstreamSystem.query.get(system_id)
    if not row:
        raise LookupError('System not found')
    if (row.custom_icon_path or '').strip():
        _delete_icon_file(row.custom_icon_path)
    IocDownstreamEvent.query.filter_by(downstream_system_id=system_id).delete()
    db.session.delete(row)
    db.session.commit()


def _event_icon_url(ev: IocDownstreamEvent) -> str:
    sys = getattr(ev, 'downstream_system', None)
    if sys is None and ev.downstream_system_id:
        sys = DownstreamSystem.query.get(ev.downstream_system_id)
    if sys and getattr(sys, 'is_custom_vendor', False) and (sys.custom_icon_path or '').strip():
        return custom_icon_url(sys.custom_icon_path)
    if ev.vendor_id == CUSTOM_VENDOR_ID:
        return vendor_icon_url('generic')
    return vendor_icon_url(ev.vendor_id)


def _event_to_distribution_dict(ev: IocDownstreamEvent) -> dict[str, Any]:
    return {
        'vendor_id': ev.vendor_id,
        'display_name': ev.display_name,
        'channel': ev.channel,
        'event_at': iso_utc(ev.event_at),
        'icon_url': _event_icon_url(ev),
        'feed_path': ev.feed_path or '',
        'api_source': ev.api_source or '',
        'downstream_system_id': ev.downstream_system_id,
        'is_active': bool(getattr(ev, 'is_active', True)),
    }


def _ioc_removed_from_hub_at(row: IOC | None) -> datetime | None:
    """When the IOC stopped being published in feeds (manual revoke or TTL expiry)."""
    if row is None:
        return None
    if getattr(row, 'revoked', False):
        return getattr(row, 'revoked_at', None) or _utcnow()
    exp = getattr(row, 'expiration_date', None)
    if exp is not None and exp <= _utcnow():
        return exp
    return None


def _mark_feed_taxii_inactive_after_pull(
    system: DownstreamSystem,
    channel: str,
    pull_at: datetime,
) -> int:
    """
    After a feed/TAXII pull, mark events inactive when the IOC was removed from ZIoCHub
    before this pull (downstream likely refreshed without it).
    """
    ch = (channel or '').strip().lower()
    if ch not in (_CHANNEL_FEED, _CHANNEL_TAXII):
        return 0
    marked = 0
    try:
        from sqlalchemy import func

        events = IocDownstreamEvent.query.filter_by(
            downstream_system_id=system.id,
            channel=ch,
            is_active=True,
        ).all()
        for ev in events:
            row = IOC.query.filter(
                IOC.type == ev.ioc_type,
                func.lower(IOC.value) == (ev.ioc_value or '').strip().lower(),
            ).first()
            removed_at = _ioc_removed_from_hub_at(row)
            if removed_at is None:
                continue
            if pull_at >= removed_at:
                ev.is_active = False
                marked += 1
    except Exception:
        logger.debug('_mark_feed_taxii_inactive_after_pull failed', exc_info=True)
    return marked


def distribution_map_for_iocs(pairs: list[tuple[str, str]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Batch lookup distribution entries for Search results."""
    clean: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for t, v in pairs or []:
        tt = (t or '').strip()
        vv = (v or '').strip()
        if not tt or not vv:
            continue
        key = (tt, vv)
        if key in seen:
            continue
        seen.add(key)
        clean.append(key)
    if not clean:
        return {}

    out: dict[tuple[str, str], list[dict[str, Any]]] = {k: [] for k in clean}
    try:
        from sqlalchemy import tuple_

        from sqlalchemy.orm import joinedload

        rows = (
            IocDownstreamEvent.query.filter(
                tuple_(IocDownstreamEvent.ioc_type, IocDownstreamEvent.ioc_value).in_(clean)
            )
            .options(joinedload(IocDownstreamEvent.downstream_system))
            .order_by(IocDownstreamEvent.event_at.asc())
            .all()
        )
    except Exception:
        logger.debug('distribution_map_for_iocs query failed', exc_info=True)
        return out

    for ev in rows:
        key = (ev.ioc_type, ev.ioc_value)
        if key not in out:
            continue
        out[key].append(_event_to_distribution_dict(ev))
    return out


def _upsert_event(
    *,
    ioc_type: str,
    ioc_value: str,
    channel: str,
    vendor_id: str,
    display_name: str,
    event_at: datetime | None = None,
    downstream_system_id: int | None = None,
    api_source: str | None = None,
    feed_path: str | None = None,
) -> None:
    tt = (ioc_type or '').strip()
    vv = (ioc_value or '').strip()
    if not tt or not vv:
        return
    ch = (channel or '').strip().lower()
    if ch not in (_CHANNEL_FEED, _CHANNEL_TAXII, _CHANNEL_API):
        return
    vid_raw = (vendor_id or '').strip()
    if vid_raw == CUSTOM_VENDOR_ID:
        vid = CUSTOM_VENDOR_ID
        dn = (display_name or '').strip() or 'Custom'
    else:
        vid = normalize_vendor_id(vid_raw) or 'generic'
        dn = (display_name or '').strip() or vendor_label(vid)
    ts = event_at or _utcnow()
    api_src = (api_source or '').strip() or None
    fp = (feed_path or '').strip()[:512] or None

    existing = IocDownstreamEvent.query.filter_by(
        ioc_type=tt,
        ioc_value=vv,
        channel=ch,
        downstream_system_id=downstream_system_id,
        api_source=api_src,
        display_name=dn,
    ).first()
    if existing:
        if ts > (existing.event_at or datetime.min):
            existing.event_at = ts
            if fp:
                existing.feed_path = fp
            existing.vendor_id = vid
        existing.is_active = True
        return

    db.session.add(IocDownstreamEvent(
        ioc_type=tt,
        ioc_value=vv,
        channel=ch,
        vendor_id=vid,
        display_name=dn,
        event_at=ts,
        downstream_system_id=downstream_system_id,
        api_source=api_src,
        feed_path=fp,
        is_active=True,
    ))


def record_api_distribution_events(
    contexts: list[dict[str, Any]],
    *,
    vendor_id: str,
    display_name: str,
    api_source: str,
    event_at: datetime | None = None,
) -> None:
    """Record successful API push for one or more IOC contexts (create actions only)."""
    if not contexts:
        return
    ts = event_at or _utcnow()
    dn = (display_name or '').strip() or vendor_label(vendor_id)
    api_src = (api_source or '').strip()
    try:
        for ctx in contexts:
            if not isinstance(ctx, dict):
                continue
            action = (str(ctx.get('action') or 'create')).strip().lower()
            if action in ('remove', 'delete', 'revoke', 'expire_remove', 'delete_remove'):
                continue
            ioc_type = (str(ctx.get('type') or '')).strip()
            value = (str(ctx.get('value') or '')).strip()
            if not ioc_type or not value:
                continue
            _upsert_event(
                ioc_type=ioc_type,
                ioc_value=value,
                channel=_CHANNEL_API,
                vendor_id=vendor_id,
                display_name=dn,
                event_at=ts,
                api_source=api_src,
            )
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
    except Exception:
        db.session.rollback()
        logger.debug('record_api_distribution_events failed', exc_info=True)


def mark_api_distribution_removed(
    contexts: list[dict[str, Any]],
    *,
    vendor_id: str,
    display_name: str,
    api_source: str,
    downstream_system_id: int | None = None,
) -> None:
    """Mark API distribution events inactive after a successful remove/revoke push."""
    if not contexts:
        return
    ts = _utcnow()
    dn = (display_name or '').strip() or vendor_label(vendor_id)
    api_src = (api_source or '').strip()
    vid = normalize_vendor_id(vendor_id) or 'generic'
    try:
        from sqlalchemy import func

        for ctx in contexts:
            if not isinstance(ctx, dict):
                continue
            action = (str(ctx.get('action') or '')).strip().lower()
            if action not in _REMOVE_ACTIONS:
                continue
            ioc_type = (str(ctx.get('type') or '')).strip()
            value = (str(ctx.get('value') or '')).strip()
            if not ioc_type or not value:
                continue
            q = IocDownstreamEvent.query.filter(
                IocDownstreamEvent.ioc_type == ioc_type,
                func.lower(IocDownstreamEvent.ioc_value) == value.lower(),
                IocDownstreamEvent.channel == _CHANNEL_API,
                IocDownstreamEvent.api_source == api_src,
                IocDownstreamEvent.display_name == dn,
            )
            if downstream_system_id is not None:
                q = q.filter(IocDownstreamEvent.downstream_system_id == downstream_system_id)
            else:
                q = q.filter(IocDownstreamEvent.vendor_id == vid)
            for ev in q.all():
                ev.is_active = False
                if ts > (ev.event_at or datetime.min):
                    ev.event_at = ts
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
    except Exception:
        db.session.rollback()
        logger.debug('mark_api_distribution_removed failed', exc_info=True)


def mark_ioc_push_target_removed(
    ctx: dict[str, Any],
    *,
    target_name: str,
) -> None:
    """HTTP IOC push remove succeeded for a registered downstream system (by display name)."""
    nm = (target_name or '').strip() or 'HTTP push target'
    matched = DownstreamSystem.query.filter_by(name=nm, enabled=True).first()
    if matched:
        mark_api_distribution_removed(
            [ctx],
            vendor_id=system_event_vendor_id(matched),
            display_name=matched.name,
            api_source='ioc_push',
            downstream_system_id=matched.id,
        )
        return
    mark_api_distribution_removed(
        [ctx],
        vendor_id='generic',
        display_name=nm,
        api_source='ioc_push',
    )


def record_ioc_push_target_success(
    ctx: dict[str, Any],
    *,
    target_name: str,
    vendor_id: str = 'generic',
) -> None:
    """HTTP IOC push target success (Integrations → HTTP IOC push)."""
    nm = (target_name or '').strip() or 'HTTP push target'
    vid = normalize_vendor_id(vendor_id) or 'generic'
    matched = DownstreamSystem.query.filter_by(name=nm, enabled=True).first()
    if matched:
        try:
            _upsert_event(
                ioc_type=(str(ctx.get('type') or '')).strip(),
                ioc_value=(str(ctx.get('value') or '')).strip(),
                channel=_CHANNEL_API,
                vendor_id=system_event_vendor_id(matched),
                display_name=matched.name,
                event_at=_utcnow(),
                downstream_system_id=matched.id,
                api_source='ioc_push',
            )
            db.session.commit()
            return
        except Exception:
            db.session.rollback()
    record_api_distribution_events(
        [ctx],
        vendor_id=vid,
        display_name=nm,
        api_source='ioc_push',
    )


def _correlate_system_pull(system: DownstreamSystem, channel: str, pull_at: datetime, feed_path: str) -> int:
    wm_attr = 'last_taxii_correlated_at' if channel == _CHANNEL_TAXII else 'last_feed_correlated_at'
    watermark = getattr(system, wm_attr) or datetime.min
    if pull_at <= watermark:
        return 0

    q = (
        IOC.query.filter(
            IOC.created_at <= pull_at,
            IOC.created_at > watermark,
            IOC.revoked.is_(False),
        )
        .order_by(IOC.id.asc())
    )
    added = 0
    for row in q.yield_per(_CORRELATE_BATCH):
        try:
            _upsert_event(
                ioc_type=row.type,
                ioc_value=row.value,
                channel=channel,
                vendor_id=system_event_vendor_id(system),
                display_name=system.name,
                event_at=pull_at,
                downstream_system_id=system.id,
                feed_path=feed_path,
            )
            added += 1
        except Exception:
            continue
    setattr(system, wm_attr, pull_at)
    system.updated_at = _utcnow()
    return added


def correlate_feed_pull(client_ip: str, feed_path: str, pull_at: datetime, ok: bool) -> None:
    """After a successful /feed or /taxii2 pull, attach IOCs created since last watermark."""
    if not ok:
        return
    ip = (client_ip or '').strip()
    path = (feed_path or '').strip()
    if not ip or not path:
        return
    channel = _CHANNEL_TAXII if path.startswith('/taxii2') else _CHANNEL_FEED
    systems = DownstreamSystem.query.filter_by(client_ip=ip, enabled=True).all()
    if not systems:
        return
    try:
        total = 0
        inactive = 0
        for sys in systems:
            total += _correlate_system_pull(sys, channel, pull_at, path)
            inactive += _mark_feed_taxii_inactive_after_pull(sys, channel, pull_at)
        db.session.commit()
        if total or inactive:
            logger.debug(
                'correlate_feed_pull ip=%s path=%s new_events=%s marked_inactive=%s',
                ip, path, total, inactive,
            )
    except Exception:
        db.session.rollback()
        logger.debug('correlate_feed_pull failed', exc_info=True)


def backfill_downstream_system(system_id: int) -> dict[str, int]:
    """
    Correlate historical feed/TAXII pulls for a registered IP against all IOCs still active
    at each pull time (for systems added after pulls already happened).
    """
    system = DownstreamSystem.query.get(system_id)
    if not system:
        raise LookupError('System not found')
    pulls = (
        FeedSourceLastSeen.query.filter_by(client_ip=system.client_ip, last_ok=True)
        .order_by(FeedSourceLastSeen.last_seen_at.asc())
        .all()
    )
    feed_count = 0
    taxii_count = 0
    for pull in pulls:
        path = (pull.feed_path or '').strip()
        if not path:
            continue
        channel = _CHANNEL_TAXII if path.startswith('/taxii2') else _CHANNEL_FEED
        pull_at = pull.last_seen_at or _utcnow()
        iocs = IOC.query.filter(IOC.created_at <= pull_at, IOC.revoked.is_(False)).all()
        for row in iocs:
            try:
                _upsert_event(
                    ioc_type=row.type,
                    ioc_value=row.value,
                    channel=channel,
                    vendor_id=system_event_vendor_id(system),
                    display_name=system.name,
                    event_at=pull_at,
                    downstream_system_id=system.id,
                    feed_path=path,
                )
                if channel == _CHANNEL_TAXII:
                    taxii_count += 1
                else:
                    feed_count += 1
            except Exception:
                continue
    system.last_feed_correlated_at = _utcnow()
    system.last_taxii_correlated_at = _utcnow()
    system.updated_at = _utcnow()
    db.session.commit()
    return {'feed_events': feed_count, 'taxii_events': taxii_count}
