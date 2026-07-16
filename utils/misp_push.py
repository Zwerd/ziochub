"""
Push IOC from ZIoCHub to MISP (add attribute to event).

Used when SOC uses ZIoCHub but wants to feed MISP so defense systems that pull from MISP
stay updated without needing Feed/TAXII/DXL on ZIoCHub.
Comment from SOC can be pushed to MISP attribute when enabled in settings.
"""
from __future__ import annotations

import logging
from typing import Optional

_log = logging.getLogger('ziochub.misp_push')

PYMISP_AVAILABLE = False
try:
    from pymisp import PyMISP
    PYMISP_AVAILABLE = True
except ImportError:
    PyMISP = None  # type: ignore


# ZIoCHub type -> MISP attribute type(s). Hash resolved by length in _misp_type_for_ioc.
ZIOCHUB_TO_MISP_TYPE = {
    'IP': 'ip-src',
    'Domain': 'domain',
    'URL': 'url',
    'Email': 'email-src',
    'Hash': None,  # resolved by value length: 32->md5, 40->sha1, 64->sha256, 128->sha512
}


def _misp_type_for_ioc(ioc_type: str, value: str) -> Optional[str]:
    """Return MISP attribute type for given ZIoCHub type and value (Hash needs length)."""
    if ioc_type == 'Hash':
        n = len((value or '').strip())
        if n == 32:
            return 'md5'
        if n == 40:
            return 'sha1'
        if n == 64:
            return 'sha256'
        if n == 128:
            return 'sha512'
        return 'sha256'  # fallback
    return ZIOCHUB_TO_MISP_TYPE.get(ioc_type)


def _record_misp_distribution_success(ioc_type: str, value: str) -> None:
    try:
        from utils.downstream import record_api_distribution_events

        record_api_distribution_events(
            [{'action': 'create', 'type': ioc_type, 'value': value}],
            vendor_id='misp',
            display_name='MISP',
            api_source='misp_push',
        )
    except Exception:
        _log.debug('MISP downstream distribution record failed', exc_info=True)


def _audit_misp_push(
    ok: bool,
    ioc_type: str,
    value: str,
    message: str,
    *,
    from_retry: bool = False,
    event_id: int | None = None,
) -> None:
    try:
        from utils.audit_events import audit_log_event

        fields: dict = {
            'type': ioc_type or None,
            'value': (value or '')[:80],
            'source': 'retry' if from_retry else 'submit',
        }
        if event_id is not None:
            fields['event_id'] = event_id
        if ok:
            fields['message'] = (message or '')[:200]
        else:
            fields['reason'] = message or 'unknown'
        audit_log_event(
            'misp_push_ok' if ok else 'misp_push_fail',
            'success' if ok else 'fail',
            **fields,
        )
    except Exception:
        _log.exception('misp_push CEF audit failed')


def push_ioc_to_misp(
    ioc_type: str,
    value: str,
    comment: Optional[str] = None,
    *,
    event_id: Optional[int] = None,
    url: str = '',
    api_key: str = '',
    verify_ssl: bool = False,
    include_comment: bool = True,
    from_retry: bool = False,
) -> tuple[bool, str]:
    """
    Push one IOC to MISP as an attribute (add to existing event or create new event).

    :param ioc_type: ZIoCHub type (IP, Domain, URL, Email, Hash).
    :param value: IOC value string.
    :param comment: ZIoCHub comment to set on MISP attribute when include_comment is True.
    :param event_id: MISP event id to add attribute to; if None, a new event is created.
    :param url: MISP base URL.
    :param api_key: MISP API key.
    :param verify_ssl: Whether to verify SSL.
    :param include_comment: If True, set MISP attribute comment from ZIoCHub comment.
    :param from_retry: True when invoked from integration retry scheduler.
    :return: (success: bool, message: str).
    """
    if not PYMISP_AVAILABLE:
        msg = 'pymisp is not installed'
        _audit_misp_push(False, ioc_type, value, msg, from_retry=from_retry, event_id=event_id)
        return False, msg
    value = (value or '').strip()
    if not value:
        msg = 'Empty IOC value'
        _audit_misp_push(False, ioc_type, value, msg, from_retry=from_retry, event_id=event_id)
        return False, msg
    misp_type = _misp_type_for_ioc(ioc_type, value)
    if not misp_type:
        msg = f'Unsupported IOC type for MISP: {ioc_type}'
        _audit_misp_push(False, ioc_type, value, msg, from_retry=from_retry, event_id=event_id)
        return False, msg
    if not url or not api_key:
        msg = 'MISP URL and API key are required'
        _audit_misp_push(False, ioc_type, value, msg, from_retry=from_retry, event_id=event_id)
        return False, msg
    try:
        misp = PyMISP(url.rstrip('/'), api_key, ssl=verify_ssl, timeout=30)
        resolved_event_id = event_id
        if resolved_event_id is None:
            ev = misp.add_event(info='ZIoCHub export', distribution=0)
            if ev is None:
                msg = 'Failed to create MISP event'
                _audit_misp_push(False, ioc_type, value, msg, from_retry=from_retry, event_id=event_id)
                return False, msg
            resolved_event_id = ev.get('id') if isinstance(ev, dict) else getattr(ev, 'id', None)
            if resolved_event_id is None:
                msg = 'Failed to get new event id'
                _audit_misp_push(False, ioc_type, value, msg, from_retry=from_retry, event_id=event_id)
                return False, msg
        attr_comment = (comment or '').strip()[:65535] if include_comment else ''
        kwargs = {'type': misp_type, 'value': value}
        if attr_comment:
            kwargs['comment'] = attr_comment
        attr = misp.add_attribute(resolved_event_id, kwargs)
        if attr is None:
            msg = 'MISP did not return the new attribute (may already exist)'
            _audit_misp_push(False, ioc_type, value, msg, from_retry=from_retry, event_id=resolved_event_id)
            return False, msg
        ok_msg = f'Pushed to MISP event {resolved_event_id}'
        _audit_misp_push(True, ioc_type, value, ok_msg, from_retry=from_retry, event_id=resolved_event_id)
        _record_misp_distribution_success(ioc_type, value)
        return True, ok_msg
    except Exception as e:
        msg = str(e)[:300]
        _log.warning('push_ioc_to_misp failed: %s', e)
        _audit_misp_push(False, ioc_type, value, msg, from_retry=from_retry, event_id=event_id)
        return False, msg
