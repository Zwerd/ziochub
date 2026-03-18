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
    :return: (success: bool, message: str).
    """
    if not PYMISP_AVAILABLE:
        return False, 'pymisp is not installed'
    value = (value or '').strip()
    if not value:
        return False, 'Empty IOC value'
    misp_type = _misp_type_for_ioc(ioc_type, value)
    if not misp_type:
        return False, f'Unsupported IOC type for MISP: {ioc_type}'
    if not url or not api_key:
        return False, 'MISP URL and API key are required'
    try:
        misp = PyMISP(url.rstrip('/'), api_key, ssl=verify_ssl, timeout=30)
        if event_id is None:
            ev = misp.add_event(info='ZIoCHub export', distribution=0)
            if ev is None:
                return False, 'Failed to create MISP event'
            event_id = ev.get('id') if isinstance(ev, dict) else getattr(ev, 'id', None)
            if event_id is None:
                return False, 'Failed to get new event id'
        attr_comment = (comment or '').strip()[:65535] if include_comment else ''
        kwargs = {'type': misp_type, 'value': value}
        if attr_comment:
            kwargs['comment'] = attr_comment
        attr = misp.add_attribute(event_id, kwargs)
        if attr is None:
            return False, 'MISP did not return the new attribute (may already exist)'
        return True, f'Pushed to MISP event {event_id}'
    except Exception as e:
        _log.warning('push_ioc_to_misp failed: %s', e)
        return False, str(e)[:300]
