"""
Google SecOps Reference Lists API (v2/lists) — optional companion to Data Table push.

Flexible Admin mapping: any number of (IOC type → list name) rows. URLs use REGEX lines
with ``/`` escaped as ``\\/`` so Chronicle does not treat ``//`` as an inline comment.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

REFERENCE_LISTS_API_VERSION = 'v2'
REFERENCE_LIST_PATCH_DELAY_SEC = 0.1

CONTENT_TYPE_DEFAULT = 'CONTENT_TYPE_DEFAULT_STRING'
CONTENT_TYPE_REGEX = 'REGEX'
CONTENT_TYPE_CIDR = 'CIDR'

REFERENCE_LIST_IOC_TYPES = ('IP', 'Domain', 'URL', 'Hash', 'Email', 'YARA')

_SECOPS_LIST_TYPE_HINT = {
    'IP': 'String / CIDR',
    'Domain': 'String',
    'URL': 'REGEX (escaped /)',
    'Hash': 'String',
    'Email': 'String',
    'YARA': 'String',
}


def secops_list_type_hint(ioc_type: str) -> str:
    return _SECOPS_LIST_TYPE_HINT.get((ioc_type or '').strip(), 'String')


def _normalize_ioc_type(raw: str) -> str:
    t = (raw or '').strip()
    if not t:
        return ''
    aliases = {
        'ip': 'IP',
        'domain': 'Domain',
        'url': 'URL',
        'hash': 'Hash',
        'email': 'Email',
        'yara': 'YARA',
    }
    low = t.lower()
    if low in aliases:
        return aliases[low]
    for known in REFERENCE_LIST_IOC_TYPES:
        if known.lower() == low:
            return known
    return t


def _legacy_dict_to_mappings(data: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for key, entry in data.items():
        if not isinstance(entry, dict):
            continue
        name = str(entry.get('list_name') or '').strip()
        if not name:
            continue
        enabled = entry.get('enabled', True)
        if isinstance(enabled, str):
            enabled = enabled.strip().lower() in ('true', '1', 'yes', 'on')
        if not enabled:
            continue
        ioc_type = _normalize_ioc_type(str(key))
        if ioc_type:
            out.append({'ioc_type': ioc_type, 'list_name': name})
    return out


def normalize_reference_lists_config(val: Any) -> str:
    """Validate Admin JSON (array of {ioc_type, list_name}); return serialized JSON array."""
    if val is None:
        return '[]'
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return '[]'
        try:
            val = json.loads(s)
        except (TypeError, ValueError) as e:
            raise ValueError(f'google_secops_reference_lists_config: invalid JSON ({e})') from e
    mappings: list[dict[str, str]] = []
    if isinstance(val, list):
        for item in val:
            if not isinstance(item, dict):
                continue
            ioc_type = _normalize_ioc_type(str(item.get('ioc_type') or item.get('type') or ''))
            list_name = str(item.get('list_name') or item.get('name') or '').strip()
            if ioc_type and list_name:
                mappings.append({'ioc_type': ioc_type, 'list_name': list_name})
    elif isinstance(val, dict):
        mappings = _legacy_dict_to_mappings(val)
    else:
        raise ValueError('google_secops_reference_lists_config must be a JSON array or legacy object')
    return json.dumps(mappings, ensure_ascii=False)


def parse_reference_lists_mappings(g: dict[str, str]) -> list[dict[str, str]]:
    raw = (g.get('google_secops_reference_lists_config') or '').strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    try:
        normalized = normalize_reference_lists_config(data)
        return json.loads(normalized)
    except ValueError:
        return []


def reference_lists_configured(g: dict[str, str]) -> bool:
    return bool(parse_reference_lists_mappings(g))


def google_secops_reference_lists_enabled(g: dict[str, str]) -> bool:
    """True when at least one list mapping is configured (legacy setting flag ignored)."""
    if reference_lists_configured(g):
        return True
    return (g.get('google_secops_reference_lists_enabled') or 'false').strip().lower() in (
        'true', '1', 'yes',
    )


def reference_lists_for_ioc_type(g: dict[str, str], ioc_type: str) -> list[str]:
    if not google_secops_reference_lists_enabled(g):
        return []
    want = _normalize_ioc_type(ioc_type)
    if not want:
        return []
    names: list[str] = []
    seen: set[str] = set()
    for row in parse_reference_lists_mappings(g):
        if _normalize_ioc_type(row.get('ioc_type') or '') != want:
            continue
        name = (row.get('list_name') or '').strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def reference_list_for_ioc_type(g: dict[str, str], ioc_type: str) -> Optional[str]:
    names = reference_lists_for_ioc_type(g, ioc_type)
    return names[0] if names else None


def reference_list_content_type(ioc_type: str, value: str) -> str:
    t = _normalize_ioc_type(ioc_type)
    v = (value or '').strip()
    if t == 'IP' and '/' in v:
        return CONTENT_TYPE_CIDR
    if t == 'URL':
        return CONTENT_TYPE_REGEX
    return CONTENT_TYPE_DEFAULT


def escape_reference_list_regex(value: str) -> str:
    """Escape a literal URL/value for SecOps REGEX reference list lines."""
    out: list[str] = []
    for ch in value or '':
        if ch == '/':
            out.append(r'\/')
        elif ch in r'.^$*+?{}[]|()\\':
            out.append('\\' + ch)
        else:
            out.append(ch)
    return ''.join(out)


def ioc_to_reference_list_line(ioc_type: str, value: str) -> str:
    v = (value or '').strip()
    t = _normalize_ioc_type(ioc_type)
    if not v:
        return ''
    if t == 'URL':
        return f'^{escape_reference_list_regex(v)}$'
    if t in ('Domain', 'Email', 'Hash'):
        return v.lower()
    return v


def _is_reference_list_comment_line(line: str) -> bool:
    return (line or '').lstrip().startswith('//')


def reference_list_lines_for_removal(ioc_type: str, value: str) -> set[str]:
    """All line forms that should be removed for this IOC (current + legacy literal URL)."""
    primary = ioc_to_reference_list_line(ioc_type, value)
    candidates = {primary} if primary else set()
    t = _normalize_ioc_type(ioc_type)
    v = (value or '').strip()
    if t == 'URL' and v:
        candidates.add(v)
        candidates.add(v.lower())
    elif t in ('Domain', 'Email', 'Hash') and v:
        candidates.add(v)
        candidates.add(v.lower())
    elif t == 'IP' and v:
        candidates.add(v)
    return {c for c in candidates if c}


def line_matches_ioc_for_removal(line: str, ioc_type: str, value: str) -> bool:
    if _is_reference_list_comment_line(line):
        return False
    return (line or '').strip() in reference_list_lines_for_removal(ioc_type, value)


def reference_lists_api_base(g: dict[str, str]) -> str:
    """Same auth endpoint as Data Table: Apigee gateway base, or regional Backstory host (direct)."""
    from utils.google_secops import CONNECTION_MODE_APIGEE, google_secops_connection_mode

    if google_secops_connection_mode(g) == CONNECTION_MODE_APIGEE:
        return (g.get('google_secops_gateway_base_url') or '').strip().rstrip('/')
    loc = (g.get('google_secops_location') or '').strip()
    if loc:
        return f'https://{loc}-backstory.googleapis.com'
    return 'https://backstory.googleapis.com'


def reference_lists_api_base_description(g: dict[str, str]) -> str:
    from utils.google_secops import CONNECTION_MODE_APIGEE, google_secops_connection_mode

    if google_secops_connection_mode(g) == CONNECTION_MODE_APIGEE:
        gw = (g.get('google_secops_gateway_base_url') or '').strip().rstrip('/')
        return f'API Gateway base + /v2/lists ({gw or "not set"})'
    loc = (g.get('google_secops_location') or '').strip()
    if loc:
        return f'https://{loc}-backstory.googleapis.com/v2/lists'
    return 'https://backstory.googleapis.com/v2/lists (set Location for regional host)'


backstory_api_base = reference_lists_api_base


def _lists_url(base: str, list_name: Optional[str] = None) -> str:
    root = f'{base.rstrip("/")}/{REFERENCE_LISTS_API_VERSION}/lists'
    if list_name:
        return f'{root}/{list_name}'
    return root


def _get_reference_list(
    session,
    base: str,
    headers: dict[str, str],
    list_name: str,
) -> tuple[bool, dict[str, Any], str]:
    from utils.outbound_http_errors import format_http_response_error, format_requests_exception

    url = _lists_url(base, list_name)
    try:
        r = session.get(url, headers=headers, params={'view': 'FULL'}, timeout=90)
    except Exception as e:
        return False, {}, format_requests_exception('referenceList.get', e)
    if r.status_code != 200:
        return False, {}, format_http_response_error('referenceList.get', r.status_code, r.text)
    try:
        data = r.json()
    except json.JSONDecodeError:
        return False, {}, 'referenceList.get invalid JSON'
    if not isinstance(data, dict):
        return False, {}, 'referenceList.get unexpected response'
    return True, data, ''


def _patch_reference_list_lines(
    session,
    base: str,
    headers: dict[str, str],
    list_name: str,
    lines: list[str],
    content_type: str,
    description: str = '',
) -> tuple[bool, str]:
    from utils.outbound_http_errors import format_http_response_error, format_requests_exception

    url = _lists_url(base)
    body: dict[str, Any] = {
        'list': {
            'name': list_name,
            'lines': lines,
            'content_type': content_type,
        },
    }
    if description:
        body['list']['description'] = description
    params = {'update_mask': 'list.lines'}
    try:
        r = session.patch(url, headers=headers, params=params, json=body, timeout=90)
    except Exception as e:
        return False, format_requests_exception('referenceList.patch', e)
    if r.status_code in (200, 201):
        return True, 'ok'
    return False, format_http_response_error('referenceList.patch', r.status_code, r.text)


def _mutate_reference_list_lines(
    session,
    base: str,
    headers: dict[str, str],
    list_name: str,
    content_type: str,
    *,
    add_lines: set[str],
    remove_specs: list[tuple[str, str]],
) -> tuple[bool, str]:
    ok, data, err = _get_reference_list(session, base, headers, list_name)
    if not ok:
        return False, err

    existing_ct = (data.get('content_type') or CONTENT_TYPE_DEFAULT).strip()
    ct = existing_ct or content_type
    description = (data.get('description') or '').strip()
    lines_in: list[str] = list(data.get('lines') or [])
    kept: list[str] = []
    for line in lines_in:
        if _is_reference_list_comment_line(line):
            kept.append(line)
            continue
        drop = False
        for ioc_type, value in remove_specs:
            if line_matches_ioc_for_removal(line, ioc_type, value):
                drop = True
                break
        if not drop:
            kept.append(line)

    present = {ln.strip() for ln in kept if not _is_reference_list_comment_line(ln)}
    for add in sorted(add_lines):
        if add and add not in present:
            kept.append(add)
            present.add(add)

    if kept == lines_in:
        return True, 'unchanged'

    ok_patch, msg = _patch_reference_list_lines(
        session, base, headers, list_name, kept, ct, description=description,
    )
    return ok_patch, msg


def push_ioc_to_reference_lists(
    session,
    g: dict[str, str],
    headers: dict[str, str],
    ioc_type: str,
    value: str,
    *,
    action: str = 'create',
) -> tuple[bool, str]:
    list_names = reference_lists_for_ioc_type(g, ioc_type)
    if not list_names:
        return True, 'skipped_no_list_for_type'

    base = reference_lists_api_base(g)
    if not base:
        return True, 'skipped_incomplete_reference_lists_config'

    ct = reference_list_content_type(ioc_type, value)
    act = (action or 'create').strip().lower()
    parts: list[str] = []
    overall_ok = True
    for list_name in list_names:
        if act in ('remove', 'delete', 'revoke', 'expire_remove', 'delete_remove'):
            ok, msg = _mutate_reference_list_lines(
                session, base, headers, list_name, ct,
                add_lines=set(),
                remove_specs=[(ioc_type, value)],
            )
        else:
            line = ioc_to_reference_list_line(ioc_type, value)
            if not line:
                ok, msg = False, 'empty_reference_line'
            else:
                ok, msg = _mutate_reference_list_lines(
                    session, base, headers, list_name, ct,
                    add_lines={line},
                    remove_specs=[],
                )
        parts.append(f'{list_name}:{msg}')
        overall_ok = overall_ok and ok
    return overall_ok, '; '.join(parts)


# Backward-compatible alias
push_ioc_to_reference_list = push_ioc_to_reference_lists


def push_contexts_to_reference_lists(
    contexts: list[dict[str, Any]],
    g: dict[str, str],
    session,
    headers: dict[str, str],
) -> tuple[bool, str, int, int]:
    """
    Batch add/remove IOC lines grouped by reference list name.
    Returns (overall_ok, message, succeeded, failed).
    """
    if not google_secops_reference_lists_enabled(g):
        return True, 'reference_lists_not_configured', 0, 0

    base = reference_lists_api_base(g)
    if not base:
        return True, 'skipped_incomplete_reference_lists_config', 0, 0

    grouped: dict[str, dict[str, Any]] = {}
    skipped = 0
    for ctx in contexts or []:
        if not isinstance(ctx, dict):
            continue
        ioc_type = (str(ctx.get('type') or '')).strip()
        value = (str(ctx.get('value') or '')).strip()
        if not ioc_type or not value:
            continue
        list_names = reference_lists_for_ioc_type(g, ioc_type)
        if not list_names:
            skipped += 1
            continue
        action = (str(ctx.get('action') or 'create')).strip().lower()
        for list_name in list_names:
            bucket = grouped.setdefault(list_name, {
                'content_type': reference_list_content_type(ioc_type, value),
                'adds': set(),
                'removes': [],
            })
            if action in ('remove', 'delete', 'revoke', 'expire_remove', 'delete_remove'):
                bucket['removes'].append((ioc_type, value))
            else:
                line = ioc_to_reference_list_line(ioc_type, value)
                if line:
                    bucket['adds'].add(line)

    if not grouped:
        return True, f'reference_lists_skipped={skipped}', 0, 0

    succeeded = 0
    failed = 0
    errors: list[str] = []
    for list_name, bucket in grouped.items():
        ok, msg = _mutate_reference_list_lines(
            session, base, headers, list_name,
            bucket['content_type'],
            add_lines=bucket['adds'],
            remove_specs=bucket['removes'],
        )
        count = len(bucket['adds']) + len(bucket['removes'])
        if ok:
            succeeded += count
        else:
            failed += count
            errors.append(f'{list_name}: {msg}')
        if REFERENCE_LIST_PATCH_DELAY_SEC > 0:
            time.sleep(REFERENCE_LIST_PATCH_DELAY_SEC)

    overall = failed == 0
    summary = f'ref_lists ok={succeeded} fail={failed}'
    if errors:
        summary += ' ' + '; '.join(errors)[:200]
    return overall, summary, succeeded, failed


def test_reference_list_exists(
    session,
    g: dict[str, str],
    headers: dict[str, str],
    list_name: str,
) -> tuple[bool, str]:
    base = reference_lists_api_base(g)
    if not base:
        return False, 'reference lists endpoint not configured'
    ok, _data, err = _get_reference_list(session, base, headers, list_name)
    return ok, err


def reference_lists_config_checklist(g: dict[str, str]) -> list[dict[str, str]]:
    steps: list[dict[str, str]] = []
    mappings = parse_reference_lists_mappings(g)
    if not mappings:
        steps.append({
            'step': 'reference_lists',
            'status': 'skipped',
            'message': 'No reference list mappings configured (optional)',
        })
        return steps

    base = reference_lists_api_base(g)
    steps.append({
        'step': 'reference_lists_endpoint',
        'status': 'ok' if base else 'fail',
        'message': reference_lists_api_base_description(g) if base else 'Set Location (direct) or API Gateway base (Apigee)',
    })
    labels = [f'{m["ioc_type"]}→{m["list_name"]}' for m in mappings]
    steps.append({
        'step': 'reference_lists_mapping',
        'status': 'ok',
        'message': ', '.join(labels),
    })
    return steps
