"""
Named LDAP/AD environments (multi-domain) with per-environment DC fallback.

Stored in system_settings as JSON under ``ldap_environments``:
[
  {
    "name": "DOM1",
    "is_default": true,
    "base_dn": "DC=corp-a,DC=local",
    "user_filter": "(sAMAccountName=%(user)s)",
    "dcs": [
      {"url": "ldap://dc1...", "bind_dn": "...", "bind_password": "..."}
    ]
  }
]
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable

_ENV_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
_DEFAULT_FILTER = '(sAMAccountName=%(user)s)'


def _norm_name(name: str) -> str:
    return (name or '').strip()


def _norm_name_key(name: str) -> str:
    return _norm_name(name).lower()


def parse_ldap_environments_raw(raw: str | None) -> list[dict]:
    """Parse ldap_environments JSON; return [] on empty/invalid."""
    text = (raw or '').strip()
    if not text or text == '[]':
        return []
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return []
    return data if isinstance(data, list) else []


def migrate_legacy_ldap_config(get_setting: Callable[[str, str], str]) -> list[dict]:
    """
    Build environments list from ldap_environments, ldap_servers, or legacy single-server keys.
    Does not write to DB.
    """
    raw = (get_setting('ldap_environments', '') or '').strip()
    envs = parse_ldap_environments_raw(raw)
    if envs:
        return normalize_ldap_environments_for_storage(envs, existing=None)

    import json as _json
    servers: list[dict] = []
    raw_servers = (get_setting('ldap_servers', '') or '').strip()
    if raw_servers and raw_servers != '[]':
        try:
            servers = _json.loads(raw_servers)
        except Exception:
            servers = []
    if not servers and (get_setting('ldap_url', '') or '').strip():
        servers = [{
            'url': get_setting('ldap_url', ''),
            'base_dn': get_setting('ldap_base_dn', ''),
            'bind_dn': get_setting('ldap_bind_dn', ''),
            'bind_password': get_setting('ldap_bind_password', ''),
        }]
    if not servers:
        return []

    global_filter = (get_setting('ldap_user_filter', _DEFAULT_FILTER) or _DEFAULT_FILTER).strip()
    dcs = []
    base_dn = ''
    for s in servers:
        if not isinstance(s, dict):
            continue
        url = (s.get('url') or '').strip()
        if not url:
            continue
        if not base_dn:
            base_dn = (s.get('base_dn') or '').strip()
        dcs.append({
            'url': url,
            'bind_dn': (s.get('bind_dn') or '').strip(),
            'bind_password': s.get('bind_password') or '',
        })
    if not dcs:
        return []
    if not base_dn and servers and isinstance(servers[0], dict):
        base_dn = (servers[0].get('base_dn') or '').strip()
    return [{
        'name': 'Default',
        'is_default': True,
        'base_dn': base_dn,
        'user_filter': global_filter or _DEFAULT_FILTER,
        'dcs': dcs,
    }]


def load_ldap_environments(get_setting: Callable[[str, str], str]) -> list[dict]:
    """Load and normalize environments from settings (with legacy migration)."""
    return migrate_legacy_ldap_config(get_setting)


def sort_environments_default_first(envs: list[dict]) -> list[dict]:
    """Default environment first; preserve relative order otherwise."""
    if not envs:
        return []
    default = [e for e in envs if e.get('is_default')]
    rest = [e for e in envs if not e.get('is_default')]
    if default:
        return default[:1] + rest
    return list(envs)


def public_login_environments(envs: list[dict]) -> list[dict]:
    """Names for login dropdown (no secrets)."""
    ordered = sort_environments_default_first(envs)
    return [{'name': e['name'], 'is_default': bool(e.get('is_default'))} for e in ordered if e.get('name')]


def find_environment_by_name(envs: list[dict], name: str | None) -> dict | None:
    key = _norm_name_key(name or '')
    if not key:
        return None
    for e in envs:
        if _norm_name_key(e.get('name')) == key:
            return e
    return None


def resolve_login_environment(envs: list[dict], requested_name: str | None) -> dict | None:
    """Pick environment for login: explicit name, else default/first."""
    if not envs:
        return None
    ordered = sort_environments_default_first(envs)
    if requested_name and _norm_name(requested_name):
        return find_environment_by_name(ordered, requested_name)
    for e in ordered:
        if e.get('is_default'):
            return e
    return ordered[0]


def _merge_dc_passwords(new_dcs: list[dict], old_dcs: list[dict]) -> list[dict]:
    """Keep existing bind_password when save sends empty string."""
    old_by_url = {}
    for d in old_dcs:
        if isinstance(d, dict):
            u = (d.get('url') or '').strip()
            if u:
                old_by_url[u] = d.get('bind_password') or ''
    out = []
    for i, d in enumerate(new_dcs):
        if not isinstance(d, dict):
            continue
        url = (d.get('url') or '').strip()
        pw = d.get('bind_password')
        if pw is None or (isinstance(pw, str) and not pw.strip()):
            if url and url in old_by_url:
                pw = old_by_url[url]
            elif i < len(old_dcs) and isinstance(old_dcs[i], dict):
                pw = old_dcs[i].get('bind_password') or ''
            else:
                pw = ''
        out.append({
            'url': url,
            'bind_dn': (d.get('bind_dn') or '').strip(),
            'bind_password': pw or '',
        })
    return out


def normalize_ldap_environments_for_storage(
    envs: list[Any],
    existing: list[dict] | None = None,
) -> list[dict]:
    """
    Validate and normalize admin-submitted environments.
    Raises ValueError on validation errors.
    """
    if not isinstance(envs, list):
        raise ValueError('ldap_environments must be a JSON array')

    existing = existing or []
    existing_by_name = {_norm_name_key(e.get('name')): e for e in existing if e.get('name')}

    out: list[dict] = []
    seen_names: set[str] = set()
    default_idx: int | None = None

    for i, raw in enumerate(envs):
        if not isinstance(raw, dict):
            raise ValueError(f'Environment #{i + 1} must be an object')
        name = _norm_name(raw.get('name'))
        if not name:
            raise ValueError(f'Environment #{i + 1}: name is required')
        if not _ENV_NAME_RE.match(name):
            raise ValueError(
                f'Environment "{name}": name must start with a letter or digit and contain only letters, digits, ., _, -'
            )
        key = _norm_name_key(name)
        if key in seen_names:
            raise ValueError(f'Duplicate environment name: {name}')
        seen_names.add(key)

        base_dn = (raw.get('base_dn') or '').strip()
        if not base_dn:
            raise ValueError(f'Environment "{name}": Base DN is required')

        user_filter = (raw.get('user_filter') or _DEFAULT_FILTER).strip() or _DEFAULT_FILTER
        is_default = bool(raw.get('is_default'))

        raw_dcs = raw.get('dcs')
        if not isinstance(raw_dcs, list) or not raw_dcs:
            raise ValueError(f'Environment "{name}": at least one DC is required')

        old_env = existing_by_name.get(key, {})
        old_dcs = old_env.get('dcs') if isinstance(old_env.get('dcs'), list) else []
        dcs = _merge_dc_passwords(raw_dcs, old_dcs)

        valid_dcs = [d for d in dcs if (d.get('url') or '').strip()]
        if not valid_dcs:
            raise ValueError(f'Environment "{name}": at least one DC URL is required')

        for j, dc in enumerate(valid_dcs):
            url = (dc.get('url') or '').strip()
            if not url.startswith(('ldap://', 'ldaps://')):
                raise ValueError(f'Environment "{name}" DC #{j + 1}: URL must start with ldap:// or ldaps://')

        entry = {
            'name': name,
            'is_default': is_default,
            'base_dn': base_dn,
            'user_filter': user_filter,
            'dcs': valid_dcs,
        }
        out.append(entry)
        if is_default:
            default_idx = len(out) - 1

    if not out:
        return []

    if default_idx is None:
        out[0]['is_default'] = True
        default_idx = 0
    else:
        for i, e in enumerate(out):
            e['is_default'] = (i == default_idx)

    return sort_environments_default_first(out)


def environments_to_json(envs: list[dict]) -> str:
    return json.dumps(envs, ensure_ascii=False)


def ldap_auth_allowed(auth_mode: str, ldap_enabled: bool) -> bool:
    if not ldap_enabled:
        return False
    return auth_mode in ('ldap', 'ldap_with_local_fallback', 'local_with_ldap_fallback')


def should_show_login_environment_picker(auth_mode: str, ldap_enabled: bool, envs: list[dict]) -> bool:
    return ldap_auth_allowed(auth_mode, ldap_enabled) and len(envs) >= 1
