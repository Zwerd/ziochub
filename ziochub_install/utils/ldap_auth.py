"""
LDAP/AD authentication helpers. Phase 3.
Supports real LDAP bind and MOCK_SYNC for dev when LDAP unavailable.
"""
from __future__ import annotations

import os
import logging

_log = logging.getLogger('ziochub.ldap')

LDAP_AVAILABLE = False
try:
    from ldap3 import Server, Connection, ALL, SUBTREE
    from ldap3.core.exceptions import LDAPException
    from ldap3.utils.conv import escape_filter_chars
    LDAP_AVAILABLE = True
except ImportError:
    escape_filter_chars = None  # type: ignore


def _is_dev_mode() -> bool:
    """True when FLASK_DEBUG or DEV_MODE=1. Phase 6.2."""
    return (
        os.environ.get('FLASK_DEBUG', '').lower() in ('true', '1', 'yes') or
        os.environ.get('DEV_MODE', '').strip().lower() in ('1', 'true', 'yes')
    )


def is_dev_mode() -> bool:
    """Public alias for _is_dev_mode."""
    return _is_dev_mode()


def is_production_env() -> bool:
    """True when environment is explicitly set to production (AppSec: warn if DEV_MODE is on)."""
    env = (os.environ.get('FLASK_ENV', '') or os.environ.get('ZIOCHUB_ENV', '')).strip().lower()
    return env == 'production'


def try_ldap_bind_servers(
    servers: list[dict],
    user_filter: str,
    username: str,
    password: str,
) -> tuple[bool, str | None]:
    """
    Try LDAP bind against a list of servers in order.
    Stops at the first successful bind. Returns (success, display_name or None).
    Each server dict: {"url": str, "base_dn": str, "bind_dn": str, "bind_password": str}.
    """
    if not servers:
        return False, None
    for s in servers:
        url = (s.get("url") or "").strip()
        base_dn = (s.get("base_dn") or "").strip()
        if not url or not base_dn:
            continue
        ok, display_name = try_ldap_bind(
            url,
            base_dn,
            (s.get("bind_dn") or "").strip(),
            s.get("bind_password") or "",
            user_filter,
            username,
            password,
        )
        if ok:
            return True, display_name
    return False, None


def try_ldap_bind(
    ldap_url: str,
    base_dn: str,
    bind_dn: str,
    bind_password: str,
    user_filter: str,
    username: str,
    password: str,
) -> tuple[bool, str | None]:
    """
    Try LDAP bind for user. Returns (success, display_name or None).
    displayName/cn from AD is returned for syncing to user_profiles.
    """
    if not LDAP_AVAILABLE:
        _log.warning('ldap3 not installed; LDAP auth skipped')
        return False, None
    if not ldap_url or not base_dn or not username or not password:
        return False, None

    username_clean = username.strip().lower()
    display_name = None

    try:
        server = Server(ldap_url, get_info=ALL)
        # Bind with service account first
        conn = Connection(
            server,
            user=bind_dn if bind_dn else None,
            password=bind_password if bind_password else None,
            auto_bind=True,
            raise_exceptions=False,
        )
        if not conn.bound and (bind_dn or bind_password):
            _log.warning('LDAP service account bind failed')
            conn.unbind()
            return False, None

        # User filter: %(user)s replaced with username. Default: (sAMAccountName=%(user)s)
        safe_username = escape_filter_chars(username_clean) if escape_filter_chars else username_clean.replace('\\', '\\\\').replace('*', '\\2a').replace('(', '\\28').replace(')', '\\29')
        filter_str = (user_filter or '(sAMAccountName=%(user)s)').replace('%(user)s', safe_username)
        conn.search(
            search_base=base_dn,
            search_filter=filter_str,
            search_scope=SUBTREE,
            attributes=['distinguishedName', 'displayName', 'cn', 'userPrincipalName'],
        )
        if not conn.entries:
            conn.unbind()
            return False, None
        entry = conn.entries[0]
        user_dn = str(entry.distinguishedName) if entry.distinguishedName else None
        display_name = None
        if entry.displayName:
            v = entry.displayName
            display_name = v.value if hasattr(v, 'value') else (v[0] if isinstance(v, (list, tuple)) else str(v))
        if not display_name and entry.cn:
            v = entry.cn
            display_name = v.value if hasattr(v, 'value') else (v[0] if isinstance(v, (list, tuple)) else str(v))
        if not user_dn:
            conn.unbind()
            return False, None

        # Re-bind as user to verify password
        conn.unbind()
        user_conn = Connection(server, user=user_dn, password=password, auto_bind=True, raise_exceptions=False)
        if user_conn.bound:
            user_conn.unbind()
            return True, display_name or username_clean
        user_conn.unbind()
        return False, None
    except LDAPException as e:
        _log.warning('LDAP error: %s', e)
        return False, None
    except Exception as e:
        _log.exception('LDAP unexpected error: %s', e)
        return False, None


def try_ldap_mock_dev(username: str, password: str) -> tuple[bool, str | None]:
    """
    MOCK_SYNC for dev: when LDAP unavailable, simulate success for test user.
    Only active when DEV_MODE=1 or FLASK_DEBUG=true.
    Returns (success, display_name).
    """
    if not _is_dev_mode():
        return False, None
    if (username or '').strip().lower() == 'ldaptest' and password == 'ldaptest':
        return True, 'LDAP Test User'
    return False, None


def test_ldap_connection_steps(
    ldap_url: str,
    base_dn: str,
    bind_dn: str,
    bind_password: str,
) -> list[dict]:
    """
    Run LDAP connection test step-by-step for Admin UI.
    Returns list of { "step": str, "status": "ok"|"fail"|"skip", "message": str }.
    """
    steps: list[dict] = []

    def add(step: str, status: str, message: str = ""):
        steps.append({"step": step, "status": status, "message": message or ""})

    # Step 1: ldap3 available
    if not LDAP_AVAILABLE:
        add("Check ldap3", "fail", "ldap3 not installed. Install with: pip install ldap3")
        return steps
    add("Check ldap3", "ok", "ldap3 is installed")

    # Step 2: URL configured
    url_clean = (ldap_url or "").strip()
    if not url_clean:
        add("LDAP URL", "fail", "LDAP URL is empty. Enter e.g. ldap://dc.example.com or ldaps://dc.example.com")
        return steps
    if not url_clean.startswith(("ldap://", "ldaps://")):
        add("LDAP URL", "fail", "URL must start with ldap:// or ldaps://")
        return steps
    # Port 636 is for LDAPS; using ldap:// on 636 causes "Connection reset by peer"
    if url_clean.startswith("ldap://") and ":636" in url_clean:
        add("LDAP URL", "fail", "Port 636 requires ldaps:// (SSL), not ldap://. Use ldaps://your-server:636")
        return steps
    add("LDAP URL", "ok", url_clean)

    # Step 3: Create server (DNS / connect)
    try:
        server = Server(url_clean, get_info=ALL)
        add("Create server object", "ok", "Server object created")
    except Exception as e:
        add("Create server object", "fail", str(e)[:200])
        return steps

    # Step 4: Bind with service account
    try:
        conn = Connection(
            server,
            user=bind_dn.strip() if bind_dn else None,
            password=bind_password if bind_password else None,
            auto_bind=True,
            raise_exceptions=False,
        )
        if conn.bound:
            add("Bind (service account)", "ok", "Connected and bound successfully")
            try:
                conn.unbind()
                add("Unbind", "ok", "Disconnected")
            except Exception as ub:
                add("Unbind", "fail", str(ub)[:100])
        else:
            err = conn.result.get("message", "Unknown") if getattr(conn, "result", None) else "Bind failed"
            add("Bind (service account)", "fail", str(err)[:200])
    except LDAPException as e:
        add("Bind (service account)", "fail", str(e)[:200])
    except Exception as e:
        add("Bind (service account)", "fail", str(e)[:200])

    return steps


def check_ldap_reachable(
    ldap_url: str,
    base_dn: str,
    bind_dn: str,
    bind_password: str,
    use_mock_in_dev: bool = True,
) -> tuple[bool, str]:
    """
    Health check: is LDAP server reachable?
    Returns (reachable, message).
    When use_mock_in_dev and dev mode, returns (True, 'mock') if URL empty.
    """
    if not LDAP_AVAILABLE:
        return False, 'ldap3 not installed'
    if not ldap_url or not ldap_url.strip():
        if use_mock_in_dev and _is_dev_mode():
            return True, 'mock (no LDAP URL; dev mode)'
        return False, 'LDAP URL not configured'
    try:
        server = Server(ldap_url.strip(), get_info=ALL)
        conn = Connection(
            server,
            user=bind_dn if bind_dn else None,
            password=bind_password if bind_password else None,
            auto_bind=True,
            raise_exceptions=False,
        )
        ok = conn.bound
        conn.unbind()
        return ok, 'connected' if ok else 'bind failed'
    except LDAPException as e:
        _log.warning('LDAP health check failed: %s', e)
        return False, str(e)[:100]
    except Exception as e:
        _log.warning('LDAP health check error: %s', e)
        return False, str(e)[:100]
