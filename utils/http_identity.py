"""
Central User-Agent for outbound HTTP from ZIoCHub integrations.
"""
from __future__ import annotations

from constants import VERSION


def ziochub_user_agent() -> str:
    ver = (VERSION or 'unknown').strip()
    return f'ZIoCHub/{ver}'


ZIOCHUB_USER_AGENT = ziochub_user_agent()


def trellix_ex_user_agent() -> str:
    """Browser-compatible UA for Trellix EX session login (still identifies ZIoCHub)."""
    return f'Mozilla/5.0 (compatible; {ziochub_user_agent()}; Trellix-EX-YARA)'


def apply_user_agent_to_request(req) -> None:
    """Set User-Agent on urllib.request.Request."""
    req.add_header('User-Agent', ZIOCHUB_USER_AGENT)


def ensure_user_agent(headers: dict | None = None) -> dict[str, str]:
    """Return headers with ZIoCHub User-Agent (always wins over prior value)."""
    out = dict(headers or {})
    out['User-Agent'] = ZIOCHUB_USER_AGENT
    return out


def configure_requests_session(session) -> None:
    """Apply ZIoCHub User-Agent to an existing requests.Session."""
    session.headers['User-Agent'] = ZIOCHUB_USER_AGENT


def new_requests_session(**kwargs):
    """Create requests.Session with ZIoCHub User-Agent."""
    import requests

    session = requests.Session(**kwargs)
    configure_requests_session(session)
    return session


def install_ziochub_user_agent() -> None:
    """
    Patch requests library defaults so third-party clients (e.g. pymisp) also identify as ZIoCHub.
    Safe to call multiple times.
    """
    try:
        import requests
        import requests.sessions as rs
    except ImportError:
        return

    def _ua(*_args, **_kwargs) -> str:
        return ZIOCHUB_USER_AGENT

    requests.utils.default_user_agent = _ua
    try:
        rs.DEFAULT_HEADERS['User-Agent'] = ZIOCHUB_USER_AGENT
    except Exception:
        pass
