"""
Jinja2 presentation helpers: UTC datetimes from the DB → configurable GUI timezone.

Storage and API serialization stay UTC (see ``models.iso_utc``). The active zone comes from
``system_settings.gui_display_timezone`` (Admin → Settings → Search display).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_GUI_DISPLAY_TIMEZONE = 'Asia/Jerusalem'
DEFAULT_DISPLAY_FORMAT = '%Y-%m-%d %H:%M:%S'

# IANA zones offered in Admin → Settings (whitelist on save).
GUI_DISPLAY_TIMEZONE_CHOICES: tuple[tuple[str, str], ...] = (
    ('UTC', 'UTC'),
    ('Asia/Jerusalem', 'Asia/Jerusalem (Israel)'),
    ('Europe/London', 'Europe/London'),
    ('Europe/Berlin', 'Europe/Berlin'),
    ('Europe/Paris', 'Europe/Paris'),
    ('America/New_York', 'America/New_York'),
    ('America/Chicago', 'America/Chicago'),
    ('America/Denver', 'America/Denver'),
    ('America/Los_Angeles', 'America/Los_Angeles'),
    ('Asia/Dubai', 'Asia/Dubai'),
    ('Asia/Singapore', 'Asia/Singapore'),
    ('Asia/Tokyo', 'Asia/Tokyo'),
    ('Australia/Sydney', 'Australia/Sydney'),
)

_ALLOWED_GUI_DISPLAY_TIMEZONES = frozenset(tz for tz, _ in GUI_DISPLAY_TIMEZONE_CHOICES)


def normalize_gui_display_timezone(val: Any) -> str:
    """Validate admin setting; fall back to default if unknown."""
    raw = str(val or '').strip() or DEFAULT_GUI_DISPLAY_TIMEZONE
    if raw in _ALLOWED_GUI_DISPLAY_TIMEZONES:
        return raw
    try:
        ZoneInfo(raw)
        return raw
    except (ZoneInfoNotFoundError, Exception):
        return DEFAULT_GUI_DISPLAY_TIMEZONE


def get_gui_display_timezone() -> str:
    """Read configured GUI timezone from ``system_settings`` (safe outside request)."""
    try:
        import app as _app
        raw = _app._get_setting('gui_display_timezone', DEFAULT_GUI_DISPLAY_TIMEZONE)
        return normalize_gui_display_timezone(raw)
    except Exception:
        return DEFAULT_GUI_DISPLAY_TIMEZONE


def _zone_for_display() -> ZoneInfo:
    """Request-scoped cache of ZoneInfo for the configured GUI timezone."""
    try:
        from flask import g, has_request_context
        if has_request_context():
            cached = getattr(g, '_ziochub_display_zoneinfo', None)
            if cached is not None:
                return cached
            zi = ZoneInfo(get_gui_display_timezone())
            g._ziochub_display_zoneinfo = zi
            return zi
    except Exception:
        pass
    return ZoneInfo(get_gui_display_timezone())


def _parse_as_utc(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            for fmt, take in (
                ('%Y-%m-%dT%H:%M:%S', 19),
                ('%Y-%m-%d %H:%M:%S', 19),
                ('%Y-%m-%d', 10),
            ):
                try:
                    dt = datetime.strptime(s[:take], fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
    else:
        return None

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_local_time(value: Any, fmt: str = DEFAULT_DISPLAY_FORMAT) -> str:
    """
    Jinja filter: convert a UTC datetime (naive or aware) to the configured GUI timezone.

    Usage in templates::

        {{ ioc.created_at | to_local_time }}
        {{ ioc.created_at | to_local_time('%d/%m/%Y %H:%M') }}
    """
    dt = _parse_as_utc(value)
    if dt is None:
        return ''
    return dt.astimezone(_zone_for_display()).strftime(fmt or DEFAULT_DISPLAY_FORMAT)


def register_jinja_datetime_filters(app) -> None:
    """Register ``to_local_time`` on the Flask app Jinja environment."""
    app.jinja_env.filters['to_local_time'] = to_local_time
