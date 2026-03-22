"""
CEF (Common Event Format) logger for ZIoCHub.
- Local file logging with 48-hour rotation (overwrites to prevent disk fill)
- Optional UDP syslog forwarding when configured in Admin Settings
- Format: CEF over syslog (RFC 5424 style prefix + CEF payload)
"""
from __future__ import annotations

import logging
import logging.handlers
import socket
from datetime import datetime, timezone


# CEF header fields (pipe-delimited)
CEF_VERSION = '0'
DEVICE_VENDOR = 'ZIoCHub'
DEVICE_PRODUCT = 'IOC-Platform'
DEVICE_VERSION = '2.0'


def _cef_escape(val: str) -> str:
    """Escape CEF special chars and strip control chars (newlines can break syslog format)."""
    if not val:
        return ''
    s = str(val)
    # Strip control chars and newlines that break CEF/syslog
    s = ''.join(c for c in s if c >= ' ' or c in '\t')
    return s.replace('\\', '\\\\').replace('|', '\\|').replace('=', '\\=')


def _cef_extension(**kwargs) -> str:
    """Build CEF extension string from key=value pairs."""
    parts = []
    for k, v in kwargs.items():
        if v is not None and v != '':
            parts.append(f'{k}={_cef_escape(str(v))}')
    return ' '.join(parts)


def format_cef(
    signature_id: str,
    name: str,
    severity: int = 5,
    **extensions
) -> str:
    """
    Build CEF message (without syslog prefix).
    Severity: 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very-High/Critical
    """
    ext_str = _cef_extension(**extensions)
    header = f'CEF:{CEF_VERSION}|{DEVICE_VENDOR}|{DEVICE_PRODUCT}|{DEVICE_VERSION}|{_cef_escape(signature_id)}|{_cef_escape(name)}|{severity}'
    if ext_str:
        return f'{header}|{ext_str}'
    return header


def _syslog_prefix() -> str:
    """RFC 5424 style timestamp + hostname for syslog."""
    now = datetime.now(timezone.utc)
    ts = now.strftime('%Y-%m-%dT%H:%M:%S.000Z')
    try:
        hostname = socket.gethostname() or 'ziochub'
    except Exception:
        hostname = 'ziochub'
    return f'{ts} {hostname}'


class CEFAuditHandler(logging.Handler):
    """Logging handler that writes CEF to file and optionally sends via UDP."""

    def __init__(self, log_path: str, udp_host: str = '', udp_port: int = 514):
        super().__init__()
        self.log_path = log_path
        self.udp_host = (udp_host or '').strip()
        self.udp_port = int(udp_port) if udp_port else 514
        self._socket = None
        self._file_handler = logging.handlers.TimedRotatingFileHandler(
            log_path,
            when='h',
            interval=48,
            backupCount=1,
            encoding='utf-8',
        )
        self._file_handler.setFormatter(
            logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        )

    def set_udp_target(self, host: str, port: int):
        """Update UDP target (call when settings change)."""
        self.udp_host = (host or '').strip()
        self.udp_port = int(port) if port else 514

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            self._file_handler.emit(logging.LogRecord(
                record.name, record.levelno, record.pathname, record.lineno,
                msg, (), None,
            ))
            if self.udp_host:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2.0)
                    full_msg = f'{_syslog_prefix()} {msg}'
                    sock.sendto(full_msg.encode('utf-8', errors='replace'), (self.udp_host, self.udp_port))
                    sock.close()
                except Exception:
                    pass
        except Exception:
            self.handleError(record)

    def close(self):
        self._file_handler.close()
        super().close()


# Module-level logger
_cef_logger: logging.Logger | None = None
_cef_handler: CEFAuditHandler | None = None


def get_cef_logger(log_path: str, udp_host: str = '', udp_port: int = 514) -> logging.Logger:
    """Get or create the CEF audit logger."""
    global _cef_logger, _cef_handler
    if _cef_logger is None:
        _cef_logger = logging.getLogger('ziochub.cef_audit')
        _cef_logger.setLevel(logging.INFO)
        _cef_logger.propagate = False
        _cef_handler = CEFAuditHandler(log_path, udp_host, udp_port)
        _cef_logger.addHandler(_cef_handler)
    else:
        _cef_handler.set_udp_target(udp_host, udp_port)
    return _cef_logger


def cef_log(
    action: str,
    detail: str = '',
    client_ip: str = '-',
    user_id: str | int | None = None,
    username: str | None = None,
    severity: int = 5,
    **extra_extensions
):
    """
    Write a CEF-formatted audit log entry.
    action: e.g. 'login', 'logout', 'ioc_submit', 'admin_settings_update'
    detail: free-form detail string
    Call init_cef_logger() before first use.
    """
    global _cef_logger
    if _cef_logger is None:
        return
    logger = _cef_logger
    ext = {
        'src': client_ip,
        'act': action,
        'msg': detail,
        **extra_extensions,
    }
    if user_id is not None:
        ext['duser'] = str(user_id)
    if username:
        ext['suser'] = username
    msg = format_cef(
        signature_id=action.replace(' ', '_')[:100],
        name=action,
        severity=severity,
        **ext
    )
    logger.info(msg)


def init_cef_logger(log_path: str, udp_host: str = '', udp_port: int = 514) -> logging.Logger:
    """Initialize CEF logger with path and optional UDP target. Call at app startup."""
    return get_cef_logger(log_path, udp_host, udp_port)


def refresh_cef_udp_target(udp_host: str, udp_port: int):
    """Update UDP target (e.g. after admin changes settings)."""
    global _cef_handler
    if _cef_handler:
        _cef_handler.set_udp_target(udp_host, udp_port)
