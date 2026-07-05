"""
Shared IOC import policy: auto | pending | block.

- Analyst submissions (Settings → Workflow): default auto.
- Inbound pulls (MISP, TAXII, AdversaryGraph): default pending.
"""
from __future__ import annotations

IOC_IMPORT_MODES = frozenset({'auto', 'pending', 'block'})

DEFAULT_ANALYST_IOC_MODE = 'auto'
DEFAULT_INTEGRATION_IOC_MODE = 'pending'

_IMPORT_MODE_ALIASES = {
    'publish': 'auto',
    'automatic': 'auto',
    'immediate': 'auto',
    'approve': 'pending',
    'approval': 'pending',
    'review': 'pending',
    'deny': 'block',
    'disabled': 'block',
    'off': 'block',
    'none': 'block',
    'never': 'block',
}


def normalize_ioc_import_mode(raw, default: str = DEFAULT_INTEGRATION_IOC_MODE) -> str:
    """Normalize import policy: auto | pending | block."""
    val = str(raw or '').strip().lower() or default
    val = _IMPORT_MODE_ALIASES.get(val, val)
    if val not in IOC_IMPORT_MODES:
        return default if default in IOC_IMPORT_MODES else DEFAULT_INTEGRATION_IOC_MODE
    return val
