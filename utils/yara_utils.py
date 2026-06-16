"""
YARA file path safety (path traversal prevention) and in-memory syntax validation.
"""
from __future__ import annotations

import hashlib
import os
import re

# Max size for validate-syntax API (bytes)
YARA_VALIDATE_MAX_SOURCE_BYTES = 512 * 1024


def yara_content_sha256(content: str) -> str:
    """Stable fingerprint of rule text as stored (UTF-8). Used for duplicate detection."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def sanitize_yara_filename(raw: str) -> tuple[str | None, bool]:
    """
    Normalize a YARA rule basename for storage, UI, and automation push.
    Spaces and unsupported characters become underscores; repeated underscores collapse.
    Returns (safe_basename, was_changed). safe_basename is None when input is invalid.
    """
    raw_base = os.path.basename((raw or '').strip())
    if not raw_base or not raw_base.lower().endswith('.yar'):
        return None, False
    safe = re.sub(r'[^a-zA-Z0-9._-]', '_', raw_base)
    safe = re.sub(r'_+', '_', safe).strip('._')
    if not safe or not safe.lower().endswith('.yar'):
        safe = 'rule.yar'
    return safe, safe != raw_base


def yara_safe_path(filename: str, yara_dir: str) -> tuple[str | None, str | None]:
    """
    Return (safe_basename, full_path) if path is under yara_dir; else (None, None).
    Prevents path traversal. Resolves spaces/invalid chars to the stored safe basename.
    """
    if '..' in filename:
        return None, None
    raw_base = os.path.basename(filename)
    if raw_base != filename:
        return None, None
    safe, _ = sanitize_yara_filename(raw_base)
    if not safe:
        return None, None
    filepath = os.path.join(yara_dir, safe)
    try:
        real_file = os.path.realpath(filepath)
        real_yara = os.path.realpath(yara_dir)
        if not real_file.startswith(real_yara + os.sep) and real_file != real_yara:
            return None, None
    except (OSError, ValueError):
        return None, None
    return safe, filepath


def validate_yara_syntax(source: str | None) -> tuple[bool, str | None]:
    """
    Compile YARA source in memory using libyara (yara-python).
    Returns (True, None) if the rule compiles, else (False, error_message).
    """
    if source is None:
        return False, "empty"
    s = source.strip()
    if not s:
        return False, "empty"
    if len(source) > YARA_VALIDATE_MAX_SOURCE_BYTES:
        return False, "too_large"
    try:
        import yara  # type: ignore[import-untyped]
    except ImportError as e:
        # Include str(e) so API/UI can show e.g. "No module named 'yara'" vs shadowing issues
        return False, f"library_unavailable:{e!s}"
    except OSError as e:
        # Missing .so/.dll or wrong arch-show detail to admins
        msg = str(e).strip() or type(e).__name__
        return False, f"library_load_failed:{msg}"
    try:
        yara.compile(source=s)
        return True, None
    except Exception as e:
        msg = str(e).strip() or type(e).__name__
        return False, msg
