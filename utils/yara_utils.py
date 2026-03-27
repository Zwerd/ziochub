"""
YARA file path safety (path traversal prevention) and in-memory syntax validation.
"""
from __future__ import annotations

import os

# Max size for validate-syntax API (bytes)
YARA_VALIDATE_MAX_SOURCE_BYTES = 512 * 1024


def yara_safe_path(filename: str, yara_dir: str) -> tuple[str | None, str | None]:
    """
    Return (safe_basename, full_path) if path is under yara_dir; else (None, None).
    Prevents path traversal.
    """
    safe = os.path.basename(filename)
    if safe != filename or '..' in filename or not safe.lower().endswith('.yar'):
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
        # Missing .so/.dll or wrong arch — show detail to admins
        msg = str(e).strip() or type(e).__name__
        return False, f"library_load_failed:{msg}"
    try:
        yara.compile(source=s)
        return True, None
    except Exception as e:
        msg = str(e).strip() or type(e).__name__
        return False, msg
