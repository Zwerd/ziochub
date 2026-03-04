"""
YARA file path safety (path traversal prevention).
"""
from __future__ import annotations

import os


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
