"""Decode uploaded TXT/CSV bytes from common encodings (UTF-8, Hebrew cp1255, UTF-16 BOM)."""


def decode_uploaded_text_bytes(raw: bytes) -> str:
    """
    Decode file body for IOC bulk TXT/CSV. Tries UTF-8 (strict), UTF-16 BOM, UTF-8 BOM,
    then Hebrew/legacy Windows encodings, then UTF-8 with replacement (never raises).
    """
    if not raw:
        return ''
    # UTF-16 LE / BE (common for Excel "CSV" or Notepad Save As Unicode)
    if len(raw) >= 2 and raw[:2] == b'\xff\xfe':
        return raw.decode('utf-16-le')
    if len(raw) >= 2 and raw[:2] == b'\xfe\xff':
        return raw.decode('utf-16-be')
    if raw.startswith(b'\xef\xbb\xbf'):
        return raw.decode('utf-8-sig')
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        pass
    for enc in ('cp1255', 'iso-8859-8'):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode('utf-8', errors='replace')
