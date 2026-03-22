"""
ZIoCHub constants.
"""
# Platform version (single source of truth for all templates, i18n, etc.)
VERSION = "2.0 Beta"

# Default limit for /api/all-iocs and similar list endpoints (max page size)
DEFAULT_IOC_LIMIT = 500
# Default page size for paginated list endpoints
DEFAULT_PAGE_SIZE = 100

# File mapping for IOC types (YARA log lives in Main for Live Feed visibility)
IOC_FILES = {
    'IP': 'ip.txt',
    'Domain': 'domain.txt',
    'Hash': 'hash.txt',
    'Email': 'email.txt',
    'URL': 'url.txt',
    'YARA': 'yara.txt',
}
