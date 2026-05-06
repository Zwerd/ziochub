"""
Offline-only domain sanity helpers (no network calls).

1) Filename-like values submitted as Domain (e.g. malware.exe, report.pdf).
2) TLD not present in bundled snapshot + optional local copy of IANA tlds-alpha-by-domain.txt

Administrators can replace utils/data/iana_tlds_alpha.txt with an air-gapped copy of:
https://data.iana.org/TLD/tlds-alpha-by-domain.txt (lowercase lines, no header comment).
"""
from __future__ import annotations

from pathlib import Path

# Must match suffix pairs used in sanity_checks._CCSLD_SUFFIXES for registry key extraction.
_CCSLD_SUFFIXES = frozenset({
    'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il', 'muni.il', 'idf.il',
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
    'co.kr', 'or.kr', 'ne.kr', 'go.kr', 'ac.kr',
    'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'ac.in', 'gov.in',
    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
    'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za',
    'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
    'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw',
    'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
    'co.id', 'or.id', 'go.id', 'ac.id', 'web.id',
    'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
    'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
    'co.th', 'or.th', 'go.th', 'ac.th', 'in.th',
    'com.ar', 'net.ar', 'org.ar', 'gov.ar', 'edu.ar',
    'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'edu.ua',
    'co.ke', 'or.ke', 'go.ke', 'ac.ke', 'ne.ke',
    'com.ng', 'org.ng', 'gov.ng', 'edu.ng', 'net.ng',
    'com.eg', 'org.eg', 'gov.eg', 'edu.eg', 'net.eg',
    'com.pk', 'net.pk', 'org.pk', 'gov.pk', 'edu.pk',
    'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
})

# Final segment(s) that look like archive / compound file names (hostname evil.payload.tar.gz).
_COMPOUND_FILE_SUFFIXES = frozenset({
    'tar.gz', 'tar.bz2', 'tar.xz', 'tar.lz', 'tar.zst',
})

# Common file extensions seen misclassified as "domain" last label (lowercase).
# Exclude labels that are also real public TLDs (e.g. com, zip) — those are handled by TLD snapshot only.
_FILE_EXTENSION_LABELS = frozenset({
    'exe', 'dll', 'scr', 'sys', 'drv', 'msi', 'msix', 'msp', 'msm',
    'pif', 'cpl', 'ocx', 'mui',
    'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'js', 'jse', 'wsf', 'wsh', 'hta',
    'pdf', 'doc', 'docx', 'docm', 'dot', 'dotx', 'rtf', 'odt',
    'xls', 'xlsx', 'xlsm', 'csv',
    'ppt', 'pptx', 'pptm',
    'txt', 'log', 'cfg', 'ini', 'xml', 'json', 'yaml', 'yml', 'toml',
    'rar', '7z', 'gz', 'bz2', 'xz', 'lz', 'z', 'cab', 'iso', 'img',
    'dmg', 'pkg', 'deb', 'rpm',
    'bin', 'dat', 'tmp', 'temp', 'bak', 'old',
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg', 'ico', 'tif', 'tiff',
    'mp4', 'avi', 'mkv', 'wmv', 'mov', 'webm', 'mp3', 'wav', 'flac',
    'apk', 'aab', 'ipa',
    'htm', 'html', 'mht', 'mhtml',
    'sql', 'mdb', 'accdb', 'sqlite', 'db',
    'pem', 'crt', 'cer', 'pfx', 'p12', 'key',
    'lnk', 'url', 'desktop',
    'wasm',
})

_IANA_DATA_FILE = Path(__file__).resolve().parent / 'data' / 'iana_tlds_alpha.txt'

# Minimal ngTLDs / multi-char labels so unknown-TLD works before admins drop full IANA file.
_BUILTIN_EXTRA_TLDS = frozenset({
    'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'name', 'pro',
    'aaa', 'aarp', 'abb', 'abc', 'academy', 'accountant', 'accountants', 'actor', 'adult', 'aero',
    'agency', 'ai', 'airforce', 'alex', 'alsace', 'amazon', 'android', 'app', 'arab', 'archi',
    'army', 'arpa', 'art', 'asia', 'associates', 'attorney', 'auction', 'audio', 'auto', 'autos',
    'baby', 'band', 'bank', 'bar', 'bargains', 'bayern', 'beer', 'berlin', 'best', 'bet', 'bid',
    'bike', 'bingo', 'bio', 'biz', 'black', 'blog', 'blue', 'boats', 'bond', 'boo', 'boutique',
    'box', 'broker', 'build', 'builders', 'business', 'buzz', 'bzh', 'cab', 'cafe', 'camera',
    'camp', 'capital', 'cards', 'care', 'careers', 'cars', 'casa', 'cash', 'casino', 'cat',
    'catering', 'center', 'ceo', 'cfd', 'channel', 'chat', 'cheap', 'christmas', 'church',
    'city', 'claims', 'cleaning', 'click', 'clinic', 'clothing', 'cloud', 'club', 'coach',
    'codes', 'coffee', 'college', 'community', 'company', 'computer', 'condos', 'construction',
    'consulting', 'contact', 'contractors', 'cooking', 'cool', 'country', 'coupon', 'courses',
    'credit', 'creditcard', 'cricket', 'cruises', 'cx', 'cymru', 'cyou', 'dad', 'dance', 'data',
    'dating', 'day', 'dds', 'deal', 'dealer', 'deals', 'degree', 'delivery', 'democrat', 'dental',
    'dentist', 'desi', 'design', 'dev', 'diamonds', 'diet', 'digital', 'direct', 'directory',
    'discount', 'diy', 'docs', 'doctor', 'dog', 'domains', 'download', 'earth', 'eco', 'education',
    'email', 'energy', 'engineer', 'engineering', 'enterprises', 'equipment', 'estate', 'events',
    'exchange', 'expert', 'exposed', 'express', 'fail', 'faith', 'family', 'fan', 'fans', 'farm',
    'fashion', 'feedback', 'film', 'finance', 'financial', 'fish', 'fitness', 'flights',
    'florist', 'flowers', 'food', 'football', 'forsale', 'foundation', 'fun', 'fund', 'furniture',
    'fyi', 'gallery', 'game', 'games', 'garden', 'gay', 'gbiz', 'gdn', 'gent', 'gift', 'gifts',
    'gives', 'giving', 'glass', 'global', 'gmbh', 'gold', 'golf', 'goog', 'gov', 'graphics',
    'gratis', 'green', 'gripe', 'group', 'guide', 'guitars', 'hair', 'haus', 'health',
    'healthcare', 'help', 'here', 'hiphop', 'hiv', 'hockey', 'holdings', 'holiday', 'homes',
    'horse', 'hospital', 'host', 'hosting', 'house', 'icu', 'immo', 'immobilien', 'inc',
    'industries', 'info', 'ing', 'ink', 'institute', 'insurance', 'international', 'investments',
    'irish', 'ismaili', 'ist', 'istanbul', 'jetzt', 'jewelry', 'jobs', 'joy', 'kim', 'kitchen',
    'kiwi', 'land', 'lat', 'law', 'lawyer', 'lease', 'legal', 'lgbt', 'life', 'lifestyle',
    'lighting', 'limited', 'limo', 'link', 'live', 'living', 'loan', 'loans', 'lol', 'love',
    'ltd', 'ltda', 'luxury', 'maison', 'management', 'market', 'marketing', 'mba', 'media',
    'memorial', 'men', 'menu', 'mobi', 'moda', 'moe', 'mom', 'money', 'monster', 'mortgage',
    'motorcycles', 'movie', 'museum', 'name', 'navy', 'network', 'news', 'ngo', 'ninja',
    'observer', 'one', 'ong', 'onl', 'online', 'ooo', 'org', 'organic', 'partners', 'parts',
    'party', 'pay', 'pet', 'photography', 'photos', 'pics', 'pictures', 'pink', 'pizza', 'place',
    'plumbing', 'plus', 'poker', 'porn', 'press', 'pro', 'productions', 'promo', 'properties',
    'pub', 'pw', 'quest', 'realestate', 'recipes', 'red', 'rehab', 'reise', 'rent', 'rentals',
    'repair', 'report', 'rest', 'restaurant', 'review', 'reviews', 'rich', 'rip', 'rocks',
    'rsvp', 'run', 'sale', 'salon', 'sarl', 'school', 'schule', 'science', 'services', 'sex',
    'shoes', 'shop', 'shopping', 'show', 'singles', 'site', 'ski', 'skin', 'soccer', 'social',
    'software', 'solar', 'solutions', 'space', 'storage', 'store', 'stream', 'studio', 'study',
    'style', 'sucks', 'supplies', 'supply', 'support', 'surf', 'surgery', 'systems', 'tattoo',
    'tax', 'taxi', 'team', 'tech', 'technology', 'tel', 'tennis', 'theater', 'theatre', 'tienda',
    'tips', 'tires', 'today', 'tools', 'top', 'tours', 'town', 'toys', 'trade', 'training',
    'travel', 'tube', 'tv', 'uk', 'university', 'uno', 'vacations', 'vc', 'vet', 'viajes', 'video',
    'villas', 'vip', 'vision', 'vodka', 'vote', 'voting', 'voto', 'voyage', 'wang', 'watch',
    'watches', 'webcam', 'website', 'wed', 'wedding', 'wiki', 'win', 'wine', 'work', 'works',
    'world', 'wtf', 'xyz', 'yachts', 'yoga', 'zone',
})

_known_tld_cache: frozenset[str] | None = None


def _all_two_letter_alpha() -> frozenset[str]:
    return frozenset(chr(a) + chr(b) for a in range(ord('a'), ord('z') + 1) for b in range(ord('a'), ord('z') + 1))


def _load_merged_tld_keys() -> frozenset[str]:
    """Merge ccTLD pairs, two-letter heuristic set, builtin extras, optional IANA file."""
    global _known_tld_cache
    if _known_tld_cache is not None:
        return _known_tld_cache
    s: set[str] = set(_CCSLD_SUFFIXES)
    s.update(_all_two_letter_alpha())
    s.update(_BUILTIN_EXTRA_TLDS)
    if _IANA_DATA_FILE.is_file():
        try:
            raw = _IANA_DATA_FILE.read_text(encoding='utf-8')
            for line in raw.splitlines():
                line = line.strip().lower()
                if not line or line.startswith('#'):
                    continue
                s.add(line)
        except OSError:
            pass
    _known_tld_cache = frozenset(s)
    return _known_tld_cache


def effective_registry_suffix_key(domain: str) -> str | None:
    """
    Return the public-suffix style key to validate (e.g. 'com', 'co.uk', 'exe').
    """
    d = (domain or '').strip().lower().strip('.')
    if not d or '.' not in d:
        return None
    parts = d.split('.')
    if len(parts) >= 2:
        duo = f'{parts[-2]}.{parts[-1]}'
        if duo in _CCSLD_SUFFIXES:
            return duo
        if duo in _COMPOUND_FILE_SUFFIXES:
            return duo
    if len(parts) >= 3:
        triple = f'{parts[-3]}.{parts[-2]}.{parts[-1]}'
        if triple in _COMPOUND_FILE_SUFFIXES:
            return triple
    return parts[-1]


def domain_looks_like_filename(domain: str) -> tuple[bool, str | None]:
    """
    True if the value looks like a file name / compound archive rather than a hostname TLD.
    Returns (flag, reason_suffix_or_compound).
    """
    d = (domain or '').strip()
    if not d or '.' not in d:
        return False, None
    parts = d.lower().strip('.').split('.')
    if len(parts) < 2:
        return False, None
    last_two = f'{parts[-2]}.{parts[-1]}'
    if last_two in _COMPOUND_FILE_SUFFIXES:
        return True, last_two
    if len(parts) >= 3:
        last_three = f'{parts[-3]}.{parts[-2]}.{parts[-1]}'
        if last_three in _COMPOUND_FILE_SUFFIXES:
            return True, last_three
    last = parts[-1]
    if last in _FILE_EXTENSION_LABELS:
        return True, last
    return False, None


def domain_has_unknown_tld_offline(domain: str) -> tuple[bool, str | None]:
    """
    True if suffix key is not in offline snapshot (two-letter ccTLDs assumed valid).
    """
    key = effective_registry_suffix_key(domain)
    if not key:
        return False, None
    if key in _COMPOUND_FILE_SUFFIXES:
        return False, None
    if key in _FILE_EXTENSION_LABELS:
        return False, None
    known = _load_merged_tld_keys()
    if key in known:
        return False, None
    # Two-letter alpha already in known via _all_two_letter_alpha
    return True, key


def offline_domain_warning_messages(domain: str) -> list[str]:
    """Human-readable warnings for Domain IOC values (offline only)."""
    out: list[str] = []
    d = (domain or '').strip()
    if not d:
        return out
    ok_fn, hint = domain_looks_like_filename(d)
    if ok_fn:
        out.append(
            f'Value looks like a file name (.{hint}) rather than a DNS domain. '
            f'Confirm IOC type — consider Hash or a proper hostname.'
        )
    unk, tld_key = domain_has_unknown_tld_offline(d)
    if unk and tld_key:
        out.append(
            f'TLD "{tld_key}" is not in the offline root-zone snapshot bundled with ZIoCHub '
            f'(replace utils/data/iana_tlds_alpha.txt from IANA for full coverage). '
            f'Verify this is a valid public domain suffix.'
        )
    return out


def offline_domain_feed_anomalies(value: str) -> list[dict]:
    """Feed Pulse / exclusion: structured entries matching get_feed_pulse_anomalies shape."""
    d = (value or '').strip()
    if not d:
        return []
    out: list[dict] = []
    fn, hint = domain_looks_like_filename(d)
    if fn:
        out.append({
            'type': 'domain_filename_like',
            'value': d,
            'message': f'Hostname looks like a file name (.{hint}) — may be mis-typed Domain IOC.',
            'ioc_type': 'Domain',
        })
    unk, tld_key = domain_has_unknown_tld_offline(d)
    if unk and tld_key:
        out.append({
            'type': 'unknown_tld_offline',
            'value': d,
            'message': f'TLD "{tld_key}" is not in the offline IANA snapshot — verify or update utils/data/iana_tlds_alpha.txt.',
            'ioc_type': 'Domain',
        })
    return out
