"""
TAXII 2.1 server so TAXII clients (e.g. Cisco IronPort ESA) can pull STIX indicators from ZIoCHub.
ZIoCHub is the feed provider (endpoint); the client polls and gets updated indicators.

Endpoints: Discovery, API Root, Collections, Collection, Get Objects (paginated), Get an Object, Get Manifests, Get Object Versions.
"""
import json
from datetime import datetime

from flask import Blueprint, Response, request


def _taxii_feeds_disabled_response():
    """Return 503 response when feeds_public_enabled is false; else None."""
    try:
        from app import _get_setting
        if _get_setting('feeds_public_enabled', 'true').strip().lower() != 'true':
            return _taxii_json_response({'error': 'Feeds are not available. Enable in Admin Settings.'}, status=503)
    except Exception:
        pass
    return None


TAXII_MEDIA_TYPE = 'application/taxii+json;version=2.1'
STIX_MEDIA_TYPE = 'application/stix+json;version=2.1'

# Fixed API root name used in URLs (e.g. /taxii2/ziochub/)
API_ROOT_ID = 'ziochub'
# Single collection ID for all indicators (IronPort pulls from one collection)
COLLECTION_ID = 'indicators'

# TAXII 2.1 Get Objects pagination defaults (what clients expect)
DEFAULT_PAGE_LIMIT = 500
MAX_PAGE_LIMIT = 10000

bp = Blueprint('taxii2', __name__, url_prefix='/taxii2')


@bp.after_request
def _record_taxii_connection_telemetry(response):
    """Track last successful TAXII response per client IP + path (Feed Pulse → Connections)."""
    try:
        from utils.integration_telemetry import record_feed_pull_if_ok
        record_feed_pull_if_ok(response)
    except Exception:
        pass
    return response


def _taxii_json_response(data, status=200, extra_headers=None):
    headers = {'X-Content-Type-Options': 'nosniff'}
    if extra_headers:
        headers.update(extra_headers)
    return Response(
        json.dumps(data, ensure_ascii=False),
        status=status,
        mimetype=TAXII_MEDIA_TYPE,
        headers=headers
    )


def _taxii_date_added_headers(first_date_added, last_date_added):
    """Headers required by TAXII 2.1 for object/manifest/versions responses."""
    h = {}
    if first_date_added:
        h['X-TAXII-Date-Added-First'] = first_date_added
    if last_date_added:
        h['X-TAXII-Date-Added-Last'] = last_date_added
    return h


def _check_accept():
    """Return True if request Accept allows TAXII 2.1; else False (caller may return 406)."""
    accept = request.headers.get('Accept') or ''
    return TAXII_MEDIA_TYPE in accept or 'application/taxii+json' in accept


def _parse_match_params():
    """Parse match[id], match[type], match[spec_version] from request.args."""
    def multi(key):
        val = request.args.get(key)
        if val is None:
            return None
        return [v.strip() for v in (val or '').split(',') if v.strip()]
    return {
        'match_ids': multi('match[id]'),
        'match_types': multi('match[type]'),
        'match_spec_versions': multi('match[spec_version]'),
    }


@bp.route('/', methods=['GET'])
def discovery():
    """
    TAXII 2.1 Discovery. Returns server title, description, and api_roots.
    Clients (e.g. Cisco IronPort) use this to find the API root URL.
    """
    # Use relative api_roots so client resolves from this request URL
    base = request.url_root.rstrip('/') + '/taxii2'
    api_root_url = f"{base}/{API_ROOT_ID}/"
    return _taxii_json_response({
        'title': 'ZIoCHub TAXII 2.1',
        'description': 'ZIoCHub IOC feed for TAXII/STIX clients (e.g. Cisco IronPort ESA). All active indicators in STIX 2.1.',
        'default': api_root_url,
        'api_roots': [api_root_url],
    })


@bp.route(f'/{API_ROOT_ID}/', methods=['GET'])
def api_root():
    """TAXII 2.1 API Root resource. Required for clients to then request collections."""
    return _taxii_json_response({
        'title': 'ZIoCHub',
        'description': 'Active IOC indicators (IP, Domain, URL, Hash, Email) in STIX 2.1.',
        'versions': ['taxii-2.1'],
        'max_content_length': 9437184,
    })


@bp.route(f'/{API_ROOT_ID}/collections/', methods=['GET'])
def collections_list():
    """TAXII 2.1 List Collections. Single collection 'indicators' with all IOCs."""
    base = request.url_root.rstrip('/') + '/taxii2/' + API_ROOT_ID
    return _taxii_json_response({
        'collections': [
            {
                'id': COLLECTION_ID,
                'title': 'ZIoCHub Indicators',
                'description': 'All active IOCs (IP, Domain, URL, Hash, Email) from ZIoCHub.',
                'can_read': True,
                'can_write': False,
                'media_types': [STIX_MEDIA_TYPE],
            }
        ]
    })


@bp.route(f'/{API_ROOT_ID}/collections/<collection_id>/', methods=['GET'])
def collection_detail(collection_id):
    """TAXII 2.1 Collection resource. Only 'indicators' is valid."""
    if collection_id != COLLECTION_ID:
        return _taxii_json_response({'error': 'Collection not found'}, status=404)
    return _taxii_json_response({
        'id': COLLECTION_ID,
        'title': 'ZIoCHub Indicators',
        'description': 'All active IOCs (IP, Domain, URL, Hash, Email) from ZIoCHub.',
        'can_read': True,
        'can_write': False,
        'media_types': [STIX_MEDIA_TYPE],
    })


def _parse_added_after(value):
    """Parse added_after query param (ISO 8601) to datetime or None."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
        return dt.replace(tzinfo=None) if dt.tzinfo else dt
    except (ValueError, TypeError):
        return None


@bp.route(f'/{API_ROOT_ID}/collections/<collection_id>/objects/', methods=['GET'])
def get_objects(collection_id):
    """
    TAXII 2.1 Get Objects. Envelope with STIX 2.1 indicators; pagination (limit, next, added_after); match[id], match[type], match[spec_version].
    """
    r = _taxii_feeds_disabled_response()
    if r is not None:
        return r
    if collection_id != COLLECTION_ID:
        return _taxii_json_response({'error': 'Collection not found'}, status=404)
    if not _check_accept():
        return _taxii_json_response({'error': 'Accept must include application/taxii+json'}, status=406)

    try:
        limit = request.args.get('limit', type=int)
        if limit is None:
            limit = DEFAULT_PAGE_LIMIT
        limit = max(1, min(limit, MAX_PAGE_LIMIT))
    except (ValueError, TypeError):
        limit = DEFAULT_PAGE_LIMIT
    try:
        next_cursor = request.args.get('next', type=str)
        offset = int(next_cursor) if next_cursor else 0
        offset = max(0, offset)
    except (ValueError, TypeError):
        offset = 0
    added_after = _parse_added_after(request.args.get('added_after'))
    match = _parse_match_params()

    from routes.feeds import _feed_stix_objects_page
    objects, has_more, first_ts, last_ts = _feed_stix_objects_page(
        added_after=added_after,
        offset=offset,
        limit=limit,
        match_ids=match['match_ids'],
        match_types=match['match_types'],
        match_spec_versions=match['match_spec_versions'],
    )

    envelope = {'objects': objects, 'more': has_more}
    if has_more:
        envelope['next'] = str(offset + len(objects))
    headers = _taxii_date_added_headers(first_ts, last_ts)
    return _taxii_json_response(envelope, extra_headers=headers)


@bp.route(f'/{API_ROOT_ID}/collections/<collection_id>/objects/<path:object_id>/', methods=['GET'])
def get_object(collection_id, object_id):
    """TAXII 2.1 Get an Object by id. Returns envelope with single STIX object or 404."""
    r = _taxii_feeds_disabled_response()
    if r is not None:
        return r
    if collection_id != COLLECTION_ID:
        return _taxii_json_response({'error': 'Collection not found'}, status=404)
    if not _check_accept():
        return _taxii_json_response({'error': 'Accept must include application/taxii+json'}, status=406)

    from routes.feeds import _feed_stix_object_by_id
    ind, date_added = _feed_stix_object_by_id(object_id.strip().rstrip('/'))
    if ind is None:
        return _taxii_json_response({'error': 'Object not found'}, status=404)
    envelope = {'objects': [ind]}
    headers = _taxii_date_added_headers(date_added, date_added)
    return _taxii_json_response(envelope, extra_headers=headers)


@bp.route(f'/{API_ROOT_ID}/collections/<collection_id>/manifest/', methods=['GET'])
def get_manifest(collection_id):
    """TAXII 2.1 Get Object Manifests. Same pagination and match[] as Get Objects; returns manifest records."""
    r = _taxii_feeds_disabled_response()
    if r is not None:
        return r
    if collection_id != COLLECTION_ID:
        return _taxii_json_response({'error': 'Collection not found'}, status=404)
    if not _check_accept():
        return _taxii_json_response({'error': 'Accept must include application/taxii+json'}, status=406)

    try:
        limit = request.args.get('limit', type=int)
        if limit is None:
            limit = DEFAULT_PAGE_LIMIT
        limit = max(1, min(limit, MAX_PAGE_LIMIT))
    except (ValueError, TypeError):
        limit = DEFAULT_PAGE_LIMIT
    try:
        next_cursor = request.args.get('next', type=str)
        offset = int(next_cursor) if next_cursor else 0
        offset = max(0, offset)
    except (ValueError, TypeError):
        offset = 0
    added_after = _parse_added_after(request.args.get('added_after'))
    match = _parse_match_params()

    from routes.feeds import _feed_stix_manifest_page
    manifest_objects, has_more, first_ts, last_ts = _feed_stix_manifest_page(
        added_after=added_after,
        offset=offset,
        limit=limit,
        match_ids=match['match_ids'],
        match_types=match['match_types'],
        match_spec_versions=match['match_spec_versions'],
    )
    payload = {'more': has_more}
    if manifest_objects:
        payload['objects'] = manifest_objects
    if has_more:
        payload['next'] = str(offset + len(manifest_objects))
    headers = _taxii_date_added_headers(first_ts, last_ts)
    return _taxii_json_response(payload, extra_headers=headers)


@bp.route(f'/{API_ROOT_ID}/collections/<collection_id>/objects/<path:object_id>/versions/', methods=['GET'])
def get_object_versions(collection_id, object_id):
    """TAXII 2.1 Get Object Versions. ZIoCHub has one version per indicator."""
    r = _taxii_feeds_disabled_response()
    if r is not None:
        return r
    if collection_id != COLLECTION_ID:
        return _taxii_json_response({'error': 'Collection not found'}, status=404)
    if not _check_accept():
        return _taxii_json_response({'error': 'Accept must include application/taxii+json'}, status=406)

    from routes.feeds import _feed_stix_object_versions
    versions, first_ts, last_ts = _feed_stix_object_versions(object_id.strip().rstrip('/'))
    if versions is None:
        return _taxii_json_response({'error': 'Object not found'}, status=404)
    payload = {'versions': versions}
    headers = _taxii_date_added_headers(first_ts, last_ts)
    return _taxii_json_response(payload, extra_headers=headers)
