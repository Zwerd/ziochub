"""
Push approved YARA rules to external APIs (any product that accepts YARA via HTTP + API key).
Used after admin approves a YARA rule. Each target: base URL, optional path, optional API key.
Results are stored for UI polling and written to audit log.
"""
import logging
import threading
import urllib.request
import urllib.error
import ssl

# In-memory status per filename for UI polling.
_yara_push_status = {}
_status_lock = threading.Lock()


def set_fireeye_status(filename: str, status: str, message: str = ''):
    """Set push status for UI polling (name kept for backward compatibility)."""
    with _status_lock:
        _yara_push_status[filename] = {'status': status, 'message': message or ''}


def get_fireeye_status(filename: str, clear_after_read: bool = True):
    """Return { 'status': 'pending'|'success'|'error', 'message': str } and optionally clear."""
    with _status_lock:
        out = _yara_push_status.get(filename, {'status': 'pending', 'message': ''})
        out = dict(out)
        if clear_after_read and filename in _yara_push_status:
            del _yara_push_status[filename]
    return out


def _norm_path(p: str) -> str:
    """Ensure path starts with / and has no trailing /."""
    p = (p or '').strip()
    if not p:
        return '/api/v1/yara'
    if not p.startswith('/'):
        p = '/' + p
    return p.rstrip('/') if p != '/' else p


def _ssl_context(verify_ssl: bool) -> ssl.SSLContext:
    """TLS context for HTTPS automation targets. verify_ssl=False allows self-signed / private CAs (use only when trusted)."""
    ctx = ssl.create_default_context()
    if verify_ssl:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def push_yara_to_appliances(
    content: str,
    filename: str,
    appliances: list,
    audit_log_fn=None,
    *,
    verify_ssl: bool = True,
) -> dict:
    """
    Push YARA file content to each target. Each target: name, base_url, path (optional), api_key (optional).
    POST to base_url + path with body=content, header X-API-Key if api_key given.
    Returns { 'overall_success': bool, 'results': [ { 'name', 'success', 'message' }, ... ] }.
    """
    if not audit_log_fn:
        def _noop(*args, **kwargs):
            pass
        audit_log_fn = _noop

    if not verify_ssl:
        logging.warning(
            'YARA push: TLS certificate verification is disabled (self-signed / ignore-cert mode)'
        )

    ctx = _ssl_context(verify_ssl)
    results = []
    for app in appliances or []:
        name = (app.get('name') or '').strip() or 'Target'
        base_url = (app.get('base_url') or '').strip().rstrip('/')
        path = _norm_path(app.get('path') or '')
        api_key = (app.get('api_key') or '').strip()
        if not base_url:
            results.append({'name': name, 'success': False, 'message': 'Missing base URL'})
            audit_log_fn('yara_push_skip', f'target={name} reason=missing_base_url')
            continue
        upload_url = base_url + path if path.startswith('/') else base_url + '/' + path
        try:
            req = urllib.request.Request(upload_url, data=content.encode('utf-8'), method='POST')
            req.add_header('Content-Type', 'text/plain; charset=utf-8')
            if api_key:
                req.add_header('X-API-Key', api_key)
            try:
                with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                    code = resp.getcode()
                    if 200 <= code < 300:
                        results.append({'name': name, 'success': True, 'message': f'HTTP {code}'})
                        audit_log_fn('yara_push_ok', f'file={filename} target={name} code={code}')
                    else:
                        results.append({'name': name, 'success': False, 'message': f'HTTP {code}'})
                        audit_log_fn('yara_push_fail', f'file={filename} target={name} code={code}')
            except urllib.error.HTTPError as e:
                results.append({'name': name, 'success': False, 'message': f'HTTP {e.code} {e.reason}'})
                audit_log_fn('yara_push_fail', f'file={filename} target={name} code={e.code} reason={e.reason}')
            except urllib.error.URLError as e:
                results.append({'name': name, 'success': False, 'message': str(e.reason or e)})
                audit_log_fn('yara_push_fail', f'file={filename} target={name} error={e.reason}')
        except Exception as e:
            logging.exception('yara_push %s to %s', filename, name)
            results.append({'name': name, 'success': False, 'message': str(e)})
            audit_log_fn('yara_push_fail', f'file={filename} target={name} error={e}')

    overall = all(r.get('success') for r in results) if results else False
    return {'overall_success': overall, 'results': results}


def delete_yara_from_appliances(
    filename: str,
    appliances: list,
    audit_log_fn=None,
    *,
    verify_ssl: bool = True,
) -> dict:
    """
    Remove a YARA rule from each automation target (HTTP DELETE).
    Default URL: base_url + path + '/' + urlencoded(filename) (same path namespace as POST upload).
    Optional per-target: delete_path with {filename} placeholder, e.g. /api/v2/rules/{filename}
    2xx and 404 are treated as success (idempotent delete).
    """
    from urllib.parse import quote

    if not audit_log_fn:
        def _noop(*args, **kwargs):
            pass
        audit_log_fn = _noop

    if not verify_ssl:
        logging.warning(
            'YARA automation delete: TLS certificate verification is disabled (self-signed / ignore-cert mode)'
        )

    ctx = _ssl_context(verify_ssl)
    safe_name = quote((filename or '').strip(), safe='')
    results = []
    for app in appliances or []:
        name = (app.get('name') or '').strip() or 'Target'
        base_url = (app.get('base_url') or '').strip().rstrip('/')
        path = _norm_path(app.get('path') or '')
        api_key = (app.get('api_key') or '').strip()
        delete_tpl = (app.get('delete_path') or '').strip()
        if not base_url:
            results.append({'name': name, 'success': False, 'message': 'Missing base URL'})
            audit_log_fn('yara_delete_skip', f'target={name} reason=missing_base_url')
            continue
        if delete_tpl:
            if '{filename}' in delete_tpl:
                rel = delete_tpl.replace('{filename}', safe_name)
            else:
                rel = delete_tpl.rstrip('/') + '/' + safe_name
            if not rel.startswith('/'):
                rel = '/' + rel
            delete_url = base_url + rel
        else:
            delete_url = base_url + path.rstrip('/') + '/' + safe_name
        try:
            req = urllib.request.Request(delete_url, method='DELETE')
            if api_key:
                req.add_header('X-API-Key', api_key)
            try:
                with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                    code = resp.getcode()
                    if 200 <= code < 300 or code == 404:
                        results.append({'name': name, 'success': True, 'message': f'HTTP {code}'})
                        audit_log_fn('yara_delete_ok', f'file={filename} target={name} code={code}')
                    else:
                        results.append({'name': name, 'success': False, 'message': f'HTTP {code}'})
                        audit_log_fn('yara_delete_fail', f'file={filename} target={name} code={code}')
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    results.append({'name': name, 'success': True, 'message': 'HTTP 404 (already absent)'})
                    audit_log_fn('yara_delete_ok', f'file={filename} target={name} code=404')
                else:
                    results.append({'name': name, 'success': False, 'message': f'HTTP {e.code} {e.reason}'})
                    audit_log_fn('yara_delete_fail', f'file={filename} target={name} code={e.code}')
            except urllib.error.URLError as e:
                results.append({'name': name, 'success': False, 'message': str(e.reason or e)})
                audit_log_fn('yara_delete_fail', f'file={filename} target={name} error={e.reason}')
        except Exception as e:
            logging.exception('yara_delete %s to %s', filename, name)
            results.append({'name': name, 'success': False, 'message': str(e)})
            audit_log_fn('yara_delete_fail', f'file={filename} target={name} error={e}')

    overall = all(r.get('success') for r in results) if results else True
    return {'overall_success': overall, 'results': results}


# Minimal valid YARA rule for Admin → Settings → YARA push "Test connection" (same POST as real approval).
# condition: false ensures it never matches if the endpoint stores the rule.
_TEST_YARA_RULE = """rule ziochub_connection_test {
    meta:
        description = "ZIoCHub connectivity test (safe; condition is false)"
    condition:
        false
}
"""


def test_yara_push_connections(appliances: list, *, verify_ssl: bool = True) -> dict:
    """
    POST each target with a minimal valid YARA body-same transport as push_yara_to_appliances.
    Does not write settings. Use from Admin UI to verify connectivity before relying on approval push.
    """
    if not appliances:
        return {'overall_success': False, 'results': [], 'message': 'No targets configured'}
    return push_yara_to_appliances(
        _TEST_YARA_RULE,
        'ziochub_connection_test.yar',
        appliances,
        audit_log_fn=lambda *a, **k: None,
        verify_ssl=verify_ssl,
    )
