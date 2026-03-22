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


def push_yara_to_appliances(content: str, filename: str, appliances: list, audit_log_fn=None) -> dict:
    """
    Push YARA file content to each target. Each target: name, base_url, path (optional), api_key (optional).
    POST to base_url + path with body=content, header X-API-Key if api_key given.
    Returns { 'overall_success': bool, 'results': [ { 'name', 'success', 'message' }, ... ] }.
    """
    if not audit_log_fn:
        def _noop(*args, **kwargs):
            pass
        audit_log_fn = _noop

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
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
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
