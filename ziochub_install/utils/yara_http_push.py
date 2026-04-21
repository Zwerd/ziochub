"""
Vendor-neutral HTTP(S) transport for approved YARA rules.

Targets are configured in Admin → Automations → YARA push (JSON key ``automation_fireeye_appliances``
for historical reasons). Each entry: base URL, upload path, optional API key, optional delete path/method.

Per-target optional fields:
- api_key_header: HTTP header name for the key (default X-API-Key). Use e.g. Authorization with
  api_key value "Bearer <token>" if needed.
- delete_path: URL template for removal; may include {filename} (URL-encoded). If empty, uses
  base_url + upload path + /filename (same as before).
- delete_http_method: DELETE (default) or POST — some products expect POST with an empty body.

Many gateways return HTTP 200 with JSON indicating failure; we parse the body accordingly.
"""
import json
import logging
import threading
import urllib.request
import urllib.error
import ssl

# Cap response read to avoid huge bodies in memory / DB telemetry.
_MAX_RESPONSE_BODY_BYTES = 256 * 1024
# Stored in telemetry / UI per target
_MAX_MESSAGE_CHARS = 4000

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


def appliance_upload_url(app: dict) -> str:
    """Canonical POST URL for YARA upload (must match push_yara_to_appliances). Used for retry matching."""
    base_url = (app.get('base_url') or '').strip().rstrip('/')
    if not base_url:
        return ''
    path = _norm_path(app.get('path') or '')
    return base_url + path if path.startswith('/') else base_url + '/' + path


def appliance_delete_url(app: dict, filename: str) -> str:
    """Canonical DELETE URL for YARA rule removal (must match delete_yara_from_appliances)."""
    from urllib.parse import quote

    base_url = (app.get('base_url') or '').strip().rstrip('/')
    if not base_url:
        return ''
    path = _norm_path(app.get('path') or '')
    delete_tpl = (app.get('delete_path') or '').strip()
    safe_name = quote((filename or '').strip(), safe='')
    if delete_tpl:
        if '{filename}' in delete_tpl:
            rel = delete_tpl.replace('{filename}', safe_name)
        else:
            rel = delete_tpl.rstrip('/') + '/' + safe_name
        if not rel.startswith('/'):
            rel = '/' + rel
        return base_url + rel
    return base_url + path.rstrip('/') + '/' + safe_name


def _norm_path(p: str) -> str:
    """Ensure path starts with / and has no trailing /."""
    p = (p or '').strip()
    if not p:
        return '/api/v1/yara'
    if not p.startswith('/'):
        p = '/' + p
    return p.rstrip('/') if p != '/' else p


def _api_key_header_name(app: dict) -> str:
    """HTTP header name for api_key; conservative charset to avoid header injection."""
    raw = (app.get('api_key_header') or '').strip()
    if not raw:
        return 'X-API-Key'
    for c in raw:
        if not (c.isascii() and (c.isalnum() or c in '-_')):
            return 'X-API-Key'
    return raw


def _add_api_key_header(req: urllib.request.Request, app: dict) -> None:
    api_key = (app.get('api_key') or '').strip()
    if not api_key:
        return
    req.add_header(_api_key_header_name(app), api_key)


def _delete_http_method(app: dict) -> str:
    """DELETE (default) or POST for rule removal requests."""
    m = (app.get('delete_http_method') or '').strip().upper()
    if m == 'POST':
        return 'POST'
    return 'DELETE'


def _truncate_msg(s: str, limit: int = _MAX_MESSAGE_CHARS) -> str:
    s = (s or '').strip()
    if len(s) <= limit:
        return s
    return s[: max(0, limit - 1)] + '…'


def _evaluate_http_response_body(http_code: int, body_bytes: bytes) -> tuple[bool, str]:
    """
    Decide if an HTTP 2xx response actually means the remote accepted the YARA rule.

    Many gateways return 200 with JSON like {"success": false, "error": "..."}.
    Returns (logical_ok, human_message) — message always includes a hint from the body when present.
    """
    if not (200 <= http_code < 300):
        return False, f'HTTP {http_code}'

    raw = body_bytes or b''
    if len(raw) > _MAX_RESPONSE_BODY_BYTES:
        raw = raw[:_MAX_RESPONSE_BODY_BYTES]

    text = raw.decode('utf-8', errors='replace').strip()
    if not text:
        return True, f'HTTP {http_code} (empty body)'

    # Non-JSON: if it looks like an HTML error page, do not count as success.
    low = text[:500].lower()
    if '<html' in low and any(x in low for x in ('error', 'denied', 'forbidden', 'unauthorized', 'invalid')):
        return False, _truncate_msg(f'HTTP {http_code}; body suggests error page: {text[:800]}')

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        # Plain text OK — include snippet so operators can see server hints
        return True, _truncate_msg(f'HTTP {http_code}; body: {text}')

    if isinstance(data, dict):
        # Explicit success:false
        if data.get('success') is False:
            return False, _truncate_msg(_format_json_rejection('HTTP 200 but success=false', data))
        # Explicit error field (common)
        err = data.get('error')
        if err is not None and err != '' and err != [] and err != {}:
            if data.get('success') is not True:
                return False, _truncate_msg(_format_json_rejection('HTTP 200 with error field', data))
        errs = data.get('errors')
        if isinstance(errs, list) and len(errs) > 0:
            if data.get('success') is not True:
                return False, _truncate_msg(_format_json_rejection('HTTP 200 with errors[]', data))
        st = str(data.get('status', '')).lower()
        if st in ('error', 'failed', 'failure'):
            return False, _truncate_msg(_format_json_rejection(f'HTTP 200 status={st!r}', data))
        if data.get('accepted') is False:
            return False, _truncate_msg(_format_json_rejection('HTTP 200 accepted=false', data))
        # Some APIs: {"result":"error"} or code != 0
        res = data.get('result')
        if isinstance(res, str) and res.lower() in ('error', 'failed', 'failure'):
            return False, _truncate_msg(_format_json_rejection('HTTP 200 bad result', data))
        code = data.get('code')
        if isinstance(code, int) and code != 0 and code != 200:
            if data.get('success') is not True:
                return False, _truncate_msg(_format_json_rejection(f'HTTP 200 code={code}', data))

    # JSON we could not classify as failure — still surface body for verification
    return True, _truncate_msg(f'HTTP {http_code}; body: {text}')


def _format_json_rejection(prefix: str, data: dict) -> str:
    """Short line for logs/UI."""
    try:
        extra = json.dumps(data, ensure_ascii=False)[:3500]
    except Exception:
        extra = str(data)[:500]
    return f'{prefix}: {extra}'


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
    Push YARA file content to each target. Each target: name, base_url, path (optional), api_key (optional),
    api_key_header (optional; default X-API-Key when api_key is set).
    POST to base_url + path with body=content.
    Returns { 'overall_success': bool, 'results': [ { 'name', 'url', 'success', 'message' }, ... ] }.
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
        if not base_url:
            results.append({'name': name, 'url': '', 'success': False, 'message': 'Missing base URL'})
            audit_log_fn('yara_push_skip', f'target={name} reason=missing_base_url')
            continue
        upload_url = base_url + path if path.startswith('/') else base_url + '/' + path
        try:
            req = urllib.request.Request(upload_url, data=content.encode('utf-8'), method='POST')
            req.add_header('Content-Type', 'text/plain; charset=utf-8')
            _add_api_key_header(req, app)
            try:
                with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                    code = resp.getcode()
                    body_bytes = b''
                    try:
                        body_bytes = resp.read()
                    except Exception:
                        pass
                    if 200 <= code < 300:
                        logical_ok, detail_msg = _evaluate_http_response_body(code, body_bytes)
                        results.append({
                            'name': name,
                            'url': upload_url,
                            'success': logical_ok,
                            'message': detail_msg,
                        })
                        if logical_ok:
                            audit_log_fn('yara_push_ok', f'file={filename} target={name} code={code}')
                        else:
                            audit_log_fn('yara_push_fail', f'file={filename} target={name} code={code} detail={detail_msg[:500]}')
                    else:
                        results.append({'name': name, 'url': upload_url, 'success': False, 'message': f'HTTP {code}'})
                        audit_log_fn('yara_push_fail', f'file={filename} target={name} code={code}')
            except urllib.error.HTTPError as e:
                err_body = ''
                try:
                    eb = e.read()
                    if eb:
                        err_body = eb.decode('utf-8', errors='replace')[:2000]
                except Exception:
                    pass
                msg = f'HTTP {e.code} {e.reason}' + (f'; {err_body}' if err_body else '')
                results.append({'name': name, 'url': upload_url, 'success': False, 'message': _truncate_msg(msg)})
                audit_log_fn('yara_push_fail', f'file={filename} target={name} code={e.code} reason={e.reason}')
            except urllib.error.URLError as e:
                results.append({'name': name, 'url': upload_url, 'success': False, 'message': str(e.reason or e)})
                audit_log_fn('yara_push_fail', f'file={filename} target={name} error={e.reason}')
        except Exception as e:
            logging.exception('yara_push %s to %s', filename, name)
            results.append({'name': name, 'url': upload_url, 'success': False, 'message': str(e)})
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
    Remove a YARA rule from each automation target (HTTP DELETE or POST per delete_http_method).
    Default URL: base_url + path + '/' + urlencoded(filename) (same path namespace as POST upload).
    Optional per-target: delete_path with {filename} placeholder, e.g. /api/v2/rules/{filename}
    POST uses an empty body (Content-Length 0).
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
        delete_tpl = (app.get('delete_path') or '').strip()
        if not base_url:
            results.append({'name': name, 'url': '', 'success': False, 'message': 'Missing base URL'})
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
            del_method = _delete_http_method(app)
            if del_method == 'POST':
                req = urllib.request.Request(delete_url, data=b'', method='POST')
            else:
                req = urllib.request.Request(delete_url, method='DELETE')
            _add_api_key_header(req, app)
            try:
                with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                    code = resp.getcode()
                    body_bytes = b''
                    try:
                        body_bytes = resp.read()
                    except Exception:
                        pass
                    if 200 <= code < 300:
                        logical_ok, detail_msg = _evaluate_http_response_body(code, body_bytes)
                        results.append({'name': name, 'url': delete_url, 'success': logical_ok, 'message': detail_msg})
                        if logical_ok:
                            audit_log_fn('yara_delete_ok', f'file={filename} target={name} code={code}')
                        else:
                            audit_log_fn('yara_delete_fail', f'file={filename} target={name} code={code} detail={detail_msg[:500]}')
                    else:
                        results.append({'name': name, 'url': delete_url, 'success': False, 'message': f'HTTP {code}'})
                        audit_log_fn('yara_delete_fail', f'file={filename} target={name} code={code}')
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    results.append({'name': name, 'url': delete_url, 'success': True, 'message': 'HTTP 404 (already absent)'})
                    audit_log_fn('yara_delete_ok', f'file={filename} target={name} code=404')
                else:
                    err_body = ''
                    try:
                        eb = e.read()
                        if eb:
                            err_body = eb.decode('utf-8', errors='replace')[:2000]
                    except Exception:
                        pass
                    msg = f'HTTP {e.code} {e.reason}' + (f'; {err_body}' if err_body else '')
                    results.append({'name': name, 'url': delete_url, 'success': False, 'message': _truncate_msg(msg)})
                    audit_log_fn('yara_delete_fail', f'file={filename} target={name} code={e.code}')
            except urllib.error.URLError as e:
                results.append({'name': name, 'url': delete_url, 'success': False, 'message': str(e.reason or e)})
                audit_log_fn('yara_delete_fail', f'file={filename} target={name} error={e.reason}')
        except Exception as e:
            logging.exception('yara_delete %s to %s', filename, name)
            results.append({'name': name, 'url': delete_url, 'success': False, 'message': str(e)})
            audit_log_fn('yara_delete_fail', f'file={filename} target={name} error={e}')

    overall = all(r.get('success') for r in results) if results else True
    return {'overall_success': overall, 'results': results}


# Minimal valid YARA rule for Admin → Automations → YARA push "Test connection" (same POST as real approval).
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
