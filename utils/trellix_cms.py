"""
Trellix CMS (central management for Email Security / EX): YARA push via /cms/yara_rules_ng/...

Reuses session login + multipart upload + delete_yara_files from ``utils.trellix_ex`` (CookieJar, CSRF).
CMS targets typically need sensor scope fields (``s_s[sensor]``, ``s_s[group]``, ``s_s[s_r_l][]``) on upload/delete.
"""

from __future__ import annotations

from typing import Any, Callable, List, Optional

from utils.trellix_ex import (
    _DEFAULT_EX_CONTENT_TYPE,
    _EX_CONNECTION_TEST_FILENAME,
    _EX_CONNECTION_TEST_YARA,
    _aggregate_step_messages,
    _auth_row_from_target,
    _step_response,
    delete_yara_session_targets,
    parse_trellix_ex_targets_json,
    push_yara_session_targets,
    trellix_ex_delete_url_for_target,
    trellix_ex_upload_url_for_target,
)

_DEFAULT_CMS_LOGIN_PATH = '/login/login'
_DEFAULT_CMS_UPLOAD_PATH = '/cms/yara_rules_ng/upload_yara'
_DEFAULT_CMS_DELETE_PATH = '/cms/yara_rules_ng/delete_yara_files'


def _cms_form_extra_from_row(r: dict) -> list[dict[str, str]]:
    """Build CMS sensor scope form fields (matches CMS UI query keys)."""
    out: list[dict[str, str]] = []
    sid = (r.get('sensor_id') or '').strip()
    if sid:
        out.append({'name': 's_s[sensor]', 'value': sid})
        grp = (r.get('sensor_group') or '').strip() or 'All'
        out.append({'name': 's_s[group]', 'value': grp})
    else:
        grp = (r.get('sensor_group') or '').strip()
        if grp:
            out.append({'name': 's_s[group]', 'value': grp})
    wtg = r.get('sensor_w_t_g')
    if wtg is not None and str(wtg).strip() != '':
        out.append({'name': 's_s[w_t_g]', 'value': str(wtg).strip().lower()})
    hsid = (r.get('sensor_h_s_id') or '').strip()
    if hsid:
        out.append({'name': 's_s[h_s_id]', 'value': hsid})
    srl = r.get('sensor_rules_list')
    names: list[str] = []
    if isinstance(srl, str) and srl.strip():
        names = [x.strip() for x in srl.replace('\n', ',').split(',') if x.strip()]
    elif isinstance(srl, list):
        names = [str(x).strip() for x in srl if str(x).strip()]
    for n in names:
        out.append({'name': 's_s[s_r_l][]', 'value': n})
    raw_extra = r.get('form_extra')
    if isinstance(raw_extra, list):
        for item in raw_extra:
            if isinstance(item, dict) and (item.get('name') or '').strip():
                out.append({
                    'name': str(item['name']).strip(),
                    'value': '' if item.get('value') is None else str(item['value']),
                })
    return out


def _verify_ssl_cms(get_setting: Callable[[str, str], str]) -> bool:
    return (get_setting('trellix_cms_verify_ssl', 'true') or 'true').lower() in ('true', '1', 'yes')


def normalize_cms_target_row(r: dict, get_setting: Callable[[str, str], str]) -> dict:
    """Resolved CMS target for login/upload (EX session helpers + CMS paths and sensor fields)."""
    name = (r.get('name') or '').strip() or 'Trellix CMS'
    base_url = (r.get('base_url') or '').strip().rstrip('/')
    login_path = (r.get('login_path') or '').strip() or (
        get_setting('trellix_cms_login_path', _DEFAULT_CMS_LOGIN_PATH) or _DEFAULT_CMS_LOGIN_PATH
    ).strip()
    upload_path = (r.get('upload_path') or '').strip() or (
        get_setting('trellix_cms_upload_path', _DEFAULT_CMS_UPLOAD_PATH) or _DEFAULT_CMS_UPLOAD_PATH
    ).strip()
    if upload_path and not upload_path.startswith('/'):
        upload_path = '/' + upload_path
    delete_path = (r.get('delete_path') or '').strip() or (
        get_setting('trellix_cms_delete_path', _DEFAULT_CMS_DELETE_PATH) or ''
    ).strip()
    username = (r.get('username') or '').strip()
    password = str(r.get('password') or '')
    manual_cookie = (r.get('manual_cookie') if isinstance(r.get('manual_cookie'), str) else str(r.get('manual_cookie') or '')).strip()
    vs_raw = r.get('verify_ssl')
    if vs_raw is None:
        verify_ssl = _verify_ssl_cms(get_setting)
    elif isinstance(vs_raw, str):
        verify_ssl = vs_raw.strip().lower() in ('true', '1', 'yes')
    else:
        verify_ssl = bool(vs_raw)
    f_type = (r.get('f_type') or '').strip() or (get_setting('trellix_cms_f_type', 'common') or 'common').strip() or 'common'
    ct = (r.get('content_type') or '').strip() or (
        get_setting('trellix_cms_content_type', _DEFAULT_EX_CONTENT_TYPE) or _DEFAULT_EX_CONTENT_TYPE
    ).strip() or _DEFAULT_EX_CONTENT_TYPE
    auth_method = (r.get('auth_method') or 'auto').strip().lower()
    if auth_method not in ('password', 'ldap', 'auto'):
        auth_method = 'auto'
    edm = (r.get('ex_delete_name_mode') or 'same').strip().lower()
    if edm not in ('same', 'yar_txt'):
        edm = 'same'
    row: dict[str, Any] = {
        'name': name,
        'base_url': base_url,
        'login_path': login_path,
        'upload_path': upload_path,
        'username': username,
        'password': password,
        'manual_cookie': manual_cookie,
        'verify_ssl': verify_ssl,
        'f_type': f_type,
        'content_type': ct,
        'csrf_param': (r.get('csrf_param') or '').strip(),
        'csrf_token': (r.get('csrf_token') or '').strip(),
        'delete_path': delete_path,
        'ex_delete_name_mode': edm,
        'auth_method': auth_method,
        'form_extra': _cms_form_extra_from_row(r),
        'sensor_id': (r.get('sensor_id') or '').strip(),
        'sensor_group': (r.get('sensor_group') or '').strip(),
        'sensor_rules_list': r.get('sensor_rules_list'),
    }
    return row


def list_trellix_cms_targets(get_setting: Callable[[str, str], str]) -> List[dict]:
    rows = parse_trellix_ex_targets_json(get_setting('trellix_cms_targets', '[]'))
    return [normalize_cms_target_row(r, get_setting) for r in rows if (r.get('base_url') or '').strip()]


def trellix_cms_enabled(get_setting: Callable[[str, str], str]) -> bool:
    return (get_setting('trellix_cms_enabled', 'false') or 'false').lower() in ('true', '1', 'yes')


def list_trellix_cms_upload_urls(get_setting: Callable[[str, str], str]) -> List[str]:
    out: List[str] = []
    for t in list_trellix_cms_targets(get_setting):
        u = trellix_ex_upload_url_for_target(t)
        if u:
            out.append(u)
    return out


def list_trellix_cms_delete_urls(get_setting: Callable[[str, str], str]) -> List[str]:
    out: List[str] = []
    for t in list_trellix_cms_targets(get_setting):
        u = trellix_ex_delete_url_for_target(t)
        if u:
            out.append(u)
    return out


def push_yara_trellix_cms(
    content: str,
    filename: str,
    get_setting: Callable[[str, str], str],
    audit_log_fn=None,
    *,
    verify_ssl: Optional[bool] = None,
    cookie_header: Optional[str] = None,
) -> dict[str, Any]:
    targets = list_trellix_cms_targets(get_setting)
    return push_yara_session_targets(
        content,
        filename,
        targets,
        audit_log_fn,
        verify_ssl=verify_ssl,
        cookie_header=cookie_header,
        empty_skip_log='yara_push_skip',
        empty_log_detail='target=Trellix_CMS reason=no_targets',
        empty_result_name='Trellix CMS',
        empty_message='No Trellix CMS targets configured',
    )


def delete_yara_trellix_cms(
    filename: str,
    get_setting: Callable[[str, str], str],
    audit_log_fn=None,
    *,
    verify_ssl: Optional[bool] = None,
    cookie_header: Optional[str] = None,
) -> dict[str, Any]:
    targets = list_trellix_cms_targets(get_setting)
    return delete_yara_session_targets(
        filename,
        targets,
        audit_log_fn,
        verify_ssl=verify_ssl,
        cookie_header=cookie_header,
        empty_skip_log='yara_delete_skip',
        empty_log_detail='target=Trellix_CMS reason=no_targets',
        empty_result_name='Trellix CMS',
        empty_message='No Trellix CMS targets configured',
    )


def _test_cms_precheck(get_setting: Callable[[str, str], str]) -> Optional[dict[str, Any]]:
    if not trellix_cms_enabled(get_setting):
        return {
            'success': False,
            'overall_success': False,
            'results': [],
            'headline': 'Trellix CMS integration is disabled.',
            'summary': 'Enable Trellix CMS under Integrations, save settings, then run the test again.',
            'message': 'Trellix CMS is disabled.',
            'hint': 'Set Enable Trellix CMS YARA push to Yes, save, then retry.',
        }
    targets = list_trellix_cms_targets(get_setting)
    if not targets:
        return {
            'success': True,
            'overall_success': False,
            'results': [],
            'headline': 'No Trellix CMS targets configured.',
            'summary': 'Add at least one CMS target with base URL (and sensor ID if required), save, then test.',
            'message': 'No targets in trellix_cms_targets.',
        }
    return None


def _auth_row_cms(target: dict, *, verify_ssl: Optional[bool]) -> dict[str, Any]:
    row = _auth_row_from_target(target, verify_ssl=verify_ssl)
    if (target.get('name') or '').strip():
        row['name'] = (target.get('name') or '').strip()
    return row


def test_trellix_cms_step(
    get_setting: Callable[[str, str], str],
    step: str,
    *,
    verify_ssl: Optional[bool] = None,
) -> dict[str, Any]:
    """Staged CMS test: auth | upload | cleanup (same flow as Trellix EX)."""
    step_l = (step or '').strip().lower()
    pre = _test_cms_precheck(get_setting)
    if pre:
        pre['step'] = step_l
        return pre

    targets = list_trellix_cms_targets(get_setting)
    n = len(targets)

    if step_l == 'auth':
        rows = [_auth_row_cms(t, verify_ssl=verify_ssl) for t in targets]
        ok = bool(rows) and all(r.get('success') for r in rows)
        msg, hint, summ = _aggregate_step_messages(rows)
        if ok:
            headline = 'Authentication completed successfully'
            subline = f'Session established for {n} CMS target{"s" if n != 1 else ""}.'
        else:
            headline = 'Authentication failed'
            subline = 'Could not establish a valid session on one or more CMS targets.'
        return _step_response(
            step='auth',
            step_number=1,
            overall_success=ok,
            headline=headline,
            subline=subline,
            results=rows,
            message=msg,
            hint=hint,
            summary=summ or headline,
        )

    if step_l == 'upload':
        res = push_yara_trellix_cms(
            _EX_CONNECTION_TEST_YARA,
            _EX_CONNECTION_TEST_FILENAME,
            get_setting,
            audit_log_fn=lambda *a, **k: None,
            verify_ssl=verify_ssl,
        )
        rows = list(res.get('results') or [])
        ok = bool(res.get('overall_success'))
        msg, hint, summ = _aggregate_step_messages(rows)
        fn = _EX_CONNECTION_TEST_FILENAME
        if ok:
            headline = 'Test rule uploaded successfully'
            subline = f'Uploaded {fn} via CMS to {n} target{"s" if n != 1 else ""}.'
        else:
            headline = 'Test rule upload failed'
            subline = f'Could not upload {fn} to all CMS targets.'
        return _step_response(
            step='upload',
            step_number=2,
            overall_success=ok,
            headline=headline,
            subline=subline,
            results=rows,
            message=msg,
            hint=hint,
            summary=summ or headline,
            test_filename=fn,
        )

    if step_l == 'cleanup':
        res = delete_yara_trellix_cms(
            _EX_CONNECTION_TEST_FILENAME,
            get_setting,
            audit_log_fn=lambda *a, **k: None,
            verify_ssl=verify_ssl,
        )
        rows = list(res.get('results') or [])
        ok = bool(res.get('overall_success'))
        msg, hint, summ = _aggregate_step_messages(rows)
        fn = _EX_CONNECTION_TEST_FILENAME
        if ok:
            headline = 'Test rule cleanup completed successfully'
            subline = f'Removed {fn} from {n} CMS target{"s" if n != 1 else ""}.'
        else:
            headline = 'Test rule cleanup failed'
            subline = f'{fn} may still be present on CMS. Try Delete name mode yar_txt if rules use .yar.txt.'
        return _step_response(
            step='cleanup',
            step_number=3,
            overall_success=ok,
            headline=headline,
            subline=subline,
            results=rows,
            message=msg,
            hint=hint,
            summary=summ or headline,
            test_filename=fn,
        )

    return {
        'success': False,
        'overall_success': False,
        'step': step_l,
        'headline': 'Unknown test step.',
        'message': f'Invalid step: {step!r}. Use auth, upload, or cleanup.',
    }


def test_trellix_cms_connection(
    get_setting: Callable[[str, str], str],
    *,
    verify_ssl: Optional[bool] = None,
) -> dict[str, Any]:
    """Single-shot CMS test (auth + upload + cleanup)."""
    pre = _test_cms_precheck(get_setting)
    if pre:
        return pre
    steps = ('auth', 'upload', 'cleanup')
    all_results: list[dict[str, Any]] = []
    overall = True
    last_headline = ''
    for st in steps:
        one = test_trellix_cms_step(get_setting, st, verify_ssl=verify_ssl)
        last_headline = one.get('headline') or last_headline
        all_results.extend(one.get('results') or [])
        overall = overall and bool(one.get('overall_success'))
    return {
        'success': True,
        'overall_success': overall,
        'results': all_results,
        'headline': last_headline or ('OK' if overall else 'Trellix CMS test failed'),
        'message': 'Staged CMS test combined.' if overall else 'One or more CMS steps failed.',
    }
