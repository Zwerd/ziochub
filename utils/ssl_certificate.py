"""
SSL/TLS certificate helpers for Admin → Certificate wizard.

Uses OpenSSL CLI (same as app._certificate_status). No CA private key handling.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
from typing import Any

logger = logging.getLogger(__name__)

_PEM_CERT_BLOCK = re.compile(
    r'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----',
    re.DOTALL,
)


def extract_certificate_blocks(pem: str) -> list[str]:
    """Return normalized PEM blocks (one certificate each)."""
    text = (pem or '').replace('\r\n', '\n').strip()
    if not text:
        return []
    blocks: list[str] = []
    for m in _PEM_CERT_BLOCK.finditer(text):
        body = m.group(1).strip()
        if body:
            blocks.append(
                '-----BEGIN CERTIFICATE-----\n'
                + body
                + '\n-----END CERTIFICATE-----\n'
            )
    return blocks


def build_certificate_chain_pem(
    server_pem: str,
    intermediate_pem: str = '',
    root_pem: str = '',
) -> tuple[str, list[str]]:
    """
    Build full chain PEM: leaf → intermediate(s) → root.

    Each argument may contain one or more PEM certificate blocks.
    Returns (combined_pem, errors).
    """
    errors: list[str] = []
    server_blocks = extract_certificate_blocks(server_pem)
    if not server_blocks:
        errors.append('Server certificate is required (valid PEM).')
        return '', errors
    if len(server_blocks) > 1:
        errors.append('Paste only the server (leaf) certificate in the server field, not the full chain.')

    parts: list[str] = [server_blocks[0].strip() + '\n']
    for label, raw in (
        ('Intermediate', intermediate_pem),
        ('Root CA', root_pem),
    ):
        for block in extract_certificate_blocks(raw):
            parts.append(block.strip() + '\n')
        if (raw or '').strip() and not extract_certificate_blocks(raw):
            errors.append(f'{label} field is not valid PEM.')

    return ''.join(parts), errors


def build_ca_bundle_pem(intermediate_pem: str = '', root_pem: str = '') -> str:
    """Intermediate + root only (for optional ca.pem / client trust distribution)."""
    parts: list[str] = []
    for raw in (intermediate_pem, root_pem):
        for block in extract_certificate_blocks(raw):
            parts.append(block.strip() + '\n')
    return ''.join(parts)


def _write_temp(content: str, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix, prefix='ziochub_ssl_')
    os.close(fd)
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(content)
    return path


def _run_openssl(args: list[str], *, timeout: int = 30) -> tuple[bool, str, str]:
    try:
        r = subprocess.run(
            ['openssl'] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = (r.stdout or '').strip()
        err = (r.stderr or '').strip()
        if r.returncode != 0:
            return False, out, err or f'openssl exited {r.returncode}'
        return True, out, err
    except FileNotFoundError:
        return False, '', 'openssl command not found on server'
    except subprocess.TimeoutExpired:
        return False, '', 'openssl timed out'
    except Exception as exc:
        return False, '', str(exc)


def certificate_key_match(cert_pem: str, key_pem: str) -> tuple[bool, str]:
    """True when cert and private key moduli match."""
    cert_path = key_path = None
    try:
        cert_path = _write_temp(cert_pem, '.pem')
        key_path = _write_temp(key_pem, '.key')
        ok1, mod1, err1 = _run_openssl(['x509', '-noout', '-modulus', '-in', cert_path])
        if not ok1:
            return False, err1 or 'Could not read certificate modulus'
        ok2, mod2, err2 = _run_openssl(['rsa', '-noout', '-modulus', '-in', key_path])
        if not ok2:
            ok2, mod2, err2 = _run_openssl(['pkey', '-noout', '-modulus', '-in', key_path])
        if not ok2:
            return False, err2 or 'Could not read private key modulus'
        if mod1.strip() != mod2.strip():
            return False, 'Certificate and private key do not match'
        return True, 'ok'
    finally:
        for p in (cert_path, key_path):
            if p and os.path.isfile(p):
                try:
                    os.remove(p)
                except OSError:
                    pass


def inspect_certificate_pem(cert_pem: str) -> dict[str, Any]:
    """Return subject, issuer, expiry for the first certificate in PEM."""
    blocks = extract_certificate_blocks(cert_pem)
    if not blocks:
        return {'valid': False, 'error': 'No certificate found'}
    cert_path = None
    try:
        cert_path = _write_temp(blocks[0], '.pem')
        info: dict[str, Any] = {'valid': True, 'chain_parts': len(blocks)}
        for field, flag in (('subject', '-subject'), ('issuer', '-issuer')):
            ok, out, err = _run_openssl(['x509', '-noout', flag, '-nameopt', 'RFC2253', '-in', cert_path])
            info[field] = out if ok else (err or '')
        ok, out, _ = _run_openssl(['x509', '-noout', '-enddate', '-in', cert_path])
        if ok and out.startswith('notAfter='):
            info['not_after'] = out.replace('notAfter=', '').strip()
        ok, out, _ = _run_openssl(['x509', '-noout', '-dates', '-in', cert_path])
        if ok:
            for line in out.splitlines():
                if line.startswith('notBefore='):
                    info['not_before'] = line.replace('notBefore=', '').strip()
        return info
    finally:
        if cert_path and os.path.isfile(cert_path):
            try:
                os.remove(cert_path)
            except OSError:
                pass


def verify_installation(
    server_pem: str,
    key_pem: str,
    intermediate_pem: str = '',
    root_pem: str = '',
) -> dict[str, Any]:
    """Validate chain composition, key match, and return inspection metadata."""
    chain, errors = build_certificate_chain_pem(server_pem, intermediate_pem, root_pem)
    result: dict[str, Any] = {
        'ok': False,
        'errors': errors,
        'chain_pem': chain,
        'chain_cert_count': len(extract_certificate_blocks(chain)) if chain else 0,
    }
    if errors or not chain or not (key_pem or '').strip():
        if not (key_pem or '').strip():
            result['errors'] = list(errors) + ['Private key is required for verification.']
        return result

    key_pem = key_pem.strip()
    if '-----BEGIN' not in key_pem:
        result['errors'] = list(errors) + ['Invalid private key PEM.']
        return result

    match, msg = certificate_key_match(extract_certificate_blocks(server_pem)[0], key_pem)
    if not match:
        result['errors'] = list(errors) + [msg]
        return result

    result['ok'] = True
    result['errors'] = []
    result['server'] = inspect_certificate_pem(extract_certificate_blocks(server_pem)[0])
    result['chain'] = inspect_certificate_pem(chain)
    return result


def _parse_sans(raw: str | list[str] | None, common_name: str) -> list[str]:
    items: list[str] = []
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.replace(';', ',').split(',') if p.strip()]
    elif isinstance(raw, list):
        parts = [str(p).strip() for p in raw if str(p).strip()]
    else:
        parts = []
    cn = (common_name or '').strip()
    if cn and cn not in parts:
        parts.insert(0, cn)
    seen: set[str] = set()
    for p in parts:
        low = p.lower()
        if low in seen:
            continue
        seen.add(low)
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', p):
            items.append(f'IP:{p}')
        else:
            items.append(f'DNS:{p}')
    return items


def generate_key_and_csr(
    common_name: str,
    *,
    subject_alt_names: str | list[str] | None = None,
    key_bits: int = 2048,
    organization: str = 'ZIoCHub',
) -> tuple[str, str, list[str]]:
    """
    Generate RSA private key PEM and CSR PEM.

    Returns (key_pem, csr_pem, errors).
    """
    cn = (common_name or '').strip()
    errors: list[str] = []
    if not cn:
        return '', '', ['Common Name (CN) is required']

    bits = int(key_bits or 2048)
    if bits not in (2048, 3072, 4096):
        bits = 2048

    sans = _parse_sans(subject_alt_names, cn)
    san_ext = ','.join(sans) if sans else f'DNS:{cn}'
    subj = f'/CN={cn}/O={organization}'

    key_path = csr_path = None
    try:
        key_path = _write_temp('', '.key')
        csr_path = _write_temp('', '.csr')
        os.remove(key_path)
        os.remove(csr_path)

        ok, _, err = _run_openssl([
            'req', '-new', '-newkey', f'rsa:{bits}', '-nodes',
            '-keyout', key_path, '-out', csr_path,
            '-subj', subj,
            '-addext', f'subjectAltName={san_ext}',
        ])
        if not ok:
            # OpenSSL 1.0.x fallback without -addext
            ok2, _, err2 = _run_openssl([
                'req', '-new', '-newkey', f'rsa:{bits}', '-nodes',
                '-keyout', key_path, '-out', csr_path,
                '-subj', subj,
            ])
            if not ok2:
                return '', '', [err or err2 or 'CSR generation failed']

        with open(key_path, 'r', encoding='utf-8') as fh:
            key_pem = fh.read()
        with open(csr_path, 'r', encoding='utf-8') as fh:
            csr_pem = fh.read()
        if '-----BEGIN' not in key_pem or '-----BEGIN' not in csr_pem:
            return '', '', ['Generated key or CSR is invalid']
        return key_pem, csr_pem, errors
    finally:
        for p in (key_path, csr_path):
            if p and os.path.isfile(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
