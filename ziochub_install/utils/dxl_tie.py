"""
DXL / TIE integration: connect to OpenDXL fabric and set file reputation (Known Malicious) in TIE.
Used when analysts submit Hash IOCs so ePO/TIE endpoints see the reputation.
Optional: if dxlclient/dxltieclient are not installed, all functions no-op or return failure steps.
"""
import logging
import os

DXL_AVAILABLE = False
try:
    from dxlclient.client import DxlClient
    from dxlclient.client_config import DxlClientConfig
    from dxltieclient.client import TieClient
    from dxltieclient.constants import TrustLevel, HashType
    DXL_AVAILABLE = True
except ImportError:
    pass

# Test hash used by Test Connection (SHA256 of "ZIoCHub-DXL-test")
TEST_HASH_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _hash_type_from_length(value):
    """Map hash value length to TIE HashType. value is hex string."""
    if not value or not isinstance(value, str):
        return None
    n = len(value.strip())
    if n == 32:
        return HashType.MD5
    if n == 40:
        return HashType.SHA1
    if n == 64:
        return HashType.SHA256
    if n == 128:
        return getattr(HashType, 'SHA512', None)  # if TIE supports it
    return None


def test_dxl_connection_steps(config_path):
    """
    Run DXL connection test step-by-step. Returns list of { step, status, message }.
    status is 'ok' or 'fail'. Includes loading config, connect, and optional set_file_reputation test.
    """
    steps = []
    if not config_path or not (config_path := str(config_path).strip()):
        steps.append({'step': 'Config path', 'status': 'fail', 'message': 'Config path is empty'})
        return steps
    if not DXL_AVAILABLE:
        steps.append({
            'step': 'DXL libraries',
            'status': 'fail',
            'message': 'dxlclient/dxltieclient not installed. Install with: pip install dxlclient dxltieclient',
        })
        return steps
    # 1) File exists
    if not os.path.isfile(config_path):
        steps.append({'step': 'Config file', 'status': 'fail', 'message': f'File not found: {config_path}'})
        return steps
    steps.append({'step': 'Config file', 'status': 'ok', 'message': f'Found: {config_path}'})

    # 2) Load config
    try:
        config = DxlClientConfig.create_dxl_config_from_file(config_path)
    except Exception as e:
        steps.append({'step': 'Load config', 'status': 'fail', 'message': str(e)})
        return steps
    steps.append({'step': 'Load config', 'status': 'ok', 'message': 'Config loaded'})

    # 3) Connect
    client = None
    try:
        client = DxlClient(config)
        client.connect()
    except Exception as e:
        steps.append({'step': 'Connect to broker', 'status': 'fail', 'message': str(e)})
        if client:
            try:
                client.destroy()
            except Exception:
                pass
        return steps
    steps.append({'step': 'Connect to broker', 'status': 'ok', 'message': 'Connected to DXL fabric'})

    # 4) TIE set_file_reputation test (so we verify broker + TIE permission)
    try:
        tie_client = TieClient(client)
        tie_client.set_file_reputation(
            TrustLevel.KNOWN_MALICIOUS,
            {HashType.SHA256: TEST_HASH_SHA256},
            filename='ZIoCHub-DXL-test',
            comment='ZIoCHub Test Connection',
        )
        steps.append({'step': 'TIE set reputation', 'status': 'ok', 'message': 'Test reputation sent to TIE'})
    except Exception as e:
        steps.append({'step': 'TIE set reputation', 'status': 'fail', 'message': str(e)})
    finally:
        try:
            client.disconnect()
            client.destroy()
        except Exception:
            pass
    return steps


def push_hash_to_tie(config_path, hash_value, audit_log_fn=None):
    """
    Set file reputation in TIE to Known Malicious for the given hash.
    config_path: path to dxlclient.config (or equivalent).
    hash_value: hex string (MD5 32, SHA1 40, SHA256 64, SHA512 128).
    audit_log_fn: optional callable(action, detail) for audit (e.g. app.audit_log).
    Returns True on success, False on failure (errors are logged; IOC is not rolled back).
    """
    if not DXL_AVAILABLE:
        logging.warning('DXL push skipped: dxlclient/dxltieclient not installed')
        return False
    if not config_path or not (config_path := str(config_path).strip()):
        logging.warning('DXL push skipped: config path empty')
        return False
    if not os.path.isfile(config_path):
        logging.warning('DXL push skipped: config file not found: %s', config_path)
        return False
    hash_value = (hash_value or '').strip()
    if not hash_value:
        return False
    hash_type = _hash_type_from_length(hash_value)
    if not hash_type:
        logging.warning('DXL push skipped: unsupported hash length for %s', hash_value[:16] + '...')
        return False

    client = None
    try:
        config = DxlClientConfig.create_dxl_config_from_file(config_path)
        client = DxlClient(config)
        client.connect()
        tie_client = TieClient(client)
        tie_client.set_file_reputation(
            TrustLevel.KNOWN_MALICIOUS,
            {hash_type: hash_value},
            comment='ZIoCHub IOC submission',
        )
        if audit_log_fn:
            try:
                audit_log_fn('DXL_TIE_PUSH', f'hash={hash_value[:16]}... type={hash_type}')
            except Exception:
                pass
        return True
    except Exception as e:
        logging.exception('DXL TIE push failed for hash %s: %s', hash_value[:16] + '...', e)
        if audit_log_fn:
            try:
                audit_log_fn('DXL_TIE_PUSH_FAIL', f'hash={hash_value[:16]}... error={str(e)[:100]}')
            except Exception:
                pass
        return False
    finally:
        if client:
            try:
                client.disconnect()
                client.destroy()
            except Exception:
                pass
