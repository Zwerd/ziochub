import os
import re
import csv
import io
import ipaddress
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, Response
import portalocker

# Try to import geoip2, but don't fail if not available
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Directory paths
DATA_MAIN = os.path.join(os.path.dirname(__file__), 'data', 'Main')
DATA_YARA = os.path.join(os.path.dirname(__file__), 'data', 'YARA')
ALLOWLIST_FILE = os.path.join(os.path.dirname(__file__), 'data', 'allowlist.txt')
GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'GeoLite2-City.mmdb')

# Ensure directories exist
os.makedirs(DATA_MAIN, exist_ok=True)
os.makedirs(DATA_YARA, exist_ok=True)

# Load GeoIP database if available
geoip_reader = None
if GEOIP_AVAILABLE and os.path.exists(GEOIP_DB_PATH):
    try:
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception:
        geoip_reader = None

# File mapping for IOC types
IOC_FILES = {
    'IP': 'ip.txt',
    'Domain': 'domain.txt',
    'Hash': 'hash.txt',
    'Email': 'email.txt',
    'URL': 'url.txt'
}

# Strict regex patterns for validation
REGEX_PATTERNS = {
    'IP': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    'Domain': r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
    'Hash': r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$',  # MD5, SHA1, SHA256
    'Email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    'URL': r'^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$'
}

# Auto-detection patterns (more lenient for CSV parsing)
AUTO_DETECT_PATTERNS = {
    'IP': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'Domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    'Hash': r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b',
    'Email': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    'URL': r'https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?'
}


def refanger(value):
    """
    Advanced input cleaning (Refanger) - cleans common IOC obfuscation patterns.
    Returns: (cleaned_value, was_changed)
    """
    if not value:
        return value, False
    
    original = value
    cleaned = value
    
    # Replace obfuscated protocols
    cleaned = re.sub(r'hxxp[s]?', lambda m: 'http' + ('s' if 's' in m.group(0) else ''), cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'h\*\*p[s]?', lambda m: 'http' + ('s' if 's' in m.group(0) else ''), cleaned, flags=re.IGNORECASE)
    
    # Replace obfuscated dots
    cleaned = re.sub(r'\[\.\]', '.', cleaned)
    cleaned = re.sub(r'\(\.\)', '.', cleaned)
    cleaned = re.sub(r'\[dot\]', '.', cleaned, flags=re.IGNORECASE)
    
    # Remove whitespace inside IPs (e.g., "1. 1. 1. 1" -> "1.1.1.1")
    ip_pattern = r'(\d+)\s*\.\s*(\d+)\s*\.\s*(\d+)\s*\.\s*(\d+)'
    cleaned = re.sub(ip_pattern, r'\1.\2.\3.\4', cleaned)
    
    # Strip common prefixes like "ip: " or "IP: "
    cleaned = re.sub(r'^(ip|IP|Ip):\s*', '', cleaned)
    
    was_changed = cleaned != original
    return cleaned.strip(), was_changed


def sanitize_comment(comment):
    """Remove newlines and excessive whitespace from comments."""
    if not comment:
        return ''
    # Replace newlines and carriage returns with spaces
    sanitized = re.sub(r'[\r\n]+', ' ', comment)
    # Collapse multiple spaces
    sanitized = re.sub(r'\s+', ' ', sanitized)
    return sanitized.strip()


def load_allowlist():
    """Load allowlist entries from file."""
    allowlist = []
    if os.path.exists(ALLOWLIST_FILE):
        try:
            with open(ALLOWLIST_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        allowlist.append(line)
        except Exception as e:
            print(f"Error loading allowlist: {e}")
    return allowlist


def check_allowlist(value, ioc_type):
    """
    Check if an IOC is in the allowlist (Safety Net).
    Returns: (is_blocked, reason)
    """
    if ioc_type not in ['IP', 'Domain']:
        return False, None
    
    allowlist = load_allowlist()
    
    for entry in allowlist:
        entry = entry.strip()
        if not entry:
            continue
        
        # Check CIDR ranges
        if '/' in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if ioc_type == 'IP':
                    try:
                        ip = ipaddress.ip_address(value)
                        if ip in network:
                            return True, f"Matches allowlist CIDR: {entry}"
                    except ValueError:
                        pass
            except ValueError:
                pass
        else:
            # Direct match
            if value.lower() == entry.lower():
                return True, f"Matches allowlist entry: {entry}"
            
            # Domain substring match (for domains)
            if ioc_type == 'Domain' and entry in value:
                return True, f"Contains allowlist domain: {entry}"
    
    return False, None


def get_country_code(ip_address):
    """Get country code (lowercase ISO 2-letter) for an IP address using GeoIP."""
    if not geoip_reader:
        return None
    
    try:
        response = geoip_reader.city(ip_address)
        country_code = response.country.iso_code
        if country_code:
            # Return lowercase 2-letter ISO code for flag-icons CSS
            return country_code.lower()
    except Exception:
        pass
    
    return None


def calculate_expiration_date(ttl):
    """Calculate expiration date based on TTL selection."""
    if ttl == 'Permanent':
        return 'NEVER'
    
    today = datetime.now()
    ttl_map = {
        '1 Week': timedelta(weeks=1),
        '1 Month': timedelta(days=30),
        '3 Months': timedelta(days=90),
        '1 Year': timedelta(days=365)
    }
    
    if ttl in ttl_map:
        exp_date = today + ttl_map[ttl]
        return exp_date.strftime('%Y-%m-%d')
    
    return 'NEVER'


def validate_ioc(value, ioc_type):
    """Validate IOC value against strict regex pattern."""
    pattern = REGEX_PATTERNS.get(ioc_type)
    if not pattern:
        return False
    return bool(re.match(pattern, value.strip()))


def write_ioc_to_file(ioc_type, value, username, comment, exp_date, ticket_id=None):
    """Write IOC to file with file locking."""
    filename = IOC_FILES.get(ioc_type)
    if not filename:
        return False
    
    filepath = os.path.join(DATA_MAIN, filename)
    
    # Sanitize inputs
    value = value.strip()
    comment = sanitize_comment(comment)
    username = username.strip()
    ticket_id = ticket_id.strip() if ticket_id else ''
    
    # Format: VALUE # Date:{ISO-8601} | User:{username} | Ref:{ticket_id} | Comment:{comment} | EXP:{YYYY-MM-DD}
    iso_date = datetime.now().isoformat()
    ref_part = f" | Ref:{ticket_id}" if ticket_id else ""
    line = f"{value} # Date:{iso_date} | User:{username}{ref_part} | Comment:{comment} | EXP:{exp_date}\n"
    
    try:
        with open(filepath, 'a', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            f.write(line)
            portalocker.unlock(f)
        return True
    except Exception as e:
        print(f"Error writing to file: {e}")
        return False


def detect_ioc_type(value):
    """Auto-detect IOC type from value."""
    value = value.strip()
    for ioc_type, pattern in REGEX_PATTERNS.items():
        if re.match(pattern, value):
            return ioc_type
    return None


@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')


@app.route('/api/submit-ioc', methods=['POST'])
def submit_ioc():
    """Handle single IOC submission."""
    try:
        data = request.get_json()
        
        value = data.get('value', '').strip()
        ioc_type = data.get('type', '')
        comment = data.get('comment', '')
        username = data.get('username', '').strip()
        ttl = data.get('ttl', 'Permanent')
        ticket_id = data.get('ticket_id', '').strip()
        
        # Validation
        if not value or not ioc_type or not username:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        if ioc_type not in IOC_FILES:
            return jsonify({'success': False, 'message': 'Invalid IOC type'}), 400
        
        # Apply refanger (input cleaning)
        cleaned_value, was_changed = refanger(value)
        value = cleaned_value
        
        # Validate after cleaning
        if not validate_ioc(value, ioc_type):
            return jsonify({'success': False, 'message': f'Invalid {ioc_type} format'}), 400
        
        # Check allowlist (Safety Net)
        is_blocked, reason = check_allowlist(value, ioc_type)
        if is_blocked:
            return jsonify({
                'success': False,
                'message': f'⛔ CRITICAL ASSET: Block Prevented! {reason}'
            }), 403
        
        # Calculate expiration
        exp_date = calculate_expiration_date(ttl)
        
        # Write to file
        if write_ioc_to_file(ioc_type, value, username, comment, exp_date, ticket_id):
            response = {
                'success': True,
                'message': f'{ioc_type} IOC submitted successfully'
            }
            if was_changed:
                response['auto_corrected'] = True
            return jsonify(response)
        else:
            return jsonify({'success': False, 'message': 'Failed to write IOC to file'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/upload-yara', methods=['POST'])
def upload_yara():
    """Handle YARA rule file upload."""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        
        file = request.files['file']
        ticket_id = request.form.get('ticket_id', '').strip()
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        # Check file extension
        if not file.filename.lower().endswith('.yar'):
            return jsonify({'success': False, 'message': 'Invalid file type. Only .yar files are allowed'}), 400
        
        # Sanitize filename
        safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', file.filename)
        if not safe_filename:
            safe_filename = 'rule.yar'
        
        # Append ticket ID to filename if provided
        if ticket_id:
            base_name, ext = os.path.splitext(safe_filename)
            safe_filename = f"{base_name}_T{ticket_id}{ext}"
        
        filepath = os.path.join(DATA_YARA, safe_filename)
        
        # Handle filename conflicts
        counter = 1
        base_name, ext = os.path.splitext(safe_filename)
        while os.path.exists(filepath):
            safe_filename = f"{base_name}_{counter}{ext}"
            filepath = os.path.join(DATA_YARA, safe_filename)
            counter += 1
        
        file.save(filepath)
        
        message = f'YARA rule uploaded successfully: {safe_filename}'
        if ticket_id:
            message += f' (Ticket: {ticket_id})'
        
        return jsonify({
            'success': True,
            'message': message
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/feed/<ioc_type>')
def feed_ioc(ioc_type):
    """Provide clean IOC feed for security devices (no metadata)."""
    # Normalize IOC type (case-insensitive)
    ioc_type = ioc_type.lower().capitalize()
    
    # Map common variations
    type_mapping = {
        'Ip': 'IP',
        'Ipaddress': 'IP',
        'Ip_address': 'IP'
    }
    ioc_type = type_mapping.get(ioc_type, ioc_type)
    
    filename = IOC_FILES.get(ioc_type)
    if not filename:
        return Response("Invalid IOC type", mimetype='text/plain', status=404)
    
    filepath = os.path.join(DATA_MAIN, filename)
    
    # Handle missing file
    if not os.path.exists(filepath):
        return Response("", mimetype='text/plain', status=200)
    
    try:
        clean_iocs = []
        with open(filepath, 'r', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_SH)  # Shared lock for reading
            lines = f.readlines()
            portalocker.unlock(f)
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Split by '#' and take only the IOC value (first part)
            parts = line.split('#', 1)
            ioc_value = parts[0].strip()
            
            if ioc_value:
                clean_iocs.append(ioc_value)
        
        # Return as plain text, one IOC per line
        response_text = '\n'.join(clean_iocs) + '\n'
        return Response(response_text, mimetype='text/plain')
        
    except Exception as e:
        return Response(f"Error reading feed: {str(e)}", mimetype='text/plain', status=500)


def parse_ioc_line(line):
    """Parse an IOC line to extract metadata."""
    line = line.strip()
    if not line:
        return None
    
    # Split by '#' to separate IOC from metadata
    parts = line.split('#', 1)
    if len(parts) < 2:
        return None
    
    ioc_value = parts[0].strip()
    metadata = parts[1].strip()
    
    # Parse metadata: Date:{ISO} | User:{user} | Ref:{ticket_id} | Comment:{comment} | EXP:{date}
    result = {
        'ioc': ioc_value,
        'date': None,
        'user': None,
        'ref': None,
        'comment': None,
        'expiration': None
    }
    
    # Extract Date
    date_match = re.search(r'Date:([^|]+)', metadata)
    if date_match:
        result['date'] = date_match.group(1).strip()
    
    # Extract User
    user_match = re.search(r'User:([^|]+)', metadata)
    if user_match:
        result['user'] = user_match.group(1).strip()
    
    # Extract Ref (ticket_id)
    ref_match = re.search(r'Ref:([^|]+)', metadata)
    if ref_match:
        result['ref'] = ref_match.group(1).strip()
    
    # Extract Comment
    comment_match = re.search(r'Comment:([^|]+)', metadata)
    if comment_match:
        result['comment'] = comment_match.group(1).strip()
    
    # Extract Expiration
    exp_match = re.search(r'EXP:([^|]+|NEVER)', metadata)
    if exp_match:
        result['expiration'] = exp_match.group(1).strip()
    
    return result


def check_expiration_status(exp_date_str):
    """Check expiration status and return detailed information."""
    if not exp_date_str or exp_date_str == 'NEVER':
        return {'status': 'Permanent', 'expires_on': None, 'is_expired': False}
    
    try:
        exp_date = datetime.strptime(exp_date_str, '%Y-%m-%d')
        today = datetime.now()
        is_expired = exp_date < today
        
        if is_expired:
            return {'status': 'Expired', 'expires_on': exp_date_str, 'is_expired': True}
        else:
            return {'status': f'Expires on {exp_date_str}', 'expires_on': exp_date_str, 'is_expired': False}
    except ValueError:
        return {'status': 'Unknown', 'expires_on': None, 'is_expired': False}


@app.route('/api/search', methods=['GET'])
def search_ioc():
    """Search for an IOC across all files with optional field filter."""
    query = request.args.get('q', '').strip()
    filter_type = request.args.get('filter', 'all').strip().lower()
    
    if not query:
        return jsonify({'success': False, 'message': 'Search query is required'}), 400
    
    results = []
    query_lower = query.lower()
    
    # Search through all IOC files
    for ioc_type, filename in IOC_FILES.items():
        filepath = os.path.join(DATA_MAIN, filename)
        
        if not os.path.exists(filepath):
            continue
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                portalocker.lock(f, portalocker.LOCK_SH)
                lines = f.readlines()
                portalocker.unlock(f)
            
            for line_num, line in enumerate(lines, 1):
                parsed = parse_ioc_line(line)
                if not parsed:
                    continue
                
                # Apply filter logic
                match_found = False
                if filter_type == 'all':
                    # Search in all fields
                    match_found = (
                        query_lower in parsed.get('ioc', '').lower() or
                        query_lower in parsed.get('user', '').lower() or
                        query_lower in parsed.get('ref', '').lower() or
                        query_lower in parsed.get('comment', '').lower() or
                        query_lower in parsed.get('date', '').lower()
                    )
                elif filter_type == 'ioc_value':
                    match_found = query_lower in parsed.get('ioc', '').lower()
                elif filter_type == 'ticket_id':
                    match_found = query_lower in parsed.get('ref', '').lower()
                elif filter_type == 'user':
                    match_found = query_lower in parsed.get('user', '').lower()
                elif filter_type == 'date':
                    match_found = query_lower in parsed.get('date', '').lower()
                
                if match_found:
                    parsed['file_type'] = ioc_type
                    parsed['line_number'] = line_num
                    parsed['raw_line'] = line.rstrip('\n\r')
                    # Get detailed expiration status
                    exp_status = check_expiration_status(parsed['expiration'])
                    parsed['expiration_status'] = exp_status['status']
                    parsed['expires_on'] = exp_status['expires_on']
                    parsed['is_expired'] = exp_status['is_expired']
                    # Keep backward compatibility
                    parsed['status'] = 'Expired' if exp_status['is_expired'] else 'Active'
                    # Add country code for IPs
                    if ioc_type == 'IP':
                        country_code = get_country_code(parsed['ioc'])
                        parsed['country_code'] = country_code
                    results.append(parsed)
        
        except Exception as e:
            print(f"Error searching in {filename}: {e}")
            continue
    
    return jsonify({
        'success': True,
        'query': query,
        'filter': filter_type,
        'results': results,
        'count': len(results)
    })


def check_ioc_exists(ioc_type, value):
    """Check if an IOC already exists in the file."""
    filename = IOC_FILES.get(ioc_type)
    if not filename:
        return False
    
    filepath = os.path.join(DATA_MAIN, filename)
    if not os.path.exists(filepath):
        return False
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_SH)
            lines = f.readlines()
            portalocker.unlock(f)
        
        value = value.strip()
        for line in lines:
            parsed = parse_ioc_line(line)
            if parsed and parsed['ioc'].strip() == value:
                return True
        return False
    except Exception:
        return False


def get_existing_iocs_set(ioc_type):
    """Get a set of all existing IOC values for a given type (for fast deduplication)."""
    filename = IOC_FILES.get(ioc_type)
    if not filename:
        return set()
    
    filepath = os.path.join(DATA_MAIN, filename)
    if not os.path.exists(filepath):
        return set()
    
    existing_iocs = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_SH)
            lines = f.readlines()
            portalocker.unlock(f)
        
        for line in lines:
            # Extract IOC value (first part before ' #')
            line = line.strip()
            if not line:
                continue
            
            # Split by '#' to get IOC value
            parts = line.split('#', 1)
            if parts:
                ioc_value = parts[0].strip()
                if ioc_value:
                    existing_iocs.add(ioc_value)
    except Exception as e:
        print(f"Error reading existing IOCs from {filename}: {e}")
    
    return existing_iocs


def load_ioc_file_to_dict(ioc_type):
    """Load an IOC file into a dictionary: {ioc_value: full_line_string}."""
    filename = IOC_FILES.get(ioc_type)
    if not filename:
        return {}
    
    filepath = os.path.join(DATA_MAIN, filename)
    if not os.path.exists(filepath):
        return {}
    
    ioc_dict = {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_SH)
            lines = f.readlines()
            portalocker.unlock(f)
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Extract IOC value (first part before ' #')
            parts = line.split('#', 1)
            if parts:
                ioc_value = parts[0].strip()
                if ioc_value:
                    # Store with newline for writing back
                    ioc_dict[ioc_value] = line + '\n'
    except Exception as e:
        print(f"Error loading IOC file {filename}: {e}")
    
    return ioc_dict


def write_ioc_dict_to_file(ioc_type, ioc_dict):
    """Write an IOC dictionary back to file (for upsert operations)."""
    filename = IOC_FILES.get(ioc_type)
    if not filename:
        return False
    
    filepath = os.path.join(DATA_MAIN, filename)
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            # Write all lines from dictionary
            for line in ioc_dict.values():
                f.write(line)
            portalocker.unlock(f)
        return True
    except Exception as e:
        print(f"Error writing IOC file {filename}: {e}")
        return False


@app.route('/api/v1/ioc', methods=['POST'])
def ingest_ioc():
    """External API endpoint for programmatic IOC ingestion (e.g., MISP integration)."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'Invalid JSON payload'}), 400
        
        ioc_type = data.get('type', '').strip()
        value = data.get('value', '').strip()
        comment = data.get('comment', '')
        username = data.get('username', '').strip()
        expiration = data.get('expiration', 'Permanent').strip()
        ticket_id = data.get('ticket_id', '').strip()
        
        # Validation
        if not value or not ioc_type or not username:
            return jsonify({'success': False, 'message': 'Missing required fields: type, value, username'}), 400
        
        if ioc_type not in IOC_FILES:
            return jsonify({'success': False, 'message': f'Invalid IOC type. Must be one of: {", ".join(IOC_FILES.keys())}'}), 400
        
        # Apply refanger (input cleaning)
        cleaned_value, was_changed = refanger(value)
        value = cleaned_value
        
        # Validate after cleaning
        if not validate_ioc(value, ioc_type):
            return jsonify({'success': False, 'message': f'Invalid {ioc_type} format'}), 400
        
        # Check allowlist (Safety Net)
        is_blocked, reason = check_allowlist(value, ioc_type)
        if is_blocked:
            return jsonify({
                'success': False,
                'message': f'⛔ CRITICAL ASSET: Block Prevented! {reason}'
            }), 403
        
        # Check for duplicates
        if check_ioc_exists(ioc_type, value):
            return jsonify({'success': False, 'message': 'IOC already exists'}), 409
        
        # Handle expiration
        if expiration.lower() == 'permanent':
            exp_date = 'NEVER'
        else:
            # Validate date format
            try:
                datetime.strptime(expiration, '%Y-%m-%d')
                exp_date = expiration
            except ValueError:
                return jsonify({'success': False, 'message': 'Invalid expiration date format. Use YYYY-MM-DD or "Permanent"'}), 400
        
        # Write to file
        if write_ioc_to_file(ioc_type, value, username, comment, exp_date, ticket_id):
            return jsonify({
                'success': True,
                'message': f'{ioc_type} IOC ingested successfully',
                'ioc': value,
                'type': ioc_type
            }), 201
        else:
            return jsonify({'success': False, 'message': 'Failed to write IOC to file'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/revoke', methods=['POST'])
def revoke_ioc():
    """Remove an IOC from the file."""
    try:
        data = request.get_json()
        
        ioc_type = data.get('type', '').strip()
        value = data.get('value', '').strip()
        
        if not value or not ioc_type:
            return jsonify({'success': False, 'message': 'Missing required fields: type, value'}), 400
        
        if ioc_type not in IOC_FILES:
            return jsonify({'success': False, 'message': 'Invalid IOC type'}), 400
        
        filename = IOC_FILES.get(ioc_type)
        filepath = os.path.join(DATA_MAIN, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'message': 'File not found'}), 404
        
        # Read all lines
        with open(filepath, 'r', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            lines = f.readlines()
            portalocker.unlock(f)
        
        # Filter out the matching line
        value = value.strip()
        original_count = len(lines)
        filtered_lines = []
        
        for line in lines:
            parsed = parse_ioc_line(line)
            if parsed and parsed['ioc'].strip() == value:
                continue  # Skip this line
            filtered_lines.append(line)
        
        if len(filtered_lines) == original_count:
            return jsonify({'success': False, 'message': 'IOC not found'}), 404
        
        # Write back filtered lines
        with open(filepath, 'w', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            f.writelines(filtered_lines)
            portalocker.unlock(f)
        
        return jsonify({
            'success': True,
            'message': f'{ioc_type} IOC revoked successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/edit', methods=['POST'])
def edit_ioc():
    """Edit an IOC's metadata (comment and expiration)."""
    try:
        data = request.get_json()
        
        ioc_type = data.get('type', '').strip()
        value = data.get('value', '').strip()
        new_comment = data.get('comment', '')
        new_expiration = data.get('expiration', '').strip()
        
        if not value or not ioc_type:
            return jsonify({'success': False, 'message': 'Missing required fields: type, value'}), 400
        
        if ioc_type not in IOC_FILES:
            return jsonify({'success': False, 'message': 'Invalid IOC type'}), 400
        
        # Validate expiration format
        if new_expiration.lower() == 'permanent':
            exp_date = 'NEVER'
        elif new_expiration:
            try:
                datetime.strptime(new_expiration, '%Y-%m-%d')
                exp_date = new_expiration
            except ValueError:
                return jsonify({'success': False, 'message': 'Invalid expiration date format. Use YYYY-MM-DD or "Permanent"'}), 400
        else:
            return jsonify({'success': False, 'message': 'Expiration is required'}), 400
        
        filename = IOC_FILES.get(ioc_type)
        filepath = os.path.join(DATA_MAIN, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'message': 'File not found'}), 404
        
        # Read all lines
        with open(filepath, 'r', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            lines = f.readlines()
            portalocker.unlock(f)
        
        # Find and update the matching line
        value = value.strip()
        updated = False
        updated_lines = []
        
        for line in lines:
            parsed = parse_ioc_line(line)
            if parsed and parsed['ioc'].strip() == value:
                # Update this line (preserve ticket_id/Ref if it exists)
                username = parsed.get('user', 'unknown')
                ticket_id = parsed.get('ref', '').strip()
                iso_date = datetime.now().isoformat()
                sanitized_comment = sanitize_comment(new_comment)
                ref_part = f" | Ref:{ticket_id}" if ticket_id else ""
                new_line = f"{value} # Date:{iso_date} | User:{username}{ref_part} | Comment:{sanitized_comment} | EXP:{exp_date}\n"
                updated_lines.append(new_line)
                updated = True
            else:
                updated_lines.append(line)
        
        if not updated:
            return jsonify({'success': False, 'message': 'IOC not found'}), 404
        
        # Write back updated lines
        with open(filepath, 'w', encoding='utf-8') as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            f.writelines(updated_lines)
            portalocker.unlock(f)
        
        return jsonify({
            'success': True,
            'message': f'{ioc_type} IOC updated successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/recent', methods=['GET'])
def get_recent():
    """Get the last 15 IOCs added across all files."""
    limit = int(request.args.get('limit', 15))
    all_iocs = []
    
    # Read all IOC files
    for ioc_type, filename in IOC_FILES.items():
        filepath = os.path.join(DATA_MAIN, filename)
        
        if not os.path.exists(filepath):
            continue
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                portalocker.lock(f, portalocker.LOCK_SH)
                lines = f.readlines()
                portalocker.unlock(f)
            
            for line in lines:
                parsed = parse_ioc_line(line)
                if parsed:
                    parsed['file_type'] = ioc_type
                    # Get country code for IPs
                    if ioc_type == 'IP':
                        country_code = get_country_code(parsed['ioc'])
                        parsed['country_code'] = country_code
                    all_iocs.append(parsed)
        
        except Exception as e:
            print(f"Error reading {filename}: {e}")
            continue
    
    # Sort by date (most recent first) and limit
    all_iocs.sort(key=lambda x: x.get('date', ''), reverse=True)
    recent = all_iocs[:limit]
    
    # Add expiration status
    for item in recent:
        exp_status = check_expiration_status(item.get('expiration'))
        item['expiration_status'] = exp_status['status']
        item['is_expired'] = exp_status['is_expired']
    
    return jsonify({
        'success': True,
        'recent': recent,
        'count': len(recent)
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get statistics for active IOCs."""
    stats = {
        'IP': 0,
        'Domain': 0,
        'Hash': 0,
        'Email': 0,
        'URL': 0
    }
    
    today = datetime.now()
    
    for ioc_type, filename in IOC_FILES.items():
        filepath = os.path.join(DATA_MAIN, filename)
        
        if not os.path.exists(filepath):
            continue
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                portalocker.lock(f, portalocker.LOCK_SH)
                lines = f.readlines()
                portalocker.unlock(f)
            
            active_count = 0
            for line in lines:
                parsed = parse_ioc_line(line)
                if parsed:
                    # Check if expired
                    exp_date_str = parsed.get('expiration')
                    if exp_date_str and exp_date_str != 'NEVER':
                        try:
                            exp_date = datetime.strptime(exp_date_str, '%Y-%m-%d')
                            if exp_date < today:
                                continue  # Skip expired
                        except ValueError:
                            pass  # Keep if date parsing fails
                    active_count += 1
            
            stats[ioc_type] = active_count
        
        except Exception as e:
            print(f"Error counting stats for {filename}: {e}")
            continue
    
    return jsonify({
        'success': True,
        'stats': stats
    })


@app.route('/api/all-iocs', methods=['GET'])
def get_all_iocs():
    """Get all IOCs across all files for historical table (limited to last 500 for performance)."""
    limit = int(request.args.get('limit', 500))
    all_iocs = []
    
    # Read all IOC files
    for ioc_type, filename in IOC_FILES.items():
        filepath = os.path.join(DATA_MAIN, filename)
        
        if not os.path.exists(filepath):
            continue
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                portalocker.lock(f, portalocker.LOCK_SH)
                lines = f.readlines()
                portalocker.unlock(f)
            
            for line in lines:
                parsed = parse_ioc_line(line)
                if parsed:
                    parsed['file_type'] = ioc_type
                    # Get country code for IPs
                    if ioc_type == 'IP':
                        country_code = get_country_code(parsed['ioc'])
                        parsed['country_code'] = country_code
                    all_iocs.append(parsed)
        
        except Exception as e:
            print(f"Error reading {filename}: {e}")
            continue
    
    # Sort by date (most recent first) and limit
    all_iocs.sort(key=lambda x: x.get('date', ''), reverse=True)
    limited_iocs = all_iocs[:limit]
    
    # Add expiration status
    for item in limited_iocs:
        exp_status = check_expiration_status(item.get('expiration'))
        item['expiration_status'] = exp_status['status']
        item['is_expired'] = exp_status['is_expired']
    
    return jsonify({
        'success': True,
        'iocs': limited_iocs,
        'count': len(limited_iocs),
        'total': len(all_iocs)
    })


@app.route('/api/bulk-csv', methods=['POST'])
def bulk_csv():
    """Handle bulk CSV intelligence dump."""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        
        file = request.files['file']
        global_comment = request.form.get('comment', '')
        username = request.form.get('username', '').strip()
        ttl = request.form.get('ttl', 'Permanent')
        
        if not username:
            return jsonify({'success': False, 'message': 'Analyst username is required'}), 400
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        # Read CSV content
        stream = io.StringIO(file.read().decode('utf-8'))
        csv_reader = csv.reader(stream)
        
        # Read header row to detect ticket ID column
        header_row = next(csv_reader, None)
        ticket_id_column_index = None
        if header_row:
            # Look for ticket ID columns (case-insensitive)
            ticket_id_keywords = ['reportid', 'ticket_id', 'ref', 'reference']
            for idx, col_name in enumerate(header_row):
                if col_name.lower().strip() in ticket_id_keywords:
                    ticket_id_column_index = idx
                    break
        
        # Calculate expiration
        exp_date = calculate_expiration_date(ttl)
        
        # Load existing IOC files into dictionaries for upsert logic
        current_data = {}
        for ioc_type in IOC_FILES.keys():
            current_data[ioc_type] = load_ioc_file_to_dict(ioc_type)
        
        # Collect all findings with ticket IDs (will be used to update/overwrite)
        findings = {
            'IP': {},
            'Domain': {},
            'Hash': {},
            'Email': {},
            'URL': {}
        }
        
        # Process every row in the CSV
        for row in csv_reader:
            # Extract ticket ID from the row if column was found
            ticket_id = None
            if ticket_id_column_index is not None and ticket_id_column_index < len(row):
                ticket_id = row[ticket_id_column_index].strip()
                if not ticket_id:
                    ticket_id = None
            
            # Process every cell in the row
            for cell in row:
                if not cell:
                    continue
                
                # Apply refanging immediately to the cell value BEFORE regex matching
                # This handles cases like "38[.]60[.]204[.]176"
                cleaned_cell = cell.replace('[.]', '.').replace('[', '').replace(']', '').strip()
                
                # Try to detect IOCs in the cleaned cell
                for ioc_type, pattern in AUTO_DETECT_PATTERNS.items():
                    matches = re.findall(pattern, cleaned_cell)
                    for match in matches:
                        # Apply full refanger for additional cleaning (hxxp, whitespace, etc.)
                        cleaned_match, _ = refanger(match)
                        # Validate the match with strict pattern
                        if validate_ioc(cleaned_match, ioc_type):
                            # Check allowlist (Safety Net)
                            is_blocked, _ = check_allowlist(cleaned_match, ioc_type)
                            if not is_blocked:
                                # Store IOC with ticket ID (use first ticket ID found for this IOC)
                                if cleaned_match not in findings[ioc_type]:
                                    findings[ioc_type][cleaned_match] = ticket_id
        
        # Build new lines for all findings and update dictionaries (upsert)
        summary = {}
        total_updated = 0
        total_new = 0
        
        for ioc_type, ioc_dict in findings.items():
            updated_count = 0
            new_count = 0
            
            for value, ticket_id in ioc_dict.items():
                # Build the new line
                comment = sanitize_comment(global_comment)
                username_val = username.strip()
                ticket_id_val = ticket_id.strip() if ticket_id else ''
                iso_date = datetime.now().isoformat()
                ref_part = f" | Ref:{ticket_id_val}" if ticket_id_val else ""
                new_line = f"{value} # Date:{iso_date} | User:{username_val}{ref_part} | Comment:{comment} | EXP:{exp_date}\n"
                
                # Upsert: Update dictionary (overwrites if exists, adds if new)
                if value in current_data[ioc_type]:
                    updated_count += 1
                else:
                    new_count += 1
                
                current_data[ioc_type][value] = new_line
            
            # Write updated dictionary back to file
            if write_ioc_dict_to_file(ioc_type, current_data[ioc_type]):
                summary[ioc_type] = {'updated': updated_count, 'new': new_count}
                total_updated += updated_count
                total_new += new_count
        
        # Build summary message
        summary_parts = []
        for ioc_type, counts in summary.items():
            if counts['new'] > 0 or counts['updated'] > 0:
                parts = []
                if counts['new'] > 0:
                    parts.append(f"{counts['new']} new")
                if counts['updated'] > 0:
                    parts.append(f"{counts['updated']} updated")
                summary_parts.append(f"{ioc_type}s ({', '.join(parts)})")
        
        message = f"Processed CSV: {', '.join(summary_parts)}" if summary_parts else "No valid IOCs found in CSV"
        
        return jsonify({
            'success': True,
            'message': message,
            'summary': summary,
            'total': total_new + total_updated
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


def remove_duplicates_from_files():
    """Remove duplicate IOCs from all IOC files, keeping the first occurrence of each IOC."""
    print("Starting duplicate cleanup...")
    total_removed = 0
    
    for ioc_type, filename in IOC_FILES.items():
        filepath = os.path.join(DATA_MAIN, filename)
        
        if not os.path.exists(filepath):
            continue
        
        try:
            # Read all lines
            with open(filepath, 'r', encoding='utf-8') as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                lines = f.readlines()
                portalocker.unlock(f)
            
            # Track seen IOC values and keep unique lines
            seen_iocs = set()
            unique_lines = []
            removed_count = 0
            
            for line in lines:
                parsed = parse_ioc_line(line)
                if parsed and parsed.get('ioc'):
                    ioc_value = parsed['ioc'].strip()
                    if ioc_value not in seen_iocs:
                        seen_iocs.add(ioc_value)
                        unique_lines.append(line)
                    else:
                        removed_count += 1
                else:
                    # Keep lines that don't parse correctly (shouldn't happen, but be safe)
                    unique_lines.append(line)
            
            # Write back unique lines if duplicates were found
            if removed_count > 0:
                with open(filepath, 'w', encoding='utf-8') as f:
                    portalocker.lock(f, portalocker.LOCK_EX)
                    f.writelines(unique_lines)
                    portalocker.unlock(f)
                print(f"  {filename}: Removed {removed_count} duplicate(s), kept {len(unique_lines)} unique line(s)")
                total_removed += removed_count
            else:
                print(f"  {filename}: No duplicates found ({len(lines)} lines)")
        
        except Exception as e:
            print(f"Error cleaning duplicates from {filename}: {e}")
            continue
    
    if total_removed > 0:
        print(f"Duplicate cleanup complete: Removed {total_removed} duplicate IOC(s) total")
    else:
        print("Duplicate cleanup complete: No duplicates found")
    
    return total_removed


@app.route('/api/analyst-stats', methods=['GET'])
def get_analyst_stats():
    """Get statistics for all analysts (for Champs Analysis)."""
    analyst_data = {}
    
    # Read all IOC files
    for ioc_type, filename in IOC_FILES.items():
        filepath = os.path.join(DATA_MAIN, filename)
        
        if not os.path.exists(filepath):
            continue
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                portalocker.lock(f, portalocker.LOCK_SH)
                lines = f.readlines()
                portalocker.unlock(f)
            
            for line in lines:
                parsed = parse_ioc_line(line)
                if parsed and parsed.get('user'):
                    user = parsed['user'].strip()
                    if not user:
                        continue
                    
                    if user not in analyst_data:
                        analyst_data[user] = {
                            'total_iocs': 0,
                            'last_activity': None
                        }
                    
                    analyst_data[user]['total_iocs'] += 1
                    
                    # Update last activity date
                    if parsed.get('date'):
                        try:
                            # Parse ISO date
                            date_str = parsed['date'].split('T')[0] if 'T' in parsed['date'] else parsed['date']
                            date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                            if analyst_data[user]['last_activity'] is None or date_obj > analyst_data[user]['last_activity']:
                                analyst_data[user]['last_activity'] = date_obj
                        except (ValueError, AttributeError):
                            pass
        
        except Exception as e:
            print(f"Error reading {filename} for analyst stats: {e}")
            continue
    
    # Convert to list and sort by total IOCs (descending)
    analyst_list = []
    for user, data in analyst_data.items():
        analyst_list.append({
            'user': user,
            'total_iocs': data['total_iocs'],
            'last_activity': data['last_activity'].strftime('%Y-%m-%d') if data['last_activity'] else 'N/A'
        })
    
    # Sort by total IOCs descending
    analyst_list.sort(key=lambda x: x['total_iocs'], reverse=True)
    
    # Add rank
    for idx, analyst in enumerate(analyst_list, 1):
        analyst['rank'] = idx
    
    return jsonify({
        'success': True,
        'analysts': analyst_list,
        'count': len(analyst_list)
    })


@app.route('/api/upload-txt', methods=['POST'])
def upload_txt():
    """Handle bulk TXT file upload with smart parsing."""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        
        file = request.files['file']
        default_ticket_id = request.form.get('ticket_id', '').strip()
        username = request.form.get('username', '').strip()
        ttl = request.form.get('ttl', 'Permanent')
        
        if not username:
            return jsonify({'success': False, 'message': 'Analyst username is required'}), 400
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        # Read file content
        content = file.read().decode('utf-8')
        lines = content.split('\n')
        
        # Calculate expiration
        exp_date = calculate_expiration_date(ttl)
        
        # Load existing IOC files into dictionaries for upsert logic
        current_data = {}
        for ioc_type in IOC_FILES.keys():
            current_data[ioc_type] = load_ioc_file_to_dict(ioc_type)
        
        # Process each line
        findings = {
            'IP': {},
            'Domain': {},
            'Hash': {},
            'Email': {},
            'URL': {}
        }
        
        # Regex patterns for date and user extraction
        date_pattern = re.compile(r'\b(\d{1,2})/(\d{1,2})/(\d{4})\b')
        user_pattern = re.compile(r'\b(?:by|user|analyst|from)[\s:]+([a-zA-Z0-9_-]+)', re.IGNORECASE)
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Split by '#' delimiter
            parts = line.split('#', 1)
            if len(parts) < 2:
                continue
            
            ioc_raw = parts[0].strip()
            metadata_raw = parts[1].strip()
            
            # Clean IOC (remove brackets, whitespace)
            ioc_cleaned = ioc_raw.replace('[.]', '.').replace('[', '').replace(']', '').strip()
            
            # Detect IOC type
            ioc_type = None
            for test_type, pattern in REGEX_PATTERNS.items():
                if re.match(pattern, ioc_cleaned):
                    ioc_type = test_type
                    break
            
            if not ioc_type:
                continue
            
            # Check allowlist
            is_blocked, _ = check_allowlist(ioc_cleaned, ioc_type)
            if is_blocked:
                continue
            
            # Smart extraction from metadata
            extracted_date = None
            extracted_user = username  # Default to provided username
            extracted_ticket_id = default_ticket_id if default_ticket_id else None
            comment = metadata_raw
            
            # Try to extract date
            date_match = date_pattern.search(metadata_raw)
            if date_match:
                try:
                    month, day, year = date_match.groups()
                    extracted_date = datetime(int(year), int(month), int(day))
                    # Remove date from comment
                    comment = date_pattern.sub('', comment).strip()
                except ValueError:
                    pass
            
            # Try to extract user
            user_match = user_pattern.search(metadata_raw)
            if user_match:
                extracted_user = user_match.group(1).strip()
                # Remove user pattern from comment
                comment = user_pattern.sub('', comment).strip()
            
            # Clean up comment (remove extra whitespace, commas)
            comment = re.sub(r'[,\|]+', ' ', comment).strip()
            comment = re.sub(r'\s+', ' ', comment)
            
            # Use extracted or default values
            final_user = extracted_user if extracted_user else username
            final_date = extracted_date if extracted_date else datetime.now()
            final_ticket_id = extracted_ticket_id
            
            # Build the line
            comment_sanitized = sanitize_comment(comment)
            iso_date = final_date.isoformat()
            ref_part = f" | Ref:{final_ticket_id}" if final_ticket_id else ""
            new_line = f"{ioc_cleaned} # Date:{iso_date} | User:{final_user}{ref_part} | Comment:{comment_sanitized} | EXP:{exp_date}\n"
            
            # Store in findings
            if ioc_cleaned not in findings[ioc_type]:
                findings[ioc_type][ioc_cleaned] = new_line
        
        # Upsert: Update dictionaries
        summary = {}
        total_updated = 0
        total_new = 0
        
        for ioc_type, ioc_dict in findings.items():
            updated_count = 0
            new_count = 0
            
            for value, new_line in ioc_dict.items():
                if value in current_data[ioc_type]:
                    updated_count += 1
                else:
                    new_count += 1
                
                current_data[ioc_type][value] = new_line
            
            # Write updated dictionary back to file
            if write_ioc_dict_to_file(ioc_type, current_data[ioc_type]):
                summary[ioc_type] = {'updated': updated_count, 'new': new_count}
                total_updated += updated_count
                total_new += new_count
        
        # Build summary message
        summary_parts = []
        for ioc_type, counts in summary.items():
            if counts['new'] > 0 or counts['updated'] > 0:
                parts = []
                if counts['new'] > 0:
                    parts.append(f"{counts['new']} new")
                if counts['updated'] > 0:
                    parts.append(f"{counts['updated']} updated")
                summary_parts.append(f"{ioc_type}s ({', '.join(parts)})")
        
        message = f"Processed TXT: {', '.join(summary_parts)}" if summary_parts else "No valid IOCs found in TXT"
        
        return jsonify({
            'success': True,
            'message': message,
            'summary': summary,
            'total': total_new + total_updated
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


if __name__ == '__main__':
    # Run one-time duplicate cleanup on server start
    remove_duplicates_from_files()
    app.run(debug=True, host='0.0.0.0', port=5000)
