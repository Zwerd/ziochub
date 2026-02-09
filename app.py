"""
ThreatGate - IOC & YARA Management (SQLite backend).

MIGRATION: Before first run with SQLite, manually backup your data/ folder:
    - Copy the entire data/ directory (e.g. data/ -> data_backup_YYYYMMDD/)
    - Migration runs once on startup when the DB is empty and imports from data/Main/*.txt and data/Main/yara.txt
"""
import os
import re
import csv
import io
import base64
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, UniqueConstraint, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload

# Try to import geoip2, but don't fail if not available
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# Directory paths — must be defined before app (data/ is SMB share, holds DB and IOC data)
_base_dir = os.path.dirname(os.path.abspath(__file__))
_data_dir = os.path.join(_base_dir, 'data')
# Resolve data/Main so it works on case-sensitive FS (e.g. "Main" vs "main")
_main_candidate = os.path.join(_data_dir, 'Main')
if os.path.isdir(_main_candidate):
    DATA_MAIN = _main_candidate
else:
    for name in (os.listdir(_data_dir) if os.path.isdir(_data_dir) else []):
        if name.lower() == 'main':
            DATA_MAIN = os.path.join(_data_dir, name)
            break
    else:
        DATA_MAIN = _main_candidate  # use default and create below
DATA_YARA = os.path.join(_data_dir, 'YARA')
ALLOWLIST_FILE = os.path.join(_data_dir, 'allowlist.txt')
GEOIP_DB_PATH = os.path.join(_data_dir, 'GeoLite2-City.mmdb')
os.makedirs(DATA_MAIN, exist_ok=True)
os.makedirs(DATA_YARA, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
# SQLite database under data/ (SMB share)
_db_path = os.path.join(_data_dir, 'threatgate.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + _db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Audit Logger ---
_audit_logger = logging.getLogger('threatgate.audit')
_audit_handler = logging.FileHandler(os.path.join(_data_dir, 'audit.log'))
_audit_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s'))
_audit_logger.addHandler(_audit_handler)
_audit_logger.setLevel(logging.INFO)

def audit_log(action: str, detail: str = ''):
    """Write a structured line to the audit log file."""
    client_ip = request.remote_addr if request else '-'
    _audit_logger.info(f'{action} | ip={client_ip} | {detail}')


def _utcnow():
    """Return current UTC time as a naive datetime (drop tzinfo for SQLite compat)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

# Load GeoIP database if available
geoip_reader = None
if GEOIP_AVAILABLE and os.path.exists(GEOIP_DB_PATH):
    try:
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception:
        geoip_reader = None

# File mapping for IOC types (YARA log lives in Main for Live Feed visibility).
# All IOC data is stored under DATA_MAIN (data/Main/): hash.txt, email.txt, url.txt, etc.
FILE_YARA = os.path.join(DATA_MAIN, 'yara.txt')
IOC_FILES = {
    'IP': 'ip.txt',
    'Domain': 'domain.txt',
    'Hash': 'hash.txt',   # data/Main/hash.txt
    'Email': 'email.txt', # data/Main/email.txt
    'URL': 'url.txt',     # data/Main/url.txt
    'YARA': 'yara.txt'
}

# --- SQLAlchemy models ---
class Campaign(db.Model):
    __tablename__ = 'campaigns'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow)
    iocs = db.relationship('IOC', backref='campaign', lazy=True, foreign_keys='IOC.campaign_id')


class IOC(db.Model):
    __tablename__ = 'iocs'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)
    value = db.Column(db.String(1024), nullable=False)
    analyst = db.Column(db.String(255), nullable=False)
    ticket_id = db.Column(db.String(255), nullable=True)
    comment = db.Column(db.Text, nullable=True)
    expiration_date = db.Column(db.DateTime, nullable=True)  # NULL = Permanent
    created_at = db.Column(db.DateTime, default=_utcnow)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=True)
    __table_args__ = (UniqueConstraint('type', 'value', name='u_type_value'),)


class YaraRule(db.Model):
    __tablename__ = 'yara_rules'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), unique=True, nullable=False)
    analyst = db.Column(db.String(255), nullable=False)
    ticket_id = db.Column(db.String(255), nullable=True)
    comment = db.Column(db.Text, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=_utcnow)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=True)


def get_ioc_filepath(ioc_type):
    """Single source of truth for IOC file paths. Used by write_ioc_to_file, get_stats, and all other readers/writers."""
    filename = IOC_FILES.get(ioc_type)
    if not filename:
        return None
    return os.path.join(DATA_MAIN, filename)

# Strict regex patterns for validation
REGEX_PATTERNS = {
    'IP': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    'Domain': r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
    'Hash': r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$',  # MD5, SHA1, SHA256
    'Email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    'URL': r'^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$'
}

# Auto-detection patterns (more lenient for CSV parsing)
# Domain uses (?<!@) so e.g. user@example.com is not matched as Domain (only as Email)
AUTO_DETECT_PATTERNS = {
    'IP': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'Domain': r'(?<!@)\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    'Hash': r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b',
    'Email': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    'URL': r'https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?'
}

# Detection priority: check more specific types first so e.g. user@example.com is Email, not Domain
PRIORITY_ORDER = ['URL', 'Email', 'IP', 'Hash', 'Domain']


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
    """Calculate expiration date based on TTL selection. Returns datetime or None (Permanent)."""
    if ttl == 'Permanent':
        return None
    today = datetime.now()
    ttl_map = {
        '1 Week': timedelta(weeks=1),
        '1 Month': timedelta(days=30),
        '3 Months': timedelta(days=90),
        '1 Year': timedelta(days=365)
    }
    if ttl in ttl_map:
        return today + ttl_map[ttl]
    return None


def validate_ioc(value, ioc_type):
    """Validate IOC value against strict regex pattern."""
    pattern = REGEX_PATTERNS.get(ioc_type)
    if not pattern:
        return False
    return bool(re.match(pattern, value.strip()))


def check_ioc_exists(ioc_type, value):
    """Check if an IOC already exists in DB (case-insensitive)."""
    return IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == value.strip().lower()).first() is not None


def detect_ioc_type(value):
    """Auto-detect IOC type from value. Uses PRIORITY_ORDER so Email is chosen over Domain."""
    value = value.strip()
    for ioc_type in PRIORITY_ORDER:
        pattern = REGEX_PATTERNS.get(ioc_type)
        if pattern and re.match(pattern, value):
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
        campaign_name = (data.get('campaign_name') or '').strip() or None
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id
        
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
        
        # Prevent duplicate IOCs (case-insensitive)
        if check_ioc_exists(ioc_type, value):
            return jsonify({'success': False, 'message': 'IOC already exists'}), 409
        
        exp_date = calculate_expiration_date(ttl)
        try:
            db.session.add(IOC(
                type=ioc_type,
                value=value.strip(),
                analyst=username.strip().lower(),
                ticket_id=ticket_id or None,
                comment=sanitize_comment(comment) or None,
                expiration_date=exp_date,
                campaign_id=campaign_id
            ))
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({'success': False, 'message': 'IOC already exists'}), 409
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500
        audit_log('IOC_CREATE', f'type={ioc_type} value={value} analyst={username}')
        response = {'success': True, 'message': f'{ioc_type} IOC submitted successfully'}
        if was_changed:
            response['auto_corrected'] = True
        return jsonify(response)
            
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
        campaign_name = (request.form.get('campaign_name') or '').strip() or None
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id
        
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
        if os.path.exists(filepath):
            return jsonify({'success': False, 'message': 'Rule name already exists'}), 409
        if YaraRule.query.filter_by(filename=safe_filename).first():
            return jsonify({'success': False, 'message': 'Rule name already exists'}), 409
        
        # Basic YARA syntax validation before saving
        file_content = file.read().decode('utf-8', errors='replace')
        if not re.search(r'\brule\s+\w+', file_content):
            return jsonify({'success': False, 'message': 'Invalid YARA file: missing "rule <name>" declaration'}), 400
        if '{' not in file_content or '}' not in file_content:
            return jsonify({'success': False, 'message': 'Invalid YARA file: missing rule body braces'}), 400
        # Save validated content
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(file_content)
        username = request.form.get('username', 'upload').strip().lower() or 'upload'
        comment = (request.form.get('comment') or '').strip() or 'Uploaded YARA Rule'
        try:
            db.session.add(YaraRule(
                filename=safe_filename,
                analyst=username,
                ticket_id=ticket_id or None,
                comment=comment,
                campaign_id=campaign_id
            ))
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except Exception:
                    pass
            return jsonify({'success': False, 'message': str(e)}), 500
        audit_log('YARA_UPLOAD', f'file={safe_filename} analyst={username}')
        message = f'YARA rule uploaded successfully: {safe_filename}'
        if ticket_id:
            message += f' (Ticket: {ticket_id})'
        
        return jsonify({
            'success': True,
            'message': message
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/list-yara', methods=['GET'])
def list_yara():
    """List YARA rule files in data/YARA/ with metadata from YaraRule table."""
    try:
        files = []
        if not os.path.isdir(DATA_YARA):
            return jsonify({'success': True, 'files': []})
        for name in sorted(os.listdir(DATA_YARA)):
            if not name.lower().endswith('.yar'):
                continue
            filepath = os.path.join(DATA_YARA, name)
            if not os.path.isfile(filepath):
                continue
            size_bytes = os.path.getsize(filepath)
            mtime = os.path.getmtime(filepath)
            size_kb = round(size_bytes / 1024, 2)
            meta = YaraRule.query.filter_by(filename=name).first()
            if meta and meta.uploaded_at:
                upload_date = meta.uploaded_at.strftime('%Y-%m-%d %H:%M')
            else:
                upload_date = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')
            files.append({
                'filename': name,
                'size_kb': size_kb,
                'upload_date': upload_date,
                'user': meta.analyst if meta else None,
                'ticket_id': meta.ticket_id if meta else None,
                'comment': meta.comment if meta else None
            })
        return jsonify({'success': True, 'files': files})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


def _yara_safe_path(filename):
    """Return (safe_basename, full_path) if path is under DATA_YARA; else (None, None). Prevents path traversal."""
    safe = os.path.basename(filename)
    if safe != filename or '..' in filename or not safe.lower().endswith('.yar'):
        return None, None
    filepath = os.path.join(DATA_YARA, safe)
    try:
        real_file = os.path.realpath(filepath)
        real_yara = os.path.realpath(DATA_YARA)
        if not real_file.startswith(real_yara + os.sep) and real_file != real_yara:
            return None, None
    except Exception:
        return None, None
    return safe, filepath


@app.route('/api/delete-yara', methods=['DELETE'])
def delete_yara():
    """Delete a YARA rule file from data/YARA/."""
    try:
        data = request.get_json() or {}
        filename = (data.get('filename') or '').strip()
        if not filename:
            return jsonify({'success': False, 'message': 'Filename is required'}), 400
        safe, filepath = _yara_safe_path(filename)
        if safe is None:
            return jsonify({'success': False, 'message': 'Invalid filename'}), 400
        if not os.path.isfile(filepath):
            return jsonify({'success': False, 'message': 'File not found'}), 404
        os.remove(filepath)
        YaraRule.query.filter_by(filename=safe).delete()
        db.session.commit()
        return jsonify({'success': True, 'message': f'Deleted {safe}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/view-yara/<path:filename>', methods=['GET'])
def view_yara(filename):
    """Return the content of a specific .yar file (path traversal safe)."""
    try:
        safe, filepath = _yara_safe_path(filename)
        if safe is None:
            return jsonify({'success': False, 'message': 'Invalid filename'}), 400
        if not os.path.isfile(filepath):
            return jsonify({'success': False, 'message': 'File not found'}), 404
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        return jsonify({'success': True, 'filename': safe, 'content': content})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/update-yara', methods=['POST'])
def update_yara():
    """Overwrite an existing YARA rule file. Accepts JSON { filename, content }."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'JSON body required'}), 400
        filename = (data.get('filename') or '').strip()
        content = data.get('content')
        if not filename:
            return jsonify({'success': False, 'message': 'Filename is required'}), 400
        if content is None:
            return jsonify({'success': False, 'message': 'Content is required'}), 400
        safe, filepath = _yara_safe_path(filename)
        if safe is None:
            return jsonify({'success': False, 'message': 'Invalid filename'}), 400
        if not os.path.isfile(filepath):
            return jsonify({'success': False, 'message': 'File not found'}), 404
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content if isinstance(content, str) else '')
        return jsonify({'success': True, 'message': f'Updated {safe}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/feed/yara-list', methods=['GET'])
def feed_yara_list():
    """Return plain text list of all .yar filenames in DATA_YARA (one per line)."""
    try:
        if not os.path.isdir(DATA_YARA):
            return Response("", mimetype='text/plain')
        names = []
        for name in sorted(os.listdir(DATA_YARA)):
            if not name.lower().endswith('.yar'):
                continue
            fp = os.path.join(DATA_YARA, name)
            if os.path.isfile(fp):
                names.append(name)
        return Response(('\n'.join(names) + ('\n' if names else '')), mimetype='text/plain')
    except Exception as e:
        return Response(f"Error: {e}", mimetype='text/plain', status=500)


@app.route('/feed/yara-content/<path:filename>', methods=['GET'])
def feed_yara_content(filename):
    """Return raw content of a .yar file. Uses _yara_safe_path to prevent path traversal."""
    safe, filepath = _yara_safe_path(filename)
    if safe is None:
        return Response("Invalid filename", mimetype='text/plain', status=400)
    if not os.path.isfile(filepath):
        return Response("File not found", mimetype='text/plain', status=404)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        return Response(content, mimetype='text/plain')
    except Exception as e:
        return Response(f"Error: {e}", mimetype='text/plain', status=500)


@app.route('/feed/<ioc_type>')
def feed_ioc(ioc_type):
    """Provide clean IOC feed for security devices: only active (non-expired) IOCs."""
    ioc_type_raw = ioc_type.strip()
    type_mapping = {
        'ip': 'IP', 'ipaddress': 'IP', 'ip_address': 'IP',
        'domain': 'Domain',
        'hash': 'Hash',
        'email': 'Email',
        'url': 'URL',
    }
    ioc_type = type_mapping.get(ioc_type_raw.lower(), ioc_type_raw)
    if ioc_type not in IOC_FILES or ioc_type == 'YARA':
        return Response("Invalid IOC type", mimetype='text/plain', status=404)
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == ioc_type,
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    response_text = '\n'.join(r.value for r in rows) + '\n'
    return Response(response_text, mimetype='text/plain')


def strip_url_protocol(url):
    """Remove http:// or https:// from URL for Palo Alto feeds."""
    if not url:
        return url
    url = url.strip()
    if url.startswith('https://'):
        return url[8:]
    elif url.startswith('http://'):
        return url[7:]
    return url


def get_hash_type(hash_value):
    """Determine hash type based on length: MD5 (32), SHA1 (40), SHA256 (64)."""
    if not hash_value:
        return None
    hash_len = len(hash_value.strip())
    if hash_len == 32:
        return 'md5'
    elif hash_len == 40:
        return 'sha1'
    elif hash_len == 64:
        return 'sha256'
    return None


def format_checkpoint_feed(rows, ioc_type):
    """Format IOC rows as Checkpoint feed with header and observe numbers."""
    if not rows:
        header = "#Uniq-Name,#Value,#Type,#Confidence,#Severity,#Product,#Comment\n"
        return header
    
    # Map IOC types to Checkpoint types
    cp_type_map = {
        'IP': 'ip',
        'Domain': 'domain',
        'URL': 'url',
        'Hash': None  # Will be determined by hash length
    }
    
    lines = ["#Uniq-Name,#Value,#Type,#Confidence,#Severity,#Product,#Comment"]
    
    observe_num = 1
    for row in rows:
        value = row.value.strip()
        
        # Determine Checkpoint type
        if ioc_type == 'Hash':
            # Determine hash type from length
            hash_type = get_hash_type(value)
            if not hash_type:
                continue
            cp_type = hash_type
        else:
            cp_type = cp_type_map.get(ioc_type, 'ip')
        
        # Format the line
        comment = f'"""Malicious {cp_type.upper()}"""'
        line = f"observe{observe_num},{value},{cp_type},high,high,AV,{comment}"
        lines.append(line)
        observe_num += 1
    
    return '\n'.join(lines) + '\n'


# Standard feed endpoints
@app.route('/feed/ip', methods=['GET'])
def feed_ip():
    """Standard IP feed."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'IP',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    response_text = '\n'.join(r.value for r in rows) + '\n'
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/domain', methods=['GET'])
def feed_domain():
    """Standard domain feed."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Domain',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    response_text = '\n'.join(r.value for r in rows) + '\n'
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/url', methods=['GET'])
def feed_url():
    """Standard URL feed."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'URL',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    response_text = '\n'.join(r.value for r in rows) + '\n'
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/md5', methods=['GET'])
def feed_md5():
    """Standard MD5 hash feed (32 hex characters)."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Hash',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    # Filter only MD5 hashes (32 characters)
    md5_rows = [r for r in rows if len(r.value.strip()) == 32]
    response_text = '\n'.join(r.value for r in md5_rows) + '\n'
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/sha1', methods=['GET'])
def feed_sha1():
    """Standard SHA1 hash feed (40 hex characters)."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Hash',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    # Filter only SHA1 hashes (40 characters)
    sha1_rows = [r for r in rows if len(r.value.strip()) == 40]
    response_text = '\n'.join(r.value for r in sha1_rows) + '\n'
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/sha256', methods=['GET'])
def feed_sha256():
    """Standard SHA256 hash feed (64 hex characters)."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Hash',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    # Filter only SHA256 hashes (64 characters)
    sha256_rows = [r for r in rows if len(r.value.strip()) == 64]
    response_text = '\n'.join(r.value for r in sha256_rows) + '\n'
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/hash', methods=['GET'])
def feed_hash():
    """Standard hash feed (all hash types: MD5, SHA1, SHA256)."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Hash',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    response_text = '\n'.join(r.value for r in rows) + '\n'
    return Response(response_text, mimetype='text/plain')


# Palo Alto feed endpoints
@app.route('/feed/pa/ip', methods=['GET'])
def feed_pa_ip():
    """Palo Alto IP feed."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'IP',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    response_text = '\n'.join(r.value for r in rows) + '\n'
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/pa/domain', methods=['GET'])
def feed_pa_domain():
    """Palo Alto domain feed."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Domain',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    response_text = '\n'.join(r.value for r in rows) + '\n'
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/pa/url', methods=['GET'])
def feed_pa_url():
    """Palo Alto URL feed (URLs without http/https protocol)."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'URL',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    # Strip protocol from URLs for Palo Alto
    urls = [strip_url_protocol(r.value) for r in rows]
    response_text = '\n'.join(urls) + '\n'
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/pa/md5', methods=['GET'])
def feed_pa_md5():
    """Palo Alto MD5 hash feed (32 hex characters)."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Hash',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    # Filter only MD5 hashes (32 characters)
    md5_rows = [r for r in rows if len(r.value.strip()) == 32]
    response_text = '\n'.join(r.value for r in md5_rows) + '\n'
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/pa/sha1', methods=['GET'])
def feed_pa_sha1():
    """Palo Alto SHA1 hash feed (40 hex characters)."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Hash',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    # Filter only SHA1 hashes (40 characters)
    sha1_rows = [r for r in rows if len(r.value.strip()) == 40]
    response_text = '\n'.join(r.value for r in sha1_rows) + '\n'
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/pa/sha256', methods=['GET'])
def feed_pa_sha256():
    """Palo Alto SHA256 hash feed (64 hex characters)."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Hash',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    # Filter only SHA256 hashes (64 characters)
    sha256_rows = [r for r in rows if len(r.value.strip()) == 64]
    response_text = '\n'.join(r.value for r in sha256_rows) + '\n'
    return Response(response_text, mimetype='text/plain')


# Checkpoint feed endpoints
@app.route('/feed/cp/ip', methods=['GET'])
def feed_cp_ip():
    """Checkpoint IP feed in CSV format."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'IP',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    response_text = format_checkpoint_feed(rows, 'IP')
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/cp/domain', methods=['GET'])
def feed_cp_domain():
    """Checkpoint domain feed in CSV format."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Domain',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    response_text = format_checkpoint_feed(rows, 'Domain')
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/cp/url', methods=['GET'])
def feed_cp_url():
    """Checkpoint URL feed in CSV format."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'URL',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    response_text = format_checkpoint_feed(rows, 'URL')
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/cp/md5', methods=['GET'])
def feed_cp_md5():
    """Checkpoint MD5 hash feed in CSV format (32 hex characters)."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Hash',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    # Filter only MD5 hashes (32 characters)
    md5_rows = [r for r in rows if len(r.value.strip()) == 32]
    response_text = format_checkpoint_feed(md5_rows, 'Hash')
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/cp/sha1', methods=['GET'])
def feed_cp_sha1():
    """Checkpoint SHA1 hash feed in CSV format (40 hex characters)."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Hash',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    # Filter only SHA1 hashes (40 characters)
    sha1_rows = [r for r in rows if len(r.value.strip()) == 40]
    response_text = format_checkpoint_feed(sha1_rows, 'Hash')
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/cp/sha256', methods=['GET'])
def feed_cp_sha256():
    """Checkpoint SHA256 hash feed in CSV format (64 hex characters)."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Hash',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    # Filter only SHA256 hashes (64 characters)
    sha256_rows = [r for r in rows if len(r.value.strip()) == 64]
    response_text = format_checkpoint_feed(sha256_rows, 'Hash')
    return Response(response_text, mimetype='text/plain')


@app.route('/feed/cp/hash', methods=['GET'])
def feed_cp_hash():
    """Checkpoint hash feed in CSV format (all hash types: MD5, SHA1, SHA256)."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == 'Hash',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
    # Include all hash types (MD5, SHA1, SHA256)
    response_text = format_checkpoint_feed(rows, 'Hash')
    return Response(response_text, mimetype='text/plain')


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


def _parse_ioc_line_permissive(line):
    """Return a dict with at least ioc, date, user, ref, comment, expiration. Raw lines (no '#') get minimal dict."""
    parsed = parse_ioc_line(line)
    if parsed:
        return parsed
    line = line.strip()
    if not line:
        return None
    ioc_value = line.split('#', 1)[0].strip()
    if not ioc_value:
        return None
    return {
        'ioc': ioc_value,
        'date': None,
        'user': '',
        'ref': '',
        'comment': '',
        'expiration': None
    }


def check_expiration_status(exp_date_str):
    """Check expiration status. Malformed dates default to Permanent/Active."""
    if not exp_date_str or exp_date_str == 'NEVER':
        return {'status': 'Permanent', 'expires_on': None, 'is_expired': False}
    try:
        exp_date = datetime.strptime(exp_date_str.strip(), '%Y-%m-%d')
        today = datetime.now()
        is_expired = exp_date < today
        if is_expired:
            return {'status': 'Expired', 'expires_on': exp_date_str, 'is_expired': True}
        return {'status': f'Expires on {exp_date_str}', 'expires_on': exp_date_str, 'is_expired': False}
    except (ValueError, TypeError, AttributeError):
        return {'status': 'Permanent', 'expires_on': None, 'is_expired': False}


def _exp_str_to_datetime(exp_str):
    """Convert legacy EXP string to datetime or None for DB."""
    if not exp_str or exp_str.strip().upper() == 'NEVER':
        return None
    try:
        return datetime.strptime(exp_str.strip(), '%Y-%m-%d')
    except (ValueError, TypeError, AttributeError):
        return None


def migrate_legacy_data():
    """Import data from data/Main/*.txt and yara.txt into SQLite. Run only when DB has no IOCs."""
    if db.session.query(IOC).limit(1).first() is not None:
        return
    print("[Migration] Empty DB detected. Importing legacy data from data/Main/...")
    # IOC types that have their own files (exclude YARA - handled separately)
    ioc_types = [k for k in IOC_FILES if k != 'YARA']
    for ioc_type in ioc_types:
        filename = IOC_FILES.get(ioc_type)
        if not filename:
            continue
        filepath = os.path.join(DATA_MAIN, filename)
        if not os.path.exists(filepath):
            continue
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parsed = _parse_ioc_line_permissive(line)
                    if not parsed or not parsed.get('ioc'):
                        continue
                    value = (parsed.get('ioc') or '').strip()
                    if not value:
                        continue
                    analyst = (parsed.get('user') or '').strip().lower() or 'unknown'
                    ticket_id = (parsed.get('ref') or '').strip() or None
                    comment = (parsed.get('comment') or '').strip() or None
                    exp_str = parsed.get('expiration')
                    exp_dt = _exp_str_to_datetime(exp_str)
                    date_str = (parsed.get('date') or '').strip()
                    try:
                        created = datetime.fromisoformat(date_str.replace('Z', '+00:00')) if date_str else _utcnow()
                        if created.tzinfo:
                            created = created.replace(tzinfo=None)
                    except (ValueError, TypeError):
                        created = _utcnow()
                    try:
                        db.session.add(IOC(
                            type=ioc_type,
                            value=value,
                            analyst=analyst,
                            ticket_id=ticket_id,
                            comment=comment,
                            expiration_date=exp_dt,
                            created_at=created
                        ))
                        db.session.commit()
                    except IntegrityError:
                        db.session.rollback()
                        continue
        except Exception as e:
            print(f"[Migration] Error reading {filename}: {e}")
            db.session.rollback()
            continue
    # Migrate yara.txt metadata into YaraRule
    if os.path.isfile(FILE_YARA):
        try:
            with open(FILE_YARA, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    parsed = _parse_ioc_line_permissive(line)
                    if not parsed or not parsed.get('ioc'):
                        continue
                    filename_yar = (parsed.get('ioc') or '').strip()
                    if not filename_yar.lower().endswith('.yar'):
                        continue
                    analyst = (parsed.get('user') or '').strip().lower() or 'upload'
                    ticket_id = (parsed.get('ref') or '').strip() or None
                    comment = (parsed.get('comment') or '').strip() or 'Uploaded YARA Rule'
                    date_str = (parsed.get('date') or '').strip()
                    try:
                        uploaded = datetime.fromisoformat(date_str.replace('Z', '+00:00')) if date_str else _utcnow()
                        if uploaded.tzinfo:
                            uploaded = uploaded.replace(tzinfo=None)
                    except (ValueError, TypeError):
                        uploaded = _utcnow()
                    try:
                        existing = YaraRule.query.filter_by(filename=filename_yar).first()
                        if not existing:
                            db.session.add(YaraRule(
                                filename=filename_yar,
                                analyst=analyst,
                                ticket_id=ticket_id,
                                comment=comment,
                                uploaded_at=uploaded
                            ))
                    except IntegrityError:
                        pass
            db.session.commit()
        except Exception as e:
            print(f"[Migration] Error reading yara.txt: {e}")
            db.session.rollback()
    print("[Migration] Legacy data import complete.")


def _ioc_row_to_search_result(row, ioc_type, query_lower, filter_type):
    """Build a search-result dict from an IOC row (same shape as frontend expects)."""
    expiration_str = row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else 'NEVER'
    exp_status = check_expiration_status(expiration_str)
    date_str = row.created_at.isoformat() if row.created_at else None
    campaign_name = None
    if row.campaign_id and row.campaign:
        campaign_name = row.campaign.name
    result = {
        'ioc': row.value,
        'date': date_str,
        'user': row.analyst or '',
        'ref': row.ticket_id or '',
        'comment': row.comment or '',
        'expiration': expiration_str,
        'file_type': ioc_type,
        'line_number': row.id,
        'raw_line': f"{row.value} # Date:{date_str} | User:{row.analyst} | Ref:{row.ticket_id or ''} | Comment:{row.comment or ''} | EXP:{expiration_str}",
        'expiration_status': exp_status['status'],
        'expires_on': exp_status['expires_on'],
        'is_expired': exp_status['is_expired'],
        'status': 'Expired' if exp_status['is_expired'] else 'Active',
        'campaign_name': campaign_name,
    }
    if ioc_type == 'IP':
        result['country_code'] = get_country_code(row.value)
    return result


@app.route('/api/search', methods=['GET'])
def search_ioc():
    """Search for an IOC across all types with optional field filter."""
    query = request.args.get('q', '').strip()
    filter_type = request.args.get('filter', 'all').strip().lower()
    if not query:
        return jsonify({'success': False, 'message': 'Search query is required'}), 400
    query_lower = query.lower()
    q = IOC.query.options(joinedload(IOC.campaign))
    if filter_type == 'ioc_value':
        q = q.filter(func.lower(IOC.value).contains(query_lower))
    elif filter_type == 'ticket_id':
        q = q.filter(IOC.ticket_id.isnot(None), func.lower(IOC.ticket_id).contains(query_lower))
    elif filter_type == 'user':
        q = q.filter(func.lower(IOC.analyst).contains(query_lower))
    elif filter_type == 'date':
        q = q.filter(IOC.created_at.isnot(None))
        # Filter by date substring in Python (SQLite-friendly)
        rows_all = q.all()
        rows = [r for r in rows_all if query_lower in (r.created_at.isoformat() if r.created_at else '').lower()]
        return jsonify({
            'success': True,
            'query': query,
            'filter': filter_type,
            'results': [_ioc_row_to_search_result(r, r.type, query_lower, filter_type) for r in rows],
            'count': len(rows)
        })
    else:
        q = q.filter(
            db.or_(
                func.lower(IOC.value).contains(query_lower),
                func.lower(IOC.analyst).contains(query_lower),
                func.lower(IOC.ticket_id).contains(query_lower),
                func.lower(IOC.comment).contains(query_lower)
            )
        )
    rows = q.all()
    # For 'all' filter, also include rows where date string matches (SQLite-friendly)
    if filter_type == 'all':
        rows = [r for r in rows if (
            query_lower in (r.value or '').lower() or
            query_lower in (r.analyst or '').lower() or
            query_lower in (r.ticket_id or '').lower() or
            query_lower in (r.comment or '').lower() or
            (r.created_at and query_lower in r.created_at.isoformat().lower())
        )]
    results = [_ioc_row_to_search_result(row, row.type, query_lower, filter_type) for row in rows]
    # Federated search: also search YaraRule (filename and comment)
    yara_matches = YaraRule.query.filter(
        db.or_(
            func.lower(YaraRule.filename).contains(query_lower),
            func.lower(YaraRule.comment).contains(query_lower)
        )
    ).all()
    for rule in yara_matches:
        campaign_name = None
        if rule.campaign_id:
            c = Campaign.query.get(rule.campaign_id)
            if c:
                campaign_name = c.name
        results.append({
            'ioc': rule.filename,
            'value': rule.filename,
            'file_type': 'YARA',
            'date': rule.uploaded_at.isoformat() if rule.uploaded_at else None,
            'user': rule.analyst or '',
            'ref': rule.ticket_id or '',
            'comment': rule.comment or '',
            'expiration': 'NEVER',
            'line_number': rule.id,
            'raw_line': f"YARA:{rule.filename}",
            'expiration_status': 'Permanent',
            'expires_on': None,
            'is_expired': False,
            'status': 'Active',
            'campaign_name': campaign_name,
        })
    return jsonify({
        'success': True,
        'query': query,
        'filter': filter_type,
        'results': results,
        'count': len(results)
    })


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
        
        if check_ioc_exists(ioc_type, value):
            return jsonify({'success': False, 'message': 'IOC already exists'}), 409
        if expiration.lower() == 'permanent':
            exp_dt = None
        else:
            try:
                exp_dt = datetime.strptime(expiration, '%Y-%m-%d')
            except ValueError:
                return jsonify({'success': False, 'message': 'Invalid expiration date format. Use YYYY-MM-DD or "Permanent"'}), 400
        try:
            db.session.add(IOC(
                type=ioc_type,
                value=value,
                analyst=username,
                ticket_id=ticket_id or None,
                comment=comment or None,
                expiration_date=exp_dt
            ))
            db.session.commit()
            return jsonify({
                'success': True,
                'message': f'{ioc_type} IOC ingested successfully',
                'ioc': value,
                'type': ioc_type
            }), 201
        except IntegrityError:
            db.session.rollback()
            return jsonify({'success': False, 'message': 'IOC already exists'}), 409
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/revoke', methods=['POST'])
def revoke_ioc():
    """Remove an IOC from the database."""
    try:
        data = request.get_json()
        ioc_type = data.get('type', '').strip()
        value = data.get('value', '').strip()
        if not value or not ioc_type:
            return jsonify({'success': False, 'message': 'Missing required fields: type, value'}), 400
        if ioc_type not in IOC_FILES:
            return jsonify({'success': False, 'message': 'Invalid IOC type'}), 400
        row = IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == value.strip().lower()).first()
        if not row:
            return jsonify({'success': False, 'message': 'IOC not found'}), 404
        db.session.delete(row)
        db.session.commit()
        return jsonify({'success': True, 'message': f'{ioc_type} IOC revoked successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/edit', methods=['POST'])
def edit_ioc():
    """Edit an IOC's metadata (comment, expiration, and optional campaign assignment)."""
    try:
        data = request.get_json()
        ioc_type = data.get('type', '').strip()
        value = data.get('value', '').strip()
        new_comment = data.get('comment', '')
        new_expiration = data.get('expiration', '').strip()
        campaign_name_raw = data.get('campaign_name')
        campaign_name = (campaign_name_raw.strip() if isinstance(campaign_name_raw, str) else '') or None
        if not value or not ioc_type:
            return jsonify({'success': False, 'message': 'Missing required fields: type, value'}), 400
        if ioc_type not in IOC_FILES:
            return jsonify({'success': False, 'message': 'Invalid IOC type'}), 400
        if new_expiration.lower() == 'permanent':
            exp_dt = None
        elif new_expiration:
            try:
                exp_dt = datetime.strptime(new_expiration, '%Y-%m-%d')
            except ValueError:
                return jsonify({'success': False, 'message': 'Invalid expiration date format. Use YYYY-MM-DD or "Permanent"'}), 400
        else:
            return jsonify({'success': False, 'message': 'Expiration is required'}), 400
        row = IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == value.strip().lower()).first()
        if not row:
            return jsonify({'success': False, 'message': 'IOC not found'}), 404
        row.comment = sanitize_comment(new_comment) or None
        row.expiration_date = exp_dt
        # Ticket ID update
        new_ticket_id = data.get('ticket_id')
        if new_ticket_id is not None:
            row.ticket_id = new_ticket_id.strip() or None
        # Campaign assignment: "None" or empty -> unlink; otherwise find campaign by name
        if campaign_name is None or campaign_name == '' or campaign_name.lower() == 'none':
            row.campaign_id = None
        else:
            camp = Campaign.query.filter_by(name=campaign_name).first()
            if camp:
                row.campaign_id = camp.id
            else:
                return jsonify({'success': False, 'message': f'Campaign "{campaign_name}" not found'}), 400
        db.session.commit()
        audit_log('IOC_EDIT', f'type={ioc_type} value={value}')
        return jsonify({'success': True, 'message': f'{ioc_type} IOC updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/edit-yara-meta', methods=['POST'])
def edit_yara_meta():
    """Edit a YARA rule's metadata (ticket_id, campaign assignment, comment)."""
    try:
        data = request.get_json()
        filename = (data.get('filename') or '').strip()
        if not filename:
            return jsonify({'success': False, 'message': 'Filename is required'}), 400
        rule = YaraRule.query.filter_by(filename=filename).first()
        if not rule:
            return jsonify({'success': False, 'message': 'YARA rule not found'}), 404

        # Update ticket_id
        new_ticket_id = data.get('ticket_id')
        if new_ticket_id is not None:
            rule.ticket_id = new_ticket_id.strip() or None

        # Update comment
        new_comment = data.get('comment')
        if new_comment is not None:
            rule.comment = sanitize_comment(new_comment) or None

        # Campaign assignment
        campaign_name_raw = data.get('campaign_name')
        if campaign_name_raw is not None:
            campaign_name = (campaign_name_raw.strip() if isinstance(campaign_name_raw, str) else '') or None
            if campaign_name is None or campaign_name == '' or campaign_name.lower() == 'none':
                rule.campaign_id = None
            else:
                camp = Campaign.query.filter_by(name=campaign_name).first()
                if camp:
                    rule.campaign_id = camp.id
                else:
                    return jsonify({'success': False, 'message': f'Campaign "{campaign_name}" not found'}), 400

        db.session.commit()
        audit_log('YARA_EDIT_META', f'file={filename}')
        return jsonify({'success': True, 'message': f'YARA rule "{filename}" updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/recent', methods=['GET'])
def get_recent():
    """Get the latest 50 items from both IOC and YaraRule tables, merged and sorted by date (newest first)."""
    limit = int(request.args.get('limit', 50))
    # Fetch IOCs (no type filter; IOCs are IP/Domain/Hash/Email/URL)
    ioc_rows = IOC.query.order_by(IOC.created_at.desc()).limit(limit).all()
    # Fetch YARA rules
    yara_rows = YaraRule.query.order_by(YaraRule.uploaded_at.desc()).limit(limit).all()
    combined = []
    for row in ioc_rows:
        exp_str = row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else 'NEVER'
        exp_status = check_expiration_status(exp_str)
        dt = row.created_at
        item = {
            'id': row.id,
            'type': row.type,
            'value': row.value,
            'analyst': row.analyst or '',
            'date': dt.isoformat() if dt else None,
            'ioc': row.value,
            'user': row.analyst or '',
            'ref': row.ticket_id or '',
            'comment': row.comment or '',
            'expiration': exp_str,
            'file_type': row.type,
            'expiration_status': exp_status['status'],
            'is_expired': exp_status['is_expired'],
        }
        if row.type == 'IP':
            item['country_code'] = get_country_code(row.value)
        combined.append((dt, item))
    for row in yara_rows:
        dt = row.uploaded_at
        item = {
            'id': row.id,
            'type': 'YARA',
            'value': row.filename,
            'analyst': row.analyst or '',
            'date': dt.isoformat() if dt else None,
            'ioc': row.filename,
            'user': row.analyst or '',
            'ref': row.ticket_id or '',
            'comment': row.comment or '',
            'expiration': 'NEVER',
            'file_type': 'YARA',
            'expiration_status': 'Permanent',
            'is_expired': False,
        }
        combined.append((dt, item))
    combined.sort(key=lambda x: x[0] if x[0] else datetime(1970, 1, 1), reverse=True)
    recent = [item for _, item in combined[:limit]]
    return jsonify({'success': True, 'recent': recent, 'count': len(recent)})


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Active IOC count per type (non-expired). YARA rules count, weighted total, and campaign stats (all campaigns with IOC counts)."""
    stats = {'IP': 0, 'Domain': 0, 'Hash': 0, 'Email': 0, 'URL': 0}
    now = datetime.now()
    for ioc_type in stats:
        count = IOC.query.filter(
            IOC.type == ioc_type,
            db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
        ).count()
        stats[ioc_type] = count
    yara_count = YaraRule.query.count()
    ioc_total = sum(stats.values())
    weighted_total = ioc_total + (yara_count * 5)

    # All campaigns with their active IOC counts (including campaigns with 0 IOCs)
    campaign_stats = {}
    rows = db.session.query(
        Campaign.name,
        func.count(IOC.id).label('cnt')
    ).outerjoin(IOC, db.and_(
        IOC.campaign_id == Campaign.id,
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    )).group_by(Campaign.id, Campaign.name).all()
    for row in rows:
        if row.name:
            campaign_stats[row.name] = row.cnt or 0

    return jsonify({
        'success': True,
        'stats': stats,
        'yara_count': yara_count,
        'weighted_total': weighted_total,
        'campaign_stats': campaign_stats,
    })


@app.route('/api/all-iocs', methods=['GET'])
def get_all_iocs():
    """Get all IOCs for historical table (limited to last 500 for performance)."""
    limit = int(request.args.get('limit', 500))
    total = IOC.query.filter(IOC.type != 'YARA').count()
    rows = IOC.query.filter(IOC.type != 'YARA').order_by(IOC.created_at.desc()).limit(limit).all()
    iocs = []
    for row in rows:
        exp_str = row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else 'NEVER'
        exp_status = check_expiration_status(exp_str)
        item = {
            'ioc': row.value,
            'date': row.created_at.isoformat() if row.created_at else None,
            'user': row.analyst or '',
            'ref': row.ticket_id or '',
            'comment': row.comment or '',
            'expiration': exp_str,
            'file_type': row.type,
            'expiration_status': exp_status['status'],
            'is_expired': exp_status['is_expired']
        }
        if row.type == 'IP':
            item['country_code'] = get_country_code(row.value)
        iocs.append(item)
    return jsonify({'success': True, 'iocs': iocs, 'count': len(iocs), 'total': total})


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
        campaign_name = (request.form.get('campaign_name') or '').strip() or None
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id
        
        if not username:
            return jsonify({'success': False, 'message': 'Analyst username is required'}), 400
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        # Stream CSV content line-by-line (avoids loading entire file into memory)
        stream = io.TextIOWrapper(file.stream, encoding='utf-8', errors='replace')
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
        
        exp_date = calculate_expiration_date(ttl)
        
        # Collect all findings with ticket IDs
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
        
        comment = sanitize_comment(global_comment)
        summary = {}
        total_updated = 0
        total_new = 0
        for ioc_type, ioc_dict in findings.items():
            updated_count = 0
            new_count = 0
            for value, ticket_id in ioc_dict.items():
                ticket_id_val = ticket_id.strip() if ticket_id else None
                existing = IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == value.lower()).first()
                if existing:
                    existing.comment = comment
                    existing.expiration_date = exp_date
                    existing.ticket_id = ticket_id_val or existing.ticket_id
                    if campaign_id is not None:
                        existing.campaign_id = campaign_id
                    updated_count += 1
                else:
                    db.session.add(IOC(
                        type=ioc_type,
                        value=value,
                        analyst=username,
                        ticket_id=ticket_id_val,
                        comment=comment,
                        expiration_date=exp_date,
                        campaign_id=campaign_id
                    ))
                    new_count += 1
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                raise
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
        audit_log('BULK_CSV', f'analyst={username} new={total_new} updated={total_updated}')
        
        return jsonify({
            'success': True,
            'message': message,
            'summary': summary,
            'total': total_new + total_updated
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/preview-csv', methods=['POST'])
def preview_csv():
    """
    Parse CSV using same logic as bulk_csv; return JSON items for staging (no DB write).
    Accepts: file, username, ttl, comment, optional ticket_id (fallback when CSV has no ticket column).
    For each IOC: existing_permanent=True if DB row exists with expiration_date IS NULL.
    """
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        username = request.form.get('username', '').strip().lower()
        if not username:
            return jsonify({'success': False, 'message': 'Analyst username is required'}), 400
        ttl = request.form.get('ttl', 'Permanent')
        comment = request.form.get('comment', '').strip()
        ticket_id_fallback = request.form.get('ticket_id', '').strip() or None

        if ttl == 'Permanent':
            expiration_display = 'Permanent'
        else:
            exp_dt = calculate_expiration_date(ttl)
            expiration_display = exp_dt.strftime('%Y-%m-%d') if exp_dt else 'Permanent'

        stream = io.StringIO(file.read().decode('utf-8'))
        csv_reader = csv.reader(stream)
        header_row = next(csv_reader, None)
        ticket_id_column_index = None
        if header_row:
            ticket_id_keywords = ['reportid', 'ticket_id', 'ref', 'reference']
            for idx, col_name in enumerate(header_row):
                if col_name.lower().strip() in ticket_id_keywords:
                    ticket_id_column_index = idx
                    break

        # Collect unique IOCs per (type, value), ticket_id from last occurrence (same as bulk_csv)
        ioc_to_ticket = {
            'IP': {}, 'Domain': {}, 'Hash': {}, 'Email': {}, 'URL': {}
        }
        for row in csv_reader:
            ticket_id = None
            if ticket_id_column_index is not None and ticket_id_column_index < len(row):
                ticket_id = row[ticket_id_column_index].strip() or None
            if not ticket_id:
                ticket_id = ticket_id_fallback

            for cell in row:
                if not cell:
                    continue
                cleaned_cell = cell.replace('[.]', '.').replace('[', '').replace(']', '').strip()
                for ioc_type, pattern in AUTO_DETECT_PATTERNS.items():
                    matches = re.findall(pattern, cleaned_cell)
                    for match in matches:
                        cleaned_match, _ = refanger(match)
                        if not validate_ioc(cleaned_match, ioc_type):
                            continue
                        is_blocked, _ = check_allowlist(cleaned_match, ioc_type)
                        if is_blocked:
                            continue
                        if cleaned_match not in ioc_to_ticket[ioc_type]:
                            ioc_to_ticket[ioc_type][cleaned_match] = ticket_id
                        break

        items = []
        for ioc_type, ioc_dict in ioc_to_ticket.items():
            for value, ticket_id in ioc_dict.items():
                existing_permanent = False
                existing_analyst = ''
                existing_comment = ''
                existing_row = IOC.query.filter(
                    IOC.type == ioc_type,
                    func.lower(IOC.value) == value.lower()
                ).first()
                if existing_row and existing_row.expiration_date is None:
                    existing_permanent = True
                    existing_analyst = (existing_row.analyst or '')
                    existing_comment = (existing_row.comment or '')

                ticket_id_val = (ticket_id.strip() if ticket_id else None) or ticket_id_fallback
                items.append({
                    'ioc': value,
                    'type': ioc_type,
                    'ticket_id': ticket_id_val or '',
                    'analyst': username,
                    'date': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
                    'comment': sanitize_comment(comment) or '',
                    'expiration': expiration_display,
                    'existing_permanent': existing_permanent,
                    'existing_analyst': existing_analyst,
                    'existing_comment': existing_comment
                })

        return jsonify({'success': True, 'items': items, 'count': len(items)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


def remove_duplicates_from_files():
    """No-op for SQLite backend: unique constraint on (type, value) prevents duplicates."""
    return 0


@app.route('/api/analyst-stats', methods=['GET'])
def get_analyst_stats():
    """Get statistics for all analysts (for Champs Analysis). YARA uploads count as 5x points."""
    ioc_rows = db.session.query(
        IOC.analyst,
        func.count(IOC.id).label('total_iocs'),
        func.max(IOC.created_at).label('last_activity')
    ).group_by(IOC.analyst).all()
    yara_rows = db.session.query(
        YaraRule.analyst,
        func.count(YaraRule.id).label('yara_count'),
        func.max(YaraRule.uploaded_at).label('last_yara')
    ).group_by(YaraRule.analyst).all()
    analyst_data = {}
    for analyst, total_iocs, last_activity in ioc_rows:
        u = (analyst or 'unknown').lower()
        analyst_data[u] = {
            'user': u,
            'total_iocs': total_iocs,
            'yara_count': 0,
            'last_activity': last_activity,
            'last_yara': None,
        }
    for analyst, yara_count, last_yara in yara_rows:
        u = (analyst or 'unknown').lower()
        if u not in analyst_data:
            analyst_data[u] = {
                'user': u,
                'total_iocs': 0,
                'yara_count': 0,
                'last_activity': None,
                'last_yara': None,
            }
        analyst_data[u]['yara_count'] = yara_count
        analyst_data[u]['last_yara'] = last_yara
    analyst_list = []
    for u, d in analyst_data.items():
        last_activity = d['last_activity']
        last_yara = d['last_yara']
        last_date = last_activity
        if last_yara and (last_date is None or last_yara > last_date):
            last_date = last_yara
        weighted = d['total_iocs'] + (d['yara_count'] * 5)
        analyst_list.append({
            'user': u,
            'total_iocs': d['total_iocs'],
            'yara_count': d['yara_count'],
            'weighted_score': weighted,
            'last_activity': last_date.strftime('%Y-%m-%d') if last_date else 'N/A',
        })
    analyst_list.sort(key=lambda x: x['weighted_score'], reverse=True)
    for idx, a in enumerate(analyst_list, 1):
        a['rank'] = idx
    return jsonify({'success': True, 'analysts': analyst_list, 'count': len(analyst_list)})


def _parse_txt_metadata(metadata_raw):
    """
    Parse metadata string per spec: Date (end) -> User 'by X' (end) -> Ticket ID 'N -' (start) -> Comment (remainder).
    Returns dict: created_at (datetime or None), analyst (str or None), ticket_id (str or None), comment (str).
    """
    s = (metadata_raw or '').strip()
    created_at = None
    analyst = None
    ticket_id = None

    # Step A: Date at end — e.g. "1/12/2026 9:47:43 PM" or "12/28/2025"
    date_time_end = re.compile(
        r'(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)\s*$',
        re.IGNORECASE
    )
    date_only_end = re.compile(r'(\d{1,2})/(\d{1,2})/(\d{4})\s*$')
    m = date_time_end.search(s)
    if m:
        try:
            month, day, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
            hour, minute = int(m.group(4)), int(m.group(5))
            sec = int(m.group(6)) if m.group(6) else 0
            ampm = (m.group(7) or '').upper()
            if ampm == 'PM' and hour != 12:
                hour += 12
            elif ampm == 'AM' and hour == 12:
                hour = 0
            created_at = datetime(year, month, day, hour, minute, sec)
        except (ValueError, IndexError):
            pass
        s = s[:m.start()].strip()
    else:
        m = date_only_end.search(s)
        if m:
            try:
                month, day, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
                created_at = datetime(year, month, day)
            except (ValueError, IndexError):
                pass
            s = s[:m.start()].strip()

    # Step B: "by <username>" at end (case-insensitive)
    by_user_end = re.compile(r'\s+by\s+([a-zA-Z0-9_-]+)\s*$', re.IGNORECASE)
    m = by_user_end.search(s)
    if m:
        analyst = m.group(1).strip().lower()
        s = s[:m.start()].strip()

    # Step C: Ticket ID at start — number followed by hyphen (e.g. "45036 - ...")
    ticket_start = re.compile(r'^\s*(\d+)\s*-\s*')
    m = ticket_start.match(s)
    if m:
        ticket_id = m.group(1).strip()
        s = s[m.end():].strip()

    # Step D: Comment = remainder; clean leading/trailing whitespace and stray separators
    comment = re.sub(r'^[\s\-]+|[\s\-]+$', '', s)
    comment = re.sub(r'\s+', ' ', comment).strip()
    return {'created_at': created_at, 'analyst': analyst, 'ticket_id': ticket_id, 'comment': comment}


@app.route('/api/preview-txt', methods=['POST'])
def preview_txt():
    """
    Parse TXT file with smart metadata logic; fill missing fields from form defaults.
    Returns JSON array of { ioc, type, ticket_id, analyst, date, comment } for staging table.
    """
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        default_analyst = request.form.get('default_analyst', '').strip().lower()
        default_ticket = request.form.get('default_ticket', '').strip() or None
        default_ttl = request.form.get('default_ttl', 'Permanent')
        default_comment = request.form.get('default_comment', '').strip()
        if not default_analyst:
            return jsonify({'success': False, 'message': 'Default analyst is required'}), 400

        if default_ttl == 'Permanent':
            expiration_display = 'Permanent'
        else:
            exp_dt = calculate_expiration_date(default_ttl)
            expiration_display = exp_dt.strftime('%Y-%m-%d') if exp_dt else 'Permanent'

        content = file.read().decode('utf-8')
        lines = content.split('\n')
        items = []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            if '#' in line:
                parts = line.split('#', 1)
                ioc_raw = parts[0].strip()
                metadata_raw = (parts[1] or '').strip()
            else:
                ioc_raw = line
                metadata_raw = ''

            ioc_cleaned = ioc_raw.replace('[.]', '.').replace('[', '').replace(']', '').strip()
            if not ioc_cleaned:
                continue
            ioc_type = None
            for test_type in PRIORITY_ORDER:
                pattern = REGEX_PATTERNS.get(test_type)
                if pattern and re.match(pattern, ioc_cleaned):
                    ioc_type = test_type
                    break
            if not ioc_type:
                continue
            is_blocked, _ = check_allowlist(ioc_cleaned, ioc_type)
            if is_blocked:
                continue

            parsed = _parse_txt_metadata(metadata_raw)
            analyst = (parsed['analyst'] or default_analyst).lower()
            ticket_id = parsed['ticket_id'] or default_ticket
            created_at = parsed['created_at'] or datetime.now()
            comment = sanitize_comment(parsed['comment'] or default_comment or '') or ''

            existing_permanent = False
            existing_analyst = ''
            existing_comment = ''
            existing_row = IOC.query.filter(
                IOC.type == ioc_type,
                func.lower(IOC.value) == ioc_cleaned.lower()
            ).first()
            if existing_row and existing_row.expiration_date is None:
                existing_permanent = True
                existing_analyst = (existing_row.analyst or '')
                existing_comment = (existing_row.comment or '')

            items.append({
                'ioc': ioc_cleaned,
                'type': ioc_type,
                'ticket_id': ticket_id or '',
                'analyst': analyst,
                'date': created_at.strftime('%Y-%m-%dT%H:%M:%S'),
                'comment': comment,
                'expiration': expiration_display,
                'existing_permanent': existing_permanent,
                'existing_analyst': existing_analyst,
                'existing_comment': existing_comment
            })

        return jsonify({'success': True, 'items': items, 'count': len(items)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/submit-staging', methods=['POST'])
def submit_staging():
    """Save staged IOC array to DB. Expects JSON: { items: [...], ttl, campaign_name? }. Each item: ioc, type, ticket_id?, analyst, date?, comment?."""
    try:
        data = request.get_json() or {}
        items = data.get('items') or []
        ttl = (data.get('ttl') or 'Permanent').strip()
        campaign_name = (data.get('campaign_name') or '').strip() or None
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id

        summary = {}
        total_updated = 0
        total_new = 0
        for raw in items:
            ioc_value = (raw.get('ioc') or '').strip()
            ioc_type = (raw.get('type') or '').strip()
            if not ioc_value or not ioc_type:
                continue
            if ioc_type not in IOC_FILES or ioc_type == 'YARA':
                continue
            is_blocked, _ = check_allowlist(ioc_value, ioc_type)
            if is_blocked:
                continue
            analyst = (raw.get('analyst') or '').strip().lower() or 'unknown'
            ticket_id = (raw.get('ticket_id') or '').strip() or None
            comment = sanitize_comment(raw.get('comment') or '') or None
            date_str = (raw.get('date') or '').strip()
            created_at = datetime.now()
            if date_str:
                try:
                    created_at = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    if created_at.tzinfo:
                        created_at = created_at.replace(tzinfo=None)
                except (ValueError, TypeError):
                    pass

            exp_str = (raw.get('expiration') or '').strip()
            if exp_str.upper() in ('PERMANENT', 'NEVER'):
                exp_date = None
            elif exp_str:
                try:
                    exp_date = datetime.strptime(exp_str[:10], '%Y-%m-%d')
                except (ValueError, TypeError):
                    exp_date = calculate_expiration_date(ttl)
            else:
                exp_date = calculate_expiration_date(ttl)

            existing = IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == ioc_value.lower()).first()
            if existing:
                existing.comment = comment
                existing.expiration_date = exp_date
                existing.ticket_id = ticket_id or existing.ticket_id
                if campaign_id is not None:
                    existing.campaign_id = campaign_id
                total_updated += 1
                summary[ioc_type] = summary.get(ioc_type, {'updated': 0, 'new': 0})
                summary[ioc_type]['updated'] += 1
            else:
                db.session.add(IOC(
                    type=ioc_type,
                    value=ioc_value,
                    analyst=analyst,
                    ticket_id=ticket_id,
                    comment=comment,
                    expiration_date=exp_date,
                    created_at=created_at,
                    campaign_id=campaign_id
                ))
                total_new += 1
                summary[ioc_type] = summary.get(ioc_type, {'updated': 0, 'new': 0})
                summary[ioc_type]['new'] += 1
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

        summary_parts = []
        for ioc_type, counts in summary.items():
            parts = []
            if counts.get('new'):
                parts.append(f"{counts['new']} new")
            if counts.get('updated'):
                parts.append(f"{counts['updated']} updated")
            if parts:
                summary_parts.append(f"{ioc_type}s ({', '.join(parts)})")
        message = f"Imported: {', '.join(summary_parts)}" if summary_parts else "No items imported"
        return jsonify({'success': True, 'message': message, 'summary': summary, 'total': total_new + total_updated})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/upload-txt', methods=['POST'])
def upload_txt():
    """Handle bulk TXT file upload with smart parsing (log-format aware)."""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        
        file = request.files['file']
        default_ticket_id = request.form.get('ticket_id', '').strip() or None
        username = request.form.get('username', '').strip().lower()
        ttl = request.form.get('ttl', 'Permanent')
        campaign_name = (request.form.get('campaign_name') or '').strip() or None
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id
        
        if not username:
            return jsonify({'success': False, 'message': 'Analyst username is required'}), 400
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        # Stream TXT content line-by-line (avoids loading entire file into memory)
        stream = io.TextIOWrapper(file.stream, encoding='utf-8', errors='replace')
        exp_date = calculate_expiration_date(ttl)
        findings = {'IP': {}, 'Domain': {}, 'Hash': {}, 'Email': {}, 'URL': {}}

        for raw_line in stream:
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split('#', 1)
            if len(parts) < 2:
                continue
            ioc_raw = parts[0].strip()
            metadata_raw = parts[1].strip()
            ioc_cleaned = ioc_raw.replace('[.]', '.').replace('[', '').replace(']', '').strip()
            ioc_type = None
            for test_type in PRIORITY_ORDER:
                pattern = REGEX_PATTERNS.get(test_type)
                if pattern and re.match(pattern, ioc_cleaned):
                    ioc_type = test_type
                    break
            if not ioc_type:
                continue
            is_blocked, _ = check_allowlist(ioc_cleaned, ioc_type)
            if is_blocked:
                continue

            parsed = _parse_txt_metadata(metadata_raw)
            final_user = (parsed['analyst'] or username).lower()
            final_date = parsed['created_at'] or datetime.now()
            final_ticket_id = parsed['ticket_id'] or default_ticket_id
            comment_sanitized = sanitize_comment(parsed['comment'] or '')

            if ioc_cleaned not in findings[ioc_type]:
                findings[ioc_type][ioc_cleaned] = {
                    'comment': comment_sanitized or None,
                    'user': final_user,
                    'ticket_id': final_ticket_id,
                    'created_at': final_date
                }
        
        summary = {}
        total_updated = 0
        total_new = 0
        for ioc_type, ioc_dict in findings.items():
            updated_count = 0
            new_count = 0
            for value, meta in ioc_dict.items():
                existing = IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == value.lower()).first()
                if existing:
                    existing.comment = meta['comment']
                    existing.expiration_date = exp_date
                    existing.ticket_id = meta['ticket_id'] or existing.ticket_id
                    if campaign_id is not None:
                        existing.campaign_id = campaign_id
                    updated_count += 1
                else:
                    db.session.add(IOC(
                        type=ioc_type,
                        value=value,
                        analyst=meta['user'],
                        ticket_id=meta['ticket_id'],
                        comment=meta['comment'],
                        expiration_date=exp_date,
                        created_at=meta['created_at'],
                        campaign_id=campaign_id
                    ))
                    new_count += 1
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                raise
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
        audit_log('BULK_TXT', f'analyst={username} new={total_new} updated={total_updated}')
        
        return jsonify({
            'success': True,
            'message': message,
            'summary': summary,
            'total': total_new + total_updated
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


def _startup_diagnostic():
    """Log files in data/Main/ and their line counts for debugging stats issues."""
    target_dir = os.path.abspath(DATA_MAIN)
    if not os.path.isdir(target_dir):
        print(f"[DIAGNOSTIC] Directory does not exist: {target_dir}")
        return
    try:
        entries = sorted(os.listdir(target_dir))
        for name in entries:
            full_path = os.path.abspath(os.path.join(target_dir, name))
            if not os.path.isfile(full_path):
                continue
            try:
                with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                    line_count = sum(1 for _ in f)
            except Exception as e:
                line_count = f"Error: {e}"
            print(f"[DIAGNOSTIC] File: {name} | Lines: {line_count} | Path: {full_path}")
    except Exception as e:
        print(f"[DIAGNOSTIC] Failed to list {target_dir}: {e}")


@app.route('/api/campaigns', methods=['GET'])
def list_campaigns():
    """List all campaigns (for future UI)."""
    try:
        campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
        return jsonify({
            'success': True,
            'campaigns': [
                {'id': c.id, 'name': c.name, 'description': c.description, 'created_at': c.created_at.isoformat() if c.created_at else None}
                for c in campaigns
            ],
            'count': len(campaigns)
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/campaigns', methods=['POST'])
def create_campaign():
    """Create a new campaign."""
    try:
        data = request.get_json() or {}
        name = (data.get('name') or '').strip()
        description = (data.get('description') or '').strip() or None
        if not name:
            return jsonify({'success': False, 'message': 'Campaign name is required'}), 400
        db.session.add(Campaign(name=name, description=description))
        db.session.commit()
        audit_log('CAMPAIGN_CREATE', f'name={name}')
        c = Campaign.query.filter_by(name=name).first()
        return jsonify({
            'success': True,
            'message': 'Campaign created',
            'campaign': {'id': c.id, 'name': c.name, 'description': c.description, 'created_at': c.created_at.isoformat() if c.created_at else None}
        }), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Campaign name already exists'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/campaigns/link', methods=['POST'])
def link_ioc_to_campaign():
    """Link an existing IOC to a campaign by value. Expects {ioc_value, campaign_id}."""
    try:
        data = request.get_json() or {}
        ioc_value = (data.get('ioc_value') or '').strip()
        campaign_id = data.get('campaign_id')
        if not ioc_value:
            return jsonify({'success': False, 'message': 'ioc_value is required'}), 400
        if campaign_id is None:
            return jsonify({'success': False, 'message': 'campaign_id is required'}), 400
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404
        ioc = IOC.query.filter(IOC.value == ioc_value).first()
        if not ioc:
            return jsonify({'success': False, 'message': 'IOC not found'}), 404
        ioc.campaign_id = campaign_id
        db.session.commit()
        return jsonify({
            'success': True,
            'message': f'IOC linked to campaign "{campaign.name}"',
            'ioc_id': ioc.id,
            'campaign_id': campaign_id
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/campaigns/<int:campaign_id>', methods=['PUT'])
def update_campaign(campaign_id):
    """Update campaign name and/or description."""
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404
        data = request.get_json() or {}
        name = (data.get('name') or '').strip()
        if name:
            campaign.name = name
        description = data.get('description')
        if description is not None:
            campaign.description = description.strip() or None
        db.session.commit()
        audit_log('CAMPAIGN_UPDATE', f'id={campaign_id} name={campaign.name}')
        return jsonify({
            'success': True,
            'message': f'Campaign "{campaign.name}" updated',
            'campaign': {'id': campaign.id, 'name': campaign.name, 'description': campaign.description}
        })
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Campaign name already exists'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/campaigns/<int:campaign_id>', methods=['DELETE'])
def delete_campaign(campaign_id):
    """Delete a campaign after unlinking all associated IOCs and YARA rules."""
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404
        # Unlink IOCs (set campaign_id to NULL, don't delete the IOCs)
        IOC.query.filter(IOC.campaign_id == campaign_id).update({'campaign_id': None})
        # Unlink YARA rules
        YaraRule.query.filter(YaraRule.campaign_id == campaign_id).update({'campaign_id': None})
        campaign_name = campaign.name
        db.session.delete(campaign)
        db.session.commit()
        audit_log('CAMPAIGN_DELETE', f'id={campaign_id} name={campaign_name}')
        return jsonify({'success': True, 'message': f'Campaign "{campaign_name}" deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/campaigns/<int:campaign_id>/export', methods=['GET'])
def export_campaign_csv(campaign_id):
    """Export all IOCs and YARA rules for a campaign as a CSV download."""
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404

        iocs = IOC.query.filter(IOC.campaign_id == campaign_id).all()
        yara_rules = YaraRule.query.filter(YaraRule.campaign_id == campaign_id).all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Type', 'Value', 'Country', 'Analyst', 'Ticket ID', 'Comment', 'Created', 'Expiration'])

        for ioc in iocs:
            country = ''
            if ioc.type == 'IP':
                country = get_country_code(ioc.value) or ''
            writer.writerow([
                ioc.type,
                ioc.value,
                country.upper() if country else '',
                ioc.analyst or '',
                ioc.ticket_id or '',
                ioc.comment or '',
                ioc.created_at.strftime('%Y-%m-%d %H:%M:%S') if ioc.created_at else '',
                ioc.expiration_date.strftime('%Y-%m-%d %H:%M:%S') if ioc.expiration_date else 'Permanent',
            ])

        for rule in yara_rules:
            writer.writerow([
                'YARA',
                rule.filename,
                '',
                rule.analyst or '',
                rule.ticket_id or '',
                rule.comment or '',
                rule.uploaded_at.strftime('%Y-%m-%d %H:%M:%S') if rule.uploaded_at else '',
                '',
            ])

        csv_content = output.getvalue()
        output.close()
        safe_name = ''.join(c if c.isalnum() or c in '-_ ' else '_' for c in campaign.name).strip()
        filename = f'campaign_{safe_name}_{campaign.id}.csv'

        return Response(
            csv_content,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# Vis.js node colors by IOC type (Commander neon theme)
_IOC_TYPE_COLORS = {
    'IP': '#00d4ff',
    'Domain': '#a78bfa',
    'Hash': '#f43f5e',
    'Email': '#22c55e',
    'URL': '#f59e0b',
    'YARA': '#eab308',
}


def _emoji_svg_data_uri(emoji, bg_color='#3b82f6'):
    """Generate a base64 data URI of an SVG circle with an emoji inside (for Vis.js circularImage)."""
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">'
        f'<circle cx="32" cy="32" r="32" fill="{bg_color}"/>'
        f'<text x="32" y="44" text-anchor="middle" font-size="32">{emoji}</text>'
        f'</svg>'
    )
    b64 = base64.b64encode(svg.encode('utf-8')).decode('ascii')
    return f'data:image/svg+xml;base64,{b64}'

# Pre-generate emoji SVGs for each IOC type (cached at module level)
_EMOJI_SVGS = {
    'campaign': _emoji_svg_data_uri('🎯', '#ef4444'),
    'IP':       _emoji_svg_data_uri('🛡️', '#0891b2'),
    'Domain':   _emoji_svg_data_uri('🌐', '#7c3aed'),
    'URL':      _emoji_svg_data_uri('🔗', '#d97706'),
    'Email':    _emoji_svg_data_uri('📧', '#16a34a'),
    'Hash':     _emoji_svg_data_uri('☣️', '#e11d48'),
    'YARA':     _emoji_svg_data_uri('📜', '#ca8a04'),
}

# Column X-offsets for the "Orchestra" layout (type → x)
_COLUMN_X = {
    'IP':     -500,
    'Domain': -250,
    'URL':       0,
    'Email':   250,
    'Hash':    500,
    'YARA':    500,   # YARA shares column with Hash
}


@app.route('/api/campaign-graph/<int:campaign_id>', methods=['GET'])
def campaign_graph(campaign_id):
    """Return Orchestra-layout Vis.js graph: Campaign at top, IOC columns below with fixed x/y."""
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404

        camp_node_id = f'camp_{campaign.id}'

        # Root node — top center (label ABOVE the image via large negative vadjust)
        # circularImage label defaults to below the node (~y+45 for size 40).
        # vadjust -120 shifts it to ~y-75, well above the 40px-radius image.
        camp_label = campaign.name[:30] + ('…' if len(campaign.name) > 30 else '')
        nodes = [{
            'id': camp_node_id,
            'label': f'<b>{camp_label}</b>',
            'title': (campaign.name + ('\n' + (campaign.description or ''))) if campaign.description else campaign.name,
            'shape': 'circularImage',
            'image': _EMOJI_SVGS['campaign'],
            'size': 40,
            'x': 0, 'y': 0,
            'fixed': {'x': True, 'y': True},
            'borderWidth': 3,
            'color': {'border': '#ef4444', 'highlight': {'border': '#f87171'}},
            'font': {
                'multi': 'html',
                'vadjust': -140,
                'size': 24,
                'color': '#ffffff',
                'face': 'Segoe UI, sans-serif',
                'bold': {'color': '#ffffff', 'size': 24, 'face': 'Segoe UI, sans-serif'},
            },
        }]
        edges = []

        # Column header labels (type name above each column)
        _COLUMN_HEADERS = {
            'IP':     ('IP Addresses',  '#00d4ff'),
            'Domain': ('Domains',       '#a78bfa'),
            'URL':    ('URLs',          '#f59e0b'),
            'Email':  ('Emails',        '#22c55e'),
            'Hash':   ('Hashes / YARA', '#f43f5e'),
        }
        for col_type, (col_label, col_color) in _COLUMN_HEADERS.items():
            col_x = _COLUMN_X.get(col_type, 0)
            nodes.append({
                'id': f'header_{col_type}',
                'label': col_label,
                'x': col_x, 'y': 85,
                'fixed': {'x': True, 'y': True},
                'shape': 'text',
                'font': {'size': 13, 'color': col_color, 'face': 'Inter, Segoe UI, sans-serif',
                          'bold': {'color': col_color, 'size': 13}},
            })

        # Track current Y position per column (start below root)
        col_y = {}  # type_key → next y

        # IOC nodes — fixed x/y per type column
        iocs = IOC.query.filter(IOC.campaign_id == campaign_id).all()
        for ioc in iocs:
            ioc_type = ioc.type or 'Hash'
            col_x = _COLUMN_X.get(ioc_type, 400)
            node_color = _IOC_TYPE_COLORS.get(ioc_type, '#94a3b8')
            truncated = (ioc.value[:24] + '…') if len(ioc.value) > 24 else ioc.value

            # Compute y for this column
            y_key = ioc_type
            if y_key not in col_y:
                col_y[y_key] = 150
            node_y = col_y[y_key]
            col_y[y_key] += 80

            node = {
                'id': f'ioc_{ioc.id}',
                'label': truncated,
                'title': f"{ioc_type}: {ioc.value}",
                'shape': 'circularImage',
                'size': 22,
                'x': col_x, 'y': node_y,
                'fixed': {'x': True, 'y': True},
                'borderWidth': 2,
                'color': {'border': node_color, 'highlight': {'border': '#ffffff'}},
                'font': {'color': '#e2e8f0', 'size': 14, 'face': 'Consolas, monospace', 'bold': True, 'vadjust': 0},
            }

            # IP nodes: use country flag image; others: emoji SVG
            if ioc_type == 'IP':
                cc = get_country_code(ioc.value)
                node['image'] = f'/static/flags/1x1/{cc}.svg' if cc else _EMOJI_SVGS['IP']
            else:
                node['image'] = _EMOJI_SVGS.get(ioc_type, _EMOJI_SVGS['Hash'])

            nodes.append(node)
            edges.append({
                'from': camp_node_id,
                'to': f'ioc_{ioc.id}',
                'color': {'color': node_color, 'opacity': 0.5},
                'width': 1.5,
            })

        # YARA rule nodes — same column logic (shares Hash column, offset right)
        yara_rules = YaraRule.query.filter(YaraRule.campaign_id == campaign_id).all()
        y_key_yara = 'YARA'
        for rule in yara_rules:
            if y_key_yara not in col_y:
                # Start YARA after Hash column entries (or at 150 if none)
                col_y[y_key_yara] = col_y.get('Hash', 150)
            node_y = col_y[y_key_yara]
            col_y[y_key_yara] += 80

            nodes.append({
                'id': f'yara_{rule.id}',
                'label': rule.filename[:20] + ('…' if len(rule.filename) > 20 else ''),
                'title': f"YARA: {rule.filename}\n{rule.comment or ''}",
                'shape': 'circularImage',
                'image': _EMOJI_SVGS['YARA'],
                'size': 22,
                'x': 500, 'y': node_y,
                'fixed': {'x': True, 'y': True},
                'borderWidth': 2,
                'color': {'border': '#eab308', 'highlight': {'border': '#fde68a'}},
                'font': {'color': '#e2e8f0', 'size': 14, 'face': 'Consolas, monospace', 'bold': True, 'vadjust': 0},
            })
            edges.append({
                'from': camp_node_id,
                'to': f'yara_{rule.id}',
                'color': {'color': '#fbbf24', 'opacity': 0.5},
                'width': 1.5,
            })

        return jsonify({
            'success': True,
            'nodes': nodes,
            'edges': edges,
            'campaign': {'id': campaign.id, 'name': campaign.name, 'description': campaign.description}
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


def _ensure_yara_campaign_id_column():
    """If yara_rules table exists without campaign_id, add it (migration safety)."""
    try:
        result = db.session.execute(text("PRAGMA table_info(yara_rules)"))
        rows = result.fetchall()
        has_campaign_id = any((row[1] == 'campaign_id' for row in rows))
        if not has_campaign_id:
            db.session.execute(text(
                "ALTER TABLE yara_rules ADD COLUMN campaign_id INTEGER REFERENCES campaigns(id)"
            ))
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] yara_rules campaign_id check/add: {e}")


def _init_db():
    """Create tables and run legacy migration if DB is empty."""
    with app.app_context():
        db.create_all()
        _ensure_yara_campaign_id_column()
        migrate_legacy_data()


if __name__ == '__main__':
    _init_db()
    app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true',
            host='0.0.0.0',
            port=int(os.environ.get('FLASK_PORT', 5000)))
