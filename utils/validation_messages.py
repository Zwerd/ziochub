"""
Centralized validation and API error messages.
Use these constants in handlers instead of hardcoded strings (Step 6).
"""

# --- IOC ---
MSG_MISSING_FIELDS = "Missing required fields"
MSG_MISSING_FIELDS_TYPE_VALUE = "Missing required fields: type, value"
MSG_INVALID_IOC_TYPE = "Invalid IOC type"
MSG_IOC_EXISTS = "IOC already exists"
MSG_IOC_NOT_FOUND = "IOC not found"

# --- YARA / files ---
MSG_INVALID_FILENAME = "Invalid filename"
MSG_YARA_FILENAME_INVALID = (
    'Invalid rule filename. Use only letters, numbers, dots, hyphens, and underscores; '
    'the name must end with .yar'
)
MSG_YARA_FILENAME_NORMALIZED = (
    'Filename adjusted to "{filename}" (spaces and special characters replaced with underscores).'
)
MSG_FILENAME_REQUIRED = "Filename is required"
MSG_FILE_NOT_FOUND = "File not found"

# --- User / Admin ---
MSG_USERNAME_EXISTS = "Username already exists"
MSG_RULE_NAME_EXISTS = "Rule name already exists"
MSG_CAMPAIGN_NAME_EXISTS = "Campaign name already exists"

# --- Generic ---
MSG_INVALID_TYPE = "Invalid type"
MSG_JSON_BODY_REQUIRED = "JSON body required"
MSG_CONTENT_REQUIRED = "Content is required"
MSG_YARA_SOURCE_EMPTY = "Rule source is empty"
MSG_YARA_SOURCE_TOO_LARGE = "Rule source exceeds maximum size"
MSG_YARA_COMPILER_UNAVAILABLE = "YARA compiler is not available on this server"
MSG_YARA_DELETE_REASON_REQUIRED = "Deletion reason is required (admin)"
MSG_YARA_EDIT_REASON_REQUIRED = "Describe why you changed the rule (required when the rule text changes)"
MSG_YARA_DUPLICATE_CONTENT_UPLOAD = (
    'This YARA rule content already exists as "{filename}". Edit that rule instead of uploading a duplicate.'
)
MSG_YARA_DUPLICATE_CONTENT_UPDATE = (
    'This content matches another rule ("{filename}"). Edit that rule or change the text so it is not identical.'
)
