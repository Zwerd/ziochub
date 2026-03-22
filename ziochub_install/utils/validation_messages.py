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
