import hashlib
import hmac
import secrets
from typing import Optional

def hash_file_content(content: bytes) -> str:
    """Generate SHA-256 hash of file content."""
    return hashlib.sha256(content).hexdigest()

def hash_string(value: str) -> str:
    """Generate SHA-256 hash of a string."""
    return hashlib.sha256(value.encode()).hexdigest()

def generate_case_id() -> str:
    """Generate a unique case identifier."""
    return f"CASE-{secrets.token_hex(8).upper()}"

def verify_hash(content: bytes, expected_hash: str) -> bool:
    """Verify content against expected hash."""
    return hmac.compare_digest(hash_file_content(content), expected_hash)

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage."""
    import re
    filename = re.sub(r'[^\w\s.-]', '', filename)
    filename = re.sub(r'\s+', '_', filename)
    return filename.strip()

def anonymize_ip(ip: str) -> str:
    """Anonymize IP address (last octet)."""
    parts = ip.split('.')
    if len(parts) == 4:
        parts[3] = 'xxx'
    return '.'.join(parts)