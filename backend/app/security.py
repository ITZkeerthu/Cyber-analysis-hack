import hashlib
import hmac
import ipaddress
import re
import secrets

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
    """Sanitize filename for safe storage.

    Removes path components and unsafe characters, and never returns an
    empty string or a dot-only name such as ``..``.
    """
    filename = (filename or "").replace("\\", "/").split("/")[-1]
    filename = re.sub(r'[^\w\s.-]', '', filename)
    filename = re.sub(r'\s+', '_', filename)
    filename = filename.strip().lstrip('.')
    return filename or "unnamed"

def anonymize_ip(ip: str) -> str:
    """Anonymize an IP address (last IPv4 octet, or last 80 bits of IPv6)."""
    ip = (ip or "").strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 4:
        parts = ip.split('.')
        parts[3] = 'xxx'
        return '.'.join(parts)
    return str(ipaddress.ip_network((addr, 48), strict=False)).split('/')[0] + '::xxxx'
