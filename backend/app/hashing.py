import hashlib
import hmac
import os
from typing import BinaryIO

CHUNK_SIZE = 8192

def hash_file(file_path: str) -> str:
    """Generate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def hash_bytes(data: bytes) -> str:
    """Generate SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()

def hash_stream(stream: BinaryIO) -> str:
    """Generate SHA-256 hash from a stream."""
    sha256_hash = hashlib.sha256()
    while chunk := stream.read(CHUNK_SIZE):
        sha256_hash.update(chunk)
    stream.seek(0)
    return sha256_hash.hexdigest()

def verify_file_integrity(file_path: str, expected_hash: str) -> bool:
    """Verify file integrity against expected hash."""
    if not os.path.exists(file_path):
        return False
    actual_hash = hash_file(file_path)
    return hmac.compare_digest(actual_hash, expected_hash)