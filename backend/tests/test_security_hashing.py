import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import hashing, security  # noqa: E402

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_hash_bytes_known_vector():
    assert hashing.hash_bytes(b"") == EMPTY_SHA256


def test_hash_file_and_integrity(tmp_path):
    f = tmp_path / "evidence.bin"
    f.write_bytes(b"abc" * 10000)
    digest = hashing.hash_file(str(f))
    assert digest == hashing.hash_bytes(b"abc" * 10000)
    assert hashing.verify_file_integrity(str(f), digest)
    assert not hashing.verify_file_integrity(str(f), EMPTY_SHA256)
    assert not hashing.verify_file_integrity(str(tmp_path / "missing"), digest)


def test_verify_hash():
    assert security.verify_hash(b"", EMPTY_SHA256)
    assert not security.verify_hash(b"x", EMPTY_SHA256)


def test_case_id_format_unique():
    a, b = security.generate_case_id(), security.generate_case_id()
    assert a.startswith("CASE-") and a != b


def test_sanitize_filename_blocks_traversal():
    assert security.sanitize_filename("../../etc/passwd") == "passwd"
    assert security.sanitize_filename("..") == "unnamed"
    assert security.sanitize_filename("") == "unnamed"
    assert security.sanitize_filename("my log (1).csv") == "my_log_1.csv"
    assert security.sanitize_filename("C:\\temp\\a b.txt") == "a_b.txt"


def test_anonymize_ip():
    assert security.anonymize_ip("192.168.1.42") == "192.168.1.xxx"
    assert security.anonymize_ip("not-an-ip") == "not-an-ip"
    assert security.anonymize_ip("2001:db8:1:2:3:4:5:6").endswith("::xxxx")
