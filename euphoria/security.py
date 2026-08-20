"""Hashing, fingerprint helpers, and comparison utilities."""
import hashlib
import hmac

from . import config


def _pepper() -> bytes:
    """Derive a stable pepper from the app secret."""
    return hashlib.sha256(config.SECRET_KEY.encode('utf-8')).digest()


def hash_device_id(value: str) -> str:
    """One-way HMAC-SHA256 of HWID / UID / browser fingerprint. Never store plaintext."""
    if not value:
        return ''
    return hmac.new(_pepper(), value.strip().encode('utf-8'), hashlib.sha256).hexdigest()


def fingerprint(hashed: str) -> str:
    """Short non-reversible display form for admin UI (first 12 hex chars)."""
    if not hashed:
        return ''
    return hashed[:12].upper()


def safe_compare(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    if not a or not b:
        return False
    return hmac.compare_digest(a, b)


def looks_like_hash(value) -> bool:
    """HMAC-SHA256 hex digest is always 64 lowercase hex characters."""
    if not value or not isinstance(value, str):
        return False
    if len(value) != 64:
        return False
    return all(c in '0123456789abcdef' for c in value)
