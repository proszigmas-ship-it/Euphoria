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


import time
import threading
from collections import defaultdict, deque


class RateLimiter:
    """Sliding-window IP rate limiter to prevent HTTP flood & DDoS attacks."""
    def __init__(self):
        self._lock = threading.Lock()
        self._requests = defaultdict(deque)
        self._auth_requests = defaultdict(deque)

    def reset(self):
        with self._lock:
            self._requests.clear()
            self._auth_requests.clear()

    def is_rate_limited(self, ip: str, is_auth: bool = False, is_testing: bool = False) -> tuple[bool, int]:
        """
        Checks if an IP exceeds rate limits.
        Limits:
        - General: 120 req / 60s
        - Auth & sensitive APIs: 20 req / 60s
        Returns (is_limited: bool, retry_after_seconds: int)
        """
        if is_testing:
            return False, 0

        now = time.time()
        window = 60.0
        limit = 20 if is_auth else 120
        queue = self._auth_requests[ip] if is_auth else self._requests[ip]

        with self._lock:
            while queue and queue[0] < now - window:
                queue.popleft()

            if len(queue) >= limit:
                oldest = queue[0]
                retry_after = max(1, int(window - (now - oldest)))
                return True, retry_after

            queue.append(now)
            return False, 0


rate_limiter = RateLimiter()
