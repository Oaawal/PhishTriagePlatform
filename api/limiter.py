"""
Simple in-memory rate limiting and reporter fingerprinting.

Works for a single server instance. If you run several instances, move
the counters to Redis.
"""
import hashlib
import re
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from api import config

_lock = threading.Lock()
_hits: dict[str, deque] = defaultdict(deque)
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


def client_ip(request: Request) -> str:
    if config.TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def device_id(request: Request) -> str | None:
    d = request.headers.get("x-device-id", "").strip()
    return d if _DEVICE_ID_RE.match(d) else None


def client_key(request: Request) -> str:
    """Identity used for rate limiting: app install ID if present, else IP."""
    d = device_id(request)
    return f"dev:{d}" if d else f"ip:{client_ip(request)}"


def check_rate_limit(request: Request, bucket: str = "default", limit: int | None = None, window: int = 60):
    limit = limit or config.RATE_LIMIT_REPORTS
    key = f"{bucket}:{client_key(request)}"
    now = time.monotonic()
    with _lock:
        q = _hits[key]
        while q and q[0] <= now - window:
            q.popleft()
        if len(q) >= limit:
            raise HTTPException(status_code=429, detail="Too many requests. Please wait a minute and try again.")
        q.append(now)


def reset_rate_limits():
    with _lock:
        _hits.clear()


def generate_fingerprint(request: Request) -> str:
    """Salted hash identifying a reporter without storing their IP or device ID."""
    d = device_id(request)
    if d:
        raw = f"dev:{d}"
    else:
        raw = f"ip:{client_ip(request)}:{request.headers.get('user-agent', 'unknown')}"
    return hashlib.sha256(f"{config.FINGERPRINT_SALT}:{raw}".encode()).hexdigest()
