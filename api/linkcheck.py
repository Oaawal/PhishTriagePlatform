"""
Link reputation check with the Google Safe Browsing Lookup API (v4).

Set SAFE_BROWSING_API_KEY to enable it. Without a key, or if Google is slow
or unreachable, scans still work: the rules engine result is returned and
`link_check.status` says why the links were not checked.

Note: Google offers the Safe Browsing API for non-commercial use. If
PhishTriage is used commercially (for example paid partner feeds), move to
Google's Web Risk API, which has the same kind of lookup. See
docs/SAFE_BROWSING_SETUP.md.
"""
from __future__ import annotations

import logging
import re
import threading
import time

import httpx

from api import config
from engine import Signal
from engine.engine import defang

log = logging.getLogger("phishtriage.linkcheck")

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
THREAT_LABELS = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing / fake login page",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "harmful app",
}
MAX_URLS = 10
CACHE_SECONDS = 30 * 60

_cache: dict[str, tuple[float, list[str]]] = {}
_lock = threading.Lock()


def enabled() -> bool:
    return bool(config.SAFE_BROWSING_API_KEY)


def normalize_url(url: str) -> str:
    u = url.strip().rstrip(".,;:!?)")
    u = re.sub(r"(?i)^hxxp", "http", u)
    if not re.match(r"(?i)^https?://", u):
        u = "http://" + u
    return u


def _cached(url: str) -> list[str] | None:
    with _lock:
        hit = _cache.get(url)
        if hit and hit[0] > time.monotonic():
            return hit[1]
    return None


def _store(url: str, threats: list[str]) -> None:
    with _lock:
        _cache[url] = (time.monotonic() + CACHE_SECONDS, threats)
        if len(_cache) > 5000:
            for k in list(_cache)[:1000]:
                _cache.pop(k, None)


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def check_urls(urls: list[str], timeout: float = 5.0) -> dict:
    """Return {"status": ..., "checked": n, "flagged": {url: [threat types]}}."""
    if not urls:
        return {"status": "no_links", "checked": 0, "flagged": {}}
    if not enabled():
        return {"status": "disabled", "checked": 0, "flagged": {}}

    wanted = list(dict.fromkeys(normalize_url(u) for u in urls))[:MAX_URLS]
    flagged: dict[str, list[str]] = {}
    to_ask = []
    for u in wanted:
        hit = _cached(u)
        if hit is None:
            to_ask.append(u)
        elif hit:
            flagged[u] = hit

    if to_ask:
        body = {
            "client": {"clientId": "phishtriage", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in to_ask],
            },
        }
        try:
            r = httpx.post(ENDPOINT, params={"key": config.SAFE_BROWSING_API_KEY}, json=body, timeout=timeout)
            r.raise_for_status()
            matches = r.json().get("matches", []) or []
        except Exception as exc:  # network, HTTP or JSON error: never break a scan
            log.warning("Safe Browsing check failed: %s", type(exc).__name__)
            return {"status": "error", "checked": 0, "flagged": flagged}
        found: dict[str, list[str]] = {}
        for m in matches:
            url = (m.get("threat") or {}).get("url")
            if url:
                found.setdefault(url, [])
                if m.get("threatType") not in found[url]:
                    found[url].append(m.get("threatType"))
        for u in to_ask:
            _store(u, found.get(u, []))
            if found.get(u):
                flagged[u] = found[u]

    return {"status": "ok", "checked": len(wanted), "flagged": flagged}


def to_signal(check: dict) -> Signal | None:
    if not check.get("flagged"):
        return None
    kinds = sorted({THREAT_LABELS.get(t, t.lower()) for ts in check["flagged"].values() for t in ts})
    return Signal(
        "KNOWN_BAD_LINK",
        f"Google Safe Browsing lists this link as dangerous ({', '.join(kinds)}). Do not open it.",
        70,
        "Phishing link",
        [defang(u) for u in check["flagged"]],
    )
