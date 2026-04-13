from collections import defaultdict
from datetime import datetime, timedelta
from fastapi import Request, HTTPException

# store: ip -> list of request timestamps
_request_log: dict = defaultdict(list)

RATE_LIMIT = 10        # max requests
WINDOW_SECONDS = 60    # per 60 seconds


def check_rate_limit(request: Request):
    ip = request.client.host
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=WINDOW_SECONDS)

    # keep only recent requests
    _request_log[ip] = [t for t in _request_log[ip] if t >= window_start]

    if len(_request_log[ip]) >= RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait before submitting again."
        )

    _request_log[ip].append(now)
