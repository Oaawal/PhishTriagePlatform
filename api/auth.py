import hmac

from fastapi import Header, HTTPException

from api import config


def verify_admin(x_api_key: str | None = Header(default=None)):
    if not config.ADMIN_API_KEY:
        raise HTTPException(status_code=503, detail="Admin API disabled: ADMIN_API_KEY is not set on the server")
    if not x_api_key or not hmac.compare_digest(x_api_key, config.ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Forbidden")
