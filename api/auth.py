from fastapi import Header, HTTPException
import os

ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "changeme-local")


def verify_admin(x_api_key: str = Header(...)):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")
