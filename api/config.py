"""Central configuration, read from environment variables."""
import os


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


APP_ENV = os.getenv("APP_ENV", "production")

# Admin endpoints are disabled unless this is set (fail closed).
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")

# Salt for hashing reporter identities. Set a long random value in production.
FINGERPRINT_SALT = os.getenv("FINGERPRINT_SALT", "dev-only-salt")

# Render, Railway, Fly etc. put the real client IP in X-Forwarded-For.
TRUST_PROXY = _bool("TRUST_PROXY", True)

ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]

# Raw (sanitised) message text attached to reports is deleted after this many days.
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "180"))

# Rate limits (requests per minute per client)
RATE_LIMIT_REPORTS = int(os.getenv("RATE_LIMIT_REPORTS", "10"))
RATE_LIMIT_ANALYZE = int(os.getenv("RATE_LIMIT_ANALYZE", "30"))

# WhatsApp Cloud API
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
WHATSAPP_APP_SECRET = os.getenv("WHATSAPP_APP_SECRET", "")
WHATSAPP_GRAPH_VERSION = os.getenv("WHATSAPP_GRAPH_VERSION", "v23.0")
