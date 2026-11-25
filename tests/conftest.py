import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["ADMIN_API_KEY"] = "test-admin-key"
os.environ["WHATSAPP_APP_SECRET"] = "test-secret"
os.environ["WHATSAPP_VERIFY_TOKEN"] = "verify-me"
os.environ.pop("LLM_API_KEY", None)
os.environ.pop("MIMO_API_KEY", None)

import pytest  # noqa: E402

db_file = ROOT / "test.db"
if db_file.exists():
    db_file.unlink()

from fastapi.testclient import TestClient  # noqa: E402

from api.limiter import reset_rate_limits  # noqa: E402
from api.main import app  # noqa: E402

ADMIN = {"X-API-Key": "test-admin-key"}


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c
    if db_file.exists():
        db_file.unlink()


@pytest.fixture(autouse=True)
def _reset_limits():
    reset_rate_limits()
