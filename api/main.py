"""PhishTriage API: scam detection, number/account reputation, recovery help and WhatsApp bot."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session

from api import config
from api.db import engine, init_db
from api import linkcheck
from api.routers import accounts, admin, analyze, numbers, recovery, training, whatsapp
from engine import ENGINE_VERSION

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("phishtriage")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    try:
        with Session(engine) as session:
            purged = admin.purge_old_message_text(session)
            if purged:
                log.info("Retention purge removed message text from %s reports", purged)
    except Exception:
        log.exception("Retention purge failed")
    if not config.ADMIN_API_KEY:
        log.warning("ADMIN_API_KEY is not set: admin endpoints are disabled")
    yield


app = FastAPI(title="PhishTriage API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "X-API-Key", "X-Device-Id"],
)

app.include_router(analyze.router)
app.include_router(numbers.router)
app.include_router(accounts.router)
app.include_router(recovery.router)
app.include_router(admin.router)
app.include_router(training.router)
app.include_router(training.admin_router)
app.include_router(whatsapp.router)


@app.get("/")
def home():
    return {"name": "PhishTriage API", "status": "running", "docs": "/docs"}


@app.get("/health")
def health():
    return {
        "status": "ok",
        "engine_version": ENGINE_VERSION,
        "whatsapp_enabled": bool(config.WHATSAPP_TOKEN and config.WHATSAPP_PHONE_NUMBER_ID),
        "safe_browsing_enabled": linkcheck.enabled(),
        "training_collection": config.TRAINING_COLLECTION,
    }
