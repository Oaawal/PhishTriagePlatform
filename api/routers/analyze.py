"""Message analysis endpoints (used by the app, the WhatsApp bot and the console)."""
from collections import Counter
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from sqlmodel import Session, select

from api import config
from api.db import get_session
from api.limiter import check_rate_limit
from api.models import utcnow, ScanLog
from api.schemas import AnalyzeRequest, LegacyMessageRequest
from engine import analyze_text

router = APIRouter(tags=["analyze"])


def run_analysis(message: str) -> dict:
    return analyze_text(message)


def log_scan(session: Session, result: dict, channel: str) -> None:
    session.add(ScanLog(
        channel=(channel or "app")[:20],
        risk=result["risk"],
        score=result["score"],
        category=result["category"],
        domains=",".join(result["indicators"]["domains"])[:500],
        engine_version=result["engine_version"],
    ))
    session.commit()


@router.post("/analyze")
def analyze(body: AnalyzeRequest, request: Request, session: Session = Depends(get_session)):
    """Analyse a message with the rules engine."""
    check_rate_limit(request, "analyze", config.RATE_LIMIT_ANALYZE)
    result = run_analysis(body.message)
    log_scan(session, result, body.channel)
    return result


# ---- Backward-compatible endpoints (old PhishTriageScanner response shape) ----

def _legacy(result: dict) -> dict:
    return {
        "risk": f"{result['risk']} Risk",
        "scam_type": result["category"],
        "score": result["score"],
        "reasons": result["reasons"],
        "advice": " ".join(result["advice"][:2]),
        "indicators": result["indicators"],
    }


@router.post("/analyze-message", include_in_schema=False)
def analyze_message_legacy(body: LegacyMessageRequest, request: Request, session: Session = Depends(get_session)):
    check_rate_limit(request, "analyze", config.RATE_LIMIT_ANALYZE)
    result = run_analysis(body.message)
    log_scan(session, result, "legacy")
    return _legacy(result)


# Old app versions call this; it now returns the same rules-engine result.
@router.post("/advanced-ai-scan", include_in_schema=False)
def advanced_scan_legacy(body: LegacyMessageRequest, request: Request, session: Session = Depends(get_session)):
    check_rate_limit(request, "analyze", config.RATE_LIMIT_ANALYZE)
    result = run_analysis(body.message)
    log_scan(session, result, "legacy")
    return _legacy(result)


@router.get("/stats/public")
def public_stats(days: int = 30, session: Session = Depends(get_session)):
    """Anonymous scam trend statistics (no message content)."""
    days = max(1, min(days, 365))
    since = utcnow() - timedelta(days=days)
    rows = session.exec(select(ScanLog).where(ScanLog.created_at >= since)).all()
    risky = [r for r in rows if r.risk != "Low"]
    domains = Counter(d for r in risky for d in r.domains.split(",") if d)
    return {
        "days": days,
        "scans": len(rows),
        "flagged": len(risky),
        "by_category": dict(Counter(r.category for r in risky).most_common()),
        "by_risk": dict(Counter(r.risk for r in rows)),
        "top_flagged_domains": [{"domain": d, "count": c} for d, c in domains.most_common(10)],
    }
