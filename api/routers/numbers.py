"""Phone number lookup, community reports and alerts."""
import re
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlmodel import Session, select

from api.auth import verify_admin
from api.db import get_session
from api.limiter import check_rate_limit, generate_fingerprint
from api.models import utcnow, Number, Report
from api.normalize import normalize_ng_number
from api.reputation import (
    VALID_CHANNELS, VALID_REASONS, confidence_from_count, recompute_number, status_note,
)
from api.routers.training import add_shared_sample
from engine.engine import extract_indicators, sanitize_message as mask_codes

router = APIRouter(tags=["numbers"])


def clean_user_text(text: str | None, limit: int = 1000) -> str | None:
    if not text:
        return None
    text = re.sub(r"<[^>]+>", "", text).strip()
    text = mask_codes(text, extract_indicators(text).codes)
    return text[:limit] or None


def _normalize_or_400(number: str) -> str:
    n = normalize_ng_number(number)
    if not n:
        raise HTTPException(status_code=400, detail="Invalid Nigerian phone number format")
    return n


def _has_open_dispute(session: Session, target_id: str) -> bool:
    from api.models import Dispute
    return session.exec(
        select(Dispute).where(Dispute.target_id == target_id, Dispute.status == "Pending")
    ).first() is not None


@router.get("/normalize")
def normalize(number: str):
    return {"input": number, "normalized": _normalize_or_400(number)}


@router.get("/lookup")
def lookup(number: str, session: Session = Depends(get_session)):
    n = _normalize_or_400(number)
    record = session.get(Number, n)
    if not record:
        return {
            "success": True,
            "found": False,
            "number": n,
            "message": "No reports or profile found",
            "status_note": status_note(0),
        }

    recompute_number(session, record)
    session.commit()
    session.refresh(record)
    under_review = _has_open_dispute(session, n)
    cleared = record.source == "cleared"
    return {
        "success": True,
        "found": True,
        "number": record.number_e164,
        "risk_level": record.risk_level,
        "confidence": confidence_from_count(record.report_count_total),
        "current_label": record.current_label or "Unknown",
        "tags": record.tags or "",
        "report_count_total": record.report_count_total or 0,
        "report_count_7d": record.report_count_7d or 0,
        "report_count_30d": record.report_count_30d or 0,
        "last_reported_at": record.last_reported_at.isoformat() if record.last_reported_at else None,
        "trend": "rising" if (record.report_count_7d or 0) >= 5 else "stable",
        "is_monitored": record.is_monitored,
        "under_review": under_review,
        "cleared": cleared,
        "status_note": status_note(record.report_count_total, under_review, cleared),
    }


@router.post("/report")
def report_number(
    request: Request,
    number: str,
    reason: str,
    channel: str,
    message: str | None = None,
    share_for_training: bool = False,
    session: Session = Depends(get_session),
):
    """Report a phone number (query parameters kept for app compatibility).

    `share_for_training=true` means the reporter agreed that the message may be
    used, with personal details removed, to train PhishTriage's own model.
    """
    check_rate_limit(request, "report")
    reason_n, channel_n = reason.lower().strip(), channel.lower().strip()
    if reason_n not in VALID_REASONS:
        raise HTTPException(status_code=400, detail=f"Invalid reason. Must be one of: {', '.join(sorted(VALID_REASONS))}")
    if channel_n not in VALID_CHANNELS:
        raise HTTPException(status_code=400, detail=f"Invalid channel. Must be one of: {', '.join(sorted(VALID_CHANNELS))}")
    n = _normalize_or_400(number)
    fingerprint = generate_fingerprint(request)

    cutoff = utcnow() - timedelta(days=30)
    existing = session.exec(
        select(Report).where(
            Report.number_e164 == n,
            Report.reporter_fingerprint == fingerprint,
            Report.created_at >= cutoff,
        )
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="You have already reported this number recently")

    report = Report(
        number_e164=n,
        reason=reason_n,
        channel=channel_n,
        message_sanitized=clean_user_text(message),
        reporter_fingerprint=fingerprint,
    )
    session.add(report)
    if not session.get(Number, n):
        session.add(Number(number_e164=n, source="community"))
    if share_for_training and message:
        add_shared_sample(session, message, "report", user_label="scam", report_id=report.id, scam_type=reason_n)
    session.commit()
    session.refresh(report)
    return {
        "success": True,
        "message": "Report submitted. A moderator will review it before it appears in lookups.",
        "report_id": report.id,
        "status": report.status,
        "number": n,
    }


@router.get("/numbers/high-risk")
def high_risk_numbers(session: Session = Depends(get_session)):
    stmt = select(Number).where(Number.risk_level == "High").order_by(Number.last_reported_at.desc())
    return [
        {
            "number": n.number_e164,
            "risk_level": n.risk_level,
            "label": n.current_label or "Reported",
            "report_count_total": n.report_count_total,
            "last_reported_at": n.last_reported_at.isoformat() if n.last_reported_at else None,
        }
        for n in session.exec(stmt).all()
    ]


@router.get("/alerts")
def alerts(session: Session = Depends(get_session)):
    cutoff_30d = utcnow() - timedelta(days=30)
    stmt = (
        select(Number)
        .where(Number.risk_level == "High")
        .where(Number.report_count_total >= 3)
        .where(Number.last_reported_at >= cutoff_30d)
        .order_by(Number.last_reported_at.desc())
    )
    numbers = session.exec(stmt).all()
    return {
        "success": True,
        "count": len(numbers),
        "alerts": [
            {
                "number": n.number_e164,
                "risk_level": n.risk_level,
                "label": n.current_label or "Unknown",
                "report_count_total": n.report_count_total,
                "report_count_7d": n.report_count_7d,
                "last_reported_at": n.last_reported_at.isoformat() if n.last_reported_at else None,
                "tags": n.tags or "",
                "trend": "rising" if (n.report_count_7d or 0) >= 5 else "stable",
            }
            for n in numbers
        ],
    }


@router.get("/numbers/{number}/reports")
def reports_for_number(number: str, session: Session = Depends(get_session)):
    """Public summary of approved reports. No reporter identity or message text."""
    n = _normalize_or_400(number)
    reports = session.exec(
        select(Report).where(Report.number_e164 == n, Report.status == "Approved").order_by(Report.created_at.desc())
    ).all()
    return {
        "success": True,
        "number": n,
        "total": len(reports),
        "reports": [
            {"reason": r.reason, "channel": r.channel, "created_at": r.created_at.isoformat()} for r in reports
        ],
    }


# ---------------- Monitoring (admin) ----------------

@router.patch("/numbers/{number}/monitor", dependencies=[Depends(verify_admin)])
def monitor_number(number: str, monitored_by: str | None = None, session: Session = Depends(get_session)):
    n = _normalize_or_400(number)
    record = session.get(Number, n)
    if not record:
        raise HTTPException(status_code=404, detail="Number not found")
    record.is_monitored = True
    record.monitored_since = utcnow()
    record.monitored_by = monitored_by
    session.add(record)
    session.commit()
    session.refresh(record)
    return {
        "success": True,
        "message": "Number is now being monitored",
        "number": n,
        "monitored_since": record.monitored_since.isoformat(),
        "monitored_by": record.monitored_by,
    }


@router.patch("/numbers/{number}/unmonitor", dependencies=[Depends(verify_admin)])
def unmonitor_number(number: str, session: Session = Depends(get_session)):
    n = _normalize_or_400(number)
    record = session.get(Number, n)
    if not record:
        raise HTTPException(status_code=404, detail="Number not found")
    record.is_monitored = False
    record.monitored_since = None
    record.monitored_by = None
    session.add(record)
    session.commit()
    return {"success": True, "message": "Number removed from monitoring", "number": n}


@router.get("/numbers/monitored", dependencies=[Depends(verify_admin)])
def monitored_numbers(session: Session = Depends(get_session)):
    numbers = session.exec(
        select(Number).where(Number.is_monitored == True).order_by(Number.monitored_since.desc())  # noqa: E712
    ).all()
    return {
        "success": True,
        "count": len(numbers),
        "numbers": [
            {
                "number": n.number_e164,
                "risk_level": n.risk_level,
                "label": n.current_label or "Unknown",
                "monitored_since": n.monitored_since.isoformat() if n.monitored_since else None,
                "monitored_by": n.monitored_by,
                "report_count_total": n.report_count_total,
            }
            for n in numbers
        ],
    }
