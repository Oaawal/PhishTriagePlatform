"""
Bank account (NUBAN) check: "Is it safe to pay into this account?"

Plus the right-of-reply dispute process for both numbers and accounts.
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlmodel import Session, select

from api.db import get_session
from api.limiter import check_rate_limit, generate_fingerprint
from api.models import utcnow, Account, AccountReport, Dispute, Number
from api.normalize import normalize_ng_number
from api.reputation import (
    VALID_CHANNELS, VALID_REASONS, account_id, confidence_from_count, normalize_account_number,
    recompute_account, status_note,
)
from api.routers.numbers import clean_user_text
from api.routers.training import add_shared_sample
from api.schemas import AccountReportRequest, DisputeRequest

router = APIRouter(tags=["accounts"])


def _account_view(session: Session, a: Account) -> dict:
    under_review = session.exec(
        select(Dispute).where(Dispute.target_id == a.id, Dispute.status == "Pending")
    ).first() is not None
    return {
        "bank": a.bank,
        "account_number": a.account_number,
        "account_name": a.account_name,
        "risk_level": a.risk_level,
        "label": a.current_label or "Reported",
        "report_count_total": a.report_count_total,
        "report_count_30d": a.report_count_30d,
        "confidence": confidence_from_count(a.report_count_total),
        "last_reported_at": a.last_reported_at.isoformat() if a.last_reported_at else None,
        "under_review": under_review,
        "cleared": a.cleared,
        "status_note": status_note(a.report_count_total, under_review, a.cleared),
    }


@router.get("/accounts/lookup")
def lookup_account(account_number: str, bank: str | None = None, session: Session = Depends(get_session)):
    acct = normalize_account_number(account_number)
    if not acct:
        raise HTTPException(status_code=400, detail="Account number must be 10 digits")
    stmt = select(Account).where(Account.account_number == acct)
    rows = session.exec(stmt).all()
    if bank:
        wanted = account_id(acct, bank)
        rows = [r for r in rows if r.id == wanted] or rows
    views = []
    for r in rows:
        recompute_account(session, r)
    session.commit()
    for r in rows:
        session.refresh(r)
        if r.report_count_total or r.cleared:
            views.append(_account_view(session, r))
    worst = max((v["risk_level"] for v in views), key=lambda x: {"Low": 0, "Medium": 1, "High": 2}[x], default="Low")
    return {
        "success": True,
        "account_number": acct,
        "found": bool(views),
        "risk_level": worst,
        "matches": views,
        "status_note": views[0]["status_note"] if len(views) == 1 else status_note(0) if not views else
        "This account number has reports at more than one bank. Check the bank name.",
        "tip": "Before paying a vendor or 'agent', confirm the account name your bank shows matches the person or business you expect.",
    }


@router.post("/accounts/report")
def report_account(body: AccountReportRequest, request: Request, session: Session = Depends(get_session)):
    check_rate_limit(request, "report")
    acct = normalize_account_number(body.account_number)
    if not acct:
        raise HTTPException(status_code=400, detail="Account number must be 10 digits")
    reason, channel = body.reason.lower().strip(), body.channel.lower().strip()
    if reason not in VALID_REASONS:
        raise HTTPException(status_code=400, detail=f"Invalid reason. Must be one of: {', '.join(sorted(VALID_REASONS))}")
    if channel not in VALID_CHANNELS:
        raise HTTPException(status_code=400, detail=f"Invalid channel. Must be one of: {', '.join(sorted(VALID_CHANNELS))}")

    aid = account_id(acct, body.bank)
    fingerprint = generate_fingerprint(request)
    dup = session.exec(
        select(AccountReport).where(
            AccountReport.account_id == aid,
            AccountReport.reporter_fingerprint == fingerprint,
            AccountReport.created_at >= utcnow() - timedelta(days=30),
        )
    ).first()
    if dup:
        raise HTTPException(status_code=400, detail="You have already reported this account recently")

    report = AccountReport(
        account_id=aid,
        account_number=acct,
        bank=(body.bank or "unknown").strip()[:60],
        account_name=(body.account_name or "").strip()[:120] or None,
        reason=reason,
        channel=channel,
        amount_lost=body.amount_lost,
        message_sanitized=clean_user_text(body.message),
        reporter_fingerprint=fingerprint,
    )
    session.add(report)
    if not session.get(Account, aid):
        session.add(Account(id=aid, account_number=acct, bank=report.bank, account_name=report.account_name))
    if body.share_for_training and body.message:
        add_shared_sample(session, body.message, "account_report", user_label="scam", report_id=report.id, scam_type=reason)
    session.commit()
    session.refresh(report)
    return {
        "success": True,
        "message": "Report submitted. A moderator will review it before it appears in checks.",
        "report_id": report.id,
        "status": report.status,
    }


@router.post("/disputes")
def create_dispute(body: DisputeRequest, request: Request, session: Session = Depends(get_session)):
    """Owners of a listed number or account can ask for a review (right of reply)."""
    check_rate_limit(request, "dispute", limit=3)
    if body.target_type == "number":
        target = normalize_ng_number(body.target)
        if not target or not session.get(Number, target):
            raise HTTPException(status_code=404, detail="That number has no listing")
    else:
        acct = normalize_account_number(body.target)
        if not acct:
            raise HTTPException(status_code=400, detail="Account number must be 10 digits")
        target = account_id(acct, body.bank)
        if not session.get(Account, target):
            raise HTTPException(status_code=404, detail="That account has no listing. Include the bank name.")
    d = Dispute(target_type=body.target_type, target_id=target, contact=body.contact.strip(),
                explanation=clean_user_text(body.explanation, 2000) or "")
    session.add(d)
    session.commit()
    return {"success": True, "dispute_id": d.id,
            "message": "Thank you. A moderator will review your request and contact you."}
