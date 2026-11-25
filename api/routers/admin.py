"""Moderation, cases, intelligence feed and maintenance. All routes need X-API-Key."""
from collections import Counter
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from api import config
from api.auth import verify_admin
from api.db import get_session
from api.models import utcnow, Account, AccountReport, Case, Dispute, Number, Report, ScanLog
from api.reputation import recompute_account, recompute_number
from api.routers.training import label_samples_for_report
from api.schemas import CaseCreate

router = APIRouter(tags=["admin"], dependencies=[Depends(verify_admin)])

CASE_STATUSES = {"Open", "InReview", "Closed"}


# ---------------- Number reports ----------------

@router.get("/reports")
def list_reports(limit: int = 500, session: Session = Depends(get_session)):
    return session.exec(select(Report).order_by(Report.created_at.desc()).limit(min(limit, 2000))).all()


@router.get("/admin/reports")
def list_admin_reports(status: str = "Pending", session: Session = Depends(get_session)):
    return session.exec(select(Report).where(Report.status == status).order_by(Report.created_at.desc())).all()


@router.patch("/admin/reports/{report_id}")
def moderate_report(report_id: str, action: str, notes: str | None = None, session: Session = Depends(get_session)):
    report = session.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="Invalid action")
    report.status = "Approved" if action == "approve" else "Rejected"
    if notes is not None:
        report.moderator_notes = notes[:1000]
    session.add(report)
    session.flush()
    number = session.get(Number, report.number_e164) or Number(number_e164=report.number_e164)
    recompute_number(session, number)
    label_samples_for_report(session, report.id, approved=action == "approve")
    session.commit()
    return {"success": True, "message": "Report updated", "status": report.status, "report_id": report.id}


@router.patch("/reports/{report_id}/link-case")
def link_report_to_case(report_id: str, case_id: str, session: Session = Depends(get_session)):
    report = session.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not session.get(Case, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    report.case_id = case_id
    session.add(report)
    session.commit()
    return {"success": True, "message": "Report linked to case", "report_id": report.id, "case_id": case_id}


# ---------------- Account reports ----------------

@router.get("/admin/account-reports")
def list_account_reports(status: str = "Pending", session: Session = Depends(get_session)):
    return session.exec(
        select(AccountReport).where(AccountReport.status == status).order_by(AccountReport.created_at.desc())
    ).all()


@router.patch("/admin/account-reports/{report_id}")
def moderate_account_report(report_id: str, action: str, notes: str | None = None, session: Session = Depends(get_session)):
    report = session.get(AccountReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="Invalid action")
    report.status = "Approved" if action == "approve" else "Rejected"
    if notes is not None:
        report.moderator_notes = notes[:1000]
    session.add(report)
    session.flush()
    account = session.get(Account, report.account_id)
    if account:
        recompute_account(session, account)
    label_samples_for_report(session, report.id, approved=action == "approve")
    session.commit()
    return {"success": True, "status": report.status, "report_id": report.id}


# ---------------- Disputes ----------------

@router.get("/admin/disputes")
def list_disputes(status: str = "Pending", session: Session = Depends(get_session)):
    return session.exec(select(Dispute).where(Dispute.status == status).order_by(Dispute.created_at.desc())).all()


@router.patch("/admin/disputes/{dispute_id}")
def resolve_dispute(dispute_id: str, action: str, notes: str | None = None, session: Session = Depends(get_session)):
    """action=uphold clears the listing; action=reject keeps it."""
    d = session.get(Dispute, dispute_id)
    if not d:
        raise HTTPException(status_code=404, detail="Dispute not found")
    if action not in ("uphold", "reject"):
        raise HTTPException(status_code=400, detail="Invalid action")
    d.status = "Upheld" if action == "uphold" else "Rejected"
    d.moderator_notes = (notes or "")[:1000] or None
    if action == "uphold":
        if d.target_type == "number":
            n = session.get(Number, d.target_id)
            if n:
                n.source, n.risk_level, n.current_label = "cleared", "Low", "Cleared after review"
                session.add(n)
        else:
            a = session.get(Account, d.target_id)
            if a:
                a.cleared, a.risk_level, a.current_label = True, "Low", "Cleared after review"
                session.add(a)
    session.add(d)
    session.commit()
    return {"success": True, "status": d.status}


# ---------------- Cases ----------------

@router.post("/cases")
def create_case(body: CaseCreate, session: Session = Depends(get_session)):
    case = Case(**body.model_dump())
    session.add(case)
    session.commit()
    session.refresh(case)
    return case


@router.get("/cases")
def list_cases(status: str = "Open", session: Session = Depends(get_session)):
    stmt = select(Case).order_by(Case.created_at.desc())
    if status != "All":
        stmt = stmt.where(Case.status == status)
    return session.exec(stmt).all()


@router.get("/cases/{case_id}")
def get_case(case_id: str, session: Session = Depends(get_session)):
    c = session.get(Case, case_id)
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    return c


@router.patch("/cases/{case_id}")
def update_case(
    case_id: str,
    status: str | None = None,
    assignee: str | None = None,
    analyst_notes: str | None = None,
    session: Session = Depends(get_session),
):
    c = session.get(Case, case_id)
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    if status:
        if status not in CASE_STATUSES:
            raise HTTPException(status_code=400, detail=f"status must be one of {sorted(CASE_STATUSES)}")
        c.status = status
    if assignee is not None:
        c.assignee = assignee
    if analyst_notes is not None:
        c.analyst_notes = analyst_notes
    session.add(c)
    session.commit()
    session.refresh(c)
    return c


# ---------------- Intelligence feed (for partners) ----------------

@router.get("/admin/feed")
def intelligence_feed(days: int = 30, session: Session = Depends(get_session)):
    """Moderated indicators for fintech / bank fraud teams. Contains no reporter data or message text."""
    since = utcnow() - timedelta(days=max(1, min(days, 365)))
    numbers = session.exec(select(Number).where(Number.risk_level != "Low", Number.last_reported_at >= since)).all()
    accounts = session.exec(select(Account).where(Account.risk_level != "Low", Account.last_reported_at >= since)).all()
    scans = session.exec(select(ScanLog).where(ScanLog.created_at >= since, ScanLog.risk == "High")).all()
    domains = Counter(d for s in scans for d in s.domains.split(",") if d)
    return {
        "generated_at": utcnow().isoformat(),
        "window_days": days,
        "numbers": [{"number": n.number_e164, "risk": n.risk_level, "label": n.current_label,
                     "reports": n.report_count_total, "last_reported_at": n.last_reported_at.isoformat()}
                    for n in numbers],
        "accounts": [{"account_number": a.account_number, "bank": a.bank, "risk": a.risk_level,
                      "label": a.current_label, "reports": a.report_count_total,
                      "last_reported_at": a.last_reported_at.isoformat()} for a in accounts if not a.cleared],
        "domains": [{"domain": d, "high_risk_scans": c} for d, c in domains.most_common(200)],
    }


# ---------------- Maintenance ----------------

def purge_old_message_text(session: Session) -> int:
    """Delete stored message text older than RETENTION_DAYS (NDPA data minimisation)."""
    cutoff = utcnow() - timedelta(days=config.RETENTION_DAYS)
    count = 0
    for model in (Report, AccountReport):
        rows = session.exec(
            select(model).where(model.created_at < cutoff, model.message_sanitized != None)  # noqa: E711
        ).all()
        for r in rows:
            r.message_sanitized = None
            session.add(r)
            count += 1
    session.commit()
    return count


@router.post("/admin/maintenance/purge")
def purge(session: Session = Depends(get_session)):
    return {"success": True, "purged_messages": purge_old_message_text(session),
            "retention_days": config.RETENTION_DAYS}
