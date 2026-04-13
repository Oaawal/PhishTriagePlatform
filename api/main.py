from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException
from sqlmodel import Session, select

from api.normalize import normalize_ng_number
from api.db import init_db, get_session
from api.models import Case, Number, Report

app = FastAPI(title="PhishTriage API", version="0.5.0")


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def home():
    return {
        "name": "PhishTriage API",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------- NORMALIZE ----------------

@app.get("/normalize")
def normalize(number: str):
    n = normalize_ng_number(number)
    if not n:
        raise HTTPException(status_code=400, detail="Invalid phone number format")
    return {"input": number, "normalized": n}


# ---------------- LOOKUP ----------------

@app.get("/lookup")
def lookup(number: str, session: Session = Depends(get_session)):
    n = normalize_ng_number(number)
    if not n:
        raise HTTPException(status_code=400, detail="Invalid phone number format")

    record = session.get(Number, n)

    if not record:
        return {
            "found": False,
            "number": n,
            "message": "No reports or profile found",
        }

    # trend logic
    trend = "stable"
    if record.report_count_7d and record.report_count_7d >= 5:
        trend = "rising"

    # confidence scoring
    confidence = min(50 + (record.report_count_total or 0) * 5, 100)

    return {
        "found": True,
        "number": record.number_e164,
        "risk_level": record.risk_level,
        "confidence": confidence,
        "current_label": record.current_label,
        "tags": record.tags,
        "report_count_total": record.report_count_total,
        "report_count_7d": record.report_count_7d,
        "report_count_30d": record.report_count_30d,
        "last_reported_at": record.last_reported_at,
        "trend": trend,
    }


# ---------------- REPORT ----------------

@app.post("/report")
def report_number(
    number: str,
    reason: str,
    channel: str,
    message: str | None = None,
    reporter_fingerprint: str | None = None,
    session: Session = Depends(get_session),
):
    n = normalize_ng_number(number)
    if not n:
        raise HTTPException(status_code=400, detail="Invalid phone number format")

    # duplicate protection: one report per number per 30 days per fingerprint
    if reporter_fingerprint:
        cutoff = datetime.utcnow() - timedelta(days=30)
        existing = session.exec(
            select(Report).where(
                Report.number_e164 == n,
                Report.reporter_fingerprint == reporter_fingerprint,
                Report.created_at >= cutoff,
            )
        ).first()

        if existing:
            raise HTTPException(
                status_code=400,
                detail="You have already reported this number recently"
            )

    report = Report(
        number_e164=n,
        reason=reason,
        channel=channel,
        message_sanitized=message,
        status="Pending",
        reporter_fingerprint=reporter_fingerprint,
    )

    session.add(report)

    # ensure number exists
    number_record = session.get(Number, n)
    if not number_record:
        number_record = Number(
            number_e164=n,
            source="community",
            report_count_total=0,
            report_count_7d=0,
            report_count_30d=0,
            risk_level="Low",
        )
        session.add(number_record)

    session.commit()
    session.refresh(report)

    return {
        "message": "Report submitted successfully",
        "report_id": report.id,
        "status": report.status,
        "number": n,
    }


# ---------------- REPORT LIST ----------------

@app.get("/reports")
def list_reports(session: Session = Depends(get_session)):
    stmt = select(Report).order_by(Report.created_at.desc())
    return session.exec(stmt).all()


@app.get("/admin/reports")
def list_admin_reports(
    status: str = "Pending",
    session: Session = Depends(get_session),
):
    stmt = select(Report).where(Report.status == status).order_by(Report.created_at.desc())
    return session.exec(stmt).all()


# ---------------- MODERATION ----------------

@app.patch("/admin/reports/{report_id}")
def moderate_report(
    report_id: str,
    action: str,
    session: Session = Depends(get_session),
):
    report = session.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if action not in ["approve", "reject"]:
        raise HTTPException(status_code=400, detail="Invalid action")

    report.status = "Approved" if action == "approve" else "Rejected"

    if action == "approve":
        number = session.get(Number, report.number_e164)

        now = datetime.utcnow()
        cutoff_7d = now - timedelta(days=7)
        cutoff_30d = now - timedelta(days=30)

        # recalculate counts from approved reports (accurate, no drift)
        approved_reports = session.exec(
            select(Report).where(
                Report.number_e164 == report.number_e164,
                Report.status == "Approved",
            )
        ).all()

        number.report_count_total = len(approved_reports)
        number.report_count_7d = sum(
            1 for r in approved_reports
            if r.created_at and r.created_at >= cutoff_7d
        )
        number.report_count_30d = sum(
            1 for r in approved_reports
            if r.created_at and r.created_at >= cutoff_30d
        )
        number.last_reported_at = now

        # risk scoring based on recalculated total
        if number.report_count_total >= 15:
            risk = "High"
        elif number.report_count_total >= 5:
            risk = "Medium"
        else:
            risk = "Low"

        # label and tag assignment with minimum threshold for High
        reason = report.reason.lower().strip()

        if reason in ["otp scam", "bank scam"]:
            number.current_label = report.reason.title()
            number.tags = "otp,bank"
            if number.report_count_total >= 3:
                risk = "High"
        elif reason == "loan scam":
            number.current_label = "Loan Scam"
            number.tags = "loan,fraud"
            if number.report_count_total >= 3:
                risk = "High"

        number.risk_level = risk
        session.add(number)

    session.add(report)
    session.commit()
    session.refresh(report)

    return {
        "message": "Report updated",
        "status": report.status,
        "report_id": report.id,
    }


# ---------------- HIGH RISK NUMBERS ----------------

@app.get("/numbers/high-risk")
def high_risk_numbers(session: Session = Depends(get_session)):
    stmt = select(Number).where(Number.risk_level == "High").order_by(Number.last_reported_at.desc())
    return session.exec(stmt).all()


# ---------------- ALERTS ----------------

@app.get("/alerts")
def alerts(session: Session = Depends(get_session)):
    cutoff_30d = datetime.utcnow() - timedelta(days=30)

    stmt = (
        select(Number)
        .where(Number.risk_level == "High")
        .where(Number.report_count_total >= 3)
        .where(Number.last_reported_at >= cutoff_30d)
        .order_by(Number.last_reported_at.desc())
    )
    numbers = session.exec(stmt).all()

    return [
        {
            "number": n.number_e164,
            "risk_level": n.risk_level,
            "label": n.current_label,
            "report_count_total": n.report_count_total,
            "report_count_7d": n.report_count_7d,
            "last_reported_at": n.last_reported_at,
            "tags": n.tags,
        }
        for n in numbers
    ]


# ---------------- CASES ----------------

@app.post("/cases")
def create_case(case: Case, session: Session = Depends(get_session)):
    session.add(case)
    session.commit()
    session.refresh(case)
    return case


@app.get("/cases")
def list_cases(status: str = "Open", session: Session = Depends(get_session)):
    stmt = select(Case).where(Case.status == status).order_by(Case.created_at.desc())
    return session.exec(stmt).all()


@app.get("/cases/{case_id}")
def get_case(case_id: str, session: Session = Depends(get_session)):
    c = session.get(Case, case_id)
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    return c


@app.patch("/cases/{case_id}")
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
        c.status = status
    if assignee is not None:
        c.assignee = assignee
    if analyst_notes is not None:
        c.analyst_notes = analyst_notes

    session.add(c)
    session.commit()
    session.refresh(c)

    return c
