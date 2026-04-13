from datetime import datetime, timedelta
import re
from fastapi import FastAPI, Depends, HTTPException, Request
from sqlmodel import Session, select
from fastapi.middleware.cors import CORSMiddleware

from api.normalize import normalize_ng_number
from api.db import init_db, get_session
from api.models import Case, Number, Report
from api.limiter import check_rate_limit, generate_fingerprint
from api.auth import verify_admin

app = FastAPI(title="PhishTriage API", version="0.5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
VALID_REASONS = {
    "otp scam",
    "bank scam",
    "loan scam",
    "impersonation",
    "investment scam",
    "romance scam",
    "job scam",
    "other",
}

VALID_CHANNELS = {"sms", "call", "whatsapp", "telegram", "email", "other"}


def sanitize_message(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = text.strip()
    return text[:1000]


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
            "success": True,
            "found": False,
            "number": n,
            "message": "No reports or profile found",
        }

    trend = "stable"
    if record.report_count_7d and record.report_count_7d >= 5:
        trend = "rising"

    confidence = min(50 + (record.report_count_total or 0) * 5, 100)

    return {
        "success": True,
        "found": True,
        "number": record.number_e164,
        "risk_level": record.risk_level,
        "confidence": confidence,
        "current_label": record.current_label or "Unknown",
        "tags": record.tags or "",
        "report_count_total": record.report_count_total or 0,
        "report_count_7d": record.report_count_7d or 0,
        "report_count_30d": record.report_count_30d or 0,
        "last_reported_at": record.last_reported_at.isoformat() if record.last_reported_at else None,
        "trend": trend,
        "is_monitored": record.is_monitored,
    }


# ---------------- REPORT ----------------

@app.post("/report")
def report_number(
    request: Request,
    number: str,
    reason: str,
    channel: str,
    message: str | None = None,
    session: Session = Depends(get_session),
):
    check_rate_limit(request)

    # generate fingerprint server-side — user cannot fake this
    reporter_fingerprint = generate_fingerprint(request)

    if reason.lower().strip() not in VALID_REASONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid reason. Must be one of: {', '.join(sorted(VALID_REASONS))}"
        )

    if channel.lower().strip() not in VALID_CHANNELS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid channel. Must be one of: {', '.join(sorted(VALID_CHANNELS))}"
        )

    n = normalize_ng_number(number)
    if not n:
        raise HTTPException(status_code=400, detail="Invalid phone number format")

    if message:
        message = sanitize_message(message)

    # duplicate protection using server-side fingerprint
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
        reason=reason.strip(),
        channel=channel.strip(),
        message_sanitized=message,
        status="Pending",
        reporter_fingerprint=reporter_fingerprint,
    )

    session.add(report)

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
        "success": True,
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


@app.get("/admin/reports", dependencies=[Depends(verify_admin)])
def list_admin_reports(
    status: str = "Pending",
    session: Session = Depends(get_session),
):
    stmt = select(Report).where(Report.status == status).order_by(Report.created_at.desc())
    return session.exec(stmt).all()


# ---------------- MODERATION ----------------

@app.patch("/admin/reports/{report_id}", dependencies=[Depends(verify_admin)])
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

        if number.report_count_total >= 15:
            risk = "High"
        elif number.report_count_total >= 5:
            risk = "Medium"
        else:
            risk = "Low"

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
        "success": True,
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


# ---------------- REPORT-CASE LINKING ----------------

@app.patch("/reports/{report_id}/link-case", dependencies=[Depends(verify_admin)])
def link_report_to_case(
    report_id: str,
    case_id: str,
    session: Session = Depends(get_session),
):
    report = session.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    case = session.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    report.case_id = case_id
    session.add(report)
    session.commit()
    session.refresh(report)

    return {
        "success": True,
        "message": "Report linked to case",
        "report_id": report.id,
        "case_id": case_id,
    }


# ---------------- NUMBER REPORT HISTORY ----------------

@app.get("/numbers/{number}/reports")
def reports_for_number(number: str, session: Session = Depends(get_session)):
    n = normalize_ng_number(number)
    if not n:
        raise HTTPException(status_code=400, detail="Invalid phone number format")

    reports = session.exec(
        select(Report)
        .where(Report.number_e164 == n)
        .order_by(Report.created_at.desc())
    ).all()

    return {
        "success": True,
        "number": n,
        "total": len(reports),
        "reports": reports,
    }


# ---------------- MONITORING ----------------

@app.patch("/numbers/{number}/monitor", dependencies=[Depends(verify_admin)])
def monitor_number(
    number: str,
    monitored_by: str | None = None,
    session: Session = Depends(get_session),
):
    n = normalize_ng_number(number)
    if not n:
        raise HTTPException(status_code=400, detail="Invalid phone number format")

    record = session.get(Number, n)
    if not record:
        raise HTTPException(status_code=404, detail="Number not found")

    record.is_monitored = True
    record.monitored_since = datetime.utcnow()
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


@app.patch("/numbers/{number}/unmonitor", dependencies=[Depends(verify_admin)])
def unmonitor_number(
    number: str,
    session: Session = Depends(get_session),
):
    n = normalize_ng_number(number)
    if not n:
        raise HTTPException(status_code=400, detail="Invalid phone number format")

    record = session.get(Number, n)
    if not record:
        raise HTTPException(status_code=404, detail="Number not found")

    record.is_monitored = False
    record.monitored_since = None
    record.monitored_by = None

    session.add(record)
    session.commit()

    return {
        "success": True,
        "message": "Number removed from monitoring",
        "number": n,
    }


@app.get("/numbers/monitored", dependencies=[Depends(verify_admin)])
def monitored_numbers(session: Session = Depends(get_session)):
    stmt = (
        select(Number)
        .where(Number.is_monitored == True)
        .order_by(Number.monitored_since.desc())
    )
    numbers = session.exec(stmt).all()

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


# ---------------- CASES ----------------

@app.post("/cases", dependencies=[Depends(verify_admin)])
def create_case(case: Case, session: Session = Depends(get_session)):
    session.add(case)
    session.commit()
    session.refresh(case)
    return case


@app.get("/cases", dependencies=[Depends(verify_admin)])
def list_cases(status: str = "Open", session: Session = Depends(get_session)):
    stmt = select(Case).where(Case.status == status).order_by(Case.created_at.desc())
    return session.exec(stmt).all()


@app.get("/cases/{case_id}", dependencies=[Depends(verify_admin)])
def get_case(case_id: str, session: Session = Depends(get_session)):
    c = session.get(Case, case_id)
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    return c


@app.patch("/cases/{case_id}", dependencies=[Depends(verify_admin)])
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
