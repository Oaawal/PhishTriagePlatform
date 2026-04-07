from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException
from sqlmodel import Session, select

from api.normalize import normalize_ng_number
from api.db import init_db, get_session
from api.models import Case, Number, Report

app = FastAPI(title="PhishTriage API", version="0.4.0")


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def home():
    return {
        "name": "PhishTriage API",
        "status": "running",
        "health": "/health",
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
            "number": n,
            "found": False,
            "message": "No reports or profile found for this number yet",
        }

    # insights
    insights = []
    if record.report_count_total > 0:
        insights.append("This number has community reports")
    if record.report_count_7d >= 3:
        insights.append("Recent activity spike detected")
    if record.current_label:
        insights.append(f"Community label: {record.current_label}")

    # trend
    trend = "stable"
    if record.report_count_7d >= 5:
        trend = "rising"

    # confidence
    confidence = min(50 + (record.report_count_total * 5), 100)

    # recommended actions
    if record.risk_level == "High":
        recommended_action = [
            "Do not share OTP or PIN",
            "Block this number",
            "Report to your bank or service provider",
        ]
    elif record.risk_level == "Medium":
        recommended_action = [
            "Exercise caution",
            "Do not send money or sensitive details",
        ]
    else:
        recommended_action = [
            "Stay cautious",
            "Report suspicious behavior if observed",
        ]

    return {
        "number": record.number_e164,
        "found": True,
        "current_label": record.current_label,
        "risk_level": record.risk_level,
        "confidence": confidence,
        "tags": record.tags,
        "report_count_total": record.report_count_total,
        "report_count_7d": record.report_count_7d,
        "report_count_30d": record.report_count_30d,
        "last_reported_at": record.last_reported_at,
        "source": record.source,
        "trend": trend,
        "insights": insights,
        "recommended_action": recommended_action,
    }


# ---------------- REPORT (NO COUNT UPDATE HERE) ----------------

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

    # basic abuse protection
    if reporter_fingerprint:
        existing = session.exec(
            select(Report).where(
                Report.number_e164 == n,
                Report.reporter_fingerprint == reporter_fingerprint,
                Report.status == "Pending",
            )
        ).first()

        if existing:
            raise HTTPException(status_code=400, detail="Duplicate report detected")

    report = Report(
        number_e164=n,
        reason=reason,
        channel=channel,
        message_sanitized=message,
        status="Pending",
        reporter_fingerprint=reporter_fingerprint,
    )

    session.add(report)

    # ensure number exists (without updating counts)
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


# ---------------- ADMIN REPORTS ----------------

@app.get("/admin/reports")
def list_admin_reports(
    status: str = "Pending",
    session: Session = Depends(get_session),
):
    stmt = select(Report).where(Report.status == status).order_by(Report.created_at.desc())
    return session.exec(stmt).all()


@app.patch("/admin/reports/{report_id}")
def moderate_report(
    report_id: str,
    action: str,
    moderator_notes: str | None = None,
    session: Session = Depends(get_session),
):
    report = session.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    action_l = action.lower().strip()
    if action_l not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="Action must be approve or reject")

    report.status = "Approved" if action_l == "approve" else "Rejected"

    if moderator_notes:
        report.moderator_notes = moderator_notes

    # 🔥 ONLY APPROVED REPORTS UPDATE REPUTATION
    if action_l == "approve":
        number_record = session.get(Number, report.number_e164)

        if number_record:
            # increment counts
            number_record.report_count_total += 1
            number_record.report_count_7d += 1
            number_record.report_count_30d += 1
            number_record.last_reported_at = datetime.utcnow()

            # clean risk logic
            count = number_record.report_count_total

            if count >= 15:
                risk = "High"
            elif count >= 5:
                risk = "Medium"
            else:
                risk = "Low"

            reason_l = report.reason.lower().strip()

            if reason_l in ["otp scam", "bank scam"]:
                number_record.current_label = report.reason.title()
                number_record.tags = "otp,bank"
                risk = "High"
            elif reason_l == "loan scam":
                number_record.current_label = "Loan Scam"
                number_record.tags = "loan,fraud"

            number_record.risk_level = risk

            session.add(number_record)

    session.add(report)
    session.commit()
    session.refresh(report)

    return {
        "message": "Report updated successfully",
        "report_id": report.id,
        "status": report.status,
    }


# ---------------- CASE QUEUE ----------------

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
