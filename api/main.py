from datetime import datetime
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
    return {"status": "running", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------- NORMALIZE ----------------

@app.get("/normalize")
def normalize(number: str):
    n = normalize_ng_number(number)
    if not n:
        raise HTTPException(400, "Invalid phone number")
    return {"normalized": n}


# ---------------- LOOKUP ----------------

@app.get("/lookup")
def lookup(number: str, session: Session = Depends(get_session)):
    n = normalize_ng_number(number)
    if not n:
        raise HTTPException(400, "Invalid phone number")

    record = session.get(Number, n)

    if not record:
        return {"found": False, "number": n}

    trend = "stable"
    if record.report_count_7d >= 5:
        trend = "rising"

    confidence = min(50 + (record.report_count_total * 5), 100)

    return {
        "found": True,
        "number": record.number_e164,
        "risk_level": record.risk_level,
        "confidence": confidence,
        "current_label": record.current_label,
        "report_count_total": record.report_count_total,
        "trend": trend,
    }


# ---------------- REPORT ----------------

@app.post("/report")
def report_number(
    number: str,
    reason: str,
    channel: str,
    session: Session = Depends(get_session),
):
    n = normalize_ng_number(number)

    report = Report(
        number_e164=n,
        reason=reason,
        channel=channel,
        status="Pending",
    )

    session.add(report)

    number_record = session.get(Number, n)
    if not number_record:
        number_record = Number(
            number_e164=n,
            report_count_total=0,
            report_count_7d=0,
            report_count_30d=0,
            risk_level="Low",
        )
        session.add(number_record)

    session.commit()
    session.refresh(report)

    return {"status": "submitted", "report_id": report.id}


# ---------------- REPORTS ----------------

@app.get("/reports")
def get_reports(session: Session = Depends(get_session)):
    return session.exec(select(Report)).all()


@app.get("/admin/reports")
def get_admin_reports(status: str = "Pending", session: Session = Depends(get_session)):
    return session.exec(select(Report).where(Report.status == status)).all()


@app.patch("/admin/reports/{report_id}")
def moderate(report_id: str, action: str, session: Session = Depends(get_session)):
    report = session.get(Report, report_id)

    if not report:
        raise HTTPException(404, "Report not found")

    report.status = "Approved" if action == "approve" else "Rejected"

    if action == "approve":
        number = session.get(Number, report.number_e164)

        number.report_count_total += 1
        number.report_count_7d += 1
        number.report_count_30d += 1
        number.last_reported_at = datetime.utcnow()

        if number.report_count_total >= 5:
            number.risk_level = "Medium"
        if number.report_count_total >= 15:
            number.risk_level = "High"

        session.add(number)

    session.add(report)
    session.commit()

    return {"status": report.status}


# ---------------- HIGH RISK ----------------

@app.get("/numbers/high-risk")
def high_risk(session: Session = Depends(get_session)):
    return session.exec(
        select(Number).where(Number.risk_level == "High")
    ).all()


# ---------------- ALERTS ----------------

@app.get("/alerts")
def alerts(session: Session = Depends(get_session)):
    numbers = session.exec(
        select(Number).where(Number.risk_level == "High")
    ).all()

    return [
        {
            "number": n.number_e164,
            "risk": n.risk_level,
            "label": n.current_label,
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
def get_cases(status: str = "Open", session: Session = Depends(get_session)):
    return session.exec(select(Case).where(Case.status == status)).all()


@app.patch("/cases/{case_id}")
def update_case(case_id: str, status: str, session: Session = Depends(get_session)):
    case = session.get(Case, case_id)
    case.status = status
    session.commit()
    return case
