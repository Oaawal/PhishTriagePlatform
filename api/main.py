from fastapi import FastAPI, Depends, HTTPException
from sqlmodel import Session, select
from api.normalize import normalize_ng_number
from api.db import init_db, get_session
from api.models import Case, Number

app = FastAPI(title="PhishTriage API", version="0.2.1")


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
        "endpoints": {
            "create_case": "POST /cases",
            "list_cases": "GET /cases?status=Open",
            "get_case": "GET /cases/{case_id}",
            "update_case": "PATCH /cases/{case_id}",
            "normalize": "GET /normalize?number=08012345678",
            "lookup": "GET /lookup?number=08012345678",
        },
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/normalize")
def normalize(number: str):
    n = normalize_ng_number(number)
    if not n:
        raise HTTPException(status_code=400, detail="Invalid phone number format")
    return {"input": number, "normalized": n}


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
            "message": "No reports or profile found for this number yet"
        }

    return {
        "number": record.number_e164,
        "found": True,
        "current_label": record.current_label,
        "risk_level": record.risk_level,
        "tags": record.tags,
        "report_count_total": record.report_count_total,
        "report_count_7d": record.report_count_7d,
        "report_count_30d": record.report_count_30d,
        "last_reported_at": record.last_reported_at,
        "source": record.source,
    }


# ---------------- Case Queue (MVP) ----------------

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
