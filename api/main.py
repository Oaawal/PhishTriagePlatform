from fastapi import FastAPI, Depends
from sqlmodel import Session, select

from api.db import init_db, get_session
from api.models import Case

app = FastAPI(title="PhishTriage API", version="0.2.0")

@app.on_event("startup")
def on_startup():
    init_db()

@app.get("/health")
def health():
    return {"status": "ok"}

# --- Case Queue (MVP) ---

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
        return {"error": "not found"}
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
        return {"error": "not found"}

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