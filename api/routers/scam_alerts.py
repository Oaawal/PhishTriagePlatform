"""
Scam warnings feed ("A fake CBN SMS is going round today") and the offline
number list used by the app's call protection.

Public:
    GET /scam-alerts          active warnings + scam types trending in scans this week
    GET /numbers/blocklist    reported numbers (Medium/High) and verified official numbers, for offline use

Admin (X-API-Key):
    GET   /admin/scam-alerts
    POST  /admin/scam-alerts
    PATCH /admin/scam-alerts/{id}
"""
from collections import Counter
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlmodel import Session, select

from api.auth import verify_admin
from api.db import get_session
from api.models import Number, OfficialContact, ScamAlert, ScanLog, utcnow
from api.schemas import ScamAlertCreate, ScamAlertUpdate

router = APIRouter(tags=["alerts"])
admin_router = APIRouter(tags=["alerts"], dependencies=[Depends(verify_admin)])

BLOCKLIST_MAX = 50000


def _alert(a: ScamAlert) -> dict:
    return {"id": a.id, "title": a.title, "body": a.body, "category": a.category, "severity": a.severity,
            "created_at": a.created_at.isoformat()}


def active_alerts(session: Session, limit: int = 20) -> list[ScamAlert]:
    now = utcnow()
    rows = session.exec(
        select(ScamAlert).where(ScamAlert.active == True).order_by(ScamAlert.created_at.desc())  # noqa: E712
    ).all()
    return [a for a in rows if not a.expires_at or a.expires_at > now][:limit]


def trending(session: Session) -> list[dict]:
    """Scam types flagged in scans this week compared with the week before."""
    now = utcnow()
    rows = session.exec(
        select(ScanLog).where(ScanLog.created_at >= now - timedelta(days=14), ScanLog.risk != "Low")
    ).all()
    week = Counter(r.category for r in rows if r.created_at >= now - timedelta(days=7))
    prev = Counter(r.category for r in rows if r.created_at < now - timedelta(days=7))
    out = []
    for cat, n in week.most_common(5):
        before = prev.get(cat, 0)
        change = None if before == 0 else round((n - before) / before * 100)
        out.append({"category": cat, "flagged_this_week": n, "flagged_last_week": before, "change_percent": change})
    return out


@router.get("/scam-alerts")
def scam_alerts(session: Session = Depends(get_session)):
    return {"success": True, "alerts": [_alert(a) for a in active_alerts(session)], "trending": trending(session)}


@router.get("/numbers/blocklist")
def blocklist(response: Response, session: Session = Depends(get_session)):
    """Compact list for the app to keep offline. Keys: n=number, r=risk, l=label, c=approved reports, o=org."""
    numbers = session.exec(
        select(Number)
        .where(Number.risk_level != "Low", Number.report_count_total >= 1, Number.source != "cleared")
        .order_by(Number.report_count_total.desc())
        .limit(BLOCKLIST_MAX)
    ).all()
    official = session.exec(
        select(OfficialContact).where(OfficialContact.verified == True, OfficialContact.active == True,  # noqa: E712
                                      OfficialContact.kind.in_(["phone", "whatsapp"]))
    ).all()
    response.headers["Cache-Control"] = "public, max-age=900"
    return {
        "generated_at": utcnow().isoformat(),
        "count": len(numbers),
        "numbers": [{"n": x.number_e164, "r": x.risk_level, "l": x.current_label or "Reported",
                     "c": x.report_count_total} for x in numbers],
        "official": [{"n": o.value_normalized, "o": o.org_name} for o in official if o.value_normalized.startswith("+")],
    }


# ---------------- Admin ----------------

@admin_router.get("/admin/scam-alerts")
def admin_alerts(session: Session = Depends(get_session)):
    return session.exec(select(ScamAlert).order_by(ScamAlert.created_at.desc())).all()


@admin_router.post("/admin/scam-alerts")
def create_alert(body: ScamAlertCreate, session: Session = Depends(get_session)):
    data = body.model_dump(exclude={"expires_in_days"})
    a = ScamAlert(**data, expires_at=utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None)
    session.add(a)
    session.commit()
    session.refresh(a)
    return a


@admin_router.patch("/admin/scam-alerts/{alert_id}")
def update_alert(alert_id: str, body: ScamAlertUpdate, session: Session = Depends(get_session)):
    a = session.get(ScamAlert, alert_id)
    if not a:
        raise HTTPException(status_code=404, detail="Not found")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(a, k, v)
    session.add(a)
    session.commit()
    session.refresh(a)
    return a
