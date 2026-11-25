"""
Official contacts directory: "Is this really my bank's number / SMS sender / website?"

Public:
    GET /directory                 verified official contacts, grouped by organisation
    GET /directory/check?value=    is this phone number, sender name, website or email official?

Admin (X-API-Key):
    GET   /admin/directory          all entries, including unverified and inactive
    POST  /admin/directory          add an entry
    PATCH /admin/directory/{id}     edit, verify or deactivate
"""
import re
from collections import OrderedDict
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from api.auth import verify_admin
from api.db import get_session
from api.models import OfficialContact, utcnow
from api.normalize import normalize_ng_number
from api.schemas import OfficialContactCreate, OfficialContactUpdate
from engine.engine import OFFICIAL_DOMAINS

router = APIRouter(tags=["directory"])
admin_router = APIRouter(tags=["directory"], dependencies=[Depends(verify_admin)])

SPOOF_NOTE = (
    "Scammers can fake caller ID and SMS sender names. Even when a contact is official, "
    "your bank or any agency will never ask for your OTP, PIN, password or full card details."
)

ORG_NAMES = {
    "gtbank": "GTBank", "zenith": "Zenith Bank", "firstbank": "First Bank", "accessbank": "Access Bank",
    "uba": "UBA", "fidelity": "Fidelity Bank", "sterling": "Sterling Bank", "wema": "Wema Bank",
    "fcmb": "FCMB", "stanbic": "Stanbic IBTC", "ecobank": "Ecobank", "opay": "OPay", "palmpay": "PalmPay",
    "moniepoint": "Moniepoint", "kuda": "Kuda", "paga": "Paga", "nimc": "NIMC", "cbn": "CBN",
    "efcc": "EFCC", "ncc": "NCC", "nysc": "NYSC", "jamb": "JAMB", "firs": "FIRS", "customs": "Nigeria Customs",
    "mtn": "MTN", "airtel": "Airtel", "glo": "Glo", "jumia": "Jumia",
}
ORG_TYPES = {
    "opay": "fintech", "palmpay": "fintech", "moniepoint": "fintech", "kuda": "fintech", "paga": "fintech",
    "nimc": "government", "cbn": "government", "efcc": "government", "ncc": "government", "nysc": "government",
    "jamb": "government", "firs": "government", "customs": "government",
    "mtn": "telco", "airtel": "telco", "glo": "telco", "jumia": "other",
}


def host_of(value: str) -> str:
    v = value.strip().lower()
    if not re.match(r"^[a-z]+://", v):
        v = "http://" + v
    try:
        host = urlsplit(v).hostname or ""
    except ValueError:
        host = ""
    return host.removeprefix("www.").strip(".")


def normalize_value(kind: str, value: str) -> str:
    v = value.strip()
    if kind in ("phone", "whatsapp"):
        return normalize_ng_number(v) or re.sub(r"\D", "", v)
    if kind == "website":
        return host_of(v)
    if kind == "email":
        return v.lower()
    if kind == "sms_sender":
        return re.sub(r"\s+", "", v).upper()
    return v.lower()


def guess_kind(value: str) -> str:
    v = value.strip()
    if "@" in v and "." in v.split("@")[-1]:
        return "email"
    if v.startswith("*") and v.endswith("#"):
        return "ussd"
    if re.search(r"[a-z0-9-]+\.[a-z]{2,}", v.lower()) and " " not in v:
        return "website"
    if normalize_ng_number(v) or (re.fullmatch(r"[\d\s+()-]{3,}", v) and len(re.sub(r"\D", "", v)) >= 3):
        return "phone"
    return "sms_sender"


def _public(c: OfficialContact) -> dict:
    return {"org_name": c.org_name, "org_type": c.org_type, "kind": c.kind, "value": c.value,
            "notes": c.notes, "source_url": c.source_url}


def seed_directory(session: Session) -> int:
    """Add the engine's known official websites as UNVERIFIED entries for moderators to check."""
    if session.exec(select(OfficialContact).limit(1)).first():
        return 0
    n = 0
    for token, domains in OFFICIAL_DOMAINS.items():
        org = ORG_NAMES.get(token)
        if not org:
            continue
        for d in domains:
            session.add(OfficialContact(
                org_name=org, org_type=ORG_TYPES.get(token, "bank"), kind="website", value=d,
                value_normalized=d, notes="Seeded from the scam engine. Verify before publishing.",
            ))
            n += 1
    session.commit()
    return n


def official_matches(session: Session, value: str, kind: str | None = None) -> list[OfficialContact]:
    kind = kind or guess_kind(value)
    norm = normalize_value(kind, value)
    if not norm:
        return []
    kinds = ["phone", "whatsapp"] if kind in ("phone", "whatsapp") else [kind]
    rows = session.exec(
        select(OfficialContact).where(OfficialContact.verified == True, OfficialContact.active == True,  # noqa: E712
                                      OfficialContact.kind.in_(kinds))
    ).all()
    if kind == "website":
        return [r for r in rows if norm == r.value_normalized or norm.endswith("." + r.value_normalized)]
    return [r for r in rows if r.value_normalized == norm]


@router.get("/directory")
def directory(q: str | None = None, org_type: str | None = None, session: Session = Depends(get_session)):
    stmt = select(OfficialContact).where(OfficialContact.verified == True, OfficialContact.active == True)  # noqa: E712
    if org_type:
        stmt = stmt.where(OfficialContact.org_type == org_type)
    rows = session.exec(stmt.order_by(OfficialContact.org_name)).all()
    if q:
        ql = q.lower().strip()
        rows = [r for r in rows if ql in r.org_name.lower() or ql in r.value.lower()]
    grouped: "OrderedDict[str, dict]" = OrderedDict()
    for r in rows:
        g = grouped.setdefault(r.org_name, {"org_name": r.org_name, "org_type": r.org_type, "contacts": []})
        g["contacts"].append(_public(r))
    return {"success": True, "count": len(rows), "organisations": list(grouped.values()), "note": SPOOF_NOTE}


@router.get("/directory/check")
def check_official(value: str, session: Session = Depends(get_session)):
    if not value.strip():
        raise HTTPException(status_code=400, detail="Enter a phone number, SMS sender name, website or email")
    kind = guess_kind(value)
    matches = official_matches(session, value, kind)
    if matches:
        orgs = sorted({m.org_name for m in matches})
        verdict = f"This {kind.replace('_', ' ')} is listed as an official contact of {', '.join(orgs)}."
    else:
        verdict = (f"This {kind.replace('_', ' ')} is not in our list of verified official contacts. "
                   "That does not prove it is fake, but be careful and contact the organisation through "
                   "its official app or website.")
    return {"success": True, "value": value, "kind": kind, "official": bool(matches),
            "matches": [_public(m) for m in matches], "verdict": verdict, "note": SPOOF_NOTE}


# ---------------- Admin ----------------

@admin_router.get("/admin/directory")
def admin_directory(session: Session = Depends(get_session)):
    return session.exec(select(OfficialContact).order_by(OfficialContact.org_name, OfficialContact.kind)).all()


@admin_router.post("/admin/directory")
def add_contact(body: OfficialContactCreate, session: Session = Depends(get_session)):
    norm = normalize_value(body.kind, body.value)
    if not norm:
        raise HTTPException(status_code=400, detail="Could not understand that value")
    c = OfficialContact(**body.model_dump(), value_normalized=norm,
                        verified_at=utcnow() if body.verified else None)
    session.add(c)
    session.commit()
    session.refresh(c)
    return c


@admin_router.patch("/admin/directory/{contact_id}")
def update_contact(contact_id: str, body: OfficialContactUpdate, session: Session = Depends(get_session)):
    c = session.get(OfficialContact, contact_id)
    if not c:
        raise HTTPException(status_code=404, detail="Not found")
    data = body.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(c, k, v)
    if "value" in data:
        c.value_normalized = normalize_value(c.kind, c.value)
    if data.get("verified"):
        c.verified_at = utcnow()
    session.add(c)
    session.commit()
    session.refresh(c)
    return c
