"""'I've been scammed, what now?' guidance and complaint letter generator."""
from fastapi import APIRouter, HTTPException, Request

from api.limiter import check_rate_limit
from api.schemas import IncidentRequest
from engine.recovery import build_incident_letter, evidence_record, get_plan, list_situations

router = APIRouter(tags=["recovery"])


@router.get("/recovery")
def recovery_options():
    return {"success": True, "situations": list_situations()}


@router.get("/recovery/{situation}")
def recovery_plan(situation: str):
    plan = get_plan(situation)
    if not plan:
        raise HTTPException(status_code=404, detail="Unknown situation")
    return {"success": True, **plan}


@router.post("/recovery/letter")
def recovery_letter(body: IncidentRequest, request: Request):
    """Generate a complaint letter. Nothing is stored on the server."""
    check_rate_limit(request, "letter", limit=10)
    data = body.model_dump(exclude={"recipient"})
    letter = build_incident_letter(data, body.recipient)
    record = evidence_record(data, letter)
    return {
        "success": True,
        "recipient": body.recipient,
        "letter": letter,
        "created_at_utc": record["created_at_utc"],
        "sha256": record["sha256"],
        "note": record["note"],
        "stored": False,
    }
