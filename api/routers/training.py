"""
Feedback and training-data collection for PhishTriage's own model.

Public:
    POST /feedback                     "Was this result right?" (+ optional consent to share the message)

Admin (X-API-Key):
    GET   /admin/training/stats        dataset size, labels, engine accuracy from feedback
    GET   /admin/training/queue        shared messages waiting for a moderator label
    PATCH /admin/training/{id}         label=scam|safe, or label=discard to delete
    GET   /admin/training/export       CSV (label,category_hint,text) for scripts/train_model.py
"""
import csv
import io
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlmodel import Session, select

from api import config
from api.auth import verify_admin
from api.db import get_session
from api.limiter import check_rate_limit
from api.models import ScanLog, TrainingSample, utcnow
from api.schemas import FeedbackRequest
from engine import ENGINE_VERSION, analyze_text, redact_for_training

router = APIRouter(tags=["training"])
admin_router = APIRouter(tags=["training"], dependencies=[Depends(verify_admin)])

LABELS = {"scam", "safe"}


def add_shared_sample(
    session: Session,
    text: str,
    source: str,
    user_label: str | None = None,
    report_id: str | None = None,
    scam_type: str | None = None,
) -> TrainingSample | None:
    """Store a consented, redacted message as a training sample (caller commits)."""
    if not config.TRAINING_COLLECTION or not (text or "").strip():
        return None
    redacted = redact_for_training(text)
    if len(redacted) < 8:
        return None
    verdict = analyze_text(text)
    sample = TrainingSample(
        source=source,
        consent=True,
        text_redacted=redacted,
        report_id=report_id,
        engine_risk=verdict["risk"],
        engine_score=verdict["score"],
        engine_category=verdict["category"],
        engine_version=ENGINE_VERSION,
        user_label=user_label,
        scam_type=scam_type,
    )
    session.add(sample)
    return sample


def label_samples_for_report(session: Session, report_id: str, approved: bool) -> None:
    """When a moderator approves a report, its shared message becomes a 'scam' example."""
    if not approved:
        return
    for s in session.exec(select(TrainingSample).where(TrainingSample.report_id == report_id)).all():
        if s.moderator_label is None:
            s.moderator_label = "scam"
            s.moderated_at = utcnow()
            session.add(s)


@router.post("/feedback")
def feedback(body: FeedbackRequest, request: Request, session: Session = Depends(get_session)):
    """Tell us whether a scan result was right. Sharing the message is optional and anonymised."""
    check_rate_limit(request, "feedback", limit=20)
    if not config.TRAINING_COLLECTION:
        return {"success": True, "stored": False}
    scan = session.get(ScanLog, body.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Unknown scan")

    if body.verdict == "correct":
        label = "scam" if scan.risk != "Low" else "safe"
    else:
        label = body.verdict

    sample = session.exec(select(TrainingSample).where(TrainingSample.scan_id == body.scan_id)).first()
    if not sample:
        sample = TrainingSample(
            scan_id=scan.id,
            source=scan.channel or "app",
            engine_risk=scan.risk,
            engine_score=scan.score,
            engine_category=scan.category,
            engine_version=scan.engine_version,
        )
    sample.user_label = label
    if body.share_message and body.message:
        redacted = redact_for_training(body.message)
        if len(redacted) >= 8:
            sample.consent = True
            sample.text_redacted = redacted
    session.add(sample)
    session.commit()
    return {
        "success": True,
        "stored": True,
        "shared_text": bool(sample.text_redacted),
        "message": "Thank you. Your feedback helps PhishTriage get better.",
    }


# ---------------- Admin ----------------

@admin_router.get("/admin/training/stats")
def training_stats(session: Session = Depends(get_session)):
    rows = session.exec(select(TrainingSample)).all()
    with_text = [r for r in rows if r.text_redacted]
    reviewed = [r for r in with_text if r.moderator_label]
    fb = [r for r in rows if r.user_label and r.engine_risk]
    confusion = Counter(
        ("flagged" if r.engine_risk != "Low" else "not_flagged", r.user_label) for r in fb
    )
    agree = confusion[("flagged", "scam")] + confusion[("not_flagged", "safe")]
    return {
        "samples_total": len(rows),
        "messages_shared": len(with_text),
        "messages_reviewed": len(reviewed),
        "reviewed_labels": dict(Counter(r.moderator_label for r in reviewed)),
        "awaiting_review": len(with_text) - len(reviewed),
        "by_source": dict(Counter(r.source for r in with_text)),
        "feedback": {
            "count": len(fb),
            "engine_agreement_rate": round(agree / len(fb), 3) if fb else None,
            "missed_scams": confusion[("not_flagged", "scam")],
            "false_alarms": confusion[("flagged", "safe")],
        },
        "ready_to_train": len(reviewed) >= 1000,
        "target_reviewed_samples": 1000,
    }


@admin_router.get("/admin/training/queue")
def training_queue(limit: int = 50, session: Session = Depends(get_session)):
    stmt = (
        select(TrainingSample)
        .where(TrainingSample.text_redacted != None, TrainingSample.moderator_label == None)  # noqa: E711
        .order_by(TrainingSample.created_at)
        .limit(max(1, min(limit, 200)))
    )
    return session.exec(stmt).all()


@admin_router.patch("/admin/training/{sample_id}")
def label_sample(sample_id: str, label: str, scam_type: str | None = None, session: Session = Depends(get_session)):
    sample = session.get(TrainingSample, sample_id)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    if label == "discard":
        session.delete(sample)
        session.commit()
        return {"success": True, "deleted": True}
    if label not in LABELS:
        raise HTTPException(status_code=400, detail="label must be scam, safe or discard")
    sample.moderator_label = label
    sample.moderated_at = utcnow()
    if scam_type:
        sample.scam_type = scam_type[:60]
    session.add(sample)
    session.commit()
    return {"success": True, "id": sample.id, "moderator_label": label}


@admin_router.get("/admin/training/export")
def export_training(include_unreviewed: bool = False, session: Session = Depends(get_session)):
    """CSV in the same format as tests/data/ng_messages.csv: label,category_hint,text."""
    rows = session.exec(select(TrainingSample).where(TrainingSample.text_redacted != None)).all()  # noqa: E711
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["label", "category_hint", "text"])
    for r in rows:
        label = r.moderator_label or (r.user_label if include_unreviewed else None)
        if label in LABELS:
            w.writerow(["scam" if label == "scam" else "legit", r.scam_type or r.source, r.text_redacted])
    return Response(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishtriage_training.csv"},
    )
