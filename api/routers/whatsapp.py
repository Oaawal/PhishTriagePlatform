"""
WhatsApp bot (Meta WhatsApp Cloud API webhook).

Users forward a suspicious message to the PhishTriage WhatsApp number and
get a verdict back. Commands:

    <any message>              -> scam check
    check 0803 123 4567        -> phone number reputation
    account 0123456789 [bank]  -> bank account reputation
    scammed                    -> recovery menu
    help                       -> menu

Setup: see docs/WHATSAPP_SETUP.md
"""
import hashlib
import hmac
import logging
import re
from collections import OrderedDict

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from sqlmodel import Session, select

from api import config
from api.db import engine as db_engine
from api.models import Account, Number
from api.normalize import normalize_ng_number
from api.reputation import confidence_from_count, normalize_account_number, recompute_account, recompute_number, status_note
from api.routers.analyze import log_scan, run_analysis
from engine.recovery import get_plan

log = logging.getLogger("phishtriage.whatsapp")
router = APIRouter(tags=["whatsapp"])

_seen: "OrderedDict[str, None]" = OrderedDict()
RISK_EMOJI = {"High": "🔴", "Medium": "🟠", "Low": "🟢"}

MENU = (
    "👋 *PhishTriage* – free scam checker\n\n"
    "• *Forward* any suspicious SMS/WhatsApp message here and I will check it.\n"
    "• *check 0803 123 4567* – has this number been reported?\n"
    "• *account 0123456789 opay* – has this bank account been reported?\n"
    "• *scammed* – what to do if you have already been scammed.\n\n"
    "I never ask for your OTP, PIN, BVN or password."
)
RECOVERY_KEYWORDS = {
    "transfer": "bank_transfer", "otp": "otp_shared", "loan": "loan_app",
    "invest": "investment", "hacked": "sim_or_account_hijack",
}
RECOVERY_MENU = (
    "😟 Sorry this happened. Reply with one word:\n\n"
    "*recover transfer* – I sent money to a scammer\n"
    "*recover otp* – I shared my OTP/PIN/card details\n"
    "*recover loan* – a loan app is threatening me\n"
    "*recover invest* – an investment is not paying back\n"
    "*recover hacked* – my WhatsApp/SIM was taken over\n\n"
    "If you sent money, call your bank *now*. Speed matters."
)


def _verify_signature(body: bytes, header: str | None) -> bool:
    if not config.WHATSAPP_APP_SECRET or not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(config.WHATSAPP_APP_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.removeprefix("sha256="))


def _already_seen(message_id: str) -> bool:
    if message_id in _seen:
        return True
    _seen[message_id] = None
    while len(_seen) > 2000:
        _seen.popitem(last=False)
    return False


def format_verdict(result: dict) -> str:
    lines = [f"{RISK_EMOJI[result['risk']]} *{result['risk'].upper()} RISK* ({result['score']}/100)",
             f"Type: {result['category']}", ""]
    if result["risk"] == "Low":
        lines.append("No common scam signs found. If unsure, verify with the sender through an official channel.")
    else:
        lines.append("*Why:*")
        lines += [f"• {r}" for r in result["reasons"][:4]]
        lines += ["", "*What to do:*"]
        lines += [f"• {a}" for a in result["advice"][:3]]
    accts, phones = result["indicators"]["accounts"], result["indicators"]["phones"]
    if accts or phones:
        lines += ["", "Check them here:"]
        lines += [f"• account {a}" for a in accts[:2]]
        lines += [f"• check {p}" for p in phones[:2]]
    return "\n".join(lines)


def format_number(session: Session, raw: str) -> str:
    n = normalize_ng_number(raw)
    if not n:
        return "That does not look like a Nigerian phone number. Example: *check 0803 123 4567*"
    rec = session.get(Number, n)
    if not rec:
        return f"🟢 {n}: no approved reports.\n{status_note(0)}"
    recompute_number(session, rec)
    session.commit()
    emoji = RISK_EMOJI.get(rec.risk_level, "⚪")
    return (f"{emoji} {n}: *{rec.risk_level}*\nLabel: {rec.current_label or 'Reported'}\n"
            f"Confidence: {confidence_from_count(rec.report_count_total)}%\n"
            f"{status_note(rec.report_count_total, cleared=rec.source == 'cleared')}")


def format_account(session: Session, raw: str) -> str:
    m = re.match(r"\s*(\d[\d\s-]{8,14}\d)\s*(.*)$", raw)
    acct = normalize_account_number(m.group(1)) if m else None
    if not acct:
        return "Send a 10-digit account number. Example: *account 0123456789 opay*"
    rows = session.exec(select(Account).where(Account.account_number == acct)).all()
    for r in rows:
        recompute_account(session, r)
    session.commit()
    rows = [r for r in rows if r.report_count_total or r.cleared]
    if not rows:
        return (f"🟢 Account {acct}: no approved reports.\n{status_note(0)}\n\n"
                "Tip: before paying, check that the account name your bank shows matches who you expect.")
    out = []
    for r in rows:
        out.append(f"{RISK_EMOJI.get(r.risk_level, '⚪')} Account {acct} ({r.bank}): *{r.risk_level}*\n"
                   f"Name on reports: {r.account_name or 'not given'}\n"
                   f"{status_note(r.report_count_total, cleared=r.cleared)}")
    return "\n\n".join(out)


def format_recovery(keyword: str) -> str:
    situation = next((v for k, v in RECOVERY_KEYWORDS.items() if k in keyword), None)
    plan = get_plan(situation) if situation else None
    if not plan:
        return RECOVERY_MENU
    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(plan["steps"], 1))
    return f"*{plan['title']}*\n\n{steps}\n\n_{plan['disclaimer']}_"


def build_reply(text: str) -> str:
    t = text.strip()
    low = t.lower()
    with Session(db_engine) as session:
        if low in {"hi", "hello", "help", "menu", "start", "hey"}:
            return MENU
        if low.startswith(("check ", "number ")):
            return format_number(session, t.split(" ", 1)[1])
        if low.startswith(("account ", "acct ")):
            return format_account(session, t.split(" ", 1)[1])
        if low.startswith("recover"):
            return format_recovery(low)
        if low in {"scammed", "i've been scammed", "i have been scammed", "i was scammed", "fraud"}:
            return RECOVERY_MENU
        if len(t) < 12:
            return MENU
        result = run_analysis(t)
        log_scan(session, result, "whatsapp")
        return format_verdict(result)


def send_whatsapp_text(to: str, body: str) -> None:
    if not (config.WHATSAPP_TOKEN and config.WHATSAPP_PHONE_NUMBER_ID):
        log.warning("WhatsApp token/phone number ID not configured; reply not sent")
        return
    url = f"https://graph.facebook.com/{config.WHATSAPP_GRAPH_VERSION}/{config.WHATSAPP_PHONE_NUMBER_ID}/messages"
    try:
        r = httpx.post(
            url,
            headers={"Authorization": f"Bearer {config.WHATSAPP_TOKEN}"},
            json={"messaging_product": "whatsapp", "to": to, "type": "text",
                  "text": {"preview_url": False, "body": body[:4000]}},
            timeout=15,
        )
        if r.status_code >= 400:
            log.warning("WhatsApp send failed: HTTP %s", r.status_code)
    except httpx.HTTPError as exc:
        log.warning("WhatsApp send error: %s", type(exc).__name__)


def handle_message(sender: str, text: str) -> None:
    try:
        reply = build_reply(text)
    except Exception:
        log.exception("Failed to build WhatsApp reply")
        reply = "Sorry, something went wrong. Please try again in a minute."
    send_whatsapp_text(sender, reply)


@router.get("/webhooks/whatsapp")
def verify_webhook(request: Request):
    p = request.query_params
    if (config.WHATSAPP_VERIFY_TOKEN and p.get("hub.mode") == "subscribe"
            and hmac.compare_digest(p.get("hub.verify_token", ""), config.WHATSAPP_VERIFY_TOKEN)):
        return Response(content=p.get("hub.challenge", ""), media_type="text/plain")
    raise HTTPException(status_code=403, detail="Verification failed")


@router.post("/webhooks/whatsapp")
async def receive_webhook(request: Request, background: BackgroundTasks):
    raw = await request.body()
    if not _verify_signature(raw, request.headers.get("x-hub-signature-256")):
        raise HTTPException(status_code=403, detail="Bad signature")
    payload = await request.json()
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})
            for msg in value.get("messages", []) or []:
                mid, sender = msg.get("id", ""), msg.get("from", "")
                if not sender or (mid and _already_seen(mid)):
                    continue
                if msg.get("type") == "text":
                    background.add_task(handle_message, sender, msg.get("text", {}).get("body", ""))
                else:
                    background.add_task(send_whatsapp_text, sender,
                                        "I can only check text for now. Please copy and paste or forward the message text.")
    return {"status": "ok"}
