"""
Reputation scoring for phone numbers and bank accounts.

Only APPROVED (moderated) reports count. Wording shown to the public is
deliberately factual ("reported N times") rather than accusatory, because
a report is not proof. Owners can dispute a listing (see /disputes).
"""
import re
from datetime import datetime, timedelta

from sqlmodel import Session, select

from api.models import utcnow, Account, AccountReport, Number, Report

REASON_LABELS = {
    "otp scam": ("OTP scam", "otp,bank"),
    "bank scam": ("Bank impersonation", "bank"),
    "loan scam": ("Loan scam", "loan"),
    "impersonation": ("Impersonation", "impersonation"),
    "investment scam": ("Investment scam", "investment"),
    "romance scam": ("Romance scam", "romance"),
    "job scam": ("Job scam", "job"),
    "wrong transfer": ("Fake wrong-transfer", "transfer"),
    "family impersonation": ("Family/new-number scam", "family"),
    "online shopping": ("Online shopping / vendor scam", "shopping"),
    "other": ("Reported", "other"),
}
VALID_REASONS = set(REASON_LABELS)
VALID_CHANNELS = {"sms", "call", "whatsapp", "telegram", "email", "instagram", "facebook", "tiktok", "x", "website", "other"}


def risk_from_count(total: int) -> str:
    if total >= 3:
        return "High"
    if total >= 1:
        return "Medium"
    return "Low"


def confidence_from_count(total: int) -> int:
    return min(40 + total * 12, 99) if total else 0


def status_note(total: int, under_review: bool = False, cleared: bool = False) -> str:
    if cleared:
        return "This listing was reviewed after a dispute and cleared."
    if total == 0:
        return "No approved reports. That does not prove it is safe. Stay careful."
    note = f"Reported by {total} {'person' if total == 1 else 'people'}. Reports are reviewed by moderators but are not proof."
    if under_review:
        note += " The owner has disputed this listing and it is under review."
    return note


def _top_reason(reasons: list[str]) -> str:
    if not reasons:
        return "other"
    return max(set(reasons), key=reasons.count)


def recompute_number(session: Session, number: Number) -> Number:
    approved = session.exec(
        select(Report).where(Report.number_e164 == number.number_e164, Report.status == "Approved")
    ).all()
    now = utcnow()
    number.report_count_total = len(approved)
    number.report_count_7d = sum(1 for r in approved if r.created_at >= now - timedelta(days=7))
    number.report_count_30d = sum(1 for r in approved if r.created_at >= now - timedelta(days=30))
    number.last_reported_at = max((r.created_at for r in approved), default=None)
    if approved:
        label, tags = REASON_LABELS.get(_top_reason([r.reason.lower() for r in approved]), REASON_LABELS["other"])
        number.current_label, number.tags = label, tags
    if number.source != "cleared":
        number.risk_level = risk_from_count(number.report_count_total)
    session.add(number)
    return number


def recompute_account(session: Session, account: Account) -> Account:
    approved = session.exec(
        select(AccountReport).where(AccountReport.account_id == account.id, AccountReport.status == "Approved")
    ).all()
    now = utcnow()
    account.report_count_total = len(approved)
    account.report_count_30d = sum(1 for r in approved if r.created_at >= now - timedelta(days=30))
    account.last_reported_at = max((r.created_at for r in approved), default=None)
    if approved:
        account.current_label = REASON_LABELS.get(_top_reason([r.reason.lower() for r in approved]), REASON_LABELS["other"])[0]
        names = [r.account_name for r in approved if r.account_name]
        if names:
            account.account_name = max(set(names), key=names.count)
    if not account.cleared:
        account.risk_level = risk_from_count(account.report_count_total)
    session.add(account)
    return account


def normalize_account_number(raw: str) -> str | None:
    digits = re.sub(r"\D", "", raw or "")
    return digits if len(digits) == 10 else None


def bank_slug(bank: str | None) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (bank or "unknown").lower()).strip("-")
    return s or "unknown"


def account_id(account_number: str, bank: str | None) -> str:
    return f"{bank_slug(bank)}:{account_number}"
