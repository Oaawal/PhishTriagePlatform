"""
Database tables.

Case, Number and Report keep their original columns so an existing
database keeps working. New tables (Account, AccountReport, Dispute,
ScanLog) are created automatically on startup.
"""
import uuid
from datetime import UTC, datetime
from typing import Optional

from pydantic import NaiveDatetime
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    """Naive UTC timestamp (matches existing 'timestamp without time zone' columns)."""
    return datetime.now(UTC).replace(tzinfo=None)


def _uuid() -> str:
    return str(uuid.uuid4())


class Case(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    created_at: NaiveDatetime = Field(default_factory=utcnow)
    source: str = "sms"  # sms|whatsapp|email|report|lookup
    risk: str
    category: str
    ai_prob: float = 0.0
    status: str = "Open"  # Open|InReview|Closed
    assignee: Optional[str] = None
    analyst_notes: Optional[str] = None
    sanitized_message: str = ""
    urls: str = ""
    phones: str = ""
    accounts: str = ""
    siem_matches_json: str = ""
    email_checks_json: str = ""
    sensitive_requested: str = ""
    otp_masked: str = ""


class Number(SQLModel, table=True):
    number_e164: str = Field(primary_key=True, index=True)
    current_label: Optional[str] = None
    risk_level: str = Field(default="Low")
    tags: Optional[str] = None
    report_count_total: int = Field(default=0)
    report_count_7d: int = Field(default=0)
    report_count_30d: int = Field(default=0)
    last_reported_at: Optional[NaiveDatetime] = None
    source: str = Field(default="community")
    is_monitored: bool = Field(default=False)
    monitored_since: Optional[NaiveDatetime] = None
    monitored_by: Optional[str] = None


class Report(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    number_e164: str = Field(index=True)
    reason: str
    channel: str
    message_sanitized: Optional[str] = None
    created_at: NaiveDatetime = Field(default_factory=utcnow)
    status: str = Field(default="Pending")  # Pending|Approved|Rejected
    moderator_notes: Optional[str] = None
    reporter_fingerprint: Optional[str] = None
    case_id: Optional[str] = Field(default=None, index=True)


class Account(SQLModel, table=True):
    """Reputation of a bank account (NUBAN) that people were asked to pay into."""
    id: str = Field(primary_key=True)  # "<bank_slug>:<account_number>"
    account_number: str = Field(index=True)
    bank: str = "unknown"
    account_name: Optional[str] = None
    risk_level: str = "Low"
    current_label: Optional[str] = None
    report_count_total: int = 0
    report_count_30d: int = 0
    last_reported_at: Optional[NaiveDatetime] = None
    under_review: bool = False  # an owner dispute is pending
    cleared: bool = False       # a dispute was upheld


class AccountReport(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    account_id: str = Field(index=True)
    account_number: str = Field(index=True)
    bank: str = "unknown"
    account_name: Optional[str] = None
    reason: str
    channel: str
    amount_lost: Optional[float] = None
    message_sanitized: Optional[str] = None
    created_at: NaiveDatetime = Field(default_factory=utcnow)
    status: str = "Pending"
    moderator_notes: Optional[str] = None
    reporter_fingerprint: Optional[str] = None


class Dispute(SQLModel, table=True):
    """Right of reply: the owner of a reported number/account asks for review."""
    id: str = Field(default_factory=_uuid, primary_key=True)
    target_type: str  # number|account
    target_id: str = Field(index=True)
    contact: str
    explanation: str
    created_at: NaiveDatetime = Field(default_factory=utcnow)
    status: str = "Pending"  # Pending|Upheld|Rejected
    moderator_notes: Optional[str] = None


class ScanLog(SQLModel, table=True):
    """Aggregate scan statistics. Never stores the message text."""
    id: str = Field(default_factory=_uuid, primary_key=True)
    created_at: NaiveDatetime = Field(default_factory=utcnow, index=True)
    channel: str = "app"
    risk: str
    score: int
    category: str
    domains: str = ""
    engine_version: str = ""
    used_llm: bool = False
