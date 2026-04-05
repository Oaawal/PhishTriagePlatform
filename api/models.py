from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field
import uuid

class Case(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    source: str = "sms"  # sms|whatsapp|email

    risk: str
    category: str
    ai_prob: float

    status: str = "Open"  # Open|InReview|Closed
    assignee: Optional[str] = None
    analyst_notes: Optional[str] = None

    sanitized_message: str

    urls: str = ""
    phones: str = ""
    accounts: str = ""

    siem_matches_json: str = ""
    email_checks_json: str = ""

    sensitive_requested: str = ""
    otp_masked: str = ""

from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field
import uuid


class Number(SQLModel, table=True):
    number_e164: str = Field(primary_key=True, index=True)
    current_label: Optional[str] = None
    risk_level: str = Field(default="Low")
    tags: Optional[str] = None
    report_count_total: int = Field(default=0)
    report_count_7d: int = Field(default=0)
    report_count_30d: int = Field(default=0)
    last_reported_at: Optional[datetime] = None
    source: str = Field(default="community")


class Report(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    number_e164: str = Field(index=True)
    reason: str
    channel: str
    message_sanitized: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    status: str = Field(default="Pending")
    moderator_notes: Optional[str] = None
    reporter_fingerprint: Optional[str] = None
