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