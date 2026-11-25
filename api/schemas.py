"""Request bodies for the JSON endpoints."""
from typing import Optional

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=5000)
    channel: str = Field(default="app", max_length=20)


class LegacyMessageRequest(BaseModel):
    message: str = Field(..., max_length=5000)


class AccountReportRequest(BaseModel):
    account_number: str = Field(..., max_length=20)
    bank: str = Field(default="unknown", max_length=60)
    account_name: Optional[str] = Field(default=None, max_length=120)
    reason: str = Field(..., max_length=40)
    channel: str = Field(..., max_length=20)
    amount_lost: Optional[float] = Field(default=None, ge=0)
    message: Optional[str] = Field(default=None, max_length=2000)


class DisputeRequest(BaseModel):
    target_type: str = Field(..., pattern="^(number|account)$")
    target: str = Field(..., max_length=40, description="Phone number, or account number")
    bank: Optional[str] = Field(default=None, max_length=60)
    contact: str = Field(..., min_length=5, max_length=120)
    explanation: str = Field(..., min_length=20, max_length=2000)


class CaseCreate(BaseModel):
    source: str = "report"
    risk: str = "Medium"
    category: str = "Reported"
    sanitized_message: str = ""
    phones: str = ""
    accounts: str = ""
    urls: str = ""
    analyst_notes: Optional[str] = None
    assignee: Optional[str] = None


class IncidentRequest(BaseModel):
    recipient: str = Field(default="bank", pattern="^(bank|police)$")
    victim_name: Optional[str] = None
    victim_address: Optional[str] = None
    victim_phone: Optional[str] = None
    victim_bank: Optional[str] = None
    victim_account: Optional[str] = None
    incident_date: Optional[str] = None
    incident_time: Optional[str] = None
    amount: Optional[str] = None
    scammer_account: Optional[str] = None
    scammer_bank: Optional[str] = None
    scammer_account_name: Optional[str] = None
    scammer_phone: Optional[str] = None
    transaction_ref: Optional[str] = None
    police_station: Optional[str] = None
    description: Optional[str] = Field(default=None, max_length=3000)
