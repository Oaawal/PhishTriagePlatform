"""
"I've been scammed, what now?" recovery guidance and document generator.

IMPORTANT: The contact details in ESCALATION_CONTACTS must be checked
against each organisation's official website before every release, and
LAST_REVIEWED updated. Entries marked verified=False have not been
confirmed by the PhishTriage team yet. The app shows a notice when an
entry is unverified.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

LAST_REVIEWED = "not yet reviewed"

# Steps are ordered by urgency. Speed matters most for bank transfers:
# the sooner the bank flags the receiving account, the better the chance
# of freezing the money before it is withdrawn.
RECOVERY_PLANS: dict[str, dict] = {
    "bank_transfer": {
        "title": "I sent money to a scammer by bank transfer",
        "steps": [
            "Call your bank NOW using the number on your card, in your bank app, or visit a branch. Say: 'I want to report a fraudulent transfer and ask you to contact the receiving bank to place a restriction (PND) on the account.'",
            "Give the bank the date, time, amount, the receiving account number and bank, and the transaction reference.",
            "Ask the bank for a complaint or reference number and write it down.",
            "Report to the police (the Nigeria Police Force National Cybercrime Centre or your nearest station) and ask for a police report or extract. Banks often ask for one.",
            "File a report with the EFCC through its official website.",
            "If your bank does not resolve your complaint, escalate to the CBN Consumer Protection department.",
            "Report the scammer's account number and phone number in PhishTriage to warn others.",
        ],
    },
    "otp_shared": {
        "title": "I shared my OTP, PIN, password or card details",
        "steps": [
            "Call your bank immediately and ask them to block your card and/or freeze your account or internet banking.",
            "Change your banking app password and PIN from a device you trust. Use your bank's USSD code to block your account if you cannot reach them.",
            "Check your recent transactions and tell the bank about any you did not make.",
            "If you shared your BVN or NIN, watch for loans or accounts opened in your name and report them to your bank.",
            "Report to the police and the EFCC if money was taken.",
        ],
    },
    "loan_app": {
        "title": "A loan app is threatening or shaming me",
        "steps": [
            "Do not pay any extra 'fee' to stop the threats.",
            "Take screenshots of every threatening message, with the date and the sender's number.",
            "Report the lender to the FCCPC (Federal Competition and Consumer Protection Commission), which regulates digital lenders.",
            "Report the app on the Google Play Store or Apple App Store.",
            "If you feel unsafe or are threatened with violence, report to the police.",
        ],
    },
    "investment": {
        "title": "I invested in a scheme that is not paying back",
        "steps": [
            "Stop sending any more money, including 'withdrawal fees' or 'tax' to unlock your funds.",
            "Collect every receipt, chat, account number and website used.",
            "Check whether the company is registered with the SEC Nigeria and report it to the SEC and the EFCC.",
            "Report the account numbers used in PhishTriage to warn others.",
        ],
    },
    "sim_or_account_hijack": {
        "title": "My WhatsApp, SIM or social media account was taken over",
        "steps": [
            "Tell your contacts from another channel that your account was hacked and not to send money.",
            "For SIM issues, visit your network provider's office with valid ID to block and replace the SIM.",
            "For WhatsApp, re-register your number and turn on two-step verification (Settings > Account > Two-step verification).",
            "If your network provider does not help, you can complain to the NCC.",
        ],
    },
}

ESCALATION_CONTACTS: list[dict] = [
    {"name": "Your bank", "how": "The number on the back of your card, your bank app, or any branch", "verified": True},
    {"name": "Nigeria Police Force National Cybercrime Centre (NPF-NCCC)", "how": "Official NPF-NCCC website, or your nearest police station", "verified": False},
    {"name": "EFCC", "how": "Online complaint form on efcc.gov.ng, or any EFCC office", "verified": False},
    {"name": "CBN Consumer Protection", "how": "Complaints about banks that do not resolve your case. See cbn.gov.ng", "verified": False},
    {"name": "NCC consumer helpline", "how": "Telecom and SIM complaints. See ncc.gov.ng", "verified": False},
    {"name": "FCCPC", "how": "Loan app and consumer complaints. See fccpc.gov.ng", "verified": False},
    {"name": "SEC Nigeria", "how": "Investment schemes. See sec.gov.ng", "verified": False},
]


def get_plan(situation: str) -> dict | None:
    plan = RECOVERY_PLANS.get(situation)
    if not plan:
        return None
    return {
        "situation": situation,
        **plan,
        "contacts": ESCALATION_CONTACTS,
        "contacts_last_reviewed": LAST_REVIEWED,
        "disclaimer": "This is general guidance, not legal advice. For legal help, contact a lawyer.",
    }


def list_situations() -> list[dict]:
    return [{"situation": k, "title": v["title"]} for k, v in RECOVERY_PLANS.items()]


def _clean(v) -> str:
    return " ".join(str(v or "").split())[:500]


def build_incident_letter(data: dict, recipient: str = "bank") -> str:
    """Build a complaint letter to the victim's bank or the police from incident details."""
    d = {k: _clean(v) for k, v in data.items()}
    today = datetime.now(timezone.utc).strftime("%d %B %Y")
    if recipient == "police":
        to_block = "The Officer in Charge\nNigeria Police Force\n" + (d.get("police_station") or "[Police station / NPF-NCCC]")
        subject = "PETITION: REPORT OF FRAUD / OBTAINING BY FALSE PRETENCE"
        ask = (
            "I respectfully request that you investigate this matter, trace the receiving account and phone "
            "number(s) listed above, and issue me a police report so that I can follow up with my bank."
        )
    else:
        to_block = "The Fraud Desk / Customer Care\n" + (d.get("victim_bank") or "[Your bank]")
        subject = "URGENT: REPORT OF FRAUDULENT TRANSFER AND REQUEST TO RESTRICT BENEFICIARY ACCOUNT"
        ask = (
            "I request that you urgently contact the beneficiary bank to place a restriction (Post No Debit) on the "
            "receiving account, recover the funds, and give me a complaint reference number."
        )

    lines = [
        d.get("victim_name") or "[Your full name]",
        d.get("victim_address") or "[Your address]",
        d.get("victim_phone") or "[Your phone number]",
        "",
        today,
        "",
        to_block,
        "",
        "Dear Sir/Madam,",
        "",
        subject,
        "",
        f"I, {d.get('victim_name') or '[Your full name]'}, write to report that I was defrauded on "
        f"{d.get('incident_date') or '[date]'} at about {d.get('incident_time') or '[time]'}.",
        "",
        "What happened:",
        d.get("description") or "[Describe briefly what happened]",
        "",
        "Transaction details:",
        f"- Amount: {d.get('amount') or '[amount]'}",
        f"- From my account: {d.get('victim_account') or '[your account number]'} ({d.get('victim_bank') or '[your bank]'})",
        f"- To account: {d.get('scammer_account') or '[receiving account number]'} ({d.get('scammer_bank') or '[receiving bank]'})",
        f"- Account name shown: {d.get('scammer_account_name') or '[name shown on transfer]'}",
        f"- Transaction reference: {d.get('transaction_ref') or '[reference]'}",
        f"- Scammer phone number(s): {d.get('scammer_phone') or '[phone number]'}",
        "",
        ask,
        "",
        "I have attached screenshots of the messages and the transaction receipt as evidence.",
        "",
        "Yours faithfully,",
        "",
        "",
        d.get("victim_name") or "[Your full name]",
    ]
    return "\n".join(lines)


def evidence_record(data: dict, letter: str) -> dict:
    """Return a timestamped record with a SHA-256 fingerprint of the letter, for the victim's records."""
    created = datetime.now(timezone.utc).isoformat()
    digest = hashlib.sha256((letter + created).encode("utf-8")).hexdigest()
    return {
        "created_at_utc": created,
        "sha256": digest,
        "fields": {k: _clean(v) for k, v in data.items()},
        "note": "Keep this record with your screenshots. The fingerprint shows the letter was not changed after it was created.",
        "json": json.dumps({"created_at_utc": created, "sha256": digest}),
    }
