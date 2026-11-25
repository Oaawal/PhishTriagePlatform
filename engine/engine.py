"""
PhishTriage detection engine (rules-based, Nigeria-focused).

Design goals
------------
* Whole-word / whole-phrase matching only. Substring matching caused
  false positives such as "nin" in "morning" or "pin" in "shipping".
* Distinguish a message that *asks for* a secret ("send me your OTP")
  from one that *warns about* it ("do not share your OTP").
* Understand common Nigerian scam scripts, including Pidgin and a starter
  set of Yoruba / Hausa / Igbo money-request phrases.
* Explainable: every point of the score comes from a named signal with a
  plain-language reason a non-technical user can understand.

The engine has no network or database dependencies so it can be unit
tested and reused by the API, the WhatsApp bot and the analyst console.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit

ENGINE_VERSION = "2.0.0"

HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 30


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

def normalize_text(text: str) -> str:
    """Lowercase, fold accents (Yoruba diacritics etc.), unify quotes/spaces."""
    t = unicodedata.normalize("NFKD", text or "")
    t = "".join(ch for ch in t if not unicodedata.combining(ch))
    t = t.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    t = t.lower()
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def _phrase_regex(phrase: str) -> str:
    """Turn a phrase into a whole-word regex fragment (spaces match any whitespace)."""
    parts = [re.escape(p) for p in phrase.split()]
    return r"(?<![a-z0-9])" + r"\s+".join(parts) + r"(?![a-z0-9])"


def _compile(phrases: list[str]) -> re.Pattern:
    return re.compile("|".join(_phrase_regex(p) for p in phrases))


def _find(pattern: re.Pattern, text: str) -> list[str]:
    return [m.group(0) for m in pattern.finditer(text)]


# ---------------------------------------------------------------------------
# Indicator extraction (URLs, phones, account numbers, amounts, codes)
# ---------------------------------------------------------------------------

_TLDS = (
    "com|ng|net|org|info|biz|xyz|top|click|buzz|icu|live|shop|site|online|vip|work|rest|"
    "cfd|sbs|monster|gq|ml|cf|tk|ga|co|io|me|app|link|ly|gd|at|cc|us|uk|io|store|tech|"
    "support|help|services|online|website|space|club|pro|world|today|life|cloud"
)
URL_RE = re.compile(
    r"(?i)\b((?:h(?:tt|xx)ps?://|www\.)[^\s<>\"']+"
    r"|(?:[a-z0-9-]+\.)+(?:" + _TLDS + r")(?:/[^\s<>\"']*)?)(?![a-z0-9])"
)
NG_PHONE_RE = re.compile(r"(?<!\d)(?:\+?234[\s-]?|0)([789][01]\d)[\s-]?(\d{3})[\s-]?(\d{4})(?!\d)")
NUBAN_RE = re.compile(r"(?<![\d+])(\d{10})(?!\d)")
AMOUNT_RE = re.compile(
    r"(?i)(?:₦|ngn|n)\s?\d[\d,]*(?:\.\d+)?k?|\b\d[\d,]*(?:\.\d+)?\s?(?:k|naira|thousand)\b"
)
CODE_RE = re.compile(r"(?<!\d)(\d{4,8})(?!\d)")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "tiny.cc",
    "ow.ly", "rebrand.ly", "s.id", "goo.gl", "t.ly", "shorturl.asia", "v.gd", "bitly.ws",
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "buzz", "icu", "live", "shop", "site", "online", "vip", "work",
    "rest", "cfd", "sbs", "monster", "gq", "ml", "cf", "tk", "ga", "support", "help",
    "services", "website", "space", "store",
}

# Brand token -> official registrable domains. Editable: keep this list
# reviewed; a brand token in a domain that is NOT one of these is a
# lookalike signal.
OFFICIAL_DOMAINS: dict[str, list[str]] = {
    "gtbank": ["gtbank.com", "gtco.com"],
    "gtco": ["gtco.com", "gtbank.com"],
    "gtb": ["gtbank.com", "gtco.com"],
    "zenith": ["zenithbank.com"],
    "firstbank": ["firstbanknigeria.com", "firstbankgroup.com"],
    "accessbank": ["accessbankplc.com"],
    "uba": ["ubagroup.com"],
    "fidelity": ["fidelitybank.ng"],
    "sterling": ["sterling.ng"],
    "wema": ["wemabank.com", "alat.ng"],
    "fcmb": ["fcmb.com"],
    "stanbic": ["stanbicibtcbank.com"],
    "ecobank": ["ecobank.com"],
    "opay": ["opayweb.com", "opay.ng"],
    "palmpay": ["palmpay.com"],
    "moniepoint": ["moniepoint.com"],
    "kuda": ["kuda.com"],
    "paga": ["mypaga.com", "paga.com"],
    "nimc": ["nimc.gov.ng"],
    "cbn": ["cbn.gov.ng"],
    "efcc": ["efcc.gov.ng"],
    "ncc": ["ncc.gov.ng"],
    "nysc": ["nysc.gov.ng", "nysc.org.ng"],
    "jamb": ["jamb.gov.ng"],
    "firs": ["firs.gov.ng"],
    "customs": ["customs.gov.ng"],
    "mtn": ["mtn.ng", "mtn.com", "mtnonline.com"],
    "airtel": ["airtel.com.ng", "airtel.com"],
    "glo": ["gloworld.com"],
    "jumia": ["jumia.com.ng", "jumia.com"],
}


def defang(url: str) -> str:
    u = re.sub(r"(?i)^http", "hxxp", url.strip())
    return u.replace(".", "[.]")


def _host_of(url: str) -> str:
    u = url.strip().rstrip(".,;:!?)")
    u = re.sub(r"(?i)^hxxp", "http", u)
    if not re.match(r"(?i)^https?://", u):
        u = "http://" + u
    try:
        host = urlsplit(u).hostname or ""
    except ValueError:
        host = ""
    return host.lower().strip(".")


def normalize_ng_phone(raw: str) -> str | None:
    m = NG_PHONE_RE.search(raw or "")
    if not m:
        return None
    return "+234" + "".join(m.groups())


@dataclass
class Indicators:
    urls: list[str] = field(default_factory=list)          # as written
    hosts: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)        # E.164
    accounts: list[str] = field(default_factory=list)      # 10-digit NUBAN candidates
    amounts: list[str] = field(default_factory=list)
    codes: list[str] = field(default_factory=list)         # 4-8 digit codes


def extract_indicators(text: str) -> Indicators:
    raw = text or ""
    ind = Indicators()

    for m in URL_RE.finditer(raw):
        url = m.group(1).rstrip(".,;:!?)")
        host = _host_of(url)
        if not host or "." not in host:
            continue
        if url not in ind.urls:
            ind.urls.append(url)
        if host not in ind.hosts:
            ind.hosts.append(host)

    phone_spans = []
    for m in NG_PHONE_RE.finditer(raw):
        e164 = "+234" + "".join(m.groups())
        phone_spans.append(m.span())
        if e164 not in ind.phones:
            ind.phones.append(e164)

    def _inside_phone(span):
        return any(s <= span[0] and span[1] <= e for s, e in phone_spans)

    for m in NUBAN_RE.finditer(raw):
        if _inside_phone(m.span()):
            continue
        acct = m.group(1)
        if acct not in ind.accounts:
            ind.accounts.append(acct)

    ind.amounts = list(dict.fromkeys(a.strip() for a in AMOUNT_RE.findall(raw)))

    for m in CODE_RE.finditer(raw):
        if _inside_phone(m.span()) or m.group(1) in ind.accounts:
            continue
        ind.codes.append(m.group(1))
    ind.codes = list(dict.fromkeys(ind.codes))
    return ind


def mask_code(code: str) -> str:
    if len(code) <= 2:
        return "*" * len(code)
    return code[:2] + "*" * (len(code) - 2)


def sanitize_message(text: str, codes: list[str]) -> str:
    """Mask OTP-like codes so they are never stored or shared in reports."""
    out = text or ""
    for c in codes:
        out = re.sub(rf"(?<!\d){re.escape(c)}(?!\d)", mask_code(c), out)
    return out


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

SENSITIVE_TERMS: dict[str, list[str]] = {
    "OTP": ["otp", "one time password", "one-time password", "verification code", "auth code",
            "token", "security code", "6 digit code", "6-digit code", "the code"],
    "PIN": ["pin", "atm pin", "card pin", "transaction pin"],
    "Password": ["password", "passcode", "login details", "internet banking details"],
    "BVN": ["bvn", "bank verification number"],
    "NIN": ["nin", "national identification number", "nin number"],
    "Card details": ["cvv", "card number", "card details", "expiry date", "atm card details", "atm number"],
}
_SENSITIVE_RE = {k: _compile(v) for k, v in SENSITIVE_TERMS.items()}

REQUEST_VERBS = _compile([
    "send", "share", "provide", "give", "forward", "tell", "confirm", "enter", "submit",
    "reply", "drop", "input", "type", "read out", "call out", "verify", "update", "what is",
    "whats", "what's", "send am", "give me", "need your", "need the",
])
NEGATIONS = _compile([
    "do not", "don't", "dont", "never", "will never", "won't", "not to", "no one should",
    "nobody should", "do not ever",
])

URGENCY = _compile([
    "urgent", "urgently", "immediately", "right now", "within 24 hours", "within 24hrs",
    "within 48 hours", "within 1 hour", "within one hour", "last warning", "final warning",
    "final notice", "act fast", "act now", "today only", "limited time", "expires today",
    "before it's too late", "asap", "as soon as possible", "quickly", "hurry", "now now",
    "sharp sharp", "before midnight", "or else",
])
THREATS = _compile([
    "arrest", "arrested", "prosecuted", "prosecution", "jail", "court action", "legal action",
    "will be blocked", "be blocked", "has been blocked", "block your account", "suspended",
    "deactivated", "restricted", "barred", "frozen", "will be disconnected", "blacklisted",
    "fine of", "penalty", "will be closed", "permanently closed", "disabled",
])
AUTHORITY = _compile([
    "cbn", "central bank", "efcc", "nimc", "ncc", "nysc", "firs", "customs", "interpol",
    "police", "dss", "icpc", "federal government", "fg", "presidency", "ministry of",
    "nigeria customs", "immigration", "jamb", "waec",
])
BANK_BRANDS = _compile([
    "gtbank", "gtb", "gtco", "guaranty trust", "zenith", "zenith bank", "first bank", "firstbank",
    "access bank", "uba", "union bank", "fidelity", "sterling", "wema", "alat", "fcmb",
    "stanbic", "ecobank", "polaris", "keystone", "opay", "palmpay", "moniepoint", "kuda",
    "paga", "carbon", "fairmoney", "your bank", "bank customer care",
])
ACCOUNT_LURE = _compile([
    "confirm your details", "verify your account", "verify your details", "update your details",
    "update your account", "reactivate your account", "unlock your account", "validate your account",
    "login to", "log in to", "sign in to", "click the link", "click this link", "click here",
    "tap the link", "follow the link", "fill the form", "complete the form", "kindly verify",
    "kindly update", "kindly confirm", "re-validate", "revalidate",
])
GENERIC_GREETING = _compile([
    "dear customer", "dear user", "dear account holder", "valued customer", "dear client",
    "dear sir/madam", "dear beneficiary", "dear winner", "dear applicant",
])
PAYMENT = _compile([
    "pay", "payment", "transfer", "send money", "send me", "deposit", "fee", "fees",
    "charges", "subscription", "registration fee", "processing fee", "training fee",
    "application fee", "delivery fee", "clearance fee", "activation fee", "unlock fee",
    "send am", "credit my account", "send to this account", "this account",
    # Yoruba / Hausa / Igbo starter phrases (review with native speakers)
    "fi owo ranse", "fi owo ranse si", "turo min kudi", "turo kudi", "aiko min kudi",
    "zitere m ego", "ziga m ego",
])
FEE_WORDS = _compile([
    "fee", "fees", "charges", "registration fee", "processing fee", "training fee",
    "application fee", "delivery fee", "clearance fee", "activation fee", "unlock fee",
    "pay small", "small amount", "token fee",
])
PRIZE = _compile([
    "you have won", "you won", "you've won", "winner", "lucky winner", "congratulations you",
    "cash prize", "claim your prize", "claim your reward", "promo winner", "giveaway",
    "selected for a grant", "you have been selected", "free airtime", "free data",
    "won a", "jackpot", "bonus has been", "claim now",
])
INVESTMENT = _compile([
    "double your money", "guaranteed profit", "guaranteed returns", "guaranteed income",
    "forex signal", "forex signals", "crypto investment", "investment opportunity",
    "invest and earn", "roi", "returns daily", "daily returns", "weekly returns",
    "trading account manager", "account manager", "mining plan", "binary option",
])
# "send 20k", "transfer N5,000", "abeg send me 30k"
SEND_AMOUNT = re.compile(r"(?<![a-z])(?:send|transfer|pay|credit|borrow)\s+(?:me\s+|us\s+)?(?:₦|ngn|n)?\s?\d")
INVESTMENT_PCT = re.compile(r"\d+\s*%\s*(?:daily|weekly|per day|per week|every day|profit|returns?|roi)")
JOB = _compile([
    "shortlisted", "recruitment", "job offer", "work from home", "hiring", "vacancy",
    "you have been employed", "employment letter", "interview slot", "secure your slot",
    "data entry job", "earn daily", "like and earn", "task and earn",
])
NEW_NUMBER = _compile([
    "na me", "it's me", "its me", "this is my new number", "my new number", "i changed my number",
    "i change number", "i change my number", "new number", "my phone spoil", "my phone fell",
    "my phone got stolen", "my phone was stolen", "lost my phone", "use this number",
    "save this number", "this na my new number",
])
FAMILY = _compile([
    "mum", "mummy", "mama", "mom", "dad", "daddy", "papa", "aunty", "auntie", "uncle",
    "bro", "sis", "my dear", "baby", "darling",
])
WRONG_TRANSFER = _compile([
    "by mistake", "mistakenly", "wrongly transferred", "wrong transfer", "erroneously credited",
    "transferred to your account in error", "sent to your account", "send it back", "reverse the money",
    "refund the money", "return the money", "mistake transfer", "wrong account",
])
LOAN_THREAT = _compile([
    "inform your contacts", "send to your contacts", "all your contacts", "your contacts will",
    "defaulter", "your picture will", "we will post", "we will publish", "fraudster and thief",
    "loan is overdue", "repay immediately",
])
LOAN_OFFER = _compile([
    "loan approved", "loan has been approved", "instant loan", "loan without collateral",
    "quick loan", "loan offer", "disburse", "disbursement",
])
SIM_ID = _compile([
    "line will be barred", "sim will be blocked", "sim card will be", "link your nin",
    "nin-sim", "nin sim", "nin verification", "update your nin", "bvn update", "update your bvn",
    "bvn linkage", "link your bvn", "bvn has been", "nin has been", "verification exercise",
])
PARCEL = _compile([
    "parcel", "package", "waybill", "your delivery", "customs clearance", "dispatch rider",
    "shipment", "consignment", "courier",
])
GIFT_CARD = _compile([
    "gift card", "itunes card", "steam card", "amazon card", "google play card", "western union",
    "moneygram", "send bitcoin", "usdt", "btc wallet", "crypto wallet",
])
OFF_PLATFORM = _compile([
    "whatsapp me", "chat me on whatsapp", "contact this number", "call this number",
    "message me on", "reach me on", "text me on", "dm me", "contact our agent",
    "customer care on whatsapp",
])


# ---------------------------------------------------------------------------
# Categories and advice
# ---------------------------------------------------------------------------

CATEGORY_ADVICE: dict[str, list[str]] = {
    "OTP / Account takeover": [
        "Never share your OTP, PIN, password, BVN or card details. Your bank will never ask for them.",
        "If you already shared a code, call your bank immediately using the number on your card or in your bank app and ask them to block the account.",
    ],
    "Bank impersonation": [
        "Contact your bank only through the number on your card, the official app, or a branch.",
        "Do not use phone numbers or links sent in the message.",
    ],
    "Government / Regulator impersonation": [
        "Government agencies (CBN, EFCC, NIMC, NCC) do not threaten arrest by SMS or WhatsApp or ask you to pay into personal accounts.",
        "Check the agency's official website (ending in .gov.ng) yourself.",
    ],
    "Phishing link": [
        "Do not open the link. If you opened it, do not enter any details.",
        "If you entered a password, change it now and turn on two-factor authentication.",
    ],
    "Family emergency / New number": [
        "Call the person on their OLD number, or ask a question only they would know, before sending anything.",
        "Scammers copy names and photos from social media.",
    ],
    "Wrong transfer refund": [
        "Do not send money back yourself. Ask your bank to confirm the credit and to reverse it through official channels.",
        "Fake 'credit alert' SMS messages are common. Check your balance in your bank app.",
    ],
    "Loan app harassment": [
        "Threats to shame you to your contacts are illegal. You can report the lender to the FCCPC and to Google Play.",
        "Do not pay any 'extra' fee to stop the harassment. Keep screenshots as evidence.",
    ],
    "Advance-fee (job, loan, prize, parcel)": [
        "Real employers, lenders and couriers do not ask you to pay a fee to receive a job, loan, prize or parcel.",
        "Verify the company on the CAC website and through its official contact details.",
    ],
    "Investment / Ponzi": [
        "Guaranteed or very high daily returns are a classic Ponzi sign.",
        "Check if the company is registered with the SEC Nigeria before investing anything.",
    ],
    "Prize / Giveaway": [
        "You cannot win a promo you did not enter. Do not pay any fee to 'claim' a prize.",
    ],
    "SIM / NIN / BVN update": [
        "NIN and BVN updates are done at official centres, through your bank's app or by USSD, never through links in messages.",
    ],
    "Gift card / Crypto payment": [
        "Requests to pay with gift cards or crypto are almost always scams. Nobody legitimate asks for this.",
    ],
    "Suspicious message": [
        "Verify the sender through an official channel before acting.",
    ],
    "Likely safe": [
        "No common scam signs were found. If you are still unsure, verify the sender through an official channel.",
    ],
}

GENERAL_ADVICE = [
    "Never share OTP, PIN, password, BVN, NIN or card details with anyone.",
    "Do not click unknown links. Type the official website address yourself.",
]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass
class Signal:
    id: str
    reason: str
    weight: int
    category: str | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "reason": self.reason,
            "weight": self.weight,
            "category": self.category,
            "evidence": self.evidence[:5],
        }


def _sensitive_requests(t: str) -> tuple[list[str], list[str]]:
    """Return (requested, mentioned) sensitive-data labels."""
    requested, mentioned = [], []
    for label, pat in _SENSITIVE_RE.items():
        for m in pat.finditer(t):
            if label == "OTP" and m.group(0) == "token" and "token fee" in t:
                continue
            window_start = max(0, m.start() - 70)
            before = t[window_start:m.start()]
            after = t[m.end():m.end() + 40]
            verbs = list(REQUEST_VERBS.finditer(before))
            is_request = False
            if verbs:
                v = verbs[-1]
                neg_zone = before[max(0, v.start() - 18):v.start()]
                # also catch "never ask for your pin" style warnings
                if not NEGATIONS.search(neg_zone) and not re.search(r"never ask|will not ask|won't ask", before):
                    is_request = True
            if not is_request and re.match(r"\s*(?:to|via|on)\s+(?:\+?\d|this|our|the agent|us|me)", after):
                is_request = True
            if not is_request and re.match(r"\s*\?", after) and "your" in before[-12:]:
                is_request = True
            if label == "OTP" and m.group(0) == "the code" and not is_request:
                continue  # "the code" only counts when actually requested
            target = requested if is_request else mentioned
            if label not in target:
                target.append(label)
    mentioned = [m for m in mentioned if m not in requested]
    return requested, mentioned


def _is_legit_otp_notice(t: str, ind: Indicators, requested: list[str]) -> bool:
    """A typical OTP delivery SMS: has a code, a warning not to share, no link, no request."""
    if requested or ind.urls or ind.phones or ind.accounts:
        return False
    if not ind.codes:
        return False
    has_otp_word = bool(_SENSITIVE_RE["OTP"].search(t)) or "code" in t
    has_warning = bool(re.search(r"(do not|don't|dont|never)\s+(share|disclose|give)", t)) or "will never ask" in t
    return has_otp_word and (has_warning or bool(re.search(r"valid for|expires in|is your", t)))


def _domain_signals(ind: Indicators) -> list[Signal]:
    sigs: list[Signal] = []
    short = [h for h in ind.hosts if h in SHORTENERS or h.removeprefix("www.") in SHORTENERS]
    if short:
        sigs.append(Signal("LINK_SHORTENER", "Uses a shortened link that hides the real website.", 15, "Phishing link", short))
    bad_tld = [h for h in ind.hosts if h.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS]
    if bad_tld:
        sigs.append(Signal("SUSPICIOUS_TLD", "Link uses a cheap domain ending often used by scammers.", 15, "Phishing link", bad_tld))
    ip_hosts = [h for h in ind.hosts if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", h)]
    if ip_hosts:
        sigs.append(Signal("IP_URL", "Link points to a raw IP address instead of a real website name.", 20, "Phishing link", ip_hosts))
    puny = [h for h in ind.hosts if "xn--" in h]
    if puny:
        sigs.append(Signal("PUNYCODE", "Link uses look-alike characters to imitate a real website.", 25, "Phishing link", puny))
    lookalike = []
    for h in ind.hosts:
        labels = re.split(r"[.-]", h)
        for brand, official in OFFICIAL_DOMAINS.items():
            if brand in labels or (len(brand) >= 5 and brand in h):
                if not any(h == d or h.endswith("." + d) for d in official):
                    lookalike.append(h)
                    break
    if lookalike:
        sigs.append(Signal("LOOKALIKE_DOMAIN", "Link pretends to be a bank, telco or government website but is not the official address.", 30, "Phishing link", lookalike))
    lure_words = [h for h in ind.hosts if re.search(r"(verify|update|secure|login|signin|account|confirm|support|bonus|promo|reward|claim)", h)]
    if lure_words:
        sigs.append(Signal("LURE_DOMAIN", "Website name contains words like 'verify', 'secure' or 'login', a common phishing trick.", 10, "Phishing link", lure_words))
    return sigs


def analyze_text(text: str) -> dict:
    """Analyse a message and return a JSON-serialisable verdict."""
    raw = (text or "")[:5000]
    t = normalize_text(raw)
    ind = extract_indicators(raw)
    sigs: list[Signal] = []

    def add(sid, reason, weight, category=None, evidence=None):
        sigs.append(Signal(sid, reason, weight, category, list(evidence or [])))

    requested, mentioned = _sensitive_requests(t)
    legit_otp = _is_legit_otp_notice(t, ind, requested)

    if requested:
        add("SENSITIVE_REQUEST", f"Asks you to share {', '.join(requested)}. Banks and agencies never ask for these.",
            60, "OTP / Account takeover", requested)
    elif mentioned and not legit_otp:
        add("SENSITIVE_MENTION", f"Mentions {', '.join(mentioned)}.", 8, None, mentioned)

    urgency = _find(URGENCY, t)
    if urgency:
        add("URGENCY", "Pressures you to act fast, a common scam tactic.", 12, None, urgency)

    threats = _find(THREATS, t)
    if threats:
        add("THREAT", "Threatens you (arrest, blocking, fines) to scare you into acting.", 18, None, threats)

    authority = _find(AUTHORITY, t)
    if authority:
        w = 15 + (20 if (threats or _find(PAYMENT, t) or requested or ind.urls) else 0)
        add("AUTHORITY_IMPERSONATION", "Claims to be from a government agency or regulator.", w,
            "Government / Regulator impersonation", authority)

    brands = _find(BANK_BRANDS, t)
    if brands and (requested or ind.urls or ind.phones or threats):
        add("BANK_IMPERSONATION", "Uses a bank or fintech name together with a link, number or threat.", 15,
            "Bank impersonation", brands)

    lure = _find(ACCOUNT_LURE, t)
    if lure:
        add("ACCOUNT_LURE", "Asks you to click, log in or 'verify' your account.", 20, "Phishing link", lure)

    greeting = _find(GENERIC_GREETING, t)
    if greeting:
        add("GENERIC_GREETING", "Uses a generic greeting like 'Dear customer' instead of your name.", 8, None, greeting)

    if ind.urls:
        add("HAS_LINK", "Contains a link.", 10, "Phishing link", [defang(u) for u in ind.urls])
        sigs.extend(_domain_signals(ind))

    payment = _find(PAYMENT, t) + [m.group(0) for m in SEND_AMOUNT.finditer(t)]
    fees = _find(FEE_WORDS, t)
    if payment:
        add("PAYMENT_REQUEST", "Asks for money, a transfer or a fee.", 15, None, payment)
    if ind.amounts and payment:
        add("AMOUNT", "Mentions a specific amount of money.", 5, None, ind.amounts)
    if ind.accounts and payment:
        add("ACCOUNT_NUMBER", "Gives a bank account number to send money to. Check it before paying.", 10, None, ind.accounts)

    prize = _find(PRIZE, t)
    if prize:
        w = 25 + (15 if (ind.phones or ind.urls or payment) else 0)
        add("PRIZE", "Says you won a prize or reward.", w, "Prize / Giveaway", prize)

    invest = _find(INVESTMENT, t) + INVESTMENT_PCT.findall(t)
    if invest:
        add("INVESTMENT", "Promises guaranteed or unrealistic returns.", 30, "Investment / Ponzi", invest)

    job = _find(JOB, t)
    if job:
        add("JOB_OFFER", "Unsolicited job or recruitment offer.", 15, "Advance-fee (job, loan, prize, parcel)", job)

    loan_offer = _find(LOAN_OFFER, t)
    parcel = _find(PARCEL, t)
    if fees and (job or loan_offer or prize or parcel):
        add("ADVANCE_FEE", "Asks for a fee before you receive a job, loan, prize or parcel.", 30,
            "Advance-fee (job, loan, prize, parcel)", fees)
    elif parcel and (ind.urls or payment):
        add("PARCEL", "Parcel or delivery message that asks you to pay or click a link.", 15,
            "Advance-fee (job, loan, prize, parcel)", parcel)

    new_number = _find(NEW_NUMBER, t)
    if new_number:
        w = 25 + (30 if payment else 0)
        add("NEW_NUMBER", "Claims to be someone you know using a new number.", w, "Family emergency / New number", new_number)
    elif _find(FAMILY, t) and payment and urgency:
        add("FAMILY_EMERGENCY", "Urgent money request that claims to come from family.", 20, "Family emergency / New number")

    wrong = _find(WRONG_TRANSFER, t)
    if wrong and (payment or "account" in t or "alert" in t):
        add("WRONG_TRANSFER", "Claims money was sent to you by mistake and asks you to send it back.", 40,
            "Wrong transfer refund", wrong)

    loan_threat = _find(LOAN_THREAT, t)
    if loan_threat:
        add("LOAN_HARASSMENT", "Loan-app style threat to shame you to your contacts.", 35, "Loan app harassment", loan_threat)

    sim = _find(SIM_ID, t)
    if sim:
        w = 15 + (20 if (ind.urls or requested or payment or threats) else 0)
        add("SIM_ID_UPDATE", "Asks you to update or link your NIN, BVN or SIM.", w, "SIM / NIN / BVN update", sim)

    gift = _find(GIFT_CARD, t)
    if gift:
        add("GIFT_CARD", "Asks for payment in gift cards or crypto.", 30, "Gift card / Crypto payment", gift)

    off = _find(OFF_PLATFORM, t)
    if off and (ind.phones or "whatsapp" in t):
        add("OFF_PLATFORM", "Pushes you to continue on WhatsApp or another number.", 10, None, off)

    if legit_otp:
        add("LEGIT_OTP_NOTICE", "Looks like a normal one-time code notification (no link, no request to share).",
            -30, "Likely safe")

    score = max(0, min(100, sum(s.weight for s in sigs)))
    risk = "High" if score >= HIGH_THRESHOLD else "Medium" if score >= MEDIUM_THRESHOLD else "Low"

    cat_weights: dict[str, int] = {}
    for s in sigs:
        if s.category and s.weight > 0:
            cat_weights[s.category] = cat_weights.get(s.category, 0) + s.weight
    if risk == "Low":
        category = "Likely safe"
    elif cat_weights:
        category = max(cat_weights.items(), key=lambda kv: kv[1])[0]
    else:
        category = "Suspicious message"

    positive = sorted((s for s in sigs if s.weight > 0), key=lambda s: -s.weight)
    reasons = [s.reason for s in positive]
    if not reasons:
        reasons = ["No common scam signs found."]

    advice = list(CATEGORY_ADVICE.get(category, []))
    if risk != "Low":
        for a in GENERAL_ADVICE:
            if a not in advice:
                advice.append(a)

    return {
        "engine_version": ENGINE_VERSION,
        "risk": risk,
        "score": score,
        "category": category,
        "reasons": reasons,
        "advice": advice,
        "signals": [s.to_dict() for s in sorted(sigs, key=lambda s: -s.weight)],
        "indicators": {
            "urls": [defang(u) for u in ind.urls],
            "domains": ind.hosts,
            "phones": ind.phones,
            "accounts": ind.accounts,
            "amounts": ind.amounts,
        },
        "sensitive_requested": requested,
        "sanitized_message": sanitize_message(raw, ind.codes),
    }
