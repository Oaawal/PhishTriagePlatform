import re

def normalize_ng_number(raw: str) -> str | None:
    if not raw:
        return None

    s = raw.strip()
    digits = re.sub(r"\D", "", s)

    # 234XXXXXXXXXX (13 digits) -> +234XXXXXXXXXX
    if digits.startswith("234") and len(digits) == 13:
        return "+" + digits

    # 0XXXXXXXXXX (11 digits) -> +234XXXXXXXXXX
    if digits.startswith("0") and len(digits) == 11:
        return "+234" + digits[1:]

    # XXXXXXXXXX (10 digits) -> +234XXXXXXXXXX (optional support)
    if len(digits) == 10:
        return "+234" + digits

    return None
