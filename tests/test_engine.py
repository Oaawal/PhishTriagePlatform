import csv
from pathlib import Path

import pytest

from engine import analyze_text, extract_indicators

DATA = Path(__file__).parent / "data" / "ng_messages.csv"
ROWS = list(csv.DictReader(DATA.open(encoding="utf-8")))


def test_dataset_quality():
    """Regression set: flagged = Medium or High. Keep precision and recall high as rules change."""
    tp = fp = fn = 0
    for r in ROWS:
        flagged = analyze_text(r["text"])["risk"] != "Low"
        if r["label"] == "scam":
            tp += flagged
            fn += not flagged
        else:
            fp += flagged
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    assert precision >= 0.95, precision
    assert recall >= 0.95, recall


@pytest.mark.parametrize("text", [
    "Good morning, are you coming for dinner this evening?",
    "I know you're running late, see you at the shipping office",
    "Your Opay OTP is 482913. Do not share this code with anyone. Opay staff will never ask for it.",
    "Hello mum, I am fine. Will call you now",
    "Pin the location on the group",
])
def test_no_false_alarm_on_substrings(text):
    assert analyze_text(text)["risk"] == "Low"


@pytest.mark.parametrize("text", [
    "Mama, na me. I change number. Abeg send 20k to this account 0123456789 urgent",
    "Dear customer, kindly confirm your details via hxxps://gtb-update.xyz",
    "Please send me the OTP you just received",
])
def test_high_risk(text):
    assert analyze_text(text)["risk"] == "High"


def test_otp_is_masked():
    res = analyze_text("Send me the OTP 482913 now")
    assert "482913" not in res["sanitized_message"]
    assert "48****" in res["sanitized_message"]


def test_indicators():
    ind = extract_indicators("Call 0803 123 4567 or pay 0123456789 at bit.ly/x")
    assert ind.phones == ["+2348031234567"]
    assert ind.accounts == ["0123456789"]
    assert "bit.ly" in ind.hosts
