import httpx
import pytest

from api import config, linkcheck
from engine import redact_for_training
from tests.conftest import ADMIN


class FakeResponse:
    def __init__(self, data, status=200):
        self._data, self.status_code = data, status

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=None)


@pytest.fixture
def safe_browsing(monkeypatch):
    """Enable the link check with a fake Google response that flags evil-login.top."""
    calls = []

    def fake_post(url, params=None, json=None, timeout=None):
        calls.append(json)
        urls = [e["url"] for e in json["threatInfo"]["threatEntries"]]
        matches = [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": u}} for u in urls if "evil-login" in u]
        return FakeResponse({"matches": matches} if matches else {})

    monkeypatch.setattr(config, "SAFE_BROWSING_API_KEY", "test-key")
    monkeypatch.setattr(linkcheck.httpx, "post", fake_post)
    linkcheck.clear_cache()
    yield calls
    linkcheck.clear_cache()


def test_link_check_disabled_by_default(client):
    r = client.post("/analyze", json={"message": "see https://example.com"}).json()
    assert r["link_check"]["status"] == "disabled"


def test_known_bad_link_raises_risk(client, safe_browsing):
    r = client.post("/analyze", json={"message": "Hello, see the photos here http://evil-login.top/a"}).json()
    assert r["link_check"] == {"provider": "Google Safe Browsing", "status": "ok", "checked": 1, "dangerous_links": 1}
    assert r["risk"] == "High"
    assert r["signals"][0]["id"] == "KNOWN_BAD_LINK"
    assert "evil-login[.]top" in r["signals"][0]["evidence"][0]


def test_clean_link_and_cache(client, safe_browsing):
    msg = {"message": "Our meeting notes are at https://example.com/notes"}
    assert client.post("/analyze", json=msg).json()["risk"] == "Low"
    client.post("/analyze", json=msg)
    assert len(safe_browsing) == 1  # second scan used the cache


def test_link_check_failure_does_not_break_scan(client, monkeypatch):
    monkeypatch.setattr(config, "SAFE_BROWSING_API_KEY", "test-key")

    def boom(*a, **k):
        raise httpx.ConnectTimeout("slow")

    monkeypatch.setattr(linkcheck.httpx, "post", boom)
    linkcheck.clear_cache()
    r = client.post("/analyze", json={"message": "Verify your account at http://gtb-update.xyz now"}).json()
    assert r["link_check"]["status"] == "error"
    assert r["risk"] == "High"  # rules still work


def test_redaction():
    out = redact_for_training("Send 20k to 0123456789 or call 08031234567, OTP 482913, BVN 22123456789, a@b.com")
    for raw in ("0123456789", "08031234567", "482913", "22123456789", "a@b.com"):
        assert raw not in out
    assert "<ACCOUNT>" in out and "<PHONE>" in out and "Send 20k" in out


def test_feedback_without_sharing_keeps_no_text(client):
    scan = client.post("/analyze", json={"message": "Good morning, see you at church"}).json()
    r = client.post("/feedback", json={"scan_id": scan["scan_id"], "verdict": "correct"}).json()
    assert r["stored"] and not r["shared_text"]


def test_feedback_with_sharing_review_and_export(client):
    msg = "Mama na me, I change number. Send 20k to 0123456789 urgent"
    scan = client.post("/analyze", json={"message": msg}).json()
    r = client.post("/feedback", json={"scan_id": scan["scan_id"], "verdict": "correct",
                                       "share_message": True, "message": msg}).json()
    assert r["shared_text"]
    assert client.post("/feedback", json={"scan_id": "nope", "verdict": "scam"}).status_code == 404
    assert client.get("/admin/training/queue").status_code == 403

    queue = client.get("/admin/training/queue", headers=ADMIN).json()
    sample = next(s for s in queue if s["scan_id"] == scan["scan_id"])
    assert "0123456789" not in sample["text_redacted"]
    assert sample["user_label"] == "scam"
    client.patch(f"/admin/training/{sample['id']}?label=scam&scam_type=family", headers=ADMIN)

    csv_text = client.get("/admin/training/export", headers=ADMIN).text
    assert csv_text.splitlines()[0] == "label,category_hint,text"
    assert "scam,family,\"Mama na me" in csv_text

    stats = client.get("/admin/training/stats", headers=ADMIN).json()
    assert stats["messages_reviewed"] >= 1
    assert stats["feedback"]["count"] >= 2


def test_report_share_becomes_labelled_on_approval(client):
    q = ("/report?number=08097776666&reason=otp scam&channel=sms&share_for_training=true"
         "&message=Send me the OTP 123456 you just received")
    rid = client.post(q, headers={"X-Device-Id": "share-device-1"}).json()["report_id"]
    client.patch(f"/admin/reports/{rid}?action=approve", headers=ADMIN)
    csv_text = client.get("/admin/training/export", headers=ADMIN).text
    assert "Send me the OTP <CODE> you just received" in csv_text
    assert "123456" not in csv_text


def test_report_without_consent_is_not_shared(client):
    q = "/report?number=08097775555&reason=otp scam&channel=sms&message=Private text ABCDEFGH unique"
    rid = client.post(q, headers={"X-Device-Id": "share-device-2"}).json()["report_id"]
    client.patch(f"/admin/reports/{rid}?action=approve", headers=ADMIN)
    assert "ABCDEFGH" not in client.get("/admin/training/export?include_unreviewed=true", headers=ADMIN).text


def test_whatsapp_feedback_reply():
    from api.routers.whatsapp import build_reply
    reply = build_reply("Dear customer your account is blocked, send your OTP to 08031234567 now", sender="234800")
    assert "reply *SCAM* or *SAFE*" in reply
    assert "Thank you" in build_reply("scam", sender="234800")
    assert "forward the message first" in build_reply("safe", sender="234800")
