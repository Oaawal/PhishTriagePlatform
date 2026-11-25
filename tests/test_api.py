import hashlib
import hmac
import json

from tests.conftest import ADMIN


def dev(i):
    return {"X-Device-Id": f"device-{i:08d}"}


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_analyze(client):
    r = client.post("/analyze", json={"message": "Mama na me, I change number, send 20k to 0123456789 urgent"})
    assert r.status_code == 200
    body = r.json()
    assert body["risk"] == "High"
    assert body["indicators"]["accounts"] == ["0123456789"]


def test_legacy_shape(client):
    r = client.post("/analyze-message", json={"message": "Good morning, see you this evening"})
    assert r.json()["risk"] == "Low Risk"


def test_admin_endpoints_need_key(client):
    assert client.get("/reports").status_code == 403
    assert client.get("/cases").status_code == 403
    assert client.get("/reports", headers=ADMIN).status_code == 200


def test_two_users_can_report_same_number(client):
    """Regression: users behind the same proxy were blocked as duplicates."""
    proxy = {"X-Forwarded-For": "1.2.3.4"}
    q = "/report?number=08031112222&reason=otp scam&channel=sms"
    assert client.post(q, headers={**proxy, **dev(1)}).status_code == 200
    assert client.post(q, headers={**proxy, **dev(2)}).status_code == 200
    assert client.post(q, headers={**proxy, **dev(1)}).status_code == 400  # same device again


def test_moderation_flow_and_lookup(client):
    q = "/report?number=08035556666&reason=bank scam&channel=call&message=send your OTP 123456"
    ids = [client.post(q, headers=dev(10 + i)).json()["report_id"] for i in range(3)]
    # not visible until approved
    assert client.get("/lookup?number=08035556666").json()["report_count_total"] == 0
    for rid in ids:
        assert client.patch(f"/admin/reports/{rid}?action=approve", headers=ADMIN).status_code == 200
    look = client.get("/lookup?number=+2348035556666").json()
    assert look["risk_level"] == "High"
    assert look["report_count_total"] == 3
    assert "not proof" in look["status_note"]
    reports = client.get("/reports", headers=ADMIN).json()
    assert all("123456" not in (r["message_sanitized"] or "") for r in reports)
    # public history hides reporter fingerprints
    hist = client.get("/numbers/08035556666/reports").json()
    assert "reporter_fingerprint" not in hist["reports"][0]


def test_account_report_and_dispute(client):
    body = {"account_number": "0123456789", "bank": "Opay", "account_name": "John Doe",
            "reason": "online shopping", "channel": "instagram", "amount_lost": 45000}
    rid = client.post("/accounts/report", json=body, headers=dev(50)).json()["report_id"]
    client.patch(f"/admin/account-reports/{rid}?action=approve", headers=ADMIN)
    look = client.get("/accounts/lookup?account_number=0123456789").json()
    assert look["found"] and look["risk_level"] == "Medium"
    d = client.post("/disputes", json={"target_type": "account", "target": "0123456789", "bank": "Opay",
                                       "contact": "owner@example.com",
                                       "explanation": "This is my business account and the order was delivered."})
    assert d.status_code == 200
    assert client.get("/accounts/lookup?account_number=0123456789").json()["matches"][0]["under_review"]
    client.patch(f"/admin/disputes/{d.json()['dispute_id']}?action=uphold", headers=ADMIN)
    look = client.get("/accounts/lookup?account_number=0123456789").json()
    assert look["risk_level"] == "Low" and look["matches"][0]["cleared"]


def test_cases(client):
    c = client.post("/cases", json={"risk": "High", "category": "OTP scam", "phones": "+2348035556666"}, headers=ADMIN)
    assert c.status_code == 200
    cid = c.json()["id"]
    assert client.patch(f"/cases/{cid}?status=Closed", headers=ADMIN).json()["status"] == "Closed"
    assert client.patch(f"/cases/{cid}?status=Bogus", headers=ADMIN).status_code == 400


def test_recovery(client):
    assert len(client.get("/recovery").json()["situations"]) >= 5
    plan = client.get("/recovery/bank_transfer").json()
    assert plan["steps"]
    letter = client.post("/recovery/letter", json={"victim_name": "Ada Obi", "amount": "N50,000",
                                                   "scammer_account": "0123456789"}).json()
    assert "Ada Obi" in letter["letter"] and len(letter["sha256"]) == 64


def test_stats_and_feed(client):
    assert client.get("/stats/public").json()["scans"] >= 1
    assert "numbers" in client.get("/admin/feed", headers=ADMIN).json()


def test_whatsapp_verify(client):
    r = client.get("/webhooks/whatsapp?hub.mode=subscribe&hub.verify_token=verify-me&hub.challenge=42")
    assert r.text == "42"
    assert client.get("/webhooks/whatsapp?hub.mode=subscribe&hub.verify_token=no&hub.challenge=42").status_code == 403


def test_whatsapp_webhook(client, monkeypatch):
    sent = []
    from api.routers import whatsapp
    monkeypatch.setattr(whatsapp, "send_whatsapp_text", lambda to, body: sent.append((to, body)))
    payload = {"entry": [{"changes": [{"value": {"messages": [
        {"id": "wamid.1", "from": "2348031234567", "type": "text",
         "text": {"body": "Dear customer your account will be blocked. Send your OTP to 08031234567 now"}}]}}]}]}
    raw = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(b"test-secret", raw, hashlib.sha256).hexdigest()
    assert client.post("/webhooks/whatsapp", content=raw, headers={"X-Hub-Signature-256": "sha256=bad",
                                                                    "Content-Type": "application/json"}).status_code == 403
    r = client.post("/webhooks/whatsapp", content=raw, headers={"X-Hub-Signature-256": sig,
                                                                "Content-Type": "application/json"})
    assert r.status_code == 200
    assert sent and "HIGH RISK" in sent[0][1]


def test_whatsapp_commands():
    from api.routers.whatsapp import build_reply
    assert "PhishTriage" in build_reply("hi")
    assert "+2348035556666" in build_reply("check 0803 555 6666")
    assert "account" in build_reply("account 0123456789").lower()
    assert "Speed matters" in build_reply("scammed")
    assert "bank" in build_reply("recover transfer").lower()
