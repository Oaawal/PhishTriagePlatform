from tests.conftest import ADMIN


def test_directory_seeded_unverified_not_public(client):
    admin = client.get("/admin/directory", headers=ADMIN).json()
    assert any(c["value"] == "gtbank.com" and not c["verified"] for c in admin)
    # unverified entries are not shown or treated as official
    assert client.get("/directory?q=gtbank").json()["count"] == 0
    assert client.get("/directory/check?value=gtbank.com").json()["official"] is False


def test_directory_verify_and_check(client):
    gt = next(c for c in client.get("/admin/directory", headers=ADMIN).json() if c["value"] == "gtbank.com")
    client.patch(f"/admin/directory/{gt['id']}", json={"verified": True, "source_url": "https://www.gtbank.com"},
                 headers=ADMIN)
    r = client.get("/directory/check?value=https://ibank.gtbank.com/login").json()
    assert r["official"] and r["kind"] == "website"
    assert client.get("/directory/check?value=gtbank-secure.com").json()["official"] is False

    c = client.post("/admin/directory", headers=ADMIN, json={
        "org_name": "Test Bank", "org_type": "bank", "kind": "phone", "value": "0700 123 4567", "verified": True})
    assert c.status_code == 200 and c.json()["value_normalized"] == "+2347001234567"
    client.post("/admin/directory", headers=ADMIN, json={
        "org_name": "Test Bank", "kind": "sms_sender", "value": "TestBank", "verified": True})
    assert client.get("/directory/check?value=TESTBANK").json()["official"]
    assert client.get("/directory/check?value=+234 700 123 4567").json()["official"]
    look = client.get("/lookup?number=07001234567").json()
    assert look["official"][0]["org_name"] == "Test Bank" and "fake caller ID" in look["official_note"]
    d = client.get("/directory?q=test").json()
    assert d["organisations"][0]["org_name"] == "Test Bank" and len(d["organisations"][0]["contacts"]) == 2
    assert client.post("/admin/directory", json={"org_name": "X", "kind": "phone", "value": "1"}).status_code == 403


def test_scam_alerts(client):
    assert client.post("/admin/scam-alerts", json={"title": "Fake CBN grant SMS", "body": "x" * 20}).status_code == 403
    a = client.post("/admin/scam-alerts", headers=ADMIN, json={
        "title": "Fake CBN grant SMS", "body": "An SMS says CBN is giving grants. It is fake.",
        "severity": "danger"}).json()
    feed = client.get("/scam-alerts").json()
    assert feed["alerts"][0]["title"] == "Fake CBN grant SMS"
    assert isinstance(feed["trending"], list)
    client.patch(f"/admin/scam-alerts/{a['id']}", headers=ADMIN, json={"active": False})
    assert all(x["id"] != a["id"] for x in client.get("/scam-alerts").json()["alerts"])


def test_blocklist(client):
    q = "/report?number=08061112233&reason=loan scam&channel=call"
    rid = client.post(q, headers={"X-Device-Id": "blocklist-dev-1"}).json()["report_id"]
    client.patch(f"/admin/reports/{rid}?action=approve", headers=ADMIN)
    bl = client.get("/numbers/blocklist").json()
    entry = next(x for x in bl["numbers"] if x["n"] == "+2348061112233")
    assert entry["r"] in ("Medium", "High") and entry["c"] >= 1
    assert any(o["o"] == "Test Bank" for o in bl["official"])


def test_whatsapp_official_and_alerts(client):
    from api.routers.whatsapp import build_reply
    for kind, value in (("phone", "07001234567"), ("sms_sender", "TestBank")):
        client.post("/admin/directory", headers=ADMIN, json={
            "org_name": "Test Bank", "kind": kind, "value": value, "verified": True})
    client.post("/admin/scam-alerts", headers=ADMIN, json={
        "title": "Fake POS reversal calls", "body": "Callers claim a POS reversal and ask for your OTP."})
    assert "Fake POS reversal" in build_reply("alerts")
    assert "Test Bank" in build_reply("official test")
    assert "official contact" in build_reply("official TESTBANK")
    assert "official number of Test Bank" in build_reply("check 07001234567")
