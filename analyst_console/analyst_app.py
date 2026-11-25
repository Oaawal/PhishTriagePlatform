"""
PhishTriage SOC Analyst Console (Streamlit).

Run:  streamlit run analyst_console/analyst_app.py

The admin key is read from (in order): Streamlit secrets `ADMIN_API_KEY`,
the ADMIN_API_KEY environment variable, or the password box in the sidebar.
"""
import os

import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="PhishTriage SOC Console", layout="wide")
st.title("🛡️ PhishTriage SOC Analyst Console")


def _secret(name: str, default: str = "") -> str:
    try:
        return st.secrets.get(name, os.getenv(name, default))
    except Exception:
        return os.getenv(name, default)


# ---------------- CONFIG ----------------
st.sidebar.header("Configuration")
api_base = st.sidebar.text_input(
    "API Base URL", value=_secret("API_BASE_URL", "https://phishtriageplatform.onrender.com")
).rstrip("/")
api_key = _secret("ADMIN_API_KEY") or st.sidebar.text_input("Admin API key", type="password")
HEADERS = {"X-API-Key": api_key} if api_key else {}


# ---------------- HELPERS ----------------
def _call(method: str, path: str, **kw):
    try:
        res = requests.request(method, f"{api_base}{path}", headers=HEADERS, timeout=60, **kw)
    except requests.RequestException as exc:
        st.error(f"Cannot reach API ({type(exc).__name__}). The server may be waking up; try again.")
        return None
    if res.status_code == 403:
        st.error("Admin key rejected. Check ADMIN_API_KEY.")
        return None
    if res.status_code == 503:
        st.error("Admin API is disabled on the server: set ADMIN_API_KEY there.")
        return None
    if not res.ok:
        st.warning(f"{method} {path} failed: HTTP {res.status_code} {res.text[:200]}")
        return None
    return res.json()


def fetch(path, params=None, default=None):
    out = _call("GET", path, params=params)
    return default if out is None else out


def patch(path, params=None):
    return _call("PATCH", path, params=params)


def post(path, payload):
    return _call("POST", path, json=payload)


if not api_key:
    st.info("Enter the admin API key in the sidebar to load moderation data.")
    st.stop()

# ---------------- FETCH DATA ----------------
reports = fetch("/reports", default=[])
pending = [r for r in reports if r.get("status") == "Pending"]
approved = [r for r in reports if r.get("status") == "Approved"]
rejected = [r for r in reports if r.get("status") == "Rejected"]
acct_pending = fetch("/admin/account-reports", {"status": "Pending"}, default=[])
disputes = fetch("/admin/disputes", {"status": "Pending"}, default=[])
cases = fetch("/cases", {"status": "Open"}, default=[])
alerts = fetch("/alerts", default={}).get("alerts", [])
stats = fetch("/stats/public", {"days": 30}, default={})

# ---------------- METRICS ----------------
st.subheader("📊 SOC Overview")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Number reports", len(reports))
c2.metric("Pending (numbers)", len(pending))
c3.metric("Pending (accounts)", len(acct_pending))
c4.metric("Pending disputes", len(disputes))
c5, c6, c7, c8 = st.columns(4)
c5.metric("Open cases", len(cases))
c6.metric("High-risk alerts", len(alerts))
c7.metric("Scans (30d)", stats.get("scans", 0))
c8.metric("Flagged scans (30d)", stats.get("flagged", 0))

if stats.get("by_category"):
    st.markdown("#### Flagged scans by scam type (30 days)")
    st.bar_chart(pd.Series(stats["by_category"]))

st.markdown("---")

tabs = st.tabs(["📋 Number reports", "🏦 Account reports", "⚖️ Disputes", "🧠 Investigation",
                "📁 Cases", "🔎 Lookup / Analyze", "📤 Partner feed", "🏷️ Training data",
                "📇 Official directory", "📣 Scam warnings"])


def moderation_buttons(prefix: str, rid: str, path: str):
    notes = st.text_input("Moderator notes", key=f"{prefix}_n_{rid}")
    col1, col2 = st.columns(2)
    if col1.button("Approve", key=f"{prefix}_a_{rid}"):
        patch(path, {"action": "approve", "notes": notes or None})
        st.rerun()
    if col2.button("Reject", key=f"{prefix}_r_{rid}"):
        patch(path, {"action": "reject", "notes": notes or None})
        st.rerun()


# ---------------- NUMBER REPORTS ----------------
with tabs[0]:
    st.subheader("Pending number reports")
    st.caption(f"Approved: {len(approved)} · Rejected: {len(rejected)}")
    if not pending:
        st.info("No pending reports")
    for r in pending:
        with st.container(border=True):
            st.write(f"📞 **{r.get('number_e164')}** · {r.get('reason')} · via {r.get('channel')} · {r.get('created_at', '')[:16]}")
            if r.get("message_sanitized"):
                st.code(r["message_sanitized"])
            moderation_buttons("num", r["id"], f"/admin/reports/{r['id']}")

# ---------------- ACCOUNT REPORTS ----------------
with tabs[1]:
    st.subheader("Pending bank account reports")
    if not acct_pending:
        st.info("No pending account reports")
    for r in acct_pending:
        with st.container(border=True):
            st.write(f"🏦 **{r.get('account_number')}** ({r.get('bank')}) · name: {r.get('account_name') or '—'}")
            st.write(f"{r.get('reason')} · via {r.get('channel')} · lost: {r.get('amount_lost') or '—'}")
            if r.get("message_sanitized"):
                st.code(r["message_sanitized"])
            moderation_buttons("acc", r["id"], f"/admin/account-reports/{r['id']}")

# ---------------- DISPUTES ----------------
with tabs[2]:
    st.subheader("Owner disputes (right of reply)")
    st.caption("Uphold clears the listing. Respond to the contact given within a reasonable time.")
    if not disputes:
        st.info("No pending disputes")
    for d in disputes:
        with st.container(border=True):
            st.write(f"**{d['target_type']}** `{d['target_id']}` · contact: {d['contact']}")
            st.write(d["explanation"])
            notes = st.text_input("Decision notes", key=f"d_n_{d['id']}")
            col1, col2 = st.columns(2)
            if col1.button("Uphold (clear listing)", key=f"d_u_{d['id']}"):
                patch(f"/admin/disputes/{d['id']}", {"action": "uphold", "notes": notes or None})
                st.rerun()
            if col2.button("Reject dispute", key=f"d_r_{d['id']}"):
                patch(f"/admin/disputes/{d['id']}", {"action": "reject", "notes": notes or None})
                st.rerun()

# ---------------- INVESTIGATION ----------------
with tabs[3]:
    st.subheader("Investigation")
    if not reports:
        st.info("No reports available")
    else:
        selected = st.selectbox(
            "Select report", reports,
            format_func=lambda x: f"{x.get('number_e164')} | {x.get('reason')} | {x.get('status')}",
        )
        st.json(selected)
        lookup = fetch("/lookup", {"number": selected.get("number_e164")}, default={})
        if lookup.get("found"):
            k1, k2, k3 = st.columns(3)
            k1.metric("Risk", lookup.get("risk_level"))
            k2.metric("Approved reports", lookup.get("report_count_total"))
            k3.metric("Confidence", f"{lookup.get('confidence')}%")
            (st.error if lookup.get("trend") == "rising" else st.success)(f"Trend: {lookup.get('trend')}")
        if st.button("Create case from this report"):
            case = post("/cases", {
                "source": "report",
                "risk": lookup.get("risk_level", "Medium"),
                "category": selected.get("reason", "Reported"),
                "sanitized_message": selected.get("message_sanitized") or "",
                "phones": selected.get("number_e164", ""),
                "analyst_notes": f"Linked report ID: {selected.get('id')}",
            })
            if case:
                patch(f"/reports/{selected['id']}/link-case", {"case_id": case["id"]})
                st.success(f"Case {case['id'][:8]} created and linked")

# ---------------- CASES ----------------
with tabs[4]:
    st.subheader("Open cases")
    if not cases:
        st.info("No open cases")
    for c in cases:
        with st.container(border=True):
            st.write(f"📁 **{c.get('category')}** · risk {c.get('risk')} · {c.get('phones') or c.get('accounts') or ''}")
            st.caption(f"{c['id']} · created {c.get('created_at', '')[:16]} · assignee: {c.get('assignee') or '—'}")
            notes = st.text_area("Analyst notes", value=c.get("analyst_notes") or "", key=f"cn_{c['id']}")
            col1, col2, col3 = st.columns(3)
            if col1.button("Save notes", key=f"cs_{c['id']}"):
                patch(f"/cases/{c['id']}", {"analyst_notes": notes})
                st.rerun()
            if col2.button("Mark in review", key=f"ci_{c['id']}"):
                patch(f"/cases/{c['id']}", {"status": "InReview"})
                st.rerun()
            if col3.button("Close case", key=f"cc_{c['id']}"):
                patch(f"/cases/{c['id']}", {"status": "Closed"})
                st.rerun()

# ---------------- LOOKUP / ANALYZE ----------------
with tabs[5]:
    left, right = st.columns(2)
    with left:
        st.subheader("Number / account lookup")
        q = st.text_input("Phone number or 10-digit account number")
        if st.button("Lookup") and q:
            digits = "".join(ch for ch in q if ch.isdigit())
            if len(digits) == 10 and not digits.startswith(("70", "80", "81", "90", "91")):
                st.json(fetch("/accounts/lookup", {"account_number": digits}, default={}))
            else:
                st.json(fetch("/lookup", {"number": q}, default={}))
    with right:
        st.subheader("Analyze a message")
        msg = st.text_area("Message text", height=150)
        if st.button("Analyze") and msg.strip():
            res = post("/analyze", {"message": msg, "channel": "console"})
            if res:
                st.metric("Risk", f"{res['risk']} ({res['score']}/100)")
                st.write(f"**Category:** {res['category']}")
                st.dataframe(pd.DataFrame(res["signals"]), use_container_width=True)
                st.json(res["indicators"])

# ---------------- PARTNER FEED ----------------
with tabs[6]:
    st.subheader("Moderated intelligence feed")
    st.caption("Shareable with partner fraud teams under a data-sharing agreement. Contains no reporter data or message text.")
    days = st.slider("Window (days)", 7, 180, 30)
    feed = fetch("/admin/feed", {"days": days}, default={})
    if feed:
        st.write(f"Numbers: {len(feed['numbers'])} · Accounts: {len(feed['accounts'])} · Domains: {len(feed['domains'])}")
        for key in ("numbers", "accounts", "domains"):
            if feed[key]:
                df = pd.DataFrame(feed[key])
                st.markdown(f"**{key.title()}**")
                st.dataframe(df, use_container_width=True)
                st.download_button(f"Download {key}.csv", df.to_csv(index=False).encode(), f"phishtriage_{key}.csv",
                                   "text/csv", key=f"dl_{key}")

# ---------------- TRAINING DATA ----------------
with tabs[7]:
    st.subheader("Training data for PhishTriage's own model")
    st.caption("Messages users chose to share, with phone numbers, account numbers, codes and emails removed. "
               "Label each one. Discard anything that still contains personal details or is not a real message.")
    tstats = fetch("/admin/training/stats", default={})
    if tstats:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Shared messages", tstats["messages_shared"])
        m2.metric("Reviewed", f"{tstats['messages_reviewed']} / {tstats['target_reviewed_samples']}")
        m3.metric("Awaiting review", tstats["awaiting_review"])
        rate = tstats["feedback"]["engine_agreement_rate"]
        m4.metric("Engine agreement (user feedback)", f"{rate:.0%}" if rate is not None else "—")
        st.caption(f"From feedback: {tstats['feedback']['missed_scams']} missed scams, "
                   f"{tstats['feedback']['false_alarms']} false alarms out of {tstats['feedback']['count']} answers.")
        st.progress(min(tstats["messages_reviewed"] / tstats["target_reviewed_samples"], 1.0))

    queue = fetch("/admin/training/queue", {"limit": 25}, default=[])
    if not queue:
        st.info("Nothing waiting for review")
    for s in queue:
        with st.container(border=True):
            st.code(s["text_redacted"])
            st.caption(f"source: {s['source']} · engine: {s.get('engine_risk')} ({s.get('engine_category')}) · "
                       f"user says: {s.get('user_label') or '—'}")
            stype = st.text_input("Scam type (optional)", value=s.get("scam_type") or "", key=f"ts_{s['id']}")
            c1, c2, c3 = st.columns(3)
            if c1.button("Scam", key=f"tscam_{s['id']}"):
                patch(f"/admin/training/{s['id']}", {"label": "scam", "scam_type": stype or None})
                st.rerun()
            if c2.button("Safe", key=f"tsafe_{s['id']}"):
                patch(f"/admin/training/{s['id']}", {"label": "safe", "scam_type": stype or None})
                st.rerun()
            if c3.button("Discard", key=f"tdel_{s['id']}"):
                patch(f"/admin/training/{s['id']}", {"label": "discard"})
                st.rerun()

    st.markdown("#### Export")
    st.caption("Reviewed samples as CSV, for scripts/train_model.py.")
    try:
        exp = requests.get(f"{api_base}/admin/training/export", headers=HEADERS, timeout=60)
        if exp.ok:
            st.download_button("Download training CSV", exp.content, "phishtriage_training.csv", "text/csv")
    except requests.RequestException:
        st.warning("Could not prepare the export right now.")

# ---------------- OFFICIAL DIRECTORY ----------------
with tabs[8]:
    st.subheader("Official contacts directory")
    st.caption("Only VERIFIED entries are shown to the public and used to mark numbers, senders and websites as "
               "official. Verify every entry on the organisation's own website and paste that page as the source.")
    entries = fetch("/admin/directory", default=[])
    if entries:
        df = pd.DataFrame(entries)[["org_name", "org_type", "kind", "value", "verified", "active", "source_url", "id"]]
        st.dataframe(df, use_container_width=True)
        pending_entries = [e for e in entries if not e["verified"] and e["active"]]
        if pending_entries:
            st.markdown(f"**{len(pending_entries)} entries waiting for verification**")
        for e in pending_entries[:20]:
            with st.container(border=True):
                st.write(f"**{e['org_name']}** · {e['kind']}: `{e['value']}`")
                src = st.text_input("Source URL (official page where you confirmed it)", key=f"src_{e['id']}")
                c1, c2 = st.columns(2)
                if c1.button("Verify", key=f"ver_{e['id']}", disabled=not src):
                    _call("PATCH", f"/admin/directory/{e['id']}", json={"verified": True, "source_url": src})
                    st.rerun()
                if c2.button("Deactivate", key=f"deact_{e['id']}"):
                    _call("PATCH", f"/admin/directory/{e['id']}", json={"active": False})
                    st.rerun()
    st.markdown("#### Add an official contact")
    with st.form("add_official"):
        org = st.text_input("Organisation (e.g. GTBank)")
        org_type = st.selectbox("Type", ["bank", "fintech", "telco", "government", "other"])
        kind = st.selectbox("Contact kind", ["phone", "sms_sender", "website", "email", "whatsapp", "ussd", "app"])
        value = st.text_input("Value (number, sender name, website...)")
        source = st.text_input("Source URL where you confirmed it")
        notes = st.text_input("Notes (optional)")
        verified = st.checkbox("I confirmed this on the organisation's official website")
        if st.form_submit_button("Add"):
            res = post("/admin/directory", {"org_name": org, "org_type": org_type, "kind": kind, "value": value,
                                            "source_url": source or None, "notes": notes or None,
                                            "verified": verified})
            if res:
                st.success("Added")

# ---------------- SCAM WARNINGS ----------------
with tabs[9]:
    st.subheader("Scam warnings shown in the app and WhatsApp bot")
    feed = fetch("/scam-alerts", default={})
    if feed.get("trending"):
        st.markdown("**Trending in scans this week**")
        st.dataframe(pd.DataFrame(feed["trending"]), use_container_width=True)
    with st.form("new_alert"):
        title = st.text_input("Title (e.g. Fake CBN grant SMS going round)")
        body = st.text_area("What people should know and do")
        category = st.text_input("Scam type (optional)")
        severity = st.selectbox("Severity", ["warning", "danger", "info"])
        days = st.number_input("Show for (days)", 1, 365, 14)
        if st.form_submit_button("Publish warning"):
            if post("/admin/scam-alerts", {"title": title, "body": body, "category": category or None,
                                           "severity": severity, "expires_in_days": int(days)}):
                st.success("Published")
    for a in fetch("/admin/scam-alerts", default=[]):
        with st.container(border=True):
            st.write(f"**{a['title']}** ({a['severity']}) · {'active' if a['active'] else 'hidden'}")
            st.write(a["body"])
            if a["active"] and st.button("Hide", key=f"hide_{a['id']}"):
                _call("PATCH", f"/admin/scam-alerts/{a['id']}", json={"active": False})
                st.rerun()
