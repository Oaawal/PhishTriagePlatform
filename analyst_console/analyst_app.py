import streamlit as st
import requests
import pandas as pd

st.set_page_config(page_title="PhishTriage SOC Console", layout="wide")

st.title("🛡️ PhishTriage SOC Analyst Console")

# ---------------- CONFIG ----------------

st.sidebar.header("Configuration")

api_base = st.sidebar.text_input(
    "API Base URL",
    value="https://phishtriageplatform.onrender.com"
).rstrip("/")


# ---------------- HELPERS ----------------

def fetch(path, params=None):
    try:
        res = requests.get(f"{api_base}{path}", params=params, timeout=30)
        if not res.ok:
            return []
        return res.json()
    except:
        return []


def patch(path, params=None):
    try:
        requests.patch(f"{api_base}{path}", params=params, timeout=30)
    except:
        pass


def post(path, payload):
    try:
        requests.post(f"{api_base}{path}", json=payload, timeout=30)
    except:
        pass


# ---------------- FETCH DATA ----------------

reports = fetch("/reports")
pending = fetch("/admin/reports", {"status": "Pending"})
approved = fetch("/admin/reports", {"status": "Approved"})
rejected = fetch("/admin/reports", {"status": "Rejected"})
cases = fetch("/cases")
alerts = fetch("/alerts")


# ---------------- METRICS ----------------

st.subheader("📊 SOC Overview")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Reports", len(reports))
c2.metric("Pending Reports", len(pending))
c3.metric("Approved Reports", len(approved))
c4.metric("Rejected Reports", len(rejected))

c5, c6 = st.columns(2)
c5.metric("Open Cases", len(cases))
c6.metric("High Risk Alerts", len(alerts))

st.markdown("---")


# ---------------- TOP RISK NUMBERS ----------------

st.markdown("## ⚠️ Top Risk Numbers")

if alerts:
    df_alerts = pd.DataFrame(alerts)
    st.dataframe(df_alerts, use_container_width=True)
else:
    st.info("No high-risk numbers yet")


# ---------------- CHARTS ----------------

st.markdown("## 📊 Report Distribution by Reason")

if reports:
    df_reports = pd.DataFrame(reports)
    if "reason" in df_reports.columns:
        st.bar_chart(df_reports["reason"].value_counts())
else:
    st.info("No report data available")


st.markdown("## 📡 Report Distribution by Channel")

if reports:
    df_reports = pd.DataFrame(reports)
    if "channel" in df_reports.columns:
        st.bar_chart(df_reports["channel"].value_counts())


st.markdown("---")


# ---------------- TABS ----------------

tab1, tab2, tab3, tab4 = st.tabs([
    "📋 Moderation",
    "🧠 Investigation",
    "📁 Cases",
    "🔎 Lookup"
])


# ===============================
# 📋 MODERATION TAB
# ===============================

with tab1:
    st.subheader("Pending Reports")

    if not pending:
        st.info("No pending reports")
    else:
        for r in pending:
            st.markdown("---")
            st.write(f"📞 {r.get('number_e164')}")
            st.write(f"Reason: {r.get('reason')}")
            st.write(f"Channel: {r.get('channel')}")

            col1, col2 = st.columns(2)

            with col1:
                if st.button("Approve", key=f"a_{r['id']}"):
                    patch(f"/admin/reports/{r['id']}", {"action": "approve"})
                    st.rerun()

            with col2:
                if st.button("Reject", key=f"r_{r['id']}"):
                    patch(f"/admin/reports/{r['id']}", {"action": "reject"})
                    st.rerun()


# ===============================
# 🧠 INVESTIGATION TAB
# ===============================

with tab2:
    st.subheader("Investigation")

    if reports:
        selected = st.selectbox(
            "Select Report",
            reports,
            format_func=lambda x: f"{x.get('number_e164')} | {x.get('reason')}"
        )

        st.markdown("### Report Details")
        st.json(selected)

        # Lookup intelligence
        lookup = fetch("/lookup", {"number": selected.get("number_e164")})

        if lookup and lookup.get("found"):
            st.markdown("### Intelligence")

            c1, c2, c3 = st.columns(3)
            c1.metric("Risk", lookup.get("risk_level"))
            c2.metric("Reports", lookup.get("report_count_total"))
            c3.metric("Confidence", f"{lookup.get('confidence')}%")

            st.write(f"Trend: {lookup.get('trend')}")

            if lookup.get("trend") == "rising":
                st.error("⚠️ Rising activity detected")
            else:
                st.success("Stable activity")

        st.markdown("### Quick Investigation Summary")
        st.write(f"Number: {selected.get('number_e164')}")
        st.write(f"Reason: {selected.get('reason')}")
        st.write(f"Channel: {selected.get('channel')}")

        st.markdown("### Create Case")

        if st.button("Create Case"):
            payload = {
                "title": f"Investigation {selected.get('number_e164')}",
                "description": f"Investigation for {selected.get('number_e164')}",
                "status": "Open",
                "analyst_notes": f"Linked Report ID: {selected.get('id')}"
            }
            post("/cases", payload)
            st.success("Case created")
    else:
        st.info("No reports available")


# ===============================
# 📁 CASES TAB
# ===============================

with tab3:
    st.subheader("Cases")

    if not cases:
        st.info("No cases found")
    else:
        for c in cases:
            st.markdown("---")
            st.write(f"📁 {c.get('title')}")
            st.write(f"Status: {c.get('status')}")

            if st.button("Close Case", key=f"close_{c['id']}"):
                patch(f"/cases/{c['id']}", {"status": "Closed"})
                st.rerun()


# ===============================
# 🔎 LOOKUP TAB
# ===============================

with tab4:
    st.subheader("Number Lookup")

    number = st.text_input("Enter phone number")

    if st.button("Lookup"):
        data = fetch("/lookup", {"number": number})

        if data and data.get("found"):
            st.success("Number found")

            st.write(f"Number: {data.get('number')}")
            st.write(f"Risk: {data.get('risk_level')}")
            st.write(f"Confidence: {data.get('confidence')}%")
            st.write(f"Reports: {data.get('report_count_total')}")

            if data.get("trend") == "rising":
                st.error("⚠️ Rising activity detected")

            st.markdown("### Quick Actions")

            if st.button("Create Case from Lookup"):
                payload = {
                    "title": f"Lookup Investigation {data.get('number')}",
                    "description": "Case created from lookup",
                    "status": "Open"
                }
                post("/cases", payload)
                st.success("Case created")
        else:
            st.warning("No data found")
