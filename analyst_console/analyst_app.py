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
)

# ---------------- HELPERS ----------------

def fetch_reports(status=None):
    try:
        if status:
            res = requests.get(f"{api_base}/admin/reports", params={"status": status})
        else:
            res = requests.get(f"{api_base}/reports")
        return res.json()
    except:
        return []

def fetch_cases():
    try:
        res = requests.get(f"{api_base}/cases")
        return res.json()
    except:
        return []

def approve_report(report_id):
    requests.patch(f"{api_base}/admin/reports/{report_id}?action=approve")

def reject_report(report_id):
    requests.patch(f"{api_base}/admin/reports/{report_id}?action=reject")

def create_case(payload):
    res = requests.post(f"{api_base}/cases", json=payload)
    return res.json()

def update_case(case_id, payload):
    requests.patch(f"{api_base}/cases/{case_id}", params=payload)

# ---------------- DASHBOARD METRICS ----------------

st.subheader("📊 SOC Overview")

reports = fetch_reports()
cases = fetch_cases()

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Reports", len(reports))
col2.metric("Pending Reports", len(fetch_reports("Pending")))
col3.metric("Approved Reports", len(fetch_reports("Approved")))
col4.metric("Open Cases", len(cases))

st.markdown("---")

# ---------------- TABS ----------------

tab1, tab2, tab3, tab4 = st.tabs([
    "📋 Moderation Queue",
    "🧠 Investigation",
    "📁 Cases",
    "🔎 Intelligence Lookup"
])

# ===============================
# 📋 MODERATION QUEUE
# ===============================

with tab1:
    st.subheader("Pending Reports")

    reports = fetch_reports("Pending")

    # Filters
    reason_filter = st.selectbox("Filter by Reason", ["All"] + list(set([r["reason"] for r in reports])) if reports else ["All"])
    channel_filter = st.selectbox("Filter by Channel", ["All"] + list(set([r["channel"] for r in reports])) if reports else ["All"])

    for r in reports:
        if reason_filter != "All" and r["reason"] != reason_filter:
            continue
        if channel_filter != "All" and r["channel"] != channel_filter:
            continue

        with st.container():
            st.markdown("---")

            col1, col2 = st.columns([3, 1])

            with col1:
                st.markdown(f"**📞 {r['number_e164']}**")
                st.markdown(f"Reason: {r['reason']}")
                st.markdown(f"Channel: {r['channel']}")
                st.markdown(f"Time: {r['created_at']}")

                if r.get("message_sanitized"):
                    st.code(r["message_sanitized"])

            with col2:
                if st.button("Approve", key=f"a_{r['id']}"):
                    approve_report(r["id"])
                    st.success("Approved")
                    st.rerun()

                if st.button("Reject", key=f"r_{r['id']}"):
                    reject_report(r["id"])
                    st.warning("Rejected")
                    st.rerun()


# ===============================
# 🧠 INVESTIGATION VIEW
# ===============================

with tab2:
    st.subheader("Investigation Panel")

    reports = fetch_reports()

    if reports:
        selected = st.selectbox(
            "Select Report",
            reports,
            format_func=lambda x: f"{x['number_e164']} | {x['reason']} | {x['status']}"
        )

        st.markdown("### Report Details")
        st.json(selected)

        # Lookup intelligence
        res = requests.get(f"{api_base}/lookup", params={"number": selected["number_e164"]})
        data = res.json()

        if data.get("found"):
            st.markdown("### 🔎 Intelligence")
            st.write(f"Risk: {data['risk_level']}")
            st.write(f"Confidence: {data['confidence']}%")
            st.write(f"Reports: {data['report_count_total']}")

        # Create case
        st.markdown("### 📁 Create Case")

        case_title = st.text_input("Case Title")
        case_notes = st.text_area("Initial Notes")

        if st.button("Create Case"):
            payload = {
                "title": case_title,
                "description": case_notes,
                "status": "Open"
            }
            case = create_case(payload)
            st.success(f"Case Created: {case.get('id')}")


# ===============================
# 📁 CASE MANAGEMENT
# ===============================

with tab3:
    st.subheader("Case Queue")

    cases = fetch_cases()

    if cases:
        for c in cases:
            with st.container():
                st.markdown("---")

                st.markdown(f"### Case ID: {c['id']}")
                st.markdown(f"Status: {c['status']}")
                st.markdown(f"Assignee: {c.get('assignee')}")

                notes = st.text_area("Update Notes", key=f"notes_{c['id']}")

                if st.button("Update Case", key=f"update_{c['id']}"):
                    update_case(c["id"], {"analyst_notes": notes})
                    st.success("Updated")
                    st.rerun()


# ===============================
# 🔎 LOOKUP
# ===============================

with tab4:
    st.subheader("Number Lookup")

    number_input = st.text_input("Enter phone number")

    if st.button("Lookup"):
        res = requests.get(f"{api_base}/lookup", params={"number": number_input})
        data = res.json()

        if not data.get("found"):
            st.warning(data.get("message"))
        else:
            st.success("Number found")

            st.markdown(f"### {data['number']}")

            col1, col2, col3 = st.columns(3)

            col1.metric("Risk", data["risk_level"])
            col2.metric("Reports", data["report_count_total"])
            col3.metric("Confidence", f"{data['confidence']}%")

            st.write("Insights:")
            for i in data["insights"]:
                st.write(f"- {i}")
