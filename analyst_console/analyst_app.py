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

def safe_get_json(url, params=None, method="GET", json_body=None):
    try:
        if method == "GET":
            res = requests.get(url, params=params, timeout=30)
        elif method == "POST":
            res = requests.post(url, json=json_body, timeout=30)
        elif method == "PATCH":
            res = requests.patch(url, params=params, timeout=30)
        else:
            return None, f"Unsupported method: {method}"

        if not res.ok:
            return None, f"HTTP {res.status_code}: {res.text}"

        try:
            return res.json(), None
        except Exception:
            return None, "Response was not valid JSON"
    except requests.exceptions.RequestException as e:
        return None, str(e)


def ensure_list(data):
    return data if isinstance(data, list) else []


def ensure_dict_list(data):
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def fetch_reports(status=None):
    if status:
        data, err = safe_get_json(
            f"{api_base}/admin/reports",
            params={"status": status}
        )
    else:
        data, err = safe_get_json(f"{api_base}/reports")

    if err:
        return [], err

    return ensure_dict_list(data), None


def fetch_cases():
    data, err = safe_get_json(f"{api_base}/cases")
    if err:
        return [], err
    return ensure_dict_list(data), None


def fetch_lookup(number):
    data, err = safe_get_json(f"{api_base}/lookup", params={"number": number})
    return data, err


def approve_report(report_id):
    return safe_get_json(
        f"{api_base}/admin/reports/{report_id}",
        params={"action": "approve"},
        method="PATCH"
    )


def reject_report(report_id):
    return safe_get_json(
        f"{api_base}/admin/reports/{report_id}",
        params={"action": "reject"},
        method="PATCH"
    )


def create_case(payload):
    return safe_get_json(
        f"{api_base}/cases",
        method="POST",
        json_body=payload
    )


def update_case(case_id, payload):
    return safe_get_json(
        f"{api_base}/cases/{case_id}",
        method="PATCH",
        params=payload
    )


def normalize_report_row(r):
    return {
        "id": r.get("id", ""),
        "number_e164": r.get("number_e164", "N/A"),
        "reason": r.get("reason", "N/A"),
        "channel": r.get("channel", "N/A"),
        "status": r.get("status", "Unknown"),
        "created_at": r.get("created_at", ""),
        "message_sanitized": r.get("message_sanitized", ""),
        "moderator_notes": r.get("moderator_notes", ""),
    }


def report_label(r):
    number = r.get("number_e164", "N/A")
    reason = r.get("reason", "N/A")
    status = r.get("status", "Unknown")
    return f"{number} | {reason} | {status}"


# ---------------- LOAD DATA ----------------

all_reports, reports_err = fetch_reports()
pending_reports, pending_err = fetch_reports("Pending")
approved_reports, approved_err = fetch_reports("Approved")
open_cases, cases_err = fetch_cases()

all_reports = [normalize_report_row(r) for r in all_reports]
pending_reports = [normalize_report_row(r) for r in pending_reports]
approved_reports = [normalize_report_row(r) for r in approved_reports]

# ---------------- DASHBOARD METRICS ----------------

st.subheader("📊 SOC Overview")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Reports", len(all_reports))
col2.metric("Pending Reports", len(pending_reports))
col3.metric("Approved Reports", len(approved_reports))
col4.metric("Open Cases", len(open_cases))

if reports_err:
    st.warning(f"Reports endpoint issue: {reports_err}")
if pending_err:
    st.warning(f"Pending reports endpoint issue: {pending_err}")
if approved_err:
    st.warning(f"Approved reports endpoint issue: {approved_err}")
if cases_err:
    st.warning(f"Cases endpoint issue: {cases_err}")

st.markdown("---")

# ---------------- TABS ----------------

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📋 Moderation Queue",
    "🧠 Investigation",
    "📁 Cases",
    "🔎 Intelligence Lookup",
    "🛠️ Debug"
])

# ===============================
# 📋 MODERATION QUEUE
# ===============================

with tab1:
    st.subheader("Pending Reports")

    if not pending_reports:
        st.info("No pending reports")
    else:
        reason_options = sorted({r.get("reason", "N/A") for r in pending_reports})
        channel_options = sorted({r.get("channel", "N/A") for r in pending_reports})

        reason_filter = st.selectbox("Filter by Reason", ["All"] + reason_options)
        channel_filter = st.selectbox("Filter by Channel", ["All"] + channel_options)

        filtered_reports = []
        for r in pending_reports:
            if reason_filter != "All" and r.get("reason") != reason_filter:
                continue
            if channel_filter != "All" and r.get("channel") != channel_filter:
                continue
            filtered_reports.append(r)

        if not filtered_reports:
            st.info("No reports match the current filters")
        else:
            for r in filtered_reports:
                with st.container():
                    st.markdown("---")
                    col1, col2 = st.columns([3, 1])

                    with col1:
                        st.markdown(f"**📞 {r.get('number_e164', 'N/A')}**")
                        st.markdown(f"**Reason:** {r.get('reason', 'N/A')}")
                        st.markdown(f"**Channel:** {r.get('channel', 'N/A')}")
                        st.markdown(f"**Status:** {r.get('status', 'Unknown')}")
                        st.markdown(f"**Time:** {r.get('created_at', '')}")

                        if r.get("message_sanitized"):
                            st.code(r["message_sanitized"])

                    with col2:
                        if st.button("Approve", key=f"approve_{r.get('id', '')}"):
                            _, err = approve_report(r.get("id"))
                            if err:
                                st.error(err)
                            else:
                                st.success("Report approved")
                                st.rerun()

                        if st.button("Reject", key=f"reject_{r.get('id', '')}"):
                            _, err = reject_report(r.get("id"))
                            if err:
                                st.error(err)
                            else:
                                st.warning("Report rejected")
                                st.rerun()

# ===============================
# 🧠 INVESTIGATION VIEW
# ===============================

with tab2:
    st.subheader("Investigation Panel")

    valid_reports = [r for r in all_reports if r.get("id")]

    if not valid_reports:
        st.info("No reports available for investigation")
    else:
        selected = st.selectbox(
            "Select Report",
            valid_reports,
            format_func=report_label
        )

        st.markdown("### Report Details")
        st.json(selected)

        number_for_lookup = selected.get("number_e164")
        if number_for_lookup and number_for_lookup != "N/A":
            lookup_data, lookup_err = fetch_lookup(number_for_lookup)

            if lookup_err:
                st.error(f"Lookup failed: {lookup_err}")
            elif isinstance(lookup_data, dict):
                st.markdown("### 🔎 Intelligence")
                if lookup_data.get("found"):
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Risk", lookup_data.get("risk_level", "N/A"))
                    c2.metric("Reports", lookup_data.get("report_count_total", 0))
                    c3.metric("Confidence", f"{lookup_data.get('confidence', 0)}%")

                    st.markdown(f"**Label:** {lookup_data.get('current_label')}")
                    st.markdown(f"**Trend:** {lookup_data.get('trend')}")
                    st.markdown(f"**Last Reported:** {lookup_data.get('last_reported_at')}")

                    insights = lookup_data.get("insights", [])
                    if insights:
                        st.markdown("#### Insights")
                        for item in insights:
                            st.write(f"- {item}")

                    actions = lookup_data.get("recommended_action", [])
                    if actions:
                        st.markdown("#### Recommended Actions")
                        for item in actions:
                            st.write(f"- {item}")
                else:
                    st.info(lookup_data.get("message", "No intelligence found"))

        st.markdown("### 📁 Create Case")

        default_title = f"Investigation: {selected.get('number_e164', 'Unknown Number')}"
        case_title = st.text_input("Case Title", value=default_title, key="case_title")
        case_description = st.text_area(
            "Initial Notes / Description",
            value=(
                f"Investigate reported number {selected.get('number_e164', 'N/A')}.\n"
                f"Reason: {selected.get('reason', 'N/A')}.\n"
                f"Channel: {selected.get('channel', 'N/A')}.\n"
                f"Report ID: {selected.get('id', 'N/A')}."
            ),
            key="case_desc"
        )
        assignee = st.text_input("Assign To (optional)", key="case_assignee")

        if st.button("Create Investigation Case"):
            payload = {
                "title": case_title,
                "description": case_description,
                "status": "Open",
                "assignee": assignee if assignee else None,
                "analyst_notes": f"Linked report ID: {selected.get('id', 'N/A')}",
            }
            data, err = create_case(payload)
            if err:
                st.error(f"Case creation failed: {err}")
            else:
                st.success("Case created successfully")
                st.json(data)

# ===============================
# 📁 CASE MANAGEMENT
# ===============================

with tab3:
    st.subheader("Case Queue")

    if not open_cases:
        st.info("No open cases")
    else:
        for c in open_cases:
            with st.container():
                st.markdown("---")
                st.markdown(f"### Case: {c.get('title', c.get('id', 'Untitled'))}")
                st.markdown(f"**ID:** {c.get('id', 'N/A')}")
                st.markdown(f"**Status:** {c.get('status', 'N/A')}")
                st.markdown(f"**Assignee:** {c.get('assignee', '')}")
                st.markdown(f"**Created At:** {c.get('created_at', '')}")

                if c.get("description"):
                    st.markdown("**Description:**")
                    st.write(c["description"])

                current_notes = c.get("analyst_notes", "") or ""
                notes = st.text_area(
                    "Update Notes",
                    value=current_notes,
                    key=f"notes_{c.get('id')}"
                )

                col1, col2, col3 = st.columns(3)

                with col1:
                    if st.button("Save Notes", key=f"save_{c.get('id')}"):
                        _, err = update_case(c.get("id"), {"analyst_notes": notes})
                        if err:
                            st.error(err)
                        else:
                            st.success("Case notes updated")
                            st.rerun()

                with col2:
                    if st.button("Mark In Progress", key=f"progress_{c.get('id')}"):
                        _, err = update_case(c.get("id"), {"status": "In Progress"})
                        if err:
                            st.error(err)
                        else:
                            st.success("Case updated")
                            st.rerun()

                with col3:
                    if st.button("Close Case", key=f"close_{c.get('id')}"):
                        _, err = update_case(c.get("id"), {"status": "Closed"})
                        if err:
                            st.error(err)
                        else:
                            st.success("Case closed")
                            st.rerun()

# ===============================
# 🔎 LOOKUP
# ===============================

with tab4:
    st.subheader("Number Intelligence Lookup")

    number_input = st.text_input("Enter phone number", key="lookup_number")

    if st.button("Lookup Number"):
        if not number_input.strip():
            st.warning("Enter a phone number")
        else:
            data, err = fetch_lookup(number_input.strip())

            if err:
                st.error(f"Lookup failed: {err}")
            elif isinstance(data, dict):
                if not data.get("found"):
                    st.warning(data.get("message", "No result found"))
                else:
                    st.success("Number found")

                    st.markdown(f"### 📞 {data.get('number', 'N/A')}")

                    c1, c2, c3 = st.columns(3)
                    c1.metric("Risk Level", data.get("risk_level", "N/A"))
                    c2.metric("Reports", data.get("report_count_total", 0))
                    c3.metric("Confidence", f"{data.get('confidence', 0)}%")

                    st.markdown(f"**Label:** {data.get('current_label')}")
                    st.markdown(f"**Trend:** {data.get('trend')}")
                    st.markdown(f"**Last Reported:** {data.get('last_reported_at')}")
                    st.markdown(f"**Tags:** {data.get('tags')}")

                    insights = data.get("insights", [])
                    if insights:
                        st.markdown("### 🧠 Insights")
                        for item in insights:
                            st.write(f"- {item}")

                    actions = data.get("recommended_action", [])
                    if actions:
                        st.markdown("### ⚠️ Recommended Actions")
                        for item in actions:
                            st.write(f"- {item}")

# ===============================
# 🛠️ DEBUG
# ===============================

with tab5:
    st.subheader("Debug API Data")

    st.markdown("### Raw /reports response")
    raw_reports, raw_reports_err = fetch_reports()
    if raw_reports_err:
        st.error(raw_reports_err)
    else:
        st.json(raw_reports)

    st.markdown("### Raw /cases response")
    raw_cases, raw_cases_err = fetch_cases()
    if raw_cases_err:
        st.error(raw_cases_err)
    else:
        st.json(raw_cases)
