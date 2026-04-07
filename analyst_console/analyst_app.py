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


def fetch_cases(status=None):
    if status:
        data, err = safe_get_json(
            f"{api_base}/cases",
            params={"status": status}
        )
    else:
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
        "reporter_fingerprint": r.get("reporter_fingerprint", ""),
    }


def normalize_case_row(c):
    return {
        "id": c.get("id", ""),
        "title": c.get("title", "Untitled"),
        "description": c.get("description", ""),
        "status": c.get("status", "Unknown"),
        "assignee": c.get("assignee", ""),
        "analyst_notes": c.get("analyst_notes", ""),
        "created_at": c.get("created_at", ""),
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
rejected_reports, rejected_err = fetch_reports("Rejected")

open_cases, open_cases_err = fetch_cases("Open")
in_progress_cases, in_progress_cases_err = fetch_cases("In Progress")
closed_cases, closed_cases_err = fetch_cases("Closed")

all_reports = [normalize_report_row(r) for r in all_reports]
pending_reports = [normalize_report_row(r) for r in pending_reports]
approved_reports = [normalize_report_row(r) for r in approved_reports]
rejected_reports = [normalize_report_row(r) for r in rejected_reports]

open_cases = [normalize_case_row(c) for c in open_cases]
in_progress_cases = [normalize_case_row(c) for c in in_progress_cases]
closed_cases = [normalize_case_row(c) for c in closed_cases]

all_cases = open_cases + in_progress_cases + closed_cases

# ---------------- DASHBOARD METRICS ----------------

st.subheader("📊 SOC Overview")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Reports", len(all_reports))
m2.metric("Pending Reports", len(pending_reports))
m3.metric("Approved Reports", len(approved_reports))
m4.metric("Rejected Reports", len(rejected_reports))

m5, m6, m7 = st.columns(3)
m5.metric("Open Cases", len(open_cases))
m6.metric("In Progress Cases", len(in_progress_cases))
m7.metric("Closed Cases", len(closed_cases))

if reports_err:
    st.warning(f"Reports endpoint issue: {reports_err}")
if pending_err:
    st.warning(f"Pending reports endpoint issue: {pending_err}")
if approved_err:
    st.warning(f"Approved reports endpoint issue: {approved_err}")
if rejected_err:
    st.warning(f"Rejected reports endpoint issue: {rejected_err}")
if open_cases_err:
    st.warning(f"Open cases endpoint issue: {open_cases_err}")
if in_progress_cases_err:
    st.warning(f"In Progress cases endpoint issue: {in_progress_cases_err}")
if closed_cases_err:
    st.warning(f"Closed cases endpoint issue: {closed_cases_err}")

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

        c1, c2 = st.columns(2)
        with c1:
            reason_filter = st.selectbox("Filter by Reason", ["All"] + reason_options)
        with c2:
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

    case_status_filter = st.selectbox(
        "Filter Cases by Status",
        ["All", "Open", "In Progress", "Closed"]
    )

    if case_status_filter == "All":
        cases_to_show = all_cases
    elif case_status_filter == "Open":
        cases_to_show = open_cases
    elif case_status_filter == "In Progress":
        cases_to_show = in_progress_cases
    else:
        cases_to_show = closed_cases

    if not cases_to_show:
        st.info("No cases found for this status")
    else:
        case_rows = []
        for c in cases_to_show:
            case_rows.append({
                "ID": c.get("id"),
                "Title": c.get("title"),
                "Status": c.get("status"),
                "Assignee": c.get("assignee"),
                "Created At": c.get("created_at"),
            })

        st.dataframe(pd.DataFrame(case_rows), use_container_width=True)

        st.markdown("### Case Details")

        selected_case = st.selectbox(
            "Select Case",
            cases_to_show,
            format_func=lambda x: f"{x.get('title', 'Untitled')} | {x.get('status', 'Unknown')}"
        )

        st.markdown(f"**ID:** {selected_case.get('id', 'N/A')}")
        st.markdown(f"**Title:** {selected_case.get('title', 'Untitled')}")
        st.markdown(f"**Status:** {selected_case.get('status', 'Unknown')}")
        st.markdown(f"**Assignee:** {selected_case.get('assignee', '')}")
        st.markdown(f"**Created At:** {selected_case.get('created_at', '')}")

        if selected_case.get("description"):
            st.markdown("**Description:**")
            st.write(selected_case["description"])

        current_notes = selected_case.get("analyst_notes", "") or ""
        updated_assignee = st.text_input(
            "Assignee",
            value=selected_case.get("assignee", "") or "",
            key=f"assignee_{selected_case.get('id')}"
        )
        notes = st.text_area(
            "Analyst Notes",
            value=current_notes,
            key=f"notes_{selected_case.get('id')}"
        )

        c1, c2, c3, c4 = st.columns(4)

        with c1:
            if st.button("Save Notes", key=f"save_{selected_case.get('id')}"):
                _, err = update_case(
                    selected_case.get("id"),
                    {"analyst_notes": notes, "assignee": updated_assignee}
                )
                if err:
                    st.error(err)
                else:
                    st.success("Case updated")
                    st.rerun()

        with c2:
            if st.button("Mark Open", key=f"open_{selected_case.get('id')}"):
                _, err = update_case(
                    selected_case.get("id"),
                    {"status": "Open", "assignee": updated_assignee, "analyst_notes": notes}
                )
                if err:
                    st.error(err)
                else:
                    st.success("Case marked Open")
                    st.rerun()

        with c3:
            if st.button("Mark In Progress", key=f"progress_{selected_case.get('id')}"):
                _, err = update_case(
                    selected_case.get("id"),
                    {"status": "In Progress", "assignee": updated_assignee, "analyst_notes": notes}
                )
                if err:
                    st.error(err)
                else:
                    st.success("Case marked In Progress")
                    st.rerun()

        with c4:
            if st.button("Close Case", key=f"close_{selected_case.get('id')}"):
                _, err = update_case(
                    selected_case.get("id"),
                    {"status": "Closed", "assignee": updated_assignee, "analyst_notes": notes}
                )
                if err:
                    st.error(err)
                else:
                    st.success("Case marked Closed")
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

    st.markdown("### Raw /admin/reports?status=Pending response")
    raw_pending, raw_pending_err = fetch_reports("Pending")
    if raw_pending_err:
        st.error(raw_pending_err)
    else:
        st.json(raw_pending)

    st.markdown("### Raw /admin/reports?status=Approved response")
    raw_approved, raw_approved_err = fetch_reports("Approved")
    if raw_approved_err:
        st.error(raw_approved_err)
    else:
        st.json(raw_approved)

    st.markdown("### Raw /admin/reports?status=Rejected response")
    raw_rejected, raw_rejected_err = fetch_reports("Rejected")
    if raw_rejected_err:
        st.error(raw_rejected_err)
    else:
        st.json(raw_rejected)

    st.markdown("### Raw Open Cases")
    raw_open_cases, raw_open_cases_err = fetch_cases("Open")
    if raw_open_cases_err:
        st.error(raw_open_cases_err)
    else:
        st.json(raw_open_cases)

    st.markdown("### Raw In Progress Cases")
    raw_in_progress_cases, raw_in_progress_cases_err = fetch_cases("In Progress")
    if raw_in_progress_cases_err:
        st.error(raw_in_progress_cases_err)
    else:
        st.json(raw_in_progress_cases)

    st.markdown("### Raw Closed Cases")
    raw_closed_cases, raw_closed_cases_err = fetch_cases("Closed")
    if raw_closed_cases_err:
        st.error(raw_closed_cases_err)
    else:
        st.json(raw_closed_cases)
