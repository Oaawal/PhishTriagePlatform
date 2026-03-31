import requests
import pandas as pd
import streamlit as st

API_BASE = st.sidebar.text_input("API Base URL", "http://127.0.0.1:8000").rstrip("/")

st.title("PhishTriage Analyst Console")
st.caption("Case Queue: Open → InReview → Closed")

status = st.sidebar.selectbox("Status", ["Open", "InReview", "Closed"])
refresh = st.sidebar.button("Refresh")

def get_cases():
    r = requests.get(f"{API_BASE}/cases", params={"status": status}, timeout=10)
    r.raise_for_status()
    return r.json()

try:
    cases = get_cases()
except Exception as e:
    st.error(f"Could not fetch cases: {e}")
    st.stop()

df = pd.DataFrame(cases)
if df.empty:
    st.info("No cases found for this status.")
    st.stop()

st.subheader("Cases")
st.dataframe(df[["created_at","id","risk","category","source","urls","sensitive_requested","otp_masked"]], use_container_width=True)

case_id = st.selectbox("Select Case ID", df["id"].tolist())
selected = df[df["id"] == case_id].iloc[0].to_dict()

st.subheader("Case Detail")
st.write("**Sanitized message:**")
st.code(selected.get("sanitized_message", ""))

st.write("**IOCs:**")
st.write(f"- URLs: {selected.get('urls','')}")
st.write(f"- Phones: {selected.get('phones','')}")
st.write(f"- Accounts: {selected.get('accounts','')}")

st.divider()
st.subheader("Update Case")

new_status = st.selectbox("New status", ["Open","InReview","Closed"], index=["Open","InReview","Closed"].index(selected.get("status","Open")))
assignee = st.text_input("Assignee", value=selected.get("assignee") or "")
notes = st.text_area("Analyst notes", value=selected.get("analyst_notes") or "", height=120)

if st.button("Save Update", type="primary"):
    r = requests.patch(
        f"{API_BASE}/cases/{case_id}",
        params={"status": new_status, "assignee": assignee, "analyst_notes": notes},
        timeout=10,
    )
    if r.status_code == 200:
        st.success("Updated successfully. Refresh to see changes.")
    else:
        st.error(f"Update failed: {r.status_code} {r.text}")