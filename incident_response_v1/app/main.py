import streamlit as st
import json
from utils.storage import save_incident

st.title("Incident Response System")

st.subheader("Log a New Incident")

incident_title = st.text_input("Incident Title")
incident_description = st.text_area("Incident Description")

if st.button("Submit Incident"):
    if incident_title.strip() and incident_description.strip():
        save_incident(incident_title, incident_description)
        st.success("Incident saved successfully.")
    else:
        st.warning("Please fill in all fields.")

st.subheader("Logged Incidents")

try:
    with open("data/incidents.json", "r") as f:
        incidents = json.load(f)
        for inc in incidents:
            st.markdown(f"### {inc['title']}")
            st.write(inc["description"])
            st.markdown(f"- **Category:** {inc['category']}")
            st.markdown(f"- **Severity:** {inc['severity']}")
            st.markdown("---")
except FileNotFoundError:
    st.info("No incidents logged yet.")
