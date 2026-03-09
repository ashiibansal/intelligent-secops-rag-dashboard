import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import json
from utils.llm_engine import generate_incident_explanation
from utils.storage import save_incident
from utils.vector_loader import load_vectorstore
from utils.retriever import retrieve_top_incident

st.set_page_config(page_title="Incident Response System", layout="centered")
st.title("🛡️ Incident Response System")

# --------------------------------------------------
# SECTION 1: Log a New Incident (UNCHANGED)
# --------------------------------------------------
st.subheader("Log a New Incident")

incident_title = st.text_input("Incident Title")
incident_description = st.text_area("Incident Description")

if st.button("Submit Incident"):
    if incident_title.strip() and incident_description.strip():
        save_incident(incident_title, incident_description)
        st.success("✅ Incident saved successfully.")
    else:
        st.warning("⚠️ Please fill in all fields.")

# --------------------------------------------------
# SECTION 2: Semantic Incident Lookup (NEW - WEEK 4)
# --------------------------------------------------
st.subheader("🔍 Check for Similar Past Incidents")

query = st.text_input(
    "Describe the incident to search historical incidents",
    placeholder="e.g. multiple failed login attempts from same IP"
)

if query:
    with st.spinner("Searching similar incidents using semantic retrieval..."):
        try:
            vectorstore = load_vectorstore()
            top_doc, score = retrieve_top_incident(vectorstore, query)

            if top_doc and score > 0.65:
                st.success("✅ Similar Incident Found")
                # Show retrieved reference (grounding)
                st.markdown("### 📌 Retrieved Reference Incident")
                st.markdown(f"**Attack Type:** {top_doc.metadata.get('attack_type', 'Unknown')}")
                st.markdown(f"**Incident Title:** {top_doc.metadata.get('incident_title', 'N/A')}")
                st.caption(f"Similarity Score: {round(score, 3)}")

                #---------- NEW: AI ANALYSIS ----------
                st.markdown("### 🧠 AI Incident Analysis")

                with st.spinner("Generating explanation using AI..."):
                    explanation = generate_incident_explanation(query, top_doc)

                st.markdown(explanation)
            else:
                st.info("ℹ️ No closely matching incident found.")
        except Exception as e:
            st.error(f"Vector search failed: {str(e)}")

# --------------------------------------------------
# SECTION 3: View Logged Incidents (UNCHANGED)
# --------------------------------------------------
st.subheader("📂 Logged Incidents")

try:
    with open("data/incidents.json", "r") as f:
        incidents = json.load(f)

        if not incidents:
            st.info("No incidents logged yet.")
        else:
            for inc in incidents:
                st.markdown(f"### {inc['title']}")
                st.write(inc["description"])
                st.markdown(f"- **Category:** {inc.get('category', 'Uncategorized')}")
                st.markdown(f"- **Severity:** {inc.get('severity', 'Unknown')}")
                st.markdown("---")

except FileNotFoundError:
    st.info("No incidents logged yet.")
