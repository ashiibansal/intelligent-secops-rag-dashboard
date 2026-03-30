import json
import streamlit as st

st.set_page_config(page_title="🛡️ Unified Cybersecurity Platform", layout="wide")

import google.generativeai as genai
import pandas as pd
import boto3

from dashboard import render_dashboard
from security_agent.security_agent_page import render_security_agent
from vector_loader import load_vectorstore
from ui_components import (
    inject_unified_ui_css,
    render_top_header,
    render_summary_cards,
    render_workflow_status,
    render_sidebar_context,
)


# ============================================================
# CORE LLM HELPERS
# ============================================================

def gemini_markdown_summary(prompt: str) -> str:
    try:
        if "api_calls_today" not in st.session_state:
            st.session_state.api_calls_today = 0

        # Soft local warning only — do not block the request
        if st.session_state.api_calls_today >= 45:
            st.warning(
                "High local Gemini usage detected in this session. "
                "The app will still try the request if your actual Gemini project quota is available."
            )

        model = genai.GenerativeModel("gemini-2.5-flash")
        response = model.generate_content(prompt)

        st.session_state.api_calls_today += 1
        return response.text.strip()

    except Exception as e:
        err = str(e).lower()
        if "quota" in err or "429" in err or "resource_exhausted" in err:
            return (
                "⚠️ **Gemini quota/rate limit reached** for the currently configured project. "
                "If you changed API keys recently, make sure the new key belongs to a different project "
                "or wait for quota reset."
            )
        if "api_key" in err or "permission" in err or "unauthenticated" in err:
            return "⚠️ **API Key Error**: Please verify your Gemini API key in `.streamlit/secrets.toml`."
        return f"⚠️ **API Error**: Unable to generate response. Error: {str(e)[:160]}..."


def apply_containment_fix():
    """
    Optional demo containment action using AWS EC2.
    If credentials or an instance ID are not configured, falls back to safe demo mode.
    """
    try:
        try:
            aws_cfg = dict(st.secrets["AWS"])
        except Exception:
            aws_cfg = {}

        access_key = aws_cfg.get("ACCESS_KEY_ID")
        secret_key = aws_cfg.get("SECRET_ACCESS_KEY")
        region = aws_cfg.get("REGION", "ap-south-1")
        instance_id = aws_cfg.get("INSTANCE_ID") or aws_cfg.get("DEMO_INSTANCE_ID")

        if access_key and secret_key and instance_id:
            ec2 = boto3.client(
                "ec2",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region,
            )
            ec2.stop_instances(InstanceIds=[instance_id])
            return True, f"✅ Containment action triggered. EC2 instance `{instance_id}` stop request submitted.", "live"

        return True, "✅ Demo mode: no live AWS instance configured, so no EC2 call was made.", "demo"

    except Exception as e:
        return False, f"❌ Failed to apply containment fix: {str(e)}", "error"


# ============================================================
# CSV NORMALIZATION HELPERS
# ============================================================

def normalize_incident_csv_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize likely column aliases from Security Agent / attack CSV exports."""
    df = df.copy()
    df.columns = [str(col).strip() for col in df.columns]

    rename_map = {}
    for col in df.columns:
        clean = col.lower()

        if clean in ["dst port", "dst_port", "destination_port", "destination port"]:
            rename_map[col] = "Dst_Port"
        elif clean in ["attack confidence", "attack_confidence"]:
            rename_map[col] = "Attack_Confidence"
        elif clean in ["attack type", "attack_type"]:
            rename_map[col] = "Attack_Type"
        elif clean in ["src ip", "src_ip", "source_ip", "source ip"]:
            rename_map[col] = "Src_IP"
        elif clean in ["dst ip", "dst_ip", "dest_ip", "destination_ip", "destination ip"]:
            rename_map[col] = "Dst_IP"
        elif clean in ["timestamp", "time_stamp", "time", "date_time", "datetime"]:
            rename_map[col] = "Timestamp"

    if rename_map:
        df = df.rename(columns=rename_map)

    return df


def build_attack_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Build a resilient attack summary depending on which columns are available."""
    agg_dict = {}

    if "Dst_Port" in df.columns:
        agg_dict["Dst_Port"] = lambda x: sorted(set(pd.Series(x).dropna().tolist()))

    if "Attack_Confidence" in df.columns:
        agg_dict["Attack_Confidence"] = lambda x: sorted(set(pd.Series(x).dropna().tolist()))

    if agg_dict:
        return df.groupby("Attack_Type").agg(agg_dict).reset_index()

    return df.groupby("Attack_Type").size().reset_index(name="Count")


def format_attack_summary(attack_summary: pd.DataFrame) -> str:
    """Convert attack summary dataframe into prompt-friendly bullet lines."""
    summary_lines = []

    for _, row in attack_summary.iterrows():
        line = f"- {row['Attack_Type']}"

        if "Dst_Port" in attack_summary.columns:
            line += f": Ports {row['Dst_Port']}"

        if "Attack_Confidence" in attack_summary.columns:
            line += f", Confidence {row['Attack_Confidence']}"

        if "Count" in attack_summary.columns:
            line += f", Count {row['Count']}"

        summary_lines.append(line)

    return "\n".join(summary_lines)


def find_relevant_incidents(attack_types, incident_library):
    """Find exact and fuzzy playbook matches from data.json."""
    matching_incidents = []
    similar_incidents = []

    for attack_type in attack_types:
        attack_type_str = str(attack_type).lower()

        for attack in incident_library:
            library_attack = attack["Attack Type"].lower()

            if library_attack == attack_type_str:
                for incident in attack["Incidents"]:
                    matching_incidents.append({
                        "Attack Type": attack["Attack Type"],
                        "Incident Title": incident["Incident Title"],
                        "Description": incident["Description"],
                        "Containment Steps": incident["Containment Steps"],
                        "Remediation Options": incident["Remediation Options"],
                        "Forensic Steps": incident["Forensic Steps"]
                    })
            elif attack_type_str in library_attack or library_attack in attack_type_str:
                for incident in attack["Incidents"]:
                    similar_incidents.append({
                        "Attack Type": attack["Attack Type"],
                        "Incident Title": incident["Incident Title"],
                        "Description": incident["Description"],
                        "Containment Steps": incident["Containment Steps"],
                        "Remediation Options": incident["Remediation Options"],
                        "Forensic Steps": incident["Forensic Steps"]
                    })

    return matching_incidents + similar_incidents


# ============================================================
# GEMINI API
# ============================================================

try:
    api_key = st.secrets["GEMINI"]["API_KEY"]
    if api_key and api_key != "your-gemini-api-key-here":
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        model.generate_content("Hello")
        api_connected = True
    else:
        api_connected = False
except Exception:
    api_connected = False


# ============================================================
# LOAD DATA
# ============================================================

@st.cache_data
def load_incident_data():
    with open("data.json", "r") as f:
        return json.load(f)


data = load_incident_data()


# ============================================================
# SESSION STATE
# ============================================================

defaults = {
    "incident": None,
    "top_doc": None,
    "chat_history": [],
    "incident_summary": None,
    "incident_metadata": {},
    "incident_query": None,
    "incident_chat_messages": [],
    "uploaded_logs": None,
    "api_calls_today": 0,
    "incident_handoff_ready": False,
    "incident_handoff_source": None,
    "incident_handoff_filename": None,
    "incident_handoff_attack_types": [],
}
for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ============================================================
# GLOBAL UI
# ============================================================

inject_unified_ui_css()

render_top_header(
    title="🛡️ Unified Cybersecurity Platform",
    subtitle="Incident response, threat triage, attack analytics, and detection workflows in one operational surface.",
    chips=[
        "Gemini Assisted",
        "RAG Incident Search",
        "Threat Analytics",
        "Security Agent Ready",
    ],
)


# ============================================================
# SIDEBAR CONTEXT
# ============================================================

with st.sidebar:
    if st.button("🔄 Reset Local Gemini Counter", use_container_width=True):
        st.session_state.api_calls_today = 0
        st.success("Local Gemini counter reset for this session.")

render_sidebar_context("Platform Status", {
    "Gemini API": "Connected" if api_connected else "Unavailable",
    "Local Gemini Count": f"{st.session_state.get('api_calls_today', 0)} calls",
    "Incident Summary": "Ready" if st.session_state.get("incident_summary") else "Not generated",
    "Uploaded CSV": "Present" if st.session_state.get("uploaded_logs") is not None else "None",
})

render_sidebar_context("Current Context", {
    "Incident Query": st.session_state.get("incident_query", "N/A"),
    "Chat Messages": len(st.session_state.get("incident_chat_messages", [])),
    "Incident Library": len(data) if data else 0,
    "Legacy Analytics": "Enabled",
})


# ============================================================
# MAIN APPLICATION TABS
# ============================================================

main_tab1, main_tab2 = st.tabs(
    ["🛡️ Detection & Security Agent", "🤖 Incident Response System"]
)


# ============================================================
# SECURITY AGENT TAB (NOW TAB 1)
# ============================================================

with main_tab1:
    render_security_agent()


# ============================================================
# INCIDENT RESPONSE SYSTEM (NOW TAB 2)
# ============================================================

with main_tab2:
    incident_count = len(data) if data else 0
    has_summary = bool(st.session_state.get("incident_summary"))
    uploaded_csv = "Yes" if st.session_state.get("uploaded_logs") is not None else "No"

    render_summary_cards([
        {
            "label": "Incident Library",
            "value": f"{incident_count}",
            "subtext": "Known incident playbooks available"
        },
        {
            "label": "Analysis State",
            "value": "Active" if has_summary else "Ready",
            "subtext": "Current incident response workflow status"
        },
        {
            "label": "CSV Analytics",
            "value": uploaded_csv,
            "subtext": "Attack CSV loaded for downstream analytics"
        },
        {
            "label": "Assistant Mode",
            "value": "Enabled" if api_connected else "Limited",
            "subtext": "Interactive cybersecurity guidance availability"
        },
    ])

    incident_steps = [
        "Describe / Select Incident",
        "Generate Summary",
        "Review Actions",
        "Ask Assistant",
        "Export / Escalate"
    ]

    incident_current_step = 0
    if st.session_state.get("incident_query") or st.session_state.get("uploaded_logs") is not None:
        incident_current_step = 1
    if st.session_state.get("incident_summary"):
        incident_current_step = 2
    if st.session_state.get("incident_chat_messages"):
        incident_current_step = 3

    render_workflow_status(
        title="Incident Response Workflow",
        steps=incident_steps,
        current_step=incident_current_step
    )

    if st.session_state.get("incident_handoff_ready"):
        handoff_source = st.session_state.get("incident_handoff_source", "Unknown")
        handoff_file = st.session_state.get("incident_handoff_filename", "Unknown file")
        handoff_types = st.session_state.get("incident_handoff_attack_types", [])

        st.success(f"✅ Handoff received from {handoff_source}: {handoff_file}")

        if handoff_types:
            st.info(f"Detected attack types: {', '.join(handoff_types)}")

        if st.button("🧹 Clear Security Agent Handoff", key="clear_ir_handoff"):
            for key in [
                "incident_handoff_ready",
                "incident_handoff_source",
                "incident_handoff_filename",
                "incident_handoff_attack_types",
            ]:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()

    TABS = ["General Purpose Use", "Ticket Raised Post Identification", "Legacy Analytics"]
    tab1, tab2, tab3 = st.tabs(TABS)

    # --------------------------------------------------------
    # TAB 1: GENERAL PURPOSE USE
    # --------------------------------------------------------
    with tab1:
        st.markdown('<div class="section-shell">', unsafe_allow_html=True)
        st.subheader("General Purpose Use")
        st.markdown("Describe what you noticed, such as a fake pop-up, a slow system, or an unknown device on Wi-Fi.")
        query = st.text_input("Incident Description:", key="general_query")

        if query:
            with st.spinner("🔍 Searching incidents..."):
                vs = load_vectorstore()
                results = vs.similarity_search_with_score(query, k=1)

            if results and results[0][1] > 0.65:
                top_doc, score = results[0]
                st.session_state.top_doc = top_doc

                metadata = top_doc.metadata
                attack_type = metadata.get("attack_type", "Unknown")

                gemini_prompt = f"""
You are a cybersecurity incident response assistant.

A user reported:
"{query}"

STEP 1 — Check relevance:
If this is NOT a cybersecurity issue, respond ONLY:
"This does not appear to be a cybersecurity issue. Please describe unusual system or network behavior."

STEP 2 — If it IS a cybersecurity issue, respond in this EXACT format:

## ✅ Attack Identified
**{attack_type}**

## 🧠 What Happened (Simple Explanation)
Explain in 2–3 short sentences using simple language.

## 🚨 Immediate Containment Steps
Provide 4–6 numbered steps.
Each step must:
• Start with a strong action verb
• Be one line only
• Be practical and specific

## 🛠️ Remediation (Fix & Prevention)
Provide 4–6 numbered steps.
Keep steps short and implementation-focused.

## 🔍 Forensic Investigation
Provide 3–5 numbered steps for evidence collection and analysis.

IMPORTANT FORMATTING RULES:
• Use bullet points or numbered lists ONLY
• NO long paragraphs
• NO technical jargon without explanation
• Make it easy for junior IT staff to follow
• Keep response concise and structured
"""
                with st.spinner("🧠 Gemini analyzing and formatting..."):
                    summary = gemini_markdown_summary(gemini_prompt)

                st.success(f"✅ Attack Type: **{attack_type}**")
                st.markdown("### 📋 Gemini Incident Summary")
                st.markdown(summary)

                st.session_state.incident = {
                    "query": query,
                    "content": summary,
                    "metadata": {"attack_type": attack_type}
                }
                st.session_state.incident_summary = summary
                st.session_state.incident_metadata = metadata
                st.session_state.incident_query = query

            else:
                st.warning("❗ No relevant incident could be identified. Please describe the issue in more technical or detailed terms.")
        st.markdown('</div>', unsafe_allow_html=True)

    # --------------------------------------------------------
    # TAB 2: TICKET RAISED POST IDENTIFICATION
    # --------------------------------------------------------
    with tab2:
        st.markdown('<div class="section-shell">', unsafe_allow_html=True)
        st.subheader("Ticket Raised Post Identification")
        st.markdown("Select from known incidents or upload a network attack CSV for playbook generation and analytics.")

        uploaded_file = st.file_uploader(
            "Upload a network attack CSV for analysis",
            type=["csv"],
            key="ticket_csv"
        )

        attack_summary_str = ""
        csv_ready = False
        df = None
        attack_summary = None

        if st.session_state.get("incident_handoff_ready") and st.session_state.get("uploaded_logs") is not None:
            df = st.session_state.uploaded_logs.copy()
            df = normalize_incident_csv_columns(df)
            csv_ready = "Attack_Type" in df.columns

            st.info("📨 Using analysis sent from Security Agent.")

            preview_cols = st.columns(4)
            with preview_cols[0]:
                st.metric("Rows Loaded", len(df))
            with preview_cols[1]:
                st.metric("Columns Detected", len(df.columns))
            with preview_cols[2]:
                st.metric("Analysis Mode", "Security Agent Handoff")
            with preview_cols[3]:
                st.metric("Attack Type Column", "Found" if "Attack_Type" in df.columns else "Missing")

            with st.expander("📋 Handoff CSV Columns", expanded=False):
                st.write(list(df.columns))

            if not csv_ready:
                st.error("❌ Security Agent handoff does not contain an `Attack_Type` column.")
                st.info("Please re-run attack classification in the Security Agent and send the results again.")

        elif uploaded_file:
            df = pd.read_csv(uploaded_file)
            df = normalize_incident_csv_columns(df)
            st.session_state.uploaded_logs = df

            preview_cols = st.columns(4)
            with preview_cols[0]:
                st.metric("Rows Uploaded", len(df))
            with preview_cols[1]:
                st.metric("Columns Detected", len(df.columns))
            with preview_cols[2]:
                st.metric("Analysis Mode", "CSV Triage")
            with preview_cols[3]:
                st.metric("Attack Type Column", "Found" if "Attack_Type" in df.columns else "Missing")

            with st.expander("📋 Detected CSV Columns", expanded=False):
                st.write(list(df.columns))

            if "Attack_Type" not in df.columns:
                st.error("❌ Uploaded CSV must contain an `Attack_Type` column for this workflow.")
                st.info("Use the Security Agent download labelled **Incident Response Ready CSV** or upload a file that includes attack classifications.")
            else:
                csv_ready = True

        if csv_ready and df is not None:
            attack_summary = build_attack_summary(df)
            attack_summary_str = format_attack_summary(attack_summary)

            st.markdown("### 🧾 Detected attack summary")
            st.dataframe(attack_summary, use_container_width=True)

            if attack_summary_str:
                all_relevant_incidents = find_relevant_incidents(
                    attack_summary["Attack_Type"].astype(str).tolist(),
                    data
                )

                if all_relevant_incidents:
                    attack_types_found = list(set([incident["Attack Type"] for incident in all_relevant_incidents]))

                    ports_found = []
                    if "Dst_Port" in attack_summary.columns:
                        for _, row in attack_summary.iterrows():
                            ports_found.extend(row["Dst_Port"])
                        ports_found = list(set(ports_found))

                    detailed_prompt = f"""
You are a cybersecurity assistant. Analyze these detected network attacks and provide comprehensive recommendations.

DETECTED ATTACKS:
{attack_summary_str}

ATTACK TYPES FOUND: {', '.join(attack_types_found)}
PORTS INVOLVED: {', '.join(map(str, ports_found)) if ports_found else 'Not available in uploaded CSV'}

RELEVANT INCIDENT PLAYBOOKS:
"""

                    for incident in all_relevant_incidents:
                        detailed_prompt += f"""
**{incident['Attack Type']} - {incident['Incident Title']}**
Description: {incident['Description']}
Containment: {incident['Containment Steps']}
Remediation: {incident['Remediation Options']}
Forensic: {incident['Forensic Steps']}
"""

                    detailed_prompt += """

Create a CLEAR, ACTIONABLE INCIDENT RESPONSE PLAN.

## 🚨 Immediate Containment
Provide 5–8 numbered steps.
Each step must be one short action line.
Focus on stopping active threats immediately.

## 🛠️ Remediation Plan
Provide 5–8 numbered steps.
Focus on fixing vulnerabilities and preventing recurrence.

## 🔍 Forensic Investigation
Provide 4–6 numbered steps.
Focus on log analysis, traffic inspection, and evidence preservation.

RESPONSE FORMAT RULES:
• ONLY numbered steps
• One action per line
• Start each step with a strong action verb
• NO long paragraphs
• NO unnecessary theory
• Use simple professional language
• Make it look like a SOC runbook
• Use emojis in section headers
"""

                    with st.status("🧠 Analyzing attacks with playbook data...", expanded=True) as status:
                        summary = gemini_markdown_summary(detailed_prompt)
                        status.update(label="✅ Analysis complete!", state="complete")

                    st.markdown("### 🧾 Tailored Fix Summary")
                    st.markdown(summary)

                    st.session_state.incident = {
                        "query": f"CSV Analysis: {', '.join(attack_summary['Attack_Type'].astype(str).tolist())}",
                        "content": summary,
                        "metadata": {"attack_types": attack_summary["Attack_Type"].astype(str).tolist()}
                    }
                    st.session_state.incident_summary = summary
                    st.session_state.incident_metadata = {
                        "uploaded_csv": True,
                        "columns": list(df.columns),
                        "has_dst_port": "Dst_Port" in df.columns,
                        "handoff_used": st.session_state.get("incident_handoff_ready", False),
                    }
                    st.session_state.incident_query = f"CSV Analysis: {', '.join(attack_summary['Attack_Type'].astype(str).tolist())}"

                else:
                    detailed_prompt = f"""
You are a cybersecurity incident response assistant.

Analyze this detected network attack data:

{attack_summary_str}

No exact incident playbooks were found. Generate a PROFESSIONAL INCIDENT RESPONSE PLAN.

## 🚨 Immediate Containment
Provide 5–8 numbered steps to stop active threats.

## 🛠️ Remediation Plan
Provide 5–8 numbered steps to prevent future attacks.

## 🔍 Forensic Investigation
Provide 4–6 numbered steps for evidence collection and analysis.

RESPONSE FORMAT RULES:
• ONLY numbered steps
• One action per line
• Start each step with a strong action verb
• NO long paragraphs
• Keep instructions concise and practical
• Use professional SOC language
• Use emojis in headers
"""

                    with st.status("🧠 Generating comprehensive recommendations...", expanded=True) as status:
                        summary = gemini_markdown_summary(detailed_prompt)
                        status.update(label="✅ Recommendations ready!", state="complete")

                    st.markdown("### 🧾 Generated Fix Summary")
                    st.markdown(summary)

                    st.session_state.incident = {
                        "query": f"CSV Analysis: {', '.join(attack_summary['Attack_Type'].astype(str).tolist())}",
                        "content": summary,
                        "metadata": {"attack_types": attack_summary["Attack_Type"].astype(str).tolist()}
                    }
                    st.session_state.incident_summary = summary
                    st.session_state.incident_metadata = {
                        "uploaded_csv": True,
                        "columns": list(df.columns),
                        "has_dst_port": "Dst_Port" in df.columns,
                        "handoff_used": st.session_state.get("incident_handoff_ready", False),
                    }
                    st.session_state.incident_query = f"CSV Analysis: {', '.join(attack_summary['Attack_Type'].astype(str).tolist())}"

                    st.markdown("---")
                    st.markdown("### 🛠️ Apply Containment Fix")
                    if st.button("🚨 Apply Fix (Stop EC2 Instance)", key="apply_fix_csv_no_match", type="primary"):
                        success, message, state = apply_containment_fix()
                        if success:
                            st.success(message)
                            st.info("📋 Ticket raised for remediation by Level 2 Engineer")
                            st.markdown("**Containment Actions Applied:**")
                            st.markdown("- ✅ Isolated affected EC2 instance")
                            st.markdown("- ✅ Stopped malicious traffic")
                            st.markdown("- ✅ Preserved evidence for forensics")
                        else:
                            st.error(message)

        if not uploaded_file and not st.session_state.get("incident_handoff_ready"):
            st.markdown("---")
            st.markdown("### Or select an incident manually:")

        incident_mapping = []
        for attack in data:
            for incident in attack["Incidents"]:
                incident_mapping.append({
                    "Attack Type": attack["Attack Type"],
                    "Incident Title": incident["Incident Title"],
                    "Description": incident["Description"],
                    "Containment Steps": incident["Containment Steps"],
                    "Remediation Options": incident["Remediation Options"],
                    "Forensic Steps": incident["Forensic Steps"]
                })

        incident_titles = [item["Incident Title"] for item in incident_mapping]
        incident_titles_with_placeholder = ["Select an incident..."] + incident_titles
        selected_title = st.selectbox("Select an incident:", incident_titles_with_placeholder, key="ticket_incident_select")

        if selected_title and selected_title != "Select an incident...":
            selected_incident = next(item for item in incident_mapping if item["Incident Title"] == selected_title)

            prompt = f"""
You are a cybersecurity incident response expert.

Analyze the incident below and produce an ACTION PLAYBOOK.

Incident: {selected_incident['Incident Title']}
Description: {selected_incident['Description']}

## 🚨 Containment Actions
Provide 5–7 numbered steps to immediately stop the threat.

## 🛠️ Remediation Actions
Provide 5–7 numbered steps to fix vulnerabilities and prevent recurrence.

## 🔍 Forensic Actions
Provide 4–6 numbered steps to investigate the incident.

FORMATTING RULES:
• Numbered steps only
• One step per line
• Start each step with an action verb
• Keep instructions concise and practical
• No long paragraphs
• Make steps easy for security teams to execute
"""

            if st.button("Generate Summary", key="generate_summary_btn"):
                with st.status("🧠 Generating comprehensive summary...", expanded=True) as status:
                    summary = gemini_markdown_summary(prompt)
                    status.update(label="✅ Summary generated!", state="complete")

                st.markdown("### 🧾 Fix Summary")
                st.markdown(summary)

                st.session_state.incident = {
                    "query": selected_incident["Incident Title"],
                    "content": summary,
                    "metadata": {}
                }
                st.session_state.incident_summary = summary
                st.session_state.incident_metadata = selected_incident
                st.session_state.incident_query = selected_incident["Incident Title"]

        if st.session_state.get("incident_summary"):
            st.markdown("---")
            st.markdown("## 🤖 Cybersecurity Assistant")

            analysis_context = f"""
            Incident Analysis Summary:
            - Query: {st.session_state.get("incident_query", "N/A")}
            - Summary: {st.session_state.get("incident_summary", "N/A")[:500]}...
            - Metadata: {st.session_state.get("incident_metadata", {})}
            """

            st.markdown("""
            <style>
            .chat-container {
                max-height: 400px;
                overflow-y: auto;
                padding: 16px;
                border: 1px solid #e0e6ed;
                border-radius: 8px;
                background-color: #ffffff;
                margin-bottom: 16px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .user-bubble {
                background-color: #0084ff;
                color: white;
                padding: 8px 12px;
                border-radius: 16px 16px 4px 16px;
                margin: 4px 0 4px 30%;
                max-width: 70%;
                word-wrap: break-word;
                float: right;
                clear: both;
                font-size: 14px;
            }
            .bot-bubble {
                background-color: #f1f3f4;
                color: #1c1e21;
                padding: 8px 12px;
                border-radius: 16px 16px 16px 4px;
                margin: 4px 30% 4px 0;
                max-width: 70%;
                word-wrap: break-word;
                float: left;
                clear: both;
                font-size: 14px;
                border: 1px solid #e4e6ea;
            }
            .welcome-bubble {
                background-color: #e7f3ff;
                color: #1565c0;
                padding: 12px 16px;
                border-radius: 8px;
                margin: 8px 0 12px 0;
                border-left: 3px solid #0084ff;
                font-size: 14px;
            }
            .clearfix::after {
                content: "";
                display: table;
                clear: both;
            }
            .chat-input-container {
                position: relative;
                margin-top: 12px;
            }
            .chat-input-container .stTextInput > div > div > input {
                padding-right: 40px;
                border-radius: 20px;
                border: 1px solid #e4e6ea;
            }
            </style>
            """, unsafe_allow_html=True)

            st.markdown('<div class="chat-container">', unsafe_allow_html=True)

            welcome_msg = """
            <div class="welcome-bubble">
                <strong>🤖 Cybersecurity Assistant</strong><br>
                I can help you understand your incident analysis, explain attack types, and suggest security measures.
            </div>
            """
            st.markdown(welcome_msg, unsafe_allow_html=True)

            for message in st.session_state.incident_chat_messages:
                if message["role"] == "user":
                    st.markdown(
                        f'<div class="user-bubble">🧑 <strong>You:</strong><br>{message["content"]}</div><div class="clearfix"></div>',
                        unsafe_allow_html=True
                    )
                else:
                    st.markdown(
                        f'<div class="bot-bubble">🤖 <strong>Assistant:</strong><br>{message["content"]}</div><div class="clearfix"></div>',
                        unsafe_allow_html=True
                    )

            st.markdown("</div>", unsafe_allow_html=True)
            st.markdown('<div class="chat-input-container">', unsafe_allow_html=True)

            col1, col2 = st.columns([5, 1])
            with col1:
                with st.form(key="incident_chat_form", clear_on_submit=True):
                    user_input = st.text_input("Message", placeholder="Ask about cybersecurity...", label_visibility="collapsed")
                    send_btn = st.form_submit_button("Send", use_container_width=True)

            with col2:
                if st.button("🧹 Clear", use_container_width=True, key="incident_clear_btn"):
                    st.session_state.incident_chat_messages = []
                    st.rerun()

            st.markdown("</div>", unsafe_allow_html=True)

            if send_btn and user_input:
                st.session_state.incident_chat_messages.append({"role": "user", "content": user_input})

                cybersecurity_keywords = [
                    "attack", "threat", "security", "anomaly", "malicious", "intrusion",
                    "vulnerability", "exploit", "malware", "breach", "network", "traffic",
                    "ddos", "dos", "sql injection", "brute force", "botnet", "infiltration",
                    "analysis", "detection", "classification", "confidence", "risk",
                    "suspicious", "benign", "mitigation", "defense", "protection",
                    "firewall", "ips", "ids", "siem", "incident", "response", "containment",
                    "remediation", "forensic", "port", "block", "isolate"
                ]

                is_cybersecurity = any(keyword in user_input.lower() for keyword in cybersecurity_keywords)

                if not is_cybersecurity:
                    response = "🚫 I can only help with cybersecurity-related questions about your incident analysis. Please ask about security, attacks, containment, remediation, or the analysis results."
                else:
                    try:
                        system_prompt = """You are a cybersecurity expert assistant analyzing incident data.
                        You MUST only answer questions related to cybersecurity, incident response, threat analysis, and the provided analysis results.
                        Keep responses concise, professional, and actionable."""

                        user_prompt = f"""
                        {system_prompt}

                        Current Incident Analysis Results:
                        {analysis_context}

                        User Question: {user_input}

                        Please provide a cybersecurity-focused response based on the analysis results above.
                        """

                        gemini = genai.GenerativeModel("gemini-1.5-flash")
                        response = gemini.generate_content(user_prompt).text

                    except Exception as e:
                        response = f"⚠️ Sorry, I encountered an error: {str(e)}. Please try rephrasing your cybersecurity question."

                st.session_state.incident_chat_messages.append({"role": "bot", "content": response})

                if len(st.session_state.incident_chat_messages) > 20:
                    st.session_state.incident_chat_messages = st.session_state.incident_chat_messages[-20:]

                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    # --------------------------------------------------------
    # TAB 3: LEGACY ANALYTICS
    # --------------------------------------------------------
    with tab3:
        st.markdown('<div class="section-shell">', unsafe_allow_html=True)
        st.subheader("Legacy Analytics")
        st.markdown("Quick visualisation of uploaded network-attack CSVs from the ticket workflow.")

        if st.session_state.get("uploaded_logs") is not None:
            if st.session_state.get("incident_handoff_ready"):
                st.success("✅ Using Security Agent handoff data")
            else:
                st.success("✅ Using uploaded CSV from the Ticket Raised Post Identification tab")

            render_dashboard(st.session_state.uploaded_logs)
        else:
            st.info("Upload a network attack CSV in 'Ticket Raised Post Identification' or send one from the Security Agent to view analytics here.")
        st.markdown('</div>', unsafe_allow_html=True)