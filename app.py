import os
import json
import streamlit as st
st.set_page_config(page_title="🛡️ Smart SecApp", layout="centered")
from vector_loader import load_vectorstore
from rag_answerer import (
    rank_remediation_steps,
    generate_fix_steps,
    gemini_answer_question
)
import google.generativeai as genai
import pandas as pd
import boto3


def gemini_markdown_summary(prompt):
    try:
        # Track API calls
        if 'api_calls_today' not in st.session_state:
            st.session_state.api_calls_today = 0
        
        # Check quota before making call
        if st.session_state.api_calls_today >= 45:  # Leave buffer
            return "⚠️ **API Quota Warning**: Approaching daily limit. Please upgrade your plan or try again tomorrow."
        
        model = genai.GenerativeModel("gemini-2.5-flash")
        response = model.generate_content(prompt)
        
        # Increment call counter
        st.session_state.api_calls_today += 1
        
        return response.text.strip()
    except Exception as e:
        if "quota" in str(e).lower() or "429" in str(e):
            return "⚠️ **API Quota Exceeded**: You've reached your daily limit for Gemini API requests. Please try again tomorrow or upgrade your plan."
        elif "api_key" in str(e).lower():
            return "⚠️ **API Key Error**: Please check your Gemini API key in the secrets configuration."
        else:
            return f"⚠️ **API Error**: Unable to generate response. Error: {str(e)[:100]}..."

# Gemini API
try:
    api_key = st.secrets["GEMINI"]["API_KEY"]
    if api_key and api_key != "your-gemini-api-key-here":
        genai.configure(api_key=api_key)
        # Test the API key with a simple call
        model = genai.GenerativeModel("gemini-2.5-flash")
        test_response = model.generate_content("Hello")
        api_connected = True
        st.sidebar.success("✅ Gemini API: Connected and Working")
    else:
        api_connected = False
        st.sidebar.error("❌ Gemini API: Invalid API Key")
except Exception as e:
    api_connected = False
    st.sidebar.error(f"❌ Gemini API: Error - {str(e)[:50]}...")

# Sidebar API status
with st.sidebar:
    st.markdown("## API Status")
    if api_connected:
        # Add quota monitoring
        if 'api_calls_today' not in st.session_state:
            st.session_state.api_calls_today = 0
        st.info(f"API Calls Today: {st.session_state.api_calls_today}/50 (Free Tier)")
    else:
        # Status already shown above
        pass

st.title("🛡️ Smart Cybersecurity Assistant")

# Load data
@st.cache_data
def load_incident_data():
    with open("data.json", "r") as f:
        return json.load(f)

data = load_incident_data()

# Session state
if 'incident' not in st.session_state:
    st.session_state.incident = None
if 'top_doc' not in st.session_state:
    st.session_state.top_doc = None
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

# Tabs for the two main flows
TABS = ["General Purpose Use", "Ticket Raised Post Identification"]
tab1, tab2 = st.tabs(TABS)

# --------------------------------------------------------
# TAB 1: GENERAL PURPOSE USE ("I Don't Know What Happened")
# --------------------------------------------------------
with tab1:
    st.header("General Purpose Use")
    st.markdown("Describe what you noticed (e.g., fake pop-up, slow system, unknown device on Wi-Fi):")
    query = st.text_input("Incident Description:", key="general_query")

    if query:
        with st.spinner("🔍 Searching incidents..."):
            vs = load_vectorstore()
            results = vs.similarity_search_with_score(query, k=1)

        if results and results[0][1] > 0.65:  # Score threshold
            top_doc, score = results[0]
            st.session_state.top_doc = top_doc

            metadata = top_doc.metadata
            attack_type = metadata.get("attack_type", "Unknown")
            containment = metadata.get("containment", "")
            remediation = metadata.get("remediation", "")
            forensic = metadata.get("forensic", "")

            gemini_prompt = f"""
You are a cybersecurity assistant.

A user described the following: "{query}"

First, evaluate whether this is a relevant cybersecurity incident.

If it is **not** a security-related description (e.g., "I like burgers", "My cat is cute", etc.), respond with:

"This does not appear to be a cybersecurity issue. Please describe something unusual on your system or network."

If it **is** a valid issue, respond with:

✅ Identified Attack Type: **{attack_type}**

### 🧠 What Likely Happened
Explain in simple terms.

### 🛑 Containment Steps
{containment}

### 🔧 Remediation Options
{remediation}

### 🔍 Forensic Steps
{forensic}

Respond in clear Markdown.
"""

            with st.spinner("🧠 Gemini analyzing and formatting..."):
                summary = gemini_markdown_summary(gemini_prompt)

            st.success(f"✅ Attack Type: **{attack_type}**")
            st.markdown("### 📋 Gemini Incident Summary")
            st.markdown(summary)

            # Save all analysis and summary to session state
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

    # After analysis and summary are saved in session state, add the chatbot UI in both tabs

# --------------------------------------------------------
# TAB 2: TICKET RAISED POST IDENTIFICATION ("I Know the Attack Type")
# --------------------------------------------------------
with tab2:
    st.header("Ticket Raised Post Identification")
    st.markdown("Select from a list of known attacks to view actions, or upload a network attack CSV for analysis.")
    
    # File uploader for network attack CSV
    uploaded_file = st.file_uploader("Upload a network attack CSV for analysis", type=["csv"], key="ticket_csv")
    csv_summary = None
    attack_summary_str = ""
    
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        attack_summary = df.groupby('Attack_Type').agg({
            'Dst_Port': lambda x: list(set(x)),
            'Attack_Confidence': lambda x: list(set(x))
        }).reset_index()
        attack_summary_str = "\n".join([
            f"- {row['Attack_Type']}: Ports {row['Dst_Port']}, Confidence {row['Attack_Confidence']}"
            for _, row in attack_summary.iterrows()
        ])
        st.write("Detected attack types and ports:")
        st.dataframe(attack_summary)
        
        # Automatically provide tailored summary for uploaded CSV
        if attack_summary_str:
            # Find matching incidents from JSON data with fuzzy matching
            matching_incidents = []
            similar_incidents = []
            
            for attack_type in attack_summary['Attack_Type']:
                found_exact_match = False
                for attack in data:
                    # Exact match
                    if attack["Attack Type"].lower() == attack_type.lower():
                        found_exact_match = True
                        for incident in attack["Incidents"]:
                            matching_incidents.append({
                                "Attack Type": attack["Attack Type"],
                                "Incident Title": incident["Incident Title"],
                                "Description": incident["Description"],
                                "Containment Steps": incident["Containment Steps"],
                                "Remediation Options": incident["Remediation Options"],
                                "Forensic Steps": incident["Forensic Steps"]
                            })
                    
                    # Fuzzy matching for similar attack types
                    elif (attack_type.lower() in attack["Attack Type"].lower() or 
                          attack["Attack Type"].lower() in attack_type.lower()):
                        for incident in attack["Incidents"]:
                            similar_incidents.append({
                                "Attack Type": attack["Attack Type"],
                                "Incident Title": incident["Incident Title"],
                                "Description": incident["Description"],
                                "Containment Steps": incident["Containment Steps"],
                                "Remediation Options": incident["Remediation Options"],
                                "Forensic Steps": incident["Forensic Steps"]
                            })
            
            # Use exact matches first, then similar matches
            all_relevant_incidents = matching_incidents + similar_incidents
            
            if all_relevant_incidents:
                # THOROUGH ANALYSIS with data.json playbooks
                # Find matching incidents from JSON data with fuzzy matching
                matching_incidents = []
                similar_incidents = []
                
                for attack_type in attack_summary['Attack_Type']:
                    found_exact_match = False
                    for attack in data:
                        # Exact match
                        if attack["Attack Type"].lower() == attack_type.lower():
                            found_exact_match = True
                            for incident in attack["Incidents"]:
                                matching_incidents.append({
                                    "Attack Type": attack["Attack Type"],
                                    "Incident Title": incident["Incident Title"],
                                    "Description": incident["Description"],
                                    "Containment Steps": incident["Containment Steps"],
                                    "Remediation Options": incident["Remediation Options"],
                                    "Forensic Steps": incident["Forensic Steps"]
                                })
                        
                        # Fuzzy matching for similar attack types
                        elif (attack_type.lower() in attack["Attack Type"].lower() or 
                              attack["Attack Type"].lower() in attack_type.lower()):
                            for incident in attack["Incidents"]:
                                similar_incidents.append({
                                    "Attack Type": attack["Attack Type"],
                                    "Incident Title": incident["Incident Title"],
                                    "Description": incident["Description"],
                                    "Containment Steps": incident["Containment Steps"],
                                    "Remediation Options": incident["Remediation Options"],
                                    "Forensic Steps": incident["Forensic Steps"]
                                })
                
                # Use exact matches first, then similar matches
                all_relevant_incidents = matching_incidents + similar_incidents
                
                if all_relevant_incidents:
                    # Create comprehensive prompt with detailed playbooks
                    attack_types_found = list(set([incident['Attack Type'] for incident in all_relevant_incidents]))
                    ports_found = []
                    for _, row in attack_summary.iterrows():
                        ports_found.extend(row['Dst_Port'])
                    ports_found = list(set(ports_found))
                    
                    # Create detailed prompt with playbook data
                    detailed_prompt = f"""
You are a cybersecurity assistant. Analyze these detected network attacks and provide comprehensive recommendations.

DETECTED ATTACKS:
{attack_summary_str}

ATTACK TYPES FOUND: {', '.join(attack_types_found)}
PORTS INVOLVED: {', '.join(map(str, ports_found))}

RELEVANT INCIDENT PLAYBOOKS:
"""
                    
                    # Add detailed playbook information
                    for incident in all_relevant_incidents:
                        detailed_prompt += f"""
**{incident['Attack Type']} - {incident['Incident Title']}**
Description: {incident['Description']}
Containment: {incident['Containment Steps']}
Remediation: {incident['Remediation Options']}
Forensic: {incident['Forensic Steps']}
"""
                    
                    detailed_prompt += f"""

Based on the detected attacks and relevant playbooks, provide:
1. **Containment Steps** - Immediate actions for the detected attack types and ports
2. **Remediation Actions** - Prevention measures based on the playbooks
3. **Forensic Steps** - Investigation priorities for the detected attacks

Focus on the most critical actions first, incorporating playbook guidance.
"""
                    
                    # Use status instead of spinner for better UX
                    with st.status("🧠 Analyzing attacks with playbook data...", expanded=True) as status:
                        summary = gemini_markdown_summary(detailed_prompt)
                        status.update(label="✅ Analysis complete!", state="complete")
                    st.markdown("### 🧾 Tailored Fix Summary")
                    st.markdown(summary)
                    
                    # Save to session state for chatbot
                    st.session_state.incident = {
                        "query": f"CSV Analysis: {', '.join(attack_summary['Attack_Type'].tolist())}",
                        "content": summary,
                        "metadata": {"attack_types": attack_summary['Attack_Type'].tolist()}
                    }
                    st.session_state.incident_summary = summary
                    st.session_state.incident_metadata = {"uploaded_csv": True}
                    st.session_state.incident_query = f"CSV Analysis: {', '.join(attack_summary['Attack_Type'].tolist())}"
                    
                    

                else:
                    # Even if no matches found, let Gemini generate recommendations based on context
                    detailed_prompt = f"""
You are a cybersecurity assistant. Analyze this network attack data:

{attack_summary_str}

No exact incident playbooks were found for these attack types. Based on your cybersecurity expertise, provide:

1. **Containment Steps** - Immediate actions to stop the detected attacks
2. **Remediation Actions** - Prevention measures to avoid future occurrences  
3. **Forensic Steps** - Investigation priorities for the detected attacks

Focus on the most critical actions first and provide practical, actionable recommendations.
"""
                    
                    # Use status instead of spinner for better UX
                    with st.status("🧠 Generating comprehensive recommendations...", expanded=True) as status:
                        summary = gemini_markdown_summary(detailed_prompt)
                        status.update(label="✅ Recommendations ready!", state="complete")
                    st.markdown("### 🧾 Generated Fix Summary")
                    st.markdown(summary)
                    
                    # Save to session state for chatbot
                    st.session_state.incident = {
                        "query": f"CSV Analysis: {', '.join(attack_summary['Attack_Type'].tolist())}",
                        "content": summary,
                        "metadata": {"attack_types": attack_summary['Attack_Type'].tolist()}
                    }
                    st.session_state.incident_summary = summary
                    st.session_state.incident_metadata = {"uploaded_csv": True}
                    st.session_state.incident_query = f"CSV Analysis: {', '.join(attack_summary['Attack_Type'].tolist())}"
                    
                    # Apply Fix Button
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

    # Independent dropdown for manual incident selection - only show when no CSV is uploaded
    if not uploaded_file:
        st.markdown("---")
        st.markdown("### Or select an incident manually:")

    # Flatten all incidents across attack types
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

        # Gemini Prompt for manual selection
        prompt = f"""
You are a cybersecurity assistant. Given the following incident, provide a comprehensive analysis with detailed steps:

**Incident:** {selected_incident['Incident Title']}
**Description:** {selected_incident['Description']}

**Containment Steps:**
{selected_incident['Containment Steps']}

**Remediation Options:**
{selected_incident['Remediation Options']}

**Forensic Steps:**
{selected_incident['Forensic Steps']}

Provide a structured response with:
1. **Containment** - Immediate actions to stop the threat
2. **Remediation** - Steps to prevent future occurrences
3. **Forensic** - Investigation and evidence collection

Keep each section detailed but concise.
"""

        # Use a container for better loading experience
        with st.container():
            if st.button("Generate Summary", key="generate_summary_btn"):
                with st.status("🧠 Generating comprehensive summary...", expanded=True) as status:
                    summary = gemini_markdown_summary(prompt)
                    status.update(label="✅ Summary generated!", state="complete")
                st.markdown("### 🧾 Fix Summary")
                st.markdown(summary)

                # Save to session state for chatbot
                st.session_state.incident = {
                    "query": selected_incident["Incident Title"],
                    "content": summary,
                    "metadata": {}
                }
                st.session_state.incident_summary = summary
                st.session_state.incident_metadata = selected_incident
                st.session_state.incident_query = selected_incident["Incident Title"]
                
                

    # REMOVE THE DUPLICATE DISPLAY SECTION - NO MORE "Analysis Complete"
    # The chatbot will appear below the analysis automatically

    # COMPLETELY ISOLATED CHATBOT - SEPARATE FROM EVERYTHING ELSE
    if 'incident_summary' in st.session_state and st.session_state.incident_summary:
        st.markdown("---")
        st.markdown("## 🤖 Cybersecurity Assistant")
        
        # ISOLATED: Initialize chat messages with unique key
        if "incident_chat_messages" not in st.session_state:
            st.session_state.incident_chat_messages = []
        
        # ISOLATED: Prepare analysis context
        analysis_context = f"""
        Incident Analysis Summary:
        - Query: {st.session_state.get("incident_query", "N/A")}
        - Summary: {st.session_state.get("incident_summary", "N/A")[:500]}...
        - Metadata: {st.session_state.get("incident_metadata", {})}
        """
        
        # ISOLATED: Chat interface CSS
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
        .send-button {
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #0084ff;
            cursor: pointer;
            font-size: 18px;
        }
        </style>
        """, unsafe_allow_html=True)
        
        # ISOLATED: Chat container
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        
        # ISOLATED: Always show welcome message first
        welcome_msg = """
        <div class="welcome-bubble">
            <strong>🤖 Cybersecurity Assistant</strong><br>
            I can help you understand your incident analysis, explain attack types, and suggest security measures.
        </div>
        """
        st.markdown(welcome_msg, unsafe_allow_html=True)
        
        # ISOLATED: Display all chat messages
        for message in st.session_state.incident_chat_messages:
            if message["role"] == "user":
                st.markdown(f'<div class="user-bubble">🧑 <strong>You:</strong><br>{message["content"]}</div><div class="clearfix"></div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="bot-bubble">🤖 <strong>Assistant:</strong><br>{message["content"]}</div><div class="clearfix"></div>', unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # ISOLATED: CVE Agent style input area
        st.markdown('<div class="chat-input-container">', unsafe_allow_html=True)
        
        # ISOLATED: Use columns for input and clear button
        col1, col2 = st.columns([5, 1])
        
        with col1:
            # ISOLATED: Create form for enter key functionality
            with st.form(key="incident_chat_form", clear_on_submit=True):
                user_input = st.text_input("Message", placeholder="Ask about cybersecurity...", label_visibility="collapsed")
                send_btn = st.form_submit_button("Send", use_container_width=True)
        
        with col2:
            if st.button("🧹 Clear", use_container_width=True, key="incident_clear_btn"):
                st.session_state.incident_chat_messages = []
                st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # ISOLATED: Process message - EXACT SAME LOGIC AS WORKING CHATBOT
        if send_btn and user_input:
            # ISOLATED: Add user message
            st.session_state.incident_chat_messages.append({"role": "user", "content": user_input})
            
            # ISOLATED: Check if cybersecurity related
            cybersecurity_keywords = [
                'attack', 'threat', 'security', 'anomaly', 'malicious', 'intrusion',
                'vulnerability', 'exploit', 'malware', 'breach', 'network', 'traffic',
                'ddos', 'dos', 'sql injection', 'brute force', 'botnet', 'infiltration',
                'analysis', 'detection', 'classification', 'confidence', 'risk',
                'suspicious', 'benign', 'mitigation', 'defense', 'protection',
                'firewall', 'ips', 'ids', 'siem', 'incident', 'response', 'containment',
                'remediation', 'forensic', 'port', 'block', 'isolate'
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
            
            # ISOLATED: Add bot response
            st.session_state.incident_chat_messages.append({"role": "bot", "content": response})
            
            # ISOLATED: Limit to last 20 messages (10 exchanges)
            if len(st.session_state.incident_chat_messages) > 20:
                st.session_state.incident_chat_messages = st.session_state.incident_chat_messages[-20:]
            
            st.rerun()