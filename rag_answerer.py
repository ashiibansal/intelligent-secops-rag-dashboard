import os
import google.generativeai as genai

import streamlit as st

# Load Gemini API Key
api_key = st.secrets["GEMINI"]["API_KEY"] if "GEMINI" in st.secrets else os.getenv("GEMINI_API_KEY")
genai.configure(api_key=api_key)

# ------------------------------
# 🔎 1. Gemini Summarization (Attack Type Unknown)
# ------------------------------
def gemini_summarize_incident(incident_text, user_query):
    prompt = f"""
You are a cybersecurity assistant.

A user described the following: "{user_query}"

First, evaluate whether this is a relevant cybersecurity incident.

If it is **not** a security-related description (e.g., "I like burgers", "My cat is cute", etc.), respond with:

"This does not appear to be a cybersecurity issue. Please describe something unusual on your system or network."

If it **is** a valid issue, respond with:

✅ Identified Attack Type: (hypothesize)

### 🧠 What Likely Happened
Explain in simple terms.

### 🛑 Containment Steps
Based on incident indicators: 
{incident_text}

### 🔧 Remediation Options
Extract what the user should do from incident_text.

### 🔍 Forensic Steps
Extract any evidence collection or root cause analysis steps.

Respond in clear Markdown.
"""
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    return response.text.strip()

# ------------------------------
# 💬 2. Gemini Q&A (Ask about known incident)
# ------------------------------
def gemini_answer_question(question, incident_context):
    prompt = f"""
You're an expert cybersecurity assistant. Based only on the following incident content and query, answer the user's question accurately.

User Input: {incident_context['query']}

Incident Content:
\"\"\"
{incident_context['content']}
\"\"\"

User's Question: {question}
"""
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    return response.text.strip()

# ------------------------------
# 📊 3. Rank Most Relevant Remediation Steps
# ------------------------------
def rank_remediation_steps(incident, query):
    steps = "\n".join(incident["remediation_steps"])
    prompt = f"""
You are a cybersecurity engineer. A user described this issue: "{query}"

Given the following remediation steps:
{steps}

Rank the 3 most relevant steps for this scenario. Return only the steps, one per line.
"""
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    return response.text.strip().split("\n")

# ------------------------------
# 🛠️ 4. Generate Fix Instructions for a Selected Step
# ------------------------------
def generate_fix_steps(selected_step, full_content):
    prompt = f"""
A user selected this remediation step:

'{selected_step}'

From the following incident details:
{full_content}

Write clear, step-by-step technical instructions to implement this fix. Use numbered steps.
"""
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    return response.text.strip()