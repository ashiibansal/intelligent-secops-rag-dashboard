from google import genai
import streamlit as st

def generate_incident_explanation(user_query, retrieved_doc):

    api_key = st.secrets.get("GEMINI_API_KEY", None)
    if not api_key:
        return "⚠️ Gemini API key not configured."

    client = genai.Client(api_key=api_key)

    context = retrieved_doc.page_content

    prompt = f"""
You are a cybersecurity incident response assistant.

User reported:
{user_query}

Relevant historical incident:
{context}

Explain clearly:

1) What likely happened
2) Why it is dangerous
3) Immediate containment steps
4) Basic remediation advice

Keep response simple and structured.
"""

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )

    return response.text
