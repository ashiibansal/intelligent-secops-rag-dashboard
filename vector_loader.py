import os
import asyncio
import sys

import streamlit as st
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_community.vectorstores import FAISS

# macOS-specific fix for asyncio event loop
if sys.platform == "darwin":
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())


def load_vectorstore():
    # Ensure event loop exists (mostly for macOS + Streamlit)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    # 🔑 Read Gemini API key correctly
    api_key = None
    if hasattr(st, "secrets") and "GEMINI" in st.secrets:
        api_key = st.secrets["GEMINI"]["API_KEY"]
    else:
        api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "Gemini API key not found. Please configure st.secrets['GEMINI']['API_KEY'] "
            "or set GEMINI_API_KEY environment variable."
        )

    # Set up Gemini embedding model (NO ADC)
    embedding = GoogleGenerativeAIEmbeddings(
        model="models/gemini-embedding-001",
        google_api_key=api_key
    )

    # Load FAISS vectorstore
    return FAISS.load_local(
        "incident_vectorstore",
        embeddings=embedding,
        allow_dangerous_deserialization=True
    )
