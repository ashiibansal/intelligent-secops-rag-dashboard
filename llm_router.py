import os
from typing import Optional

import streamlit as st

# Gemini
try:
    import google.generativeai as genai
    GEMINI_IMPORT_OK = True
except Exception:
    GEMINI_IMPORT_OK = False

# Groq
try:
    from groq import Groq
    GROQ_IMPORT_OK = True
except Exception:
    GROQ_IMPORT_OK = False


def _get_secret(section: str, key: str, default: Optional[str] = None) -> Optional[str]:
    try:
        return st.secrets[section][key]
    except Exception:
        env_key = f"{section}_{key}"
        return os.getenv(env_key, default)


def get_primary_provider() -> str:
    try:
        return str(st.secrets["LLM"]["PRIMARY_PROVIDER"]).strip().lower()
    except Exception:
        return "gemini"


def get_secondary_provider() -> str:
    try:
        return str(st.secrets["LLM"]["SECONDARY_PROVIDER"]).strip().lower()
    except Exception:
        return "groq"


def _call_gemini(prompt: str, model_name: str = "gemini-2.5-flash") -> str:
    if not GEMINI_IMPORT_OK:
        raise RuntimeError("Gemini SDK is not installed.")

    api_key = _get_secret("GEMINI", "API_KEY")
    if not api_key:
        raise RuntimeError("Gemini API key is missing.")

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name)
    response = model.generate_content(prompt)
    return response.text.strip()


def _call_groq(prompt: str) -> str:
    if not GROQ_IMPORT_OK:
        raise RuntimeError("Groq SDK is not installed.")

    api_key = _get_secret("GROQ", "API_KEY")
    if not api_key:
        raise RuntimeError("Groq API key is missing.")

    model_name = _get_secret("GROQ", "MODEL", "llama-3.3-70b-versatile")
    client = Groq(api_key=api_key)

    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "user", "content": prompt}
        ],
        temperature=0.2,
    )

    return completion.choices[0].message.content.strip()


def _is_quota_or_rate_error(err: Exception) -> bool:
    msg = str(err).lower()
    markers = [
        "429",
        "quota",
        "rate limit",
        "rate_limit",
        "resource_exhausted",
        "too many requests",
    ]
    return any(m in msg for m in markers)


def generate_text_with_fallback(
    prompt: str,
    primary_provider: Optional[str] = None,
    secondary_provider: Optional[str] = None,
) -> str:
    """
    Try primary LLM first. If quota/rate-limit hits, fall back to secondary.
    """
    primary = (primary_provider or get_primary_provider()).strip().lower()
    secondary = (secondary_provider or get_secondary_provider()).strip().lower()

    provider_map = {
        "gemini": _call_gemini,
        "groq": _call_groq,
    }

    if primary not in provider_map:
        raise RuntimeError(f"Unsupported primary provider: {primary}")
    if secondary not in provider_map:
        raise RuntimeError(f"Unsupported secondary provider: {secondary}")

    try:
        return provider_map[primary](prompt)
    except Exception as primary_err:
        if _is_quota_or_rate_error(primary_err) and secondary != primary:
            try:
                st.warning(
                    f"Primary provider '{primary}' hit quota/rate limit. "
                    f"Falling back to '{secondary}'."
                )
                return provider_map[secondary](prompt)
            except Exception as secondary_err:
                raise RuntimeError(
                    f"Primary provider failed: {primary_err} | "
                    f"Secondary provider failed: {secondary_err}"
                )
        raise