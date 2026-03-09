## Smart Cybersecurity Assistant – Credential Setup

This project uses Google Gemini for generation and embeddings, and optionally AWS (EC2) for a demo containment action. No real credentials are included in this repo; placeholders are used.

### Where credentials are referenced
- `app.py`
  - Reads Gemini API key from `st.secrets["GEMINI"]["API_KEY"]` and configures `google.generativeai`.
  - Uses AWS credentials from `st.secrets["AWS"]` to create a `boto3` EC2 client for the demo stop-instance action.
- `rag_answerer.py`
  - Imports `google.generativeai as genai` and configures with `API_KEY` (from Streamlit secrets fallback to env `GEMINI_API_KEY`).
- `vector_loader.py`
  - Uses `GoogleGenerativeAIEmbeddings` with `google_api_key` from Streamlit secrets fallback to env `GEMINI_API_KEY`.
- `.streamlit/secrets.toml`
  - Stores placeholders for Gemini and AWS credentials (you must fill these in locally; do not commit real keys).

### Provide credentials (preferred)
Use Streamlit secrets. Create `.streamlit/secrets.toml` in the project root:

```toml
[GEMINI]
API_KEY = "your-gemini-api-key-here"

[AWS]
ACCESS_KEY_ID = "your-aws-access-key-here"
SECRET_ACCESS_KEY = "your-aws-secret-key-here"
REGION = "ap-south-1"
```

Notes:
- Gemini is required for generation and embeddings.
- AWS is optional; if not provided, the EC2 containment action runs in demo mode and does not call AWS.

### Alternative: Environment variables
You can also supply the Gemini key via an environment variable if you are not using Streamlit secrets:

- `GEMINI_API_KEY` – used in `rag_answerer.py` and `vector_loader.py` when `st.secrets` is not set.

Example (PowerShell):
```powershell
$env:GEMINI_API_KEY = "sk-..."
```
Example (cmd):
```cmd
set GEMINI_API_KEY=sk-...
```

### Installing and running
1. Create and fill `.streamlit/secrets.toml` as above (or set `GEMINI_API_KEY`).
2. Install dependencies:
```bash
pip install -r requirements.txt
```
3. Run the app:
```bash
streamlit run app.py
```

### Security checklist before sharing
- Ensure `.streamlit/secrets.toml` contains only placeholders and is not tracked with real keys.
- Do not hardcode keys in code. This repository uses secrets/env only.
- If you previously committed keys, rotate them in your provider consoles (Google Cloud Console, AWS IAM).


