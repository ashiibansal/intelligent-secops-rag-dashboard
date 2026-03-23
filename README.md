## Smart Cybersecurity Assistant – Credential Setup

A Streamlit-based cybersecurity platform that combines:

- **Incident response guidance** using RAG + Gemini
- **Known-attack playbook generation**
- **Legacy attack analytics dashboard** for uploaded CSVs
- **Security Agent Console** for:
  - network anomaly detection
  - attack type classification
  - login anomaly detection
  - interactive visual analytics
  - exportable results

This project uses Google Gemini for generation and embeddings, and optionally AWS (EC2) for a demo containment action. No real credentials are included in this repo; placeholders are used.
___

## Features

### 1. Incident Response System
Supports two workflows:

#### General Purpose Use
Describe suspicious activity in plain language, such as:
- fake pop-up
- unusually slow device
- suspicious Wi-Fi device
- unknown login behaviour

The system uses:
- vector similarity search
- Gemini-based summarisation
- structured incident-response formatting

#### Ticket Raised Post Identification
Choose a known incident or upload a network attack CSV to:
- identify relevant attack patterns
- generate containment actions
- generate remediation steps
- generate forensic investigation steps

---

### 2. Legacy Analytics Dashboard
Inside the Incident Response tab, the **Legacy Analytics** subtab provides:
- attack type distribution
- risk-level distribution
- destination-port analysis
- source-IP analysis
- attack timeline
- heatmaps
- prioritised review tables
- downloadable filtered outputs

This dashboard uses the uploaded CSV from the ticket workflow.

---

### 3. Security Agent Console
The Security Agent tab supports automatic file classification and model-based detection.

#### Supported modes
- **Network traffic analysis**
  - anomaly detection
  - attack classification
  - confidence visualisation
  - export to CSV / JSON

- **Login anomaly detection**
  - suspicious login pattern analysis
  - affected-user analysis
  - temporal anomaly charts
  - anomaly export

#### AI assistant
If Gemini is configured, the Security Agent also provides a built-in assistant for analysis-specific questions.

---

## Project Structure

```text
.
├── app.py
├── dashboard.py
├── ui_components.py
├── rag_answerer.py
├── vector_loader.py
├── data.json
├── README.md
├── requirements.txt
├── .streamlit/
│   └── secrets.toml
└── security_agent/
    ├── __init__.py
    ├── security_agent_page.py
    ├── model_inference.py
    ├── trained_models/
    └── login_models/

```
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


