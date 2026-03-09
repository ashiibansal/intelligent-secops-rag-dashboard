import os
import json
from dotenv import load_dotenv
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.docstore.document import Document

# Load environment variables
load_dotenv()

def load_json_file(path):
    with open(path, "r") as f:
        return json.load(f)

# Load data
full_data = load_json_file("data.json")
incidents_data = load_json_file("incidents.json")

docs = []

# --------- PART 1: Process full data.json ---------
for block in full_data:
    try:
        attack_type = block.get("Attack Type", "Unknown")
        source = block.get("Source", "unknown.pdf")
        for incident in block.get("Incidents", []):
            title = incident.get("Incident Title", "Untitled")
            description = incident.get("Description", "No description provided.")
            containment = incident.get("Containment Steps", [])
            remediation_blocks = incident.get("Remediation Options", [])
            remediation_steps = []
            for option in remediation_blocks:
                remediation_steps.extend(option.get("steps", []))
            forensic = incident.get("Forensic Steps", [])

            content = (
                f"Title: {title}\n"
                f"Attack Type: {attack_type}\n"
                f"Description: {description}\n"
                f"Containment Steps:\n- " + "\n- ".join(containment) + "\n"
                f"Remediation Steps:\n- " + "\n- ".join(remediation_steps) + "\n"
                f"Forensic Steps:\n- " + "\n- ".join(forensic)
            )

            docs.append(Document(
                page_content=content,
                metadata={
                    "attack_type": attack_type,
                    "incident_title": title,
                    "source": source,
                    "type": "playbook"
                }
            ))
    except Exception as e:
        print(f"⚠️ Error processing block: {e}")

# --------- PART 2: Process incidents.json ---------
for block in incidents_data:
    try:
        attack_type = block.get("Attack Type", "Unknown")
        for ind in block.get("Indicators", []):
            indicator = ind.get("Indicator", "No indicator")
            desc = ind.get("Description", "No description.")
            content = f"Indicator: {indicator}\nDescription: {desc}\nRelated Attack: {attack_type}"

            docs.append(Document(
                page_content=content,
                metadata={
                    "attack_type": attack_type,
                    "indicator": indicator,
                    "type": "indicator"
                }
            ))
    except Exception as e:
        print(f"⚠️ Error processing indicator block: {e}")

print(f"\n📦 Total Documents Prepared: {len(docs)}")

# --------- Create and save vectorstore ---------
if docs:
    try:
        embedding = GoogleGenerativeAIEmbeddings(
        model="models/gemini-embedding-001",
        google_api_key=os.getenv("GEMINI_API_KEY")
        )
        vectorstore = FAISS.from_documents(docs, embedding)
        vectorstore.save_local("incident_vectorstore")
        print("✅ Vector store created and saved at 'incident_vectorstore/'")
    except Exception as e:
        print(f"❌ Failed to create vectorstore: {e}")
else:
    print("❌ No documents to index. Please fix your inputs.")
