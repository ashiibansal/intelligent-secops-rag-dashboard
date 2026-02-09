import json
from langchain.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.docstore.document import Document

def build_vectorstore():
    with open("data.json", "r") as f:
        data = json.load(f)

    docs = []
    for attack in data:
        for incident in attack["Incidents"]:
            docs.append(
                Document(
                    page_content=incident["Description"],
                    metadata={
                        "attack_type": attack["Attack Type"],
                        "incident_title": incident["Incident Title"]
                    }
                )
            )

    embedding = HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2"
    )

    vectorstore = FAISS.from_documents(docs, embedding)
    vectorstore.save_local("incident_vectorstore")
