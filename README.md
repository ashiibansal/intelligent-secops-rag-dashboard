# An Intelligent SecOps Dashboard for Cyber Threat Detection and Explanation using RAG and Visual Analytics

## 📝 Project Description
This project focuses on bridging the gap between automated threat detection and human-readable analysis. It utilizes Machine Learning to identify anomalies in server logs and employs **Retrieval-Augmented Generation (RAG)** to provide context-aware explanations of security incidents. 

The core deliverable is an interactive **Visual Analytics** dashboard that allows security analysts to monitor threats in real-time and query an AI Assistant for deep-dive investigations.

## 🎯 Syllabus Mapping (Key Deliverables)
This project is built to satisfy the following core requirements:

* **Retrieval-Augmented Generation (RAG):** Integrating an LLM (Gemini/OpenAI) to retrieve context from flagged security logs and provide natural language explanations of threats.
* **Advanced Data Visualization:** Developing an interactive dashboard using **Streamlit** to visualize temporal attack trends, threat heatmaps, and confidence intervals.
* **Machine Learning Integration:** Implementing specialized models for Network Traffic analysis (DoS/Brute Force) and User Behavior Analytics (Login Anomalies).

## 🛠️ Tech Stack
* **Frontend/Dashboard:** Streamlit
* **Data Processing:** Pandas, NumPy
* **Visualization:** Plotly, Matplotlib
* **AI/LLM:** Gemini API / LangChain (for RAG)
* **Machine Learning:** Scikit-learn (XGBoost / Isolation Forest)
* **Version Control:** Git/GitHub

## 🚀 Key Features
- **Intelligent Ingestion:** Automated classification of CSV log files.
- **Threat Heatmaps:** Visual breakdown of anomalies per user and distribution of risk scores.
- **AI Security Assistant:** A context-aware chatbot that explains "Why" a specific log was flagged as a threat.
- **Temporal Analysis:** Line charts showing real-time attack frequency over time.

## 📁 Project Structure (Planned)
```text
├── data/               # Sample log datasets (CSV)
├── models/             # Pre-trained ML models (.pkl)
├── src/
│   ├── app.py          # Main Streamlit application
│   ├── rag_engine.py   # RAG & LLM logic
│   └── detector.py     # ML inference scripts
├── requirements.txt    # Project dependencies
└── README.md
