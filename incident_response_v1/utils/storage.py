import json
from datetime import datetime
from utils.analyzer import classify_incident

def save_incident(title, description):
    category, severity = classify_incident(description)

    incident = {
        "title": title,
        "description": description,
        "category": category,
        "severity": severity,
        "timestamp": str(datetime.now())
    }

    try:
        with open("data/incidents.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = []

    data.append(incident)

    with open("data/incidents.json", "w") as f:
        json.dump(data, f, indent=4)
