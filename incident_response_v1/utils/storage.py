import json
from datetime import datetime

def save_incident(title, description):
    incident = {
        "title": title,
        "description": description,
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
