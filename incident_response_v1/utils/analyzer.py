def classify_incident(description: str):
    desc = description.lower()

    if any(word in desc for word in ["malware", "virus", "trojan"]):
        return "Malware Attack", "High"
    elif any(word in desc for word in ["phishing", "email fraud", "scam"]):
        return "Phishing Attempt", "Medium"
    elif any(word in desc for word in ["ddos", "traffic flood", "service down"]):
        return "DDoS Attack", "High"
    elif any(word in desc for word in ["unauthorized", "breach", "access"]):
        return "Unauthorized Access", "Critical"
    else:
        return "General Security Incident", "Low"
