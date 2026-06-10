def calculate_trust(
    publisher,
    signature_status,
    virustotal,
    location_classification
):
    # Neutral starting point
    trust_score = 50

    # Publisher
    if publisher and publisher != "Unknown":

        if "microsoft" in publisher.lower():
            trust_score += 30
        else:
            trust_score += 10

    # Digital Signature
    if signature_status == "Valid":
        trust_score += 20

    elif signature_status == "NotSigned":
        trust_score -= 10

    else:
        trust_score -= 20

    # VirusTotal
    # Only evaluate when we have a real VT result
    if virustotal and "error" not in virustotal:

        malicious = virustotal.get("malicious", 0)
        suspicious = virustotal.get("suspicious", 0)

        if malicious > 0:
            trust_score -= 50

        elif suspicious > 0:
            trust_score -= 20

        else:
            trust_score += 20

    # Location
    if location_classification == "Trusted":
        trust_score += 10

    elif location_classification == "Suspicious":
        trust_score -= 15

    # Clamp between 0 and 100
    return max(0, min(trust_score, 100))