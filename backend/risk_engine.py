def compute(
    header_result: dict,
    nlp_result: dict,
    ip_result: dict
) -> dict:
    """
    Calculate the final email risk score.

    Locked sprint formula:
        NLP    = 40%
        Header = 40%
        IP     = 20%

    Risk bands:
        0-30   = LOW
        31-60  = MEDIUM
        61-80  = HIGH
        81-100 = CRITICAL
    """

    # Get the three scores from the upstream modules.
    nlp_score = int(
        nlp_result.get("phishing_probability", 0)
    )

    header_score = int(
        header_result.get("header_risk_score", 0)
    )

    ip_score = int(
        ip_result.get("ip_risk_score", 0)
    )

    # Keep all inputs inside the expected 0-100 range.
    nlp_score = max(0, min(100, nlp_score))
    header_score = max(0, min(100, header_score))
    ip_score = max(0, min(100, ip_score))

    # Locked sprint formula.
    risk_score = round(
        nlp_score * 0.40
        + header_score * 0.40
        + ip_score * 0.20
    )

    # Determine classification.
    if risk_score <= 30:
        classification = "LOW"
    elif risk_score <= 60:
        classification = "MEDIUM"
    elif risk_score <= 80:
        classification = "HIGH"
    else:
        classification = "CRITICAL"

    # Build human-readable reasons.
    reasons = []

    for anomaly in header_result.get("anomalies", []):
        if anomaly not in reasons:
            reasons.append(anomaly)

    if header_result.get("spf") == "fail":
        reasons.append("SPF failed")

    if header_result.get("dkim") == "fail":
        reasons.append("DKIM failed")

    if header_result.get("dmarc") == "fail":
        reasons.append("DMARC failed")

    if header_result.get("sender_reply_mismatch", False):
        reasons.append("Sender/Reply-To mismatch")

    if nlp_score > 50:
        reasons.append(
            f"High phishing probability ({nlp_score}%)"
        )

    return {
        "risk_score": risk_score,
        "classification": classification,
        "reasons": reasons,
        "breakdown": {
            "nlp": nlp_score,
            "header": header_score,
            "ip": ip_score
        }
    }


if __name__ == "__main__":
    # Mock M3 Header Analysis result
    header_result = {
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
        "sender_reply_mismatch": True,
        "domain_lookalike": False,
        "domain_age_days": None,
        "anomalies": [
            "Sender identity mismatch",
            "Multiple authentication failures"
        ],
        "header_risk_score": 80
    }

    # Mock M4 NLP result
    nlp_result = {
        "phishing_probability": 91,
        "legitimate_probability": 9,
        "flagged_terms": [
            "urgent",
            "account suspended",
            "click immediately"
        ],
        "method": "heuristic"
    }

    # Mock M5 IP result
    ip_result = {
        "extracted_ips": ["185.123.45.67"],
        "primary_ip": "185.123.45.67",
        "geo": {
            "country": "Germany",
            "city": "Frankfurt",
            "isp": "Example Hosting Provider"
        },
        "ip_risk_score": 60
    }

    result = compute(
        header_result,
        nlp_result,
        ip_result
    )

    print(result)