"""
Risk Engine Module

Aggregates individual threat scores from Header Analyzer, NLP Phishing Model,
and IP Analyzer into a composite risk score (0-100), risk band classification
(LOW / MEDIUM / HIGH / CRITICAL), and prioritized explainable reasons.
"""


def compute(
    header_result: dict,
    nlp_result: dict,
    ip_result: dict
) -> dict:
    """
    Calculate the composite email risk score and classification.

    Formula:
        NLP Model   = 40%
        Header Risk = 40%
        IP Risk     = 20%

    Risk Bands:
        0 - 30   = LOW
        31 - 60  = MEDIUM
        61 - 80  = HIGH
        81 - 100 = CRITICAL
    """
    # 1. Extract sub-scores safely with validation
    nlp_score = int(nlp_result.get("phishing_probability", 0) or 0)
    header_score = int(header_result.get("header_risk_score", 0) or 0)
    ip_score = int(ip_result.get("ip_risk_score", 0) or 0)

    # Constrain inputs within 0-100 range
    nlp_score = max(0, min(100, nlp_score))
    header_score = max(0, min(100, header_score))
    ip_score = max(0, min(100, ip_score))

    # 2. Weighted Composite Calculation
    risk_score = round(
        nlp_score * 0.40
        + header_score * 0.40
        + ip_score * 0.20
    )
    risk_score = max(0, min(100, risk_score))

    # 3. Determine Classification Band
    if risk_score <= 30:
        classification = "LOW"
    elif risk_score <= 60:
        classification = "MEDIUM"
    elif risk_score <= 80:
        classification = "HIGH"
    else:
        classification = "CRITICAL"

    # 4. Generate Prioritized, Deduplicated Reasons
    reasons = []

    def add_reason(reason_text: str):
        if reason_text and reason_text not in reasons:
            reasons.append(reason_text)

    # A. Header Anomalies
    for anomaly in header_result.get("anomalies", []):
        add_reason(anomaly)

    # Explicit checks if not already listed in anomalies
    if header_result.get("spf") in ("fail", "softfail"):
        add_reason(f"SPF failed ({header_result.get('spf')})")

    if header_result.get("dkim") == "fail":
        add_reason("DKIM signature failed")

    if header_result.get("dmarc") in ("fail", "softfail"):
        add_reason("DMARC verification failed")

    if header_result.get("sender_reply_mismatch"):
        add_reason("Sender/Reply-To mismatch detected")

    # B. NLP Content Signals
    flagged_terms = nlp_result.get("flagged_terms", [])
    if nlp_score >= 70:
        terms_str = f": {', '.join(flagged_terms[:3])}" if flagged_terms else ""
        add_reason(f"High phishing probability ({nlp_score}%){terms_str}")
    elif nlp_score >= 40:
        terms_str = f": {', '.join(flagged_terms[:2])}" if flagged_terms else ""
        add_reason(f"Suspicious language detected ({nlp_score}%){terms_str}")

    # C. IP & Geolocation Signals
    if ip_score >= 50:
        primary_ip = ip_result.get("primary_ip")
        isp = ip_result.get("geo", {}).get("isp", "hosting provider")
        add_reason(f"Suspicious origin IP ({primary_ip or 'unknown'}) hosted on {isp}")

    # D. Clean email fallback reason
    if not reasons and risk_score <= 30:
        add_reason("Email authentication passed and no malicious indicators detected")

    return {
        "risk_score": risk_score,
        "classification": classification,
        "reasons": reasons,
        "breakdown": {
            "nlp": nlp_score,
            "header": header_score,
            "ip": ip_score,
        },
    }


if __name__ == "__main__":
    test_header = {
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
        "sender_reply_mismatch": True,
        "domain_lookalike": False,
        "domain_age_days": None,
        "anomalies": ["Sender identity mismatch", "Multiple authentication failures"],
        "header_risk_score": 80,
    }
    test_nlp = {
        "phishing_probability": 91,
        "legitimate_probability": 9,
        "flagged_terms": ["urgent", "account suspended", "click immediately"],
        "method": "ml_classifier",
    }
    test_ip = {
        "extracted_ips": ["185.123.45.67"],
        "primary_ip": "185.123.45.67",
        "geo": {
            "country": "Germany",
            "city": "Frankfurt",
            "isp": "Example Hosting Provider",
        },
        "ip_risk_score": 60,
    }
    res = compute(test_header, test_nlp, test_ip)
    print("Risk Engine Result:")
    print(res)