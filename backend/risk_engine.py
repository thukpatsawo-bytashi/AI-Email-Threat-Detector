"""
Risk Engine Module

Aggregates threat evidence from header analysis, NLP phishing detection, and IP
intelligence into a composite risk score. The score is evidence-aware: missing
data is neutral, weak one-off signals are capped, and high severity requires
corroborating proof across multiple signal families.
"""


AUTH_FAILURE_WEIGHTS = {
    "spf": {"fail": 10, "softfail": 6, "permerror": 4},
    "dkim": {"fail": 10, "permerror": 5},
    "dmarc": {"fail": 16, "softfail": 9, "permerror": 5},
}


def clamp_score(value) -> int:
    """Return an integer score constrained to 0-100."""
    try:
        score = int(round(float(value or 0)))
    except (TypeError, ValueError):
        score = 0
    return max(0, min(100, score))


def normalize_status(value) -> str:
    return str(value or "none").strip().lower()


def cap(value: int, limit: int) -> int:
    return max(0, min(limit, value))


def as_list(value) -> list:
    if isinstance(value, list):
        return value
    if not value:
        return []
    return [value]


def authentication_points(spf: str, dkim: str, dmarc: str) -> int:
    points = 0
    failure_count = 0
    for key, status in {"spf": spf, "dkim": dkim, "dmarc": dmarc}.items():
        status_points = AUTH_FAILURE_WEIGHTS.get(key, {}).get(status, 0)
        points += status_points
        if status_points:
            failure_count += 1
    if failure_count >= 2:
        points += 6
    return cap(points, 40)


def identity_points(header_result: dict, anomalies: list[str]) -> int:
    points = 0
    if header_result.get("sender_reply_mismatch"):
        points += 14
    if any("envelope sender mismatch" in str(a).lower() for a in anomalies):
        points += 8
    return cap(points, 22)


def domain_points(header_result: dict, anomalies: list[str]) -> int:
    points = 0
    if header_result.get("domain_lookalike"):
        points += 16

    domain_age_days = header_result.get("domain_age_days")
    if isinstance(domain_age_days, int):
        if domain_age_days < 7:
            points += 12
        elif domain_age_days < 30:
            points += 8
        elif domain_age_days < 90:
            points += 4

    if any("high-risk top-level domain" in str(a).lower() for a in anomalies):
        points += 4

    return cap(points, 28)


def content_points(nlp_score: int, flagged_terms: list[str]) -> int:
    term_count = len(flagged_terms)

    if nlp_score >= 80:
        base = 34
    elif nlp_score >= 65:
        base = 24
    elif nlp_score >= 50:
        base = 14 if term_count else 8
    elif term_count >= 2:
        base = 10
    else:
        base = 0

    term_bonus = min(14, term_count * 3)
    return cap(base + term_bonus, 50)


def network_points(ip_score: int) -> int:
    if ip_score >= 70:
        return 16
    if ip_score >= 50:
        return 12
    if ip_score >= 35:
        return 8
    return 0


def url_risk_points(url_score: int) -> int:
    """Map aggregate URL phishing score (0-100) to risk engine points (0-20)."""
    if url_score >= 70:
        return 20
    if url_score >= 50:
        return 15
    if url_score >= 30:
        return 10
    if url_score >= 15:
        return 5
    return 0


def synergy_points(
    content: int,
    authentication: int,
    identity: int,
    domain: int,
    network: int,
    url: int = 0,
) -> int:
    points = 0
    if content >= 30 and authentication >= 15:
        points += 8
    if content >= 25 and domain >= 15:
        points += 8
    if content >= 20 and identity >= 10:
        points += 5
    if domain >= 15 and authentication >= 15:
        points += 5
    if network >= 10 and (authentication >= 15 or domain >= 15):
        points += 4
    # URL synergy: phishing URLs corroborated by content or auth failures
    if url >= 10 and content >= 15:
        points += 6
    if url >= 10 and (authentication >= 15 or domain >= 15):
        points += 4
    return cap(points, 25)


def classify_risk(risk_score: int) -> str:
    if risk_score <= 30:
        return "LOW"
    if risk_score <= 60:
        return "MEDIUM"
    if risk_score <= 80:
        return "HIGH"
    return "CRITICAL"


def apply_evidence_caps(risk_score: int, evidence_sources: list[str], content: int) -> int:
    source_count = len(evidence_sources)

    if source_count == 0:
        return min(risk_score, 24)
    if source_count == 1:
        if evidence_sources[0] == "content" and content >= 40:
            return min(risk_score, 58)
        return min(risk_score, 45)
    if source_count == 2:
        return min(risk_score, 78)
    return risk_score


def compute(
    header_result: dict,
    nlp_result: dict,
    ip_result: dict,
    url_result: dict | None = None,
) -> dict:
    """
    Calculate the composite email risk score and classification.

    The engine scores five signal families:
    - content: ML probability plus concrete phishing terms
    - authentication: SPF/DKIM/DMARC failures only, not missing data
    - identity: From/Reply-To and envelope sender mismatch
    - domain: lookalikes, suspicious TLDs, and newly registered domains
    - network: IP reputation only when the network itself is suspicious
    """
    nlp_score = clamp_score(nlp_result.get("phishing_probability", 0))
    header_score = clamp_score(header_result.get("header_risk_score", 0))
    ip_score = clamp_score(ip_result.get("ip_risk_score", 0))

    spf = normalize_status(header_result.get("spf"))
    dkim = normalize_status(header_result.get("dkim"))
    dmarc = normalize_status(header_result.get("dmarc"))
    auth_statuses = [spf, dkim, dmarc]

    anomalies = [str(a) for a in as_list(header_result.get("anomalies", []))]
    flagged_terms = [str(t) for t in as_list(nlp_result.get("flagged_terms", []))]

    content = content_points(nlp_score, flagged_terms)
    authentication = authentication_points(spf, dkim, dmarc)
    identity = identity_points(header_result, anomalies)
    domain = domain_points(header_result, anomalies)
    network = network_points(ip_score)

    # URL risk integration
    url_data = url_result or {}
    url_score_raw = int(url_data.get("url_risk_score", 0) or 0)
    url = url_risk_points(url_score_raw)

    synergy = synergy_points(content, authentication, identity, domain, network, url)

    evidence_sources = []
    if content >= 15:
        evidence_sources.append("content")
    if authentication > 0:
        evidence_sources.append("authentication")
    if identity > 0:
        evidence_sources.append("identity")
    if domain > 0:
        evidence_sources.append("domain")
    if network > 0:
        evidence_sources.append("network")
    if url > 0:
        evidence_sources.append("url")

    risk_score = content + authentication + identity + domain + network + url + synergy

    auth_passes = sum(1 for status in auth_statuses if status == "pass")
    auth_missing = sum(1 for status in auth_statuses if status == "none")
    auth_failures = sum(
        1 for status in auth_statuses
        if status in {"fail", "softfail", "permerror"}
    )

    if auth_passes >= 2 and content < 20 and authentication == 0 and identity == 0 and domain == 0:
        risk_score -= 8

    risk_score = cap(risk_score, 100)
    risk_score = apply_evidence_caps(risk_score, evidence_sources, content)

    # CRITICAL should mean corroborated evidence, not one noisy model output.
    critical_has_proof = (
        len(evidence_sources) >= 3
        and content >= 20
        and (authentication >= 15 or identity >= 10 or domain >= 15)
    )
    if risk_score > 80 and not critical_has_proof:
        risk_score = 80

    classification = classify_risk(risk_score)

    reasons = []

    def add_reason(reason_text: str):
        if reason_text and reason_text not in reasons:
            reasons.append(reason_text)

    def has_reason_token(token: str) -> bool:
        return any(token.lower() in reason.lower() for reason in reasons)

    for anomaly in anomalies:
        add_reason(anomaly)

    if spf in AUTH_FAILURE_WEIGHTS["spf"] and not has_reason_token("spf"):
        add_reason(f"SPF authentication failed ({spf})")
    if dkim in AUTH_FAILURE_WEIGHTS["dkim"] and not has_reason_token("dkim"):
        add_reason("DKIM signature verification failed")
    if dmarc in AUTH_FAILURE_WEIGHTS["dmarc"] and not has_reason_token("dmarc"):
        add_reason(f"DMARC policy check failed ({dmarc})")

    if content >= 30:
        terms = f": {', '.join(flagged_terms[:4])}" if flagged_terms else ""
        add_reason(f"Strong phishing-language evidence ({nlp_score}%){terms}")
    elif content >= 15:
        terms = f": {', '.join(flagged_terms[:3])}" if flagged_terms else ""
        add_reason(f"Possible phishing language ({nlp_score}%){terms}")

    if network >= 8:
        primary_ip = ip_result.get("primary_ip")
        isp = str(ip_result.get("geo", {}).get("isp", "Unknown"))
        add_reason(f"Risky sending network ({primary_ip or 'unknown'}) associated with {isp}")

    # URL evidence
    if url >= 5:
        url_evidence = url_data.get("url_evidence", [])
        for ev in url_evidence[:3]:
            add_reason(str(ev))
        mal_count = int(url_data.get("malicious_url_count", 0) or 0)
        sus_count = int(url_data.get("suspicious_url_count", 0) or 0)
        if mal_count and not has_reason_token("malicious url"):
            add_reason(f"{mal_count} malicious URL(s) detected in email body")
        elif sus_count and not has_reason_token("suspicious url"):
            add_reason(f"{sus_count} suspicious URL(s) detected in email body")

    if not reasons:
        if auth_passes >= 2 and nlp_score < 50 and ip_score < 35:
            add_reason("No strong malicious evidence found; authentication and content signals look benign")
        else:
            add_reason("No strong malicious evidence found")

    if risk_score <= 30:
        evidence_level = "LOW"
    elif len(evidence_sources) >= 3:
        evidence_level = "STRONG"
    else:
        evidence_level = "MODERATE"

    known_auth_checks = 3 - auth_missing
    analysis_confidence = cap(
        40
        + len(evidence_sources) * 10
        + known_auth_checks * 8
        + (8 if ip_result.get("primary_ip") else 0),
        100,
    )

    return {
        "risk_score": risk_score,
        "classification": classification,
        "evidence_level": evidence_level,
        "reasons": reasons,
        "breakdown": {
            "nlp": nlp_score,
            "header": header_score,
            "ip": ip_score,
            "url": url_score_raw,
        },
        "risk_metrics": {
            "content": content,
            "authentication": authentication,
            "identity": identity,
            "domain": domain,
            "network": network,
            "url": url,
            "synergy": synergy,
            "evidence_sources": evidence_sources,
            "auth_passes": auth_passes,
            "auth_failures": auth_failures,
            "auth_missing": auth_missing,
            "flagged_term_count": len(flagged_terms),
            "analysis_confidence": analysis_confidence,
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
