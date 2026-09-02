"""
Header Analyzer Module

Analyzes email headers for:
- Email authentication failures (SPF, DKIM, DMARC)
- Sender identity spoofing (From vs Reply-To vs Return-Path mismatch)
- Display name impersonation (e.g. "PayPal Support" from an unrelated domain)
- Domain lookalikes, typosquatting, and suspicious TLDs
- Domain age / newly registered domain detection via RDAP
- Calculates a weighted header risk score (0-100) and anomalies list.
"""

import json
import re
import urllib.request
import urllib.error
import email.utils
from datetime import datetime
from functools import lru_cache

# Fallback lookup table for demo consistency
DEMO_WHOIS_FALLBACK = {
    "company-payments.xyz": 3,
    "paypa1-security.xyz": 2,
    "evil.xyz": 1,
    "paypal.com": 9000,
    "example.com": 10000,
    "gmail.com": 10000,
    "microsoft.com": 11000,
    "google.com": 10000,
    "apple.com": 12000,
    "amazon.com": 10500,
}

# High-profile brands frequently targeted by phishing
TARGETED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "chase", "bankofamerica", "wellsfargo", "dhl", "fedex", "ups",
    "docusign", "irs", "facebook", "instagram", "linkedin", "dropbox",
    "coinbase", "binance", "metamask", "whatsapp", "adobe"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".online", ".site", ".buzz", ".work",
    ".icu", ".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov",
    ".fit", ".cfd", ".sbs", ".rest"
]


def extract_email_address(raw_header: str) -> tuple[str, str, str]:
    """
    Parses an RFC-822 header like 'PayPal Support <support@paypal.com>'
    Returns (display_name, email_address, domain).
    """
    if not raw_header:
        return ("", "", "")

    display_name, addr = email.utils.parseaddr(str(raw_header))
    addr = addr.strip().lower()
    display_name = display_name.strip()

    domain = ""
    if "@" in addr:
        domain = addr.split("@")[-1].strip().lower()

    return (display_name, addr, domain)


@lru_cache(maxsize=256)
def get_domain_age_days(domain: str) -> int | None:
    """
    Attempts to find the age of a domain in days.
    Checks demo cache first, then tries live RDAP lookup with a 2-second timeout.
    """
    if not domain:
        return None

    # 1. Safety fallback table for demo stability
    if domain in DEMO_WHOIS_FALLBACK:
        return DEMO_WHOIS_FALLBACK[domain]

    # 2. Attempt live RDAP (RFC 7482 / 9082) lookup
    try:
        url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "AIEmailThreatDetector/1.0"}
        )
        with urllib.request.urlopen(req, timeout=2.0) as response:
            data = json.loads(response.read().decode())
            for event in data.get("events", []):
                if event.get("eventAction") in ("registration", "transfer"):
                    reg_date_str = event.get("eventDate")
                    if reg_date_str:
                        reg_date = datetime.strptime(reg_date_str[:10], "%Y-%m-%d")
                        delta = datetime.utcnow() - reg_date
                        return max(0, delta.days)
    except Exception:
        # Graceful failure on timeout, rate limit, or invalid domain
        pass

    return None


def detect_domain_lookalike(domain: str, display_name: str) -> tuple[bool, str | None]:
    """
    Detects typosquatting, digit substitutions, brand impersonation,
    or suspicious TLDs on a domain.
    """
    if not domain:
        return (False, None)

    domain_lower = domain.lower()
    parts = domain_lower.split(".")
    base_domain = parts[0] if parts else ""

    # Heuristic 1: Brand name in subdomain (e.g. paypal.com.security-verify.xyz)
    for brand in TARGETED_BRANDS:
        if brand in domain_lower and not domain_lower.endswith(f"{brand}.com") and not domain_lower.endswith(f"{brand}.org"):
            return (True, f"Brand '{brand}' detected in untrusted domain '{domain}'")

    # Heuristic 2: Digit-for-letter substitution in base domain (paypa1, g00gle, micros0ft)
    if re.search(r"[a-z]+[0-9]+[a-z]*|[a-z]*[0-9]+[a-z]+", base_domain):
        # Check if substituting numbers with letters resembles a targeted brand
        variants = {
            base_domain.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})),
            base_domain.translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})),
        }
        for brand in TARGETED_BRANDS:
            if any(brand in variant or brand == variant for variant in variants):
                return (True, f"Typosquatting/homoglyph detected mimicking '{brand}' ({domain})")
        return (True, f"Suspicious alphanumeric substitution in domain name ({domain})")

    # Heuristic 3: Display name claims to be a brand, but sender domain does not match
    if display_name:
        display_lower = display_name.lower()
        for brand in TARGETED_BRANDS:
            if brand in display_lower:
                if not (domain_lower == f"{brand}.com" or domain_lower.endswith(f".{brand}.com")):
                    return (True, f"Display name '{display_name}' impersonates '{brand}' but domain is '{domain}'")

    # Heuristic 4: Suspicious / Disposable / High-abuse TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            return (True, f"Suspicious high-risk top-level domain ({tld})")

    return (False, None)


def header_value(raw_headers: dict, header_name: str) -> str:
    """
    Fetch a header value case-insensitively from parser-normalized headers.
    """
    header_name = header_name.lower()
    for key, value in raw_headers.items():
        if key.lower() == header_name:
            return str(value)
    return ""


def parse_authentication_results(raw_headers: dict) -> tuple[str, str, str]:
    """
    Extracts SPF, DKIM, and DMARC status from Authentication-Results,
    Received-SPF, or ARC-Authentication-Results headers.
    """
    spf = "none"
    dkim = "none"
    dmarc = "none"

    # 1. Inspect Authentication-Results header
    auth_results = header_value(raw_headers, "Authentication-Results")
    arc_results = header_value(raw_headers, "ARC-Authentication-Results")
    all_auth = f"{auth_results} {arc_results}"

    if all_auth.strip():
        spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", all_auth, re.IGNORECASE)
        dkim_match = re.search(r"dkim=(pass|fail|neutral|none|temperror|permerror)", all_auth, re.IGNORECASE)
        dmarc_match = re.search(r"dmarc=(pass|fail|neutral|none|temperror|permerror)", all_auth, re.IGNORECASE)

        if spf_match:
            spf = spf_match.group(1).lower()
        if dkim_match:
            dkim = dkim_match.group(1).lower()
        if dmarc_match:
            dmarc = dmarc_match.group(1).lower()

    # 2. Check Received-SPF header if SPF still none or missing
    if spf == "none":
        received_spf = header_value(raw_headers, "Received-SPF")
        if received_spf:
            r_match = re.search(r"^(pass|fail|softfail|neutral|none)", received_spf.strip(), re.IGNORECASE)
            if r_match:
                spf = r_match.group(1).lower()

    return (spf, dkim, dmarc)


def analyze(parsed_email: dict) -> dict:
    """
    Analyzes email headers for spoofing, authentication failures,
    domain reputation, and lookalike domains.
    """
    raw_headers = parsed_email.get("raw_headers", {})
    from_header = parsed_email.get("from", "")
    reply_to_header = parsed_email.get("reply_to", "")
    return_path_header = parsed_email.get("return_path", "")

    # 1. Parse email addresses and domains
    display_name, from_addr, from_domain = extract_email_address(from_header)
    _, reply_addr, reply_domain = extract_email_address(reply_to_header)
    _, return_addr, return_domain = extract_email_address(return_path_header)

    # 2. Extract Authentication (SPF, DKIM, DMARC)
    spf, dkim, dmarc = parse_authentication_results(raw_headers)

    # 3. Sender Identity Mismatch Checks
    sender_reply_mismatch = False
    anomalies = []
    header_risk_score = 0

    if reply_domain and from_domain and reply_domain != from_domain:
        sender_reply_mismatch = True
        anomalies.append(f"Sender identity mismatch: From ({from_domain}) vs Reply-To ({reply_domain})")
        header_risk_score += 30

    if return_domain and from_domain and return_domain != from_domain:
        # Return-Path envelope mismatch
        anomalies.append(f"Envelope sender mismatch: From ({from_domain}) vs Return-Path ({return_domain})")
        header_risk_score += 15

    # 4. Domain Lookalike & Brand Impersonation
    domain_lookalike, lookalike_reason = detect_domain_lookalike(from_domain, display_name)
    if domain_lookalike:
        anomalies.append(lookalike_reason or "Domain lookalike detected (suspicious TLD or typosquatting)")
        header_risk_score += 40

    # 5. Domain Age Lookup
    domain_age_days = get_domain_age_days(from_domain) if from_domain else None
    if domain_age_days is not None and domain_age_days < 30:
        anomalies.append(f"Newly registered domain (only {domain_age_days} day{'s' if domain_age_days != 1 else ''} old)")
        header_risk_score += 30

    # 6. Authentication Failures Scoring
    if spf in ("fail", "softfail"):
        anomalies.append(f"SPF authentication failed ({spf})")
        header_risk_score += 20

    if dkim == "fail":
        anomalies.append("DKIM cryptographic signature verification failed")
        header_risk_score += 20

    if dmarc in ("fail", "softfail"):
        anomalies.append("DMARC policy check failed")
        header_risk_score += 20

    # Cap score at 100
    header_risk_score = max(0, min(100, header_risk_score))

    # Normalize output format matching the contract
    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "sender_reply_mismatch": sender_reply_mismatch,
        "domain_lookalike": domain_lookalike,
        "domain_age_days": domain_age_days,
        "anomalies": anomalies,
        "header_risk_score": header_risk_score,
    }


if __name__ == "__main__":
    test_parsed = {
        "from": '"PayPal Security" <service@company-payments.xyz>',
        "to": "victim@example.com",
        "subject": "URGENT: Outstanding Invoice",
        "reply_to": "payments.help@gmail.com",
        "return_path": "bounce@evil.xyz",
        "raw_headers": {
            "Authentication-Results": "spf=fail dkim=fail dmarc=fail"
        },
        "received_chain": ["Received: from mail.evil.xyz by mx.google.com"]
    }
    res = analyze(test_parsed)
    print("Header analyzer result:")
    print(json.dumps(res, indent=2))
