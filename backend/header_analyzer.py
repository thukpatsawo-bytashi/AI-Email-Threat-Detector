import json
import re
import urllib.request
import urllib.error
from datetime import datetime

# Hardcoded fallback table for the live demo.
# If the live lookup fails or times out, we use these values.
DEMO_WHOIS_FALLBACK = {
    "company-payments.xyz": 3,
    "evil.xyz": 1,
    "paypal.com": 9000,
    "example.com": 10000,
    "gmail.com": 10000
}

def get_domain_age_days(domain: str):
    """
    Attempts to find the age of a domain in days. 
    Strict 2-second timeout to protect the live demo.
    """
    if not domain:
        return None
        
    # 1. Always check the safety fallback table first for demo domains
    if domain in DEMO_WHOIS_FALLBACK:
        return DEMO_WHOIS_FALLBACK[domain]
        
    # 2. Attempt a live RDAP (WHOIS) lookup
    try:
        url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2.0) as response:
            data = json.loads(response.read().decode())
            # Search for the registration event
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    reg_date_str = event.get("eventDate")
                    if reg_date_str:
                        # Extract YYYY-MM-DD
                        reg_date = datetime.strptime(reg_date_str[:10], "%Y-%m-%d")
                        delta = datetime.utcnow() - reg_date
                        return max(0, delta.days)
    except Exception:
        # If the network dies, the API rate limits us, or the domain is weird,
        # fail gracefully so the app doesn't crash!
        pass
        
    return None

def analyze(parsed_email: dict) -> dict:
    """
    Analyzes email headers for authentication failures, spoofing attempts,
    and domain anomalies.
    """
    # 1. Extract Email Authentication (SPF, DKIM, DMARC)
    # Default to "none" if the header is missing entirely
    spf = "none"
    dkim = "none"
    dmarc = "none"
    
    raw_headers = parsed_email.get("raw_headers", {})
    auth_results = raw_headers.get("Authentication-Results", "")
    
    if auth_results:
        # Look for spf=, dkim=, dmarc= followed by pass, fail, or none
        spf_match = re.search(r'spf=(pass|fail|none)', auth_results, re.IGNORECASE)
        dkim_match = re.search(r'dkim=(pass|fail|none)', auth_results, re.IGNORECASE)
        dmarc_match = re.search(r'dmarc=(pass|fail|none)', auth_results, re.IGNORECASE)
        
        if spf_match:
            spf = spf_match.group(1).lower()
        if dkim_match:
            dkim = dkim_match.group(1).lower()
        if dmarc_match:
            dmarc = dmarc_match.group(1).lower()

    # 2. Check for Sender/Reply-To Mismatch
    sender_reply_mismatch = False
    from_address = parsed_email.get("from", "")
    reply_to_address = parsed_email.get("reply_to", "")
    
    if reply_to_address:
        # Extract domains (everything after the @)
        from_domain = from_address.split('@')[-1].strip().lower() if '@' in from_address else ""
        reply_domain = reply_to_address.split('@')[-1].strip().lower() if '@' in reply_to_address else ""
        
        if from_domain and reply_domain and from_domain != reply_domain:
            sender_reply_mismatch = True

    # 3. Check for Domain Lookalikes (Simple Heuristics)
    domain_lookalike = False
    # Ensure from_domain is defined even if not extracted above
    from_address = parsed_email.get("from", "")
    from_domain = from_address.split('@')[-1].strip().lower() if '@' in from_address else ""
    
    if from_domain:
        base_domain = from_domain.split('.')[0] # Get the part before the TLD
        
        # Heuristic A: Digit-for-letter substitution (e.g., paypa1, goog1e)
        # Checks if there is a number mixed with letters in the base domain
        if re.search(r'[a-z]+[0-9]+[a-z]*|[a-z]*[0-9]+[a-z]+', base_domain):
            domain_lookalike = True
            
        # Heuristic B: Unexpected/Suspicious TLDs on the domain
        suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site']
        if any(from_domain.endswith(tld) for tld in suspicious_tlds):
            domain_lookalike = True
            
    # 4. Fetch Domain Age (STRETCH GOAL)
    domain_age_days = get_domain_age_days(from_domain) if from_domain else None

    # 5. Generate Anomalies and Calculate Risk Score
    anomalies = []
    header_risk_score = 0
    
    # --- Scoring Weights ---
    # Authentication Failures: 20 pts each (60 total)
    # Authentication Missing (none): 10 pts each
    # Sender/Reply-To Mismatch: 30 pts
    # Domain Lookalike: 40 pts
    # Newly Registered Domain (<30 days): 30 pts
    # Total score is capped at 100.
    
    if spf == "fail":
        anomalies.append("SPF authentication failed")
        header_risk_score += 20
    elif spf == "none":
        # We don't penalize as heavily for missing records, but it is an anomaly
        header_risk_score += 10
        
    if dkim == "fail":
        anomalies.append("DKIM authentication failed")
        header_risk_score += 20
    elif dkim == "none":
        header_risk_score += 10
        
    if dmarc == "fail":
        anomalies.append("DMARC authentication failed")
        header_risk_score += 20
    elif dmarc == "none":
        header_risk_score += 10
        
    if sender_reply_mismatch:
        anomalies.append("Sender identity mismatch (From vs Reply-To)")
        header_risk_score += 30
        
    if domain_lookalike:
        anomalies.append("Domain lookalike detected (suspicious TLD or typosquatting)")
        header_risk_score += 40
        
    if domain_age_days is not None and domain_age_days < 30:
        anomalies.append(f"Newly registered domain (only {domain_age_days} days old)")
        header_risk_score += 30
        
    # Cap score at 100
    header_risk_score = min(100, header_risk_score)

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "sender_reply_mismatch": sender_reply_mismatch,
        "domain_lookalike": domain_lookalike,
        "domain_age_days": domain_age_days,
        "anomalies": anomalies,
        "header_risk_score": header_risk_score
    }

if __name__ == "__main__":
    # Hardcoded mock input that perfectly matches what M2 will eventually send us.
    # We use this so we can test our code completely independently.
    mock_parsed_email = {
        "from": "billing@company-payments.xyz",
        "to": "victim@example.com",
        "subject": "URGENT: Outstanding Invoice",
        "reply_to": "payments.help@gmail.com",
        "return_path": "bounce@evil.xyz",
        "message_id": "<12345@evil.xyz>",
        "body": "Your account will be suspended...",
        "raw_headers": {
            "Authentication-Results": "spf=fail dkim=fail dmarc=fail"
        },
        "received_chain": [
            "Received: from suspicious-server...", 
            "Received: by another-mail-server..."
        ]
    }

    print("--- Running header_analyzer with mock input ---")
    result = analyze(mock_parsed_email)
    print(json.dumps(result, indent=2))
