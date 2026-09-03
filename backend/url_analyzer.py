"""
URL Analyzer Module

Performs explainable URL phishing analysis on URLs extracted from .eml emails.
Extracts URLs from HTML href/anchor, img src, and plain-text bodies, normalizes
them via public-suffix-aware domain parsing (tldextract), and evaluates 14+
phishing detection signals — each classified as strong, moderate, or weak —
to produce per-URL scores and an aggregate risk assessment.
"""

from __future__ import annotations

import html as html_module
import ipaddress
import re
import os
import requests
from urllib.parse import urlparse, unquote, parse_qs

from bs4 import BeautifulSoup
from dotenv import load_dotenv
from pydantic import BaseModel, Field
import tldextract

load_dotenv("/workspaces/AI-Email-Threat-Detector/.env")

def lookup_url_virustotal(url: str) -> dict:
    """Look up a URL in VirusTotal and return reputation evidence."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "available": False,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "message": "VirusTotal API key not configured",
        }

    try:
        import base64

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=5,
        )

        if response.status_code != 200:
            return {
                "available": False,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "message": f"VirusTotal HTTP {response.status_code}",
            }

        data = response.json().get("data", {})
        stats = data.get("attributes", {}).get("last_analysis_stats", {})

        return {
            "available": True,
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "message": "VirusTotal lookup successful",
        }

    except Exception as exc:
        return {
            "available": False,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "message": f"VirusTotal lookup failed: {exc}",
        }


_TLD_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    fallback_to_snapshot=True,
)


# ═══════════════════════════════════════════════════════════════════════════
#  Configurable Brand Database (MVP)
# ═══════════════════════════════════════════════════════════════════════════

BRAND_DB: dict[str, dict] = {
    "paypal":    {"domains": {"paypal.com", "paypal.me"}},
    "microsoft": {"domains": {"microsoft.com", "microsoftonline.com",
                              "office.com", "live.com", "outlook.com",
                              "hotmail.com", "office365.com"}},
    "google":    {"domains": {"google.com", "gmail.com", "youtube.com",
                              "googleapis.com"}},
    "apple":     {"domains": {"apple.com", "icloud.com"}},
    "amazon":    {"domains": {"amazon.com", "amazonaws.com"}},
    "docusign":  {"domains": {"docusign.com", "docusign.net"}},
    "netflix":   {"domains": {"netflix.com"}},
    "chase":     {"domains": {"chase.com"}},
    "facebook":  {"domains": {"facebook.com", "fb.com", "meta.com"}},
    "dropbox":   {"domains": {"dropbox.com"}},
    "linkedin":  {"domains": {"linkedin.com"}},
}

# Reverse-lookup: registrable domain → brand name
_DOMAIN_TO_BRAND: dict[str, str] = {}
for _brand, _info in BRAND_DB.items():
    for _d in _info["domains"]:
        _DOMAIN_TO_BRAND[_d] = _brand


# ═══════════════════════════════════════════════════════════════════════════
#  Known URL Shortener Domains
# ═══════════════════════════════════════════════════════════════════════════

URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bl.ink", "lnkd.in", "db.tt", "qr.ae",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "v.gd",
    "t.ly", "s.id", "clck.ru", "u.to", "0rz.tw",
}


# ═══════════════════════════════════════════════════════════════════════════
#  Homoglyph / Lookalike Mapping
# ═══════════════════════════════════════════════════════════════════════════

HOMOGLYPH_MAP: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "!": "i", "|": "l",
    # Cyrillic confusables
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x",
    # Latin-like
    "\u0131": "i", "\u1e37": "l",
}

HOMOGLYPH_MAP_ALT: dict[str, str] = {
    **HOMOGLYPH_MAP,
    "1": "i",  # alternate mapping
}


# ═══════════════════════════════════════════════════════════════════════════
#  Redirect Parameter Names
# ═══════════════════════════════════════════════════════════════════════════

REDIRECT_PARAMS: set[str] = {
    "url", "redirect", "next", "return", "continue", "goto",
    "returnurl", "redirect_uri", "return_url", "target", "dest",
    "destination", "redir", "link", "forward", "callback",
}


# ═══════════════════════════════════════════════════════════════════════════
#  Suspicious Path Keywords
# ═══════════════════════════════════════════════════════════════════════════

SUSPICIOUS_PATH_KEYWORDS: list[str] = [
    "login", "signin", "sign-in", "verify", "verification",
    "account", "secure", "update", "confirm", "password",
    "credential", "billing", "payment", "invoice", "suspend",
    "unlock", "restore", "reactivate",
]


# ═══════════════════════════════════════════════════════════════════════════
#  Signal Strengths & Points
# ═══════════════════════════════════════════════════════════════════════════

class SignalStrength:
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


SIGNAL_DEFS: dict[str, dict] = {
    "raw_ip_url":           {"strength": SignalStrength.STRONG,   "points": 25},
    "credentials_in_url":   {"strength": SignalStrength.STRONG,   "points": 30},
    "brand_impersonation":  {"strength": SignalStrength.STRONG,   "points": 30},
    "homoglyph_domain":     {"strength": SignalStrength.STRONG,   "points": 25},
    "anchor_mismatch":      {"strength": SignalStrength.STRONG,   "points": 30},
    "http_no_tls":          {"strength": SignalStrength.WEAK,     "points": 8},
    "suspicious_port":      {"strength": SignalStrength.MODERATE, "points": 15},
    "url_shortener":        {"strength": SignalStrength.MODERATE, "points": 12},
    "redirect_param":       {"strength": SignalStrength.MODERATE, "points": 10},
    "punycode_idn":         {"strength": SignalStrength.MODERATE, "points": 15},
    "excessive_subdomains": {"strength": SignalStrength.WEAK,     "points": 8},
    "suspicious_length":    {"strength": SignalStrength.WEAK,     "points": 5},
    "suspicious_encoding":  {"strength": SignalStrength.WEAK,     "points": 8},
    "suspicious_path":      {"strength": SignalStrength.WEAK,     "points": 8},
}

# Weak-signal-only cap: prevents MALICIOUS from weak heuristics alone
WEAK_ONLY_SCORE_CAP = 40


# ═══════════════════════════════════════════════════════════════════════════
#  Pydantic Models
# ═══════════════════════════════════════════════════════════════════════════

class URLDetection(BaseModel):
    """A single triggered detection signal."""
    signal: str
    strength: str
    points: int
    explanation: str


class URLFinding(BaseModel):
    """Per-URL analysis result."""
    original_url: str
    normalized_url: str
    hostname: str = ""
    registrable_domain: str = ""
    anchor_text: str | None = None
    detections: list[URLDetection] = Field(default_factory=list)
    risk_score: int = 0
    classification: str = "SAFE"  # SAFE | SUSPICIOUS | MALICIOUS
    virustotal: dict = Field(default_factory=dict)

class URLAnalysisResult(BaseModel):
    """Aggregate result across all URLs found in the email."""
    url_count: int = 0
    suspicious_url_count: int = 0
    malicious_url_count: int = 0
    url_risk_score: int = 0
    urls: list[URLFinding] = Field(default_factory=list)
    url_evidence: list[str] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
#  URL Extraction
# ═══════════════════════════════════════════════════════════════════════════

# Regex for extracting bare URLs from plain text
_URL_RE = re.compile(
    r"https?://[^\s<>\"'\)\]},;]+",
    re.IGNORECASE,
)


def _extract_urls_from_html(html_content: str) -> list[dict]:
    """
    Extract URLs from HTML content, capturing:
    - <a href="...">anchor text</a>
    - <img src="...">
    Returns list of {"url": str, "anchor_text": str|None, "source": str}
    """
    if not html_content:
        return []

    results: list[dict] = []
    seen_urls: set[str] = set()

    soup = BeautifulSoup(html_content, "html.parser")

    # <a> tags with href
    for tag in soup.find_all("a", href=True):
        href = str(tag["href"]).strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        anchor = tag.get_text(strip=True) or None
        if href not in seen_urls:
            seen_urls.add(href)
            results.append({"url": href, "anchor_text": anchor, "source": "html_href"})

    # <img> tags with src
    for tag in soup.find_all("img", src=True):
        src = str(tag["src"]).strip()
        if src.startswith(("data:", "cid:")):
            continue
        if src not in seen_urls and src.startswith(("http://", "https://")):
            seen_urls.add(src)
            results.append({"url": src, "anchor_text": None, "source": "html_img"})

    return results


def _extract_urls_from_text(text: str) -> list[dict]:
    """
    Extract bare URLs from plain-text content.
    Returns list of {"url": str, "anchor_text": None, "source": "plaintext"}
    """
    if not text:
        return []

    results: list[dict] = []
    seen: set[str] = set()

    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;:!?)")
        if url not in seen:
            seen.add(url)
            results.append({"url": url, "anchor_text": None, "source": "plaintext"})

    return results


def extract_urls_from_email(parsed_email: dict) -> list[dict]:
    """
    Extract all URLs from a parsed email dict (as returned by email_parser.parse_email).
    Examines both HTML parts and the plain-text body.

    Returns deduplicated list of {"url": str, "anchor_text": str|None, "source": str}
    """
    results: list[dict] = []
    seen_urls: set[str] = set()

    def _add(entries: list[dict]):
        for entry in entries:
            url = entry["url"]
            if url not in seen_urls:
                seen_urls.add(url)
                results.append(entry)
            elif entry.get("anchor_text"):
                # Update anchor text if we found a richer version
                for existing in results:
                    if existing["url"] == url and not existing.get("anchor_text"):
                        existing["anchor_text"] = entry["anchor_text"]
                        break

    # Try to get raw HTML parts from the email for richer extraction.
    # The existing parser only returns cleaned text in the "body" field,
    # but if raw_html is available, use it.
    raw_html = parsed_email.get("raw_html", "")
    if raw_html:
        _add(_extract_urls_from_html(raw_html))

    # Always check the body text (plain or cleaned HTML → text)
    body = parsed_email.get("body", "")
    if body:
        _add(_extract_urls_from_text(body))

    return results


# ═══════════════════════════════════════════════════════════════════════════
#  URL Normalization
# ═══════════════════════════════════════════════════════════════════════════

def normalize_url(raw_url: str) -> str:
    """
    Normalize a URL for safe analysis:
    1. HTML entity decoding
    2. Whitespace stripping
    3. Percent-encoding normalization (decode unreserved chars)
    4. Lowercase scheme and hostname
    """
    if not raw_url:
        return ""

    # HTML entity decode
    url = html_module.unescape(raw_url.strip())

    # Parse
    parsed = urlparse(url)

    # Lowercase scheme and hostname
    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower() if parsed.hostname else ""

    # Reconstruct netloc (handle port)
    port = parsed.port
    if port and port not in (80, 443):
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    # Re-include userinfo if present (for detection purposes)
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        netloc = f"{userinfo}@{netloc}"

    # Normalize path percent encoding
    path = _normalize_percent_encoding(parsed.path)
    query = parsed.query
    fragment = parsed.fragment

    # Rebuild
    normalized = f"{scheme}://{netloc}{path}"
    if query:
        normalized += f"?{query}"
    if fragment:
        normalized += f"#{fragment}"

    return normalized


def _normalize_percent_encoding(s: str) -> str:
    """Decode percent-encoded unreserved characters (RFC 3986 §2.3)."""
    unreserved = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    result = []
    i = 0
    while i < len(s):
        if s[i] == "%" and i + 2 < len(s):
            hex_chars = s[i + 1:i + 3]
            try:
                char = chr(int(hex_chars, 16))
                if char in unreserved:
                    result.append(char)
                else:
                    result.append(f"%{hex_chars.upper()}")
                i += 3
                continue
            except ValueError:
                pass
        result.append(s[i])
        i += 1
    return "".join(result)


def get_registrable_domain(hostname: str) -> str:
    """
    Return the registrable domain using tldextract (public-suffix-aware).
    e.g. 'paypal.com.attacker.com' → 'attacker.com'
         'login.paypal.com' → 'paypal.com'
    """
    if not hostname:
        return ""
    ext = _TLD_EXTRACT(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return hostname.lower()


# ═══════════════════════════════════════════════════════════════════════════
#  Detection Logic
# ═══════════════════════════════════════════════════════════════════════════

def _is_ip_address(hostname: str) -> bool:
    """Check if the hostname is a raw IP address."""
    if not hostname:
        return False
    # Strip brackets from IPv6
    clean = hostname.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def _apply_homoglyph(s: str, mapping: dict[str, str]) -> str:
    """Replace homoglyph characters in a string using the given mapping."""
    return "".join(mapping.get(c, c) for c in s)


def _detect_signals(
    url: str,
    parsed: object,  # urlparse result
    hostname: str,
    registrable_domain: str,
    anchor_text: str | None,
) -> list[URLDetection]:
    """Run all detection checks on a single URL. Returns list of detections."""
    detections: list[URLDetection] = []

    def _add(signal_name: str, explanation: str):
        sig = SIGNAL_DEFS[signal_name]
        detections.append(URLDetection(
            signal=signal_name,
            strength=sig["strength"],
            points=sig["points"],
            explanation=explanation,
        ))

    # 1. Raw IP URL
    if _is_ip_address(hostname):
        _add("raw_ip_url", f"URL uses raw IP address ({hostname}) instead of a domain name")

    # 2. HTTP (no TLS)
    if parsed.scheme == "http":
        _add("http_no_tls", "URL uses unencrypted HTTP instead of HTTPS")

    # 3. Suspicious port
    if parsed.port and parsed.port not in (80, 443, None):
        _add("suspicious_port", f"URL uses non-standard port {parsed.port}")

    # 4. Credentials in URL
    if parsed.username:
        _add("credentials_in_url",
             f"URL contains embedded credentials (username: {parsed.username})")

    # 5. Excessive subdomains
    if hostname and not _is_ip_address(hostname):
        labels = hostname.split(".")
        if len(labels) >= 5:
            _add("excessive_subdomains",
                 f"URL hostname has {len(labels)} labels ({hostname}), suggesting obfuscation")

    # 6. Suspicious URL length
    if len(url) > 100:
        _add("suspicious_length",
             f"URL is unusually long ({len(url)} characters)")

    # 7. Suspicious percent encoding
    if url:
        encoded_chars = url.count("%")
        if len(url) > 0 and encoded_chars > 0:
            ratio = encoded_chars / len(url)
            if ratio > 0.15 or encoded_chars > 10:
                _add("suspicious_encoding",
                     f"URL contains excessive percent-encoding ({encoded_chars} encoded sequences)")

    # 8. URL shortener
    if registrable_domain in URL_SHORTENERS or hostname in URL_SHORTENERS:
        _add("url_shortener",
             f"URL uses known shortener service ({hostname})")

    # 9. Redirect parameters
    if parsed.query:
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        matched_params = [
            p for p in query_params
            if p.lower() in REDIRECT_PARAMS
        ]
        if matched_params:
            _add("redirect_param",
                 f"URL contains redirect parameter(s): {', '.join(matched_params)}")

    # 10. Brand impersonation (brand name in domain but wrong registrable domain)
    if hostname and not _is_ip_address(hostname):
        hostname_lower = hostname.lower()
        for brand, info in BRAND_DB.items():
            if brand in hostname_lower:
                # Check if the registrable domain is one of the brand's legitimate domains
                if registrable_domain not in info["domains"]:
                    _add("brand_impersonation",
                         f"Brand '{brand}' appears in hostname '{hostname}' "
                         f"but registrable domain is '{registrable_domain}' "
                         f"(not an official {brand} domain)")
                    break  # one brand match is enough

    # 11. Homoglyph / lookalike domain detection
    if hostname and not _is_ip_address(hostname) and registrable_domain:
        ext = _TLD_EXTRACT(hostname)
        domain_label = ext.domain.lower() if ext.domain else ""
        if domain_label:
            # Check if the domain label, after homoglyph substitution, matches a brand
            variant1 = _apply_homoglyph(domain_label, HOMOGLYPH_MAP)
            variant2 = _apply_homoglyph(domain_label, HOMOGLYPH_MAP_ALT)
            for brand, info in BRAND_DB.items():
                if domain_label == brand:
                    # Exact match — only flag if the registrable domain is wrong
                    # (handled by brand_impersonation above)
                    continue
                if brand in (variant1, variant2) and registrable_domain not in info["domains"]:
                    # The domain label is a homoglyph of a brand
                    already_flagged = any(d.signal == "brand_impersonation" for d in detections)
                    if not already_flagged:
                        _add("homoglyph_domain",
                             f"Domain '{domain_label}' is a lookalike/homoglyph "
                             f"of '{brand}' (resolved: '{variant1}')")
                    break

    # 12. Punycode / IDN domain
    if hostname:
        if hostname.startswith("xn--") or any(
            label.startswith("xn--") for label in hostname.split(".")
        ):
            _add("punycode_idn",
                 f"URL uses internationalized domain name (Punycode: {hostname})")

    # 13. Suspicious path keywords
    path_lower = (parsed.path or "").lower()
    matched_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path_lower]
    if matched_keywords:
        _add("suspicious_path",
             f"URL path contains sensitive keyword(s): {', '.join(matched_keywords[:3])}")

    # 14. Anchor text vs destination mismatch
    if anchor_text:
        anchor_clean = anchor_text.strip()
        # Check if anchor looks like a URL
        anchor_url_match = _URL_RE.match(anchor_clean)
        if anchor_url_match:
            anchor_parsed = urlparse(anchor_clean)
            anchor_host = (anchor_parsed.hostname or "").lower()
            anchor_reg_domain = get_registrable_domain(anchor_host)
            if anchor_reg_domain and registrable_domain and anchor_reg_domain != registrable_domain:
                _add("anchor_mismatch",
                     f"Anchor text shows '{anchor_host}' but URL destination is "
                     f"'{hostname}' (domain mismatch: {anchor_reg_domain} != {registrable_domain})")
        else:
            # Check if anchor text contains a well-known brand that doesn't match dest
            anchor_lower = anchor_clean.lower()
            for brand, info in BRAND_DB.items():
                if brand in anchor_lower and registrable_domain not in info["domains"]:
                    # Anchor claims to be a brand but URL goes elsewhere
                    _add("anchor_mismatch",
                         f"Anchor text mentions '{brand}' but URL destination is "
                         f"'{hostname}' ({registrable_domain})")
                    break

    return detections


# ═══════════════════════════════════════════════════════════════════════════
#  Per-URL Scoring & Classification
# ═══════════════════════════════════════════════════════════════════════════

def _score_url(detections: list[URLDetection]) -> tuple[int, str]:
    """
    Calculate risk score and classification for a single URL.
    Weak-signal-only results are capped to prevent false MALICIOUS labels.

    Returns (score, classification).
    """
    if not detections:
        return 0, "SAFE"

    total = sum(d.points for d in detections)
    has_strong = any(d.strength == SignalStrength.STRONG for d in detections)
    has_moderate = any(d.strength == SignalStrength.MODERATE for d in detections)

    # Cap if only weak signals
    if not has_strong and not has_moderate:
        total = min(total, WEAK_ONLY_SCORE_CAP)

    total = max(0, min(100, total))

    if total <= 25:
        classification = "SAFE"
    elif total <= 60:
        classification = "SUSPICIOUS"
    else:
        classification = "MALICIOUS"

    return total, classification


# ═══════════════════════════════════════════════════════════════════════════
#  Main Analysis Entry Point
# ═══════════════════════════════════════════════════════════════════════════

def analyze_urls(parsed_email: dict) -> dict:
    """
    Analyze all URLs found in a parsed email.

    Args:
        parsed_email: dict as returned by email_parser.parse_email()

    Returns:
        dict matching URLAnalysisResult shape, ready for merging into API response.
    """
    raw_entries = extract_urls_from_email(parsed_email)

    findings: list[URLFinding] = []
    evidence: list[str] = []
    max_score = 0

    for entry in raw_entries:
        raw_url = entry["url"]
        anchor_text = entry.get("anchor_text")

        # Normalize
        normalized = normalize_url(raw_url)
        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").lower() if parsed.hostname else ""
        registrable_domain = get_registrable_domain(hostname)

        # Detect signals
        detections = _detect_signals(
            url=normalized,
            parsed=parsed,
            hostname=hostname,
            registrable_domain=registrable_domain,
            anchor_text=anchor_text,
        )

        # Score
        score, classification = _score_url(detections)

        virustotal = lookup_url_virustotal(normalized)

        if virustotal.get("available"):
            malicious = virustotal.get("malicious", 0)
            suspicious = virustotal.get("suspicious", 0)

            if malicious >= 3:
                score += 40
            elif suspicious >= 3:
                score += 20

            score = min(100, score)

            if score <= 25:
                classification = "SAFE"
            elif score <= 60:
                classification = "SUSPICIOUS"
            else:
                classification = "MALICIOUS"

        max_score = max(max_score, score)

        finding = URLFinding(
            original_url=raw_url,
            normalized_url=normalized,
            hostname=hostname,
            registrable_domain=registrable_domain,
            anchor_text=anchor_text,
            detections=detections,
            risk_score=score,
            classification=classification,
            virustotal=virustotal,
        )
        findings.append(finding)

        # Collect evidence strings
        if classification in ("SUSPICIOUS", "MALICIOUS"):
            for det in detections:
                ev = f"[URL] {det.explanation}"
                if ev not in evidence:
                    evidence.append(ev)

    suspicious_count = sum(1 for f in findings if f.classification == "SUSPICIOUS")
    malicious_count = sum(1 for f in findings if f.classification == "MALICIOUS")

    result = URLAnalysisResult(
        url_count=len(findings),
        suspicious_url_count=suspicious_count,
        malicious_url_count=malicious_count,
        url_risk_score=max_score,
        urls=findings,
        url_evidence=evidence,
    )

    return result.model_dump()


# ═══════════════════════════════════════════════════════════════════════════
#  Convenience: Analyze a single URL (for testing / direct use)
# ═══════════════════════════════════════════════════════════════════════════

def analyze_single_url(url: str, anchor_text: str | None = None) -> dict:
    """
    Analyze a single URL string. Useful for unit tests and direct invocations.
    Returns a URLFinding dict.
    """
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower() if parsed.hostname else ""
    registrable_domain = get_registrable_domain(hostname)

    detections = _detect_signals(
        url=normalized,
        parsed=parsed,
        hostname=hostname,
        registrable_domain=registrable_domain,
        anchor_text=anchor_text,
    )

    score, classification = _score_url(detections)

    virustotal = lookup_url_virustotal(normalized)

    if virustotal.get("available"):
        malicious = virustotal.get("malicious", 0)
        suspicious = virustotal.get("suspicious", 0)

        if malicious >= 3:
            score += 40
        elif suspicious >= 3:
            score += 20

        score = min(100, score)

        if score <= 25:
            classification = "SAFE"
        elif score <= 60:
            classification = "SUSPICIOUS"
        else:
            classification = "MALICIOUS"

    finding = URLFinding(
        original_url=url,
        normalized_url=normalized,
        hostname=hostname,
        registrable_domain=registrable_domain,
        anchor_text=anchor_text,
        detections=detections,
        risk_score=score,
        classification=classification,
        virustotal=virustotal,
    )

    return finding.model_dump()


# ═══════════════════════════════════════════════════════════════════════════
#  Standalone Test
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json

    test_urls = [
        ("https://www.paypal.com/account/activity", None),
        ("https://paypal.com.attacker.com/login", None),
        ("https://paypal-login.attacker.com/verify", None),
        ("https://paypa1.com/login", None),
        ("http://185.123.45.67/steal-creds", None),
        ("https://bit.ly/3xPhish", None),
        ("http://evil.com/phish", "https://www.paypal.com/login"),
        ("https://docs.google.com/spreadsheets/d/abc123", None),
    ]

    for url, anchor in test_urls:
        result = analyze_single_url(url, anchor)
        print(f"\n{'='*60}")
        print(f"URL: {url}")
        if anchor:
            print(f"Anchor: {anchor}")
        print(f"Score: {result['risk_score']} -> {result['classification']}")
        for det in result["detections"]:
            print(f"  [{det['strength'].upper()}] {det['signal']}: {det['explanation']}")
