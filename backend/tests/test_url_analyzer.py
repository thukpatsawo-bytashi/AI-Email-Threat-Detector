"""
Unit Tests for URL Analyzer Module

Tests cover:
- Legitimate brand URLs (PayPal, Google)
- Brand-in-subdomain impersonation (paypal.com.attacker.com)
- Brand-in-label impersonation (paypal-login.attacker.com)
- Homoglyph/lookalike domains (paypa1.com)
- Raw IP-based URLs
- Known URL shorteners
- Anchor text vs destination mismatch
- Normal legitimate URLs
- HTTP-only weak signal isolation
- Redirect parameters
- Credential embedding
- Full email integration via analyze_urls()
"""

import pytest

from url_analyzer import (
    analyze_single_url,
    analyze_urls,
    normalize_url,
    get_registrable_domain,
    extract_urls_from_email,
    _extract_urls_from_html,
    _extract_urls_from_text,
)


# ═══════════════════════════════════════════════════════════════════════════
#  Registrable Domain (tldextract)
# ═══════════════════════════════════════════════════════════════════════════

class TestRegistrableDomain:
    def test_simple_domain(self):
        assert get_registrable_domain("www.paypal.com") == "paypal.com"

    def test_subdomain_attack(self):
        """paypal.com.attacker.com should resolve to attacker.com, NOT paypal.com"""
        assert get_registrable_domain("paypal.com.attacker.com") == "attacker.com"

    def test_deep_subdomain(self):
        assert get_registrable_domain("a.b.c.d.example.com") == "example.com"

    def test_co_uk(self):
        assert get_registrable_domain("login.paypal.co.uk") == "paypal.co.uk"


# ═══════════════════════════════════════════════════════════════════════════
#  URL Normalization
# ═══════════════════════════════════════════════════════════════════════════

class TestNormalization:
    def test_html_entity_decoding(self):
        url = "https://example.com/path?a=1&amp;b=2"
        norm = normalize_url(url)
        assert "&amp;" not in norm
        assert "a=1&b=2" in norm

    def test_lowercase_hostname(self):
        norm = normalize_url("https://WWW.PAYPAL.COM/Account")
        assert "www.paypal.com" in norm

    def test_strips_whitespace(self):
        norm = normalize_url("  https://example.com  ")
        assert norm == "https://example.com"


# ═══════════════════════════════════════════════════════════════════════════
#  Legitimate URLs → SAFE
# ═══════════════════════════════════════════════════════════════════════════

class TestLegitimateURLs:
    def test_paypal_legitimate(self):
        result = analyze_single_url("https://www.paypal.com/account/activity")
        assert result["classification"] == "SAFE"
        assert result["risk_score"] <= 25
        assert result["registrable_domain"] == "paypal.com"

    def test_google_docs_legitimate(self):
        result = analyze_single_url("https://docs.google.com/spreadsheets/d/abc123")
        assert result["classification"] == "SAFE"
        assert result["risk_score"] <= 25

    def test_microsoft_legitimate(self):
        result = analyze_single_url("https://login.microsoftonline.com/common/oauth2")
        assert result["classification"] == "SAFE"
        assert result["risk_score"] == 0

    def test_plain_https(self):
        result = analyze_single_url("https://www.example.com/page")
        assert result["classification"] == "SAFE"
        assert result["risk_score"] <= 25


# ═══════════════════════════════════════════════════════════════════════════
#  Brand Impersonation → SUSPICIOUS / MALICIOUS
# ═══════════════════════════════════════════════════════════════════════════

class TestBrandImpersonation:
    def test_paypal_in_subdomain(self):
        """paypal.com.attacker.com → registrable domain is attacker.com"""
        result = analyze_single_url("https://paypal.com.attacker.com/login")
        assert result["classification"] in ("SUSPICIOUS", "MALICIOUS")
        assert result["risk_score"] > 25
        signals = [d["signal"] for d in result["detections"]]
        assert "brand_impersonation" in signals

    def test_paypal_login_attacker(self):
        """paypal-login.attacker.com → brand in hostname, wrong domain"""
        result = analyze_single_url("https://paypal-login.attacker.com/verify")
        assert result["classification"] in ("SUSPICIOUS", "MALICIOUS")
        signals = [d["signal"] for d in result["detections"]]
        assert "brand_impersonation" in signals

    def test_google_in_subdomain(self):
        result = analyze_single_url("https://google.com.evil.xyz/login")
        assert result["classification"] in ("SUSPICIOUS", "MALICIOUS")
        signals = [d["signal"] for d in result["detections"]]
        assert "brand_impersonation" in signals

    def test_amazon_impersonation(self):
        result = analyze_single_url("https://amazon-security.phishing.com/verify")
        assert result["classification"] in ("SUSPICIOUS", "MALICIOUS")


# ═══════════════════════════════════════════════════════════════════════════
#  Homoglyph / Lookalike Domains
# ═══════════════════════════════════════════════════════════════════════════

class TestHomoglyphs:
    def test_paypa1_lookalike(self):
        """paypa1.com with digit '1' instead of 'l'"""
        result = analyze_single_url("https://paypa1.com/login")
        assert result["risk_score"] > 20
        signals = [d["signal"] for d in result["detections"]]
        assert "homoglyph_domain" in signals

    def test_g00gle_lookalike(self):
        """g00gle with zeros instead of 'o's"""
        result = analyze_single_url("https://g00gle.com/login")
        signals = [d["signal"] for d in result["detections"]]
        assert "homoglyph_domain" in signals

    def test_micros0ft_lookalike(self):
        result = analyze_single_url("https://micros0ft.com/login")
        signals = [d["signal"] for d in result["detections"]]
        assert "homoglyph_domain" in signals


# ═══════════════════════════════════════════════════════════════════════════
#  Raw IP URLs
# ═══════════════════════════════════════════════════════════════════════════

class TestIPUrls:
    def test_ip_http(self):
        result = analyze_single_url("http://185.123.45.67/steal-creds")
        assert result["classification"] in ("SUSPICIOUS", "MALICIOUS")
        signals = [d["signal"] for d in result["detections"]]
        assert "raw_ip_url" in signals

    def test_ip_https(self):
        result = analyze_single_url("https://93.184.216.34/login")
        signals = [d["signal"] for d in result["detections"]]
        assert "raw_ip_url" in signals

    def test_ip_with_port(self):
        result = analyze_single_url("http://185.123.45.67:8080/admin")
        signals = [d["signal"] for d in result["detections"]]
        assert "raw_ip_url" in signals
        assert "suspicious_port" in signals


# ═══════════════════════════════════════════════════════════════════════════
#  URL Shorteners
# ═══════════════════════════════════════════════════════════════════════════

class TestShorteners:
    def test_bitly(self):
        result = analyze_single_url("https://bit.ly/3xPhish")
        signals = [d["signal"] for d in result["detections"]]
        assert "url_shortener" in signals
        assert result["classification"] == "SUSPICIOUS" or result["risk_score"] >= 10

    def test_tinyurl(self):
        result = analyze_single_url("https://tinyurl.com/y4abcdef")
        signals = [d["signal"] for d in result["detections"]]
        assert "url_shortener" in signals

    def test_t_co(self):
        result = analyze_single_url("https://t.co/abc123xyz")
        signals = [d["signal"] for d in result["detections"]]
        assert "url_shortener" in signals


# ═══════════════════════════════════════════════════════════════════════════
#  Anchor / Destination Mismatch
# ═══════════════════════════════════════════════════════════════════════════

class TestAnchorMismatch:
    def test_anchor_url_mismatch(self):
        """Anchor shows paypal.com but URL goes to evil.com"""
        result = analyze_single_url(
            "http://evil.com/steal",
            anchor_text="https://www.paypal.com/login"
        )
        signals = [d["signal"] for d in result["detections"]]
        assert "anchor_mismatch" in signals
        assert result["classification"] in ("SUSPICIOUS", "MALICIOUS")

    def test_anchor_brand_mismatch(self):
        """Anchor text mentions 'PayPal' but URL goes to attacker.com"""
        result = analyze_single_url(
            "https://attacker.com/phish",
            anchor_text="Click here to verify your PayPal account"
        )
        signals = [d["signal"] for d in result["detections"]]
        assert "anchor_mismatch" in signals

    def test_anchor_matches_destination(self):
        """Anchor and destination are the same domain — no mismatch"""
        result = analyze_single_url(
            "https://www.paypal.com/login",
            anchor_text="https://www.paypal.com/login"
        )
        signals = [d["signal"] for d in result["detections"]]
        assert "anchor_mismatch" not in signals


# ═══════════════════════════════════════════════════════════════════════════
#  HTTP-only Weak Signal (Isolation Test)
# ═══════════════════════════════════════════════════════════════════════════

class TestWeakSignalIsolation:
    def test_http_only_stays_safe(self):
        """A single weak signal (HTTP) should NOT escalate beyond SAFE"""
        result = analyze_single_url("http://www.example.com/page")
        assert result["classification"] == "SAFE"
        assert result["risk_score"] <= 25

    def test_weak_signals_capped(self):
        """Multiple weak signals alone should be capped at WEAK_ONLY_SCORE_CAP (40)"""
        # Long HTTP URL with suspicious path (3 weak signals)
        long_path = "/verify/account/login/" + "a" * 80
        result = analyze_single_url(f"http://example.com{long_path}")
        assert result["risk_score"] <= 40


# ═══════════════════════════════════════════════════════════════════════════
#  Redirect Parameters
# ═══════════════════════════════════════════════════════════════════════════

class TestRedirectParams:
    def test_redirect_url_param(self):
        result = analyze_single_url("https://example.com/login?redirect=https://evil.com")
        signals = [d["signal"] for d in result["detections"]]
        assert "redirect_param" in signals

    def test_next_param(self):
        result = analyze_single_url("https://example.com/auth?next=https://evil.com")
        signals = [d["signal"] for d in result["detections"]]
        assert "redirect_param" in signals


# ═══════════════════════════════════════════════════════════════════════════
#  Credentials in URL
# ═══════════════════════════════════════════════════════════════════════════

class TestCredentials:
    def test_userinfo_in_url(self):
        result = analyze_single_url("https://admin:password@evil.com/panel")
        signals = [d["signal"] for d in result["detections"]]
        assert "credentials_in_url" in signals
        assert result["risk_score"] >= 25


# ═══════════════════════════════════════════════════════════════════════════
#  URL Extraction
# ═══════════════════════════════════════════════════════════════════════════

class TestExtraction:
    def test_extract_from_text(self):
        text = "Visit https://example.com/page and http://test.org/path for more."
        urls = _extract_urls_from_text(text)
        assert len(urls) == 2
        assert urls[0]["url"] == "https://example.com/page"
        assert urls[1]["url"] == "http://test.org/path"

    def test_extract_from_html(self):
        html = '<a href="https://evil.com/phish">Click here</a>'
        urls = _extract_urls_from_html(html)
        assert len(urls) == 1
        assert urls[0]["url"] == "https://evil.com/phish"
        assert urls[0]["anchor_text"] == "Click here"

    def test_extract_img_src(self):
        html = '<img src="https://tracker.evil.com/pixel.gif" />'
        urls = _extract_urls_from_html(html)
        assert len(urls) == 1
        assert "tracker.evil.com" in urls[0]["url"]

    def test_dedup(self):
        text = "Link: https://example.com and again https://example.com"
        urls = _extract_urls_from_text(text)
        assert len(urls) == 1


# ═══════════════════════════════════════════════════════════════════════════
#  Full Email Integration
# ═══════════════════════════════════════════════════════════════════════════

class TestFullEmailIntegration:
    def test_clean_email(self):
        """An email with no URLs should return zero counts."""
        parsed = {
            "from": "sarah@google.com",
            "to": "alex@example.com",
            "subject": "Meeting tomorrow",
            "body": "Hi Alex, let's meet at 2pm.",
            "raw_headers": {},
            "received_chain": [],
        }
        result = analyze_urls(parsed)
        assert result["url_count"] == 0
        assert result["suspicious_url_count"] == 0
        assert result["malicious_url_count"] == 0
        assert result["url_risk_score"] == 0

    def test_phishing_email_with_url(self):
        """An email body containing a suspicious URL."""
        parsed = {
            "from": "billing@company-payments.xyz",
            "to": "victim@example.com",
            "subject": "URGENT: Verify",
            "body": (
                "Dear Customer,\n"
                "Please verify your account: https://paypal.com.attacker.com/login\n"
                "Regards"
            ),
            "raw_headers": {},
            "received_chain": [],
        }
        result = analyze_urls(parsed)
        assert result["url_count"] >= 1
        assert result["suspicious_url_count"] + result["malicious_url_count"] >= 1
        assert result["url_risk_score"] > 20

    def test_html_anchor_mismatch_integration(self):
        """HTML anchor text should be compared against the actual href destination."""
        parsed = {
            "from": "support@example.com",
            "to": "victim@example.com",
            "subject": "Account notice",
            "body": "Please review your account.",
            "raw_html": '<a href="https://evil.example/login">https://www.paypal.com/login</a>',
            "raw_headers": {},
            "received_chain": [],
        }
        result = analyze_urls(parsed)
        signals = [
            detection["signal"]
            for finding in result["urls"]
            for detection in finding["detections"]
        ]
        assert "anchor_mismatch" in signals
        assert result["suspicious_url_count"] + result["malicious_url_count"] >= 1

    def test_legitimate_email_with_url(self):
        """An email with a legitimate PayPal URL should remain SAFE."""
        parsed = {
            "from": "support@paypal.com",
            "to": "user@example.com",
            "subject": "Your receipt",
            "body": "Thank you. View at https://www.paypal.com/activity/receipt",
            "raw_headers": {},
            "received_chain": [],
        }
        result = analyze_urls(parsed)
        assert result["url_count"] >= 1
        assert result["malicious_url_count"] == 0
        assert result["url_risk_score"] <= 25

    def test_result_has_correct_keys(self):
        """Verify the returned dict has the expected contract keys."""
        parsed = {"body": "See https://example.com", "raw_headers": {}, "received_chain": []}
        result = analyze_urls(parsed)
        assert "url_count" in result
        assert "suspicious_url_count" in result
        assert "malicious_url_count" in result
        assert "url_risk_score" in result
        assert "urls" in result
        assert "url_evidence" in result

    def test_url_finding_structure(self):
        """Verify per-URL findings have all required fields."""
        parsed = {"body": "Link: https://bit.ly/abc", "raw_headers": {}, "received_chain": []}
        result = analyze_urls(parsed)
        assert len(result["urls"]) >= 1
        finding = result["urls"][0]
        assert "original_url" in finding
        assert "normalized_url" in finding
        assert "hostname" in finding
        assert "registrable_domain" in finding
        assert "detections" in finding
        assert "risk_score" in finding
        assert "classification" in finding


# ═══════════════════════════════════════════════════════════════════════════
#  Punycode / IDN
# ═══════════════════════════════════════════════════════════════════════════

class TestPunycode:
    def test_punycode_domain(self):
        result = analyze_single_url("https://xn--pypal-4ve.com/login")
        signals = [d["signal"] for d in result["detections"]]
        assert "punycode_idn" in signals


# ═══════════════════════════════════════════════════════════════════════════
#  Suspicious Port
# ═══════════════════════════════════════════════════════════════════════════

class TestSuspiciousPort:
    def test_port_8080(self):
        result = analyze_single_url("https://example.com:8080/admin")
        signals = [d["signal"] for d in result["detections"]]
        assert "suspicious_port" in signals

    def test_standard_port_not_flagged(self):
        result = analyze_single_url("https://example.com:443/page")
        signals = [d["signal"] for d in result["detections"]]
        assert "suspicious_port" not in signals
