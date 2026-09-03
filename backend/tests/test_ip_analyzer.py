"""
Unit tests for backend/analyzers/ip_analyzer.py.

Tests public IP normalization, extraction from Received hops,
AbuseIPDB reputation lookups, error fallbacks, and risk calculation.
"""

from unittest.mock import MagicMock, patch
import pytest

from analyzers.ip_analyzer import (
    is_public_ip,
    normalize_public_ip,
    extract_public_ips,
    lookup_geo,
    lookup_ip_reputation,
    calculate_ip_risk,
    analyze,
)


def test_normalize_public_ip():
    """Verify public vs private/reserved IP filtering."""
    # Valid public IPs
    assert normalize_public_ip("8.8.8.8") == "8.8.8.8"
    assert normalize_public_ip("185.123.45.67") == "185.123.45.67"
    assert normalize_public_ip("[1.1.1.1]") == "1.1.1.1"

    # Private, loopback, and invalid
    assert normalize_public_ip("127.0.0.1") is None
    assert normalize_public_ip("192.168.1.100") is None
    assert normalize_public_ip("10.0.0.1") is None
    assert normalize_public_ip("172.16.0.5") is None
    assert normalize_public_ip("not-an-ip") is None
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("8.8.4.4") is True


def test_extract_public_ips_reverse_chronological():
    """Verify that hops are evaluated in reverse chronological order (origin first)."""
    chain = [
        "Received: from internal.mx (10.0.0.2) by dest.mx (10.0.0.1)",
        "Received: from relay.net (93.184.216.34) by internal.mx with ESMTP",
        "Received: from mail.origin.xyz (185.123.45.67) by relay.net",
    ]
    extracted = extract_public_ips(chain)
    # The bottom hop (origin) should come first
    assert extracted == ["185.123.45.67", "93.184.216.34"]


def test_lookup_ip_reputation_missing_key(monkeypatch):
    """When ABUSEIPDB_API_KEY is not set, returns safe zero-risk fallback."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    rep = lookup_ip_reputation("185.123.45.67")
    assert rep["reputation_available"] is False
    assert rep["abuse_confidence_score"] == 0


def test_lookup_ip_reputation_with_valid_api_response(monkeypatch):
    """When API returns 200, parses abuseConfidenceScore accurately."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key-12345")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "ipAddress": "185.123.45.67",
            "abuseConfidenceScore": 88,
            "totalReports": 42,
        }
    }

    with patch("analyzers.ip_analyzer.requests.get", return_value=mock_resp) as mock_get:
        rep = lookup_ip_reputation("185.123.45.67")
        assert rep["reputation_available"] is True
        assert rep["abuse_confidence_score"] == 88


def test_lookup_ip_reputation_handles_api_failure(monkeypatch):
    """When API fails or times out, returns safe fallback."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key-12345")
    with patch("analyzers.ip_analyzer.requests.get", side_effect=Exception("Connection timeout")):
        rep = lookup_ip_reputation("185.123.45.67")
        assert rep["reputation_available"] is False
        assert rep["abuse_confidence_score"] == 0


def test_calculate_ip_risk_with_reputation():
    """When reputation is available, it overrides keyword heuristics."""
    geo = {"isp": "Google LLC"}  # Normally trusted -> 5
    rep = {"reputation_available": True, "abuse_confidence_score": 95}
    score = calculate_ip_risk(geo, "185.123.45.67", rep)
    assert score == 95


def test_calculate_ip_risk_fallback_heuristics():
    """When reputation is not available, uses ISP keyword heuristics."""
    # Trusted ISP
    assert calculate_ip_risk({"isp": "Google Cloud"}, "8.8.8.8", None) == 5

    # Suspicious/Bulletproof ISP
    assert calculate_ip_risk({"isp": "Bulletproof Hosting Ltd"}, "185.123.45.67", {"reputation_available": False}) == 60

    # Generic unlisted ISP
    assert calculate_ip_risk({"isp": "Regional Broadband Co"}, "1.2.3.4", None) == 10

    # No IP
    assert calculate_ip_risk({"isp": "Any"}, "", None) == 0


def test_analyze_end_to_end():
    """Verify analyze() returns the complete expected payload shape."""
    chain = [
        "Received: from mail.evil.xyz (unknown [185.123.45.67]) by mx.google.com with ESMTPS",
    ]
    with patch("analyzers.ip_analyzer.lookup_geo", return_value={"country": "Germany", "city": "Frankfurt", "isp": "BadHost VPN"}), \
         patch("analyzers.ip_analyzer.lookup_ip_reputation", return_value={"reputation_available": True, "abuse_confidence_score": 75}):

        res = analyze(chain)
        assert res["primary_ip"] == "185.123.45.67"
        assert res["geo"]["country"] == "Germany"
        assert res["ip_risk_score"] == 75
        assert "reputation" in res
        assert res["reputation"]["reputation_available"] is True
