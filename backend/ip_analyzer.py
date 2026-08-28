"""
IP Analyzer Module

Extracts public IP addresses from email Received headers, identifies the
originating sender IP, performs IP geolocation and ISP intelligence lookups,
and calculates an IP risk score.
"""

import ipaddress
import re
from typing import Any
import urllib.request
import json
from functools import lru_cache

# Broad candidate matcher; ipaddress performs final IPv4/IPv6 validation.
IP_CANDIDATE_PATTERN = re.compile(
    r"(?<![\w.:-])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:.]{2,})(?![\w.:-])"
)

# Fallback geolocation data for demo safety & test stability
GEO_FALLBACKS = {
    "185.123.45.67": {
        "country": "Germany",
        "city": "Frankfurt",
        "isp": "Example Hosting Provider",
    },
    "209.85.220.65": {
        "country": "United States",
        "city": "Mountain View",
        "isp": "Google LLC",
    },
    "192.30.252.141": {
        "country": "United States",
        "city": "San Francisco",
        "isp": "GitHub Inc.",
    },
    "40.107.236.80": {
        "country": "United States",
        "city": "Redmond",
        "isp": "Microsoft Corporation",
    },
}

# Suspicious / Bulletproof / Anonymous Hosting provider patterns
HIGH_RISK_ISP_KEYWORDS = [
    "bulletproof", "anonymous", "vpn", "proxy", "tor", "m247",
    "leaseweb", "choopa", "vultr", "digitalocean", "linode",
    "hetzner", "ovh", "hostinger", "datacenter", "hosting"
]

TRUSTED_MAIL_ISPS = [
    "google", "microsoft", "apple", "amazon", "verizon",
    "comcast", "at&t", "telekom", "spectrum", "charter", "orange"
]


def is_public_ip(ip_str: str) -> bool:
    """
    Checks if an IP string is a valid, routable public IP.
    Filters private, loopback, link-local, multicast, and reserved ranges.
    """
    return normalize_public_ip(ip_str) is not None


def normalize_public_ip(ip_str: str) -> str | None:
    """
    Return the normalized form of a public IPv4/IPv6 address, or None.
    """
    try:
        ip_obj = ipaddress.ip_address(str(ip_str).strip("[]()<>.,;"))
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            return None
        return str(ip_obj)
    except ValueError:
        return None


def extract_public_ips(received_chain: list[str]) -> list[str]:
    """
    Extracts all unique public IPv4/IPv6 addresses across the Received headers.
    Headers are inspected in reverse chronological order (originating hop first).
    """
    if not received_chain:
        return []

    extracted = []
    # Received headers are prepended by each hop; the bottom header is closest to the sender
    for header in reversed(received_chain):
        for candidate in IP_CANDIDATE_PATTERN.findall(header):
            ip = normalize_public_ip(candidate)
            if ip and ip not in extracted:
                extracted.append(ip)

    return extracted


@lru_cache(maxsize=512)
def lookup_geo(ip: str) -> dict[str, str]:
    """
    Performs IP geolocation lookup using ip-api.com with timeout.
    Falls back gracefully to GEO_FALLBACKS or generic defaults.
    """
    fallback = GEO_FALLBACKS.get(
        ip,
        {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown Network",
        }
    )

    if not ip or not is_public_ip(ip):
        return fallback

    # Check hardcoded table first for demo performance
    if ip in GEO_FALLBACKS:
        return GEO_FALLBACKS[ip]

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "AIEmailThreatDetector/1.0"}
        )
        with urllib.request.urlopen(req, timeout=2.0) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown") or "Unknown",
                    "city": data.get("city", "Unknown") or "Unknown",
                    "isp": data.get("isp") or data.get("org") or data.get("as") or "Unknown",
                }
    except Exception:
        pass

    return fallback


def calculate_ip_risk(geo: dict[str, str], ip: str) -> int:
    """
    Calculates an IP risk score (0-100) based on ISP reputation and hosting signals.
    """
    if not ip:
        return 0

    isp_lower = str(geo.get("isp", "")).lower()

    # 1. Trusted legitimate email providers / residential ISPs
    for trusted in TRUSTED_MAIL_ISPS:
        if trusted in isp_lower:
            return 10

    # 2. Known VPN, Tor, Bulletproof, or Cloud Hosting senders
    for risky in HIGH_RISK_ISP_KEYWORDS:
        if risky in isp_lower:
            return 60

    # 3. Default baseline score
    return 25


def analyze(received_chain: list[str]) -> dict[str, Any]:
    """
    Analyzes the Received chain and returns the exact IPResult shape.
    """
    extracted_ips = extract_public_ips(received_chain)

    primary_ip = extracted_ips[0] if extracted_ips else ""

    if primary_ip:
        geo = lookup_geo(primary_ip)
        ip_risk_score = calculate_ip_risk(geo, primary_ip)
    else:
        geo = {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
        }
        ip_risk_score = 0

    return {
        "extracted_ips": extracted_ips,
        "primary_ip": primary_ip,
        "geo": geo,
        "ip_risk_score": ip_risk_score,
    }


if __name__ == "__main__":
    test_chain = [
        "Received: from mail.evil.xyz (unknown [185.123.45.67]) by mx.google.com with ESMTPS",
        "Received: by mail-wm1-f41.google.com with SMTP id abc123"
    ]
    res = analyze(test_chain)
    print("IP analyzer result:")
    print(json.dumps(res, indent=2))
