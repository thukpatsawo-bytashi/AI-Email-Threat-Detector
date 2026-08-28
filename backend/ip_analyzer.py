import ipaddress
import re
from typing import Any


# IPv4 pattern.
IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


# Demo fallback data.
# Keep this limited to IPs used by your prepared demo emails.
GEO_FALLBACKS = {
    "209.85.220.65": {
        "country": "United States",
        "city": "Mountain View",
        "isp": "Google LLC",
    },
    "192.30.252.141": {
        "country": "United States",
        "city": "San Francisco",
        "isp": "GitHub",
    },
}


def extract_public_ips(received_chain: list[str]) -> list[str]:
    """
    Extract valid public IPv4 addresses from Received headers.

    Note:
    Received headers can be forged or altered by an attacker.
    Therefore, extracted IPs are evidence/context, not proof of
    the attacker's physical origin.
    """

    public_ips = []

    for header in received_chain:
        matches = IPV4_PATTERN.findall(header)

        for ip in matches:
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue

            if ip_obj.version != 4:
                continue

            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            ):
                continue

            if ip not in public_ips:
                public_ips.append(ip)

    return public_ips


def lookup_geo(ip: str) -> dict[str, str]:
    """
    Look up IP geolocation using ip-api.com.

    Falls back to the hardcoded demo table if the request fails.
    """

    fallback = GEO_FALLBACKS.get(
        ip,
        {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
        },
    )

    try:
        import requests

        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": "status,country,city,isp"
            },
            timeout=2,
        )

        response.raise_for_status()
        data = response.json()

        if data.get("status") != "success":
            return fallback

        return {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("isp", "Unknown"),
        }

    except Exception:
        return fallback


def calculate_ip_risk(geo: dict[str, str]) -> int:
    """
    Simple baseline IP risk heuristic.

    This is intentionally lightweight for the prototype.
    """

    isp = geo.get("isp", "").lower()

    risky_patterns = [
        "hosting",
        "bulletproof",
        "anonymous",
        "vpn",
        "proxy",
    ]

    for pattern in risky_patterns:
        if pattern in isp:
            return 60

    return 20


def analyze(received_chain: list[str]) -> dict[str, Any]:
    """
    Analyze the Received chain and return the exact IPResult shape.
    """

    extracted_ips = extract_public_ips(received_chain)

    primary_ip = (
        extracted_ips[0]
        if extracted_ips
        else ""
    )

    if primary_ip:
        geo = lookup_geo(primary_ip)
        ip_risk_score = calculate_ip_risk(geo)
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