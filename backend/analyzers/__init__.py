"""
Email Threat Analyzers Package.

Combines RFC-822 email parsing, header authentication analysis,
URL intelligence, IP reputation, and evidence-aware composite risk calculation.
"""

from .email_parser import parse_email
from .header_analyzer import analyze as analyze_headers
from .url_analyzer import (
    analyze_urls,
    analyze_single_url,
    extract_urls_from_email,
    normalize_url,
    get_registrable_domain,
    URLAnalysisResult,
)
from .ip_analyzer import analyze as analyze_ip
from .risk_engine import compute as compute_risk

__all__ = [
    "parse_email",
    "analyze_headers",
    "analyze_urls",
    "analyze_single_url",
    "extract_urls_from_email",
    "normalize_url",
    "get_registrable_domain",
    "URLAnalysisResult",
    "analyze_ip",
    "compute_risk",
]
