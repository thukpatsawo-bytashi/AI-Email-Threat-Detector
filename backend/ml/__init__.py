"""
Machine Learning & NLP Phishing Classification Package.
"""

from .phishing_model import classify, classify as classify_nlp

__all__ = [
    "classify",
    "classify_nlp",
]
