"""
Email Ingestion & IMAP Polling Package.
"""

from .imap_poller import fetch_emails_after_uid
from .processor import analyze_email, process_new_emails
from .state import load_last_uid, save_last_uid

__all__ = [
    "fetch_emails_after_uid",
    "analyze_email",
    "process_new_emails",
    "load_last_uid",
    "save_last_uid",
]
