import logging
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

try:
    from analyzers.email_parser import parse_email
except ImportError:
    from backend.analyzers.email_parser import parse_email

try:
    from ingestion.imap_poller import fetch_emails_after_uid
    from ingestion.state import load_last_uid, save_last_uid
except ImportError:
    from backend.ingestion.imap_poller import fetch_emails_after_uid
    from backend.ingestion.state import load_last_uid, save_last_uid


# Load backend/.env
ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(ENV_PATH)


ANALYZE_API_URL = os.getenv(
    "ANALYZE_API_URL",
    "http://127.0.0.1:8000/api/analyze-text"
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def _build_analyze_payload(parsed_email):
    """
    Map the dict returned by ``parse_email()`` onto the
    ``DirectEmailInput`` JSON schema accepted by
    ``POST /api/analyze-text``.
    """
    raw_hdrs = parsed_email.get("raw_headers")
    if isinstance(raw_hdrs, dict):
        raw_headers_str = "\n".join(
            f"{k}: {v}" for k, v in raw_hdrs.items()
        )
    elif isinstance(raw_hdrs, str):
        raw_headers_str = raw_hdrs
    else:
        raw_headers_str = None

    return {
        "from_email": parsed_email.get("from_email") or parsed_email.get("from") or "",
        "to_email": parsed_email.get("to_email") or parsed_email.get("to") or "",
        "subject": parsed_email.get("subject", "") or "",
        "body": parsed_email.get("body", "") or "",
        "raw_headers": raw_headers_str,
        "raw_eml_text": parsed_email.get("raw_eml_text"),
    }


build_analyze_payload = _build_analyze_payload


def analyze_email(parsed_email):
    """
    Send a parsed email to the team's analysis API.

    This module does NOT determine whether an email is
    malicious, risky, HIGH, or CRITICAL.

    The analysis/risk engine is responsible for that.
    """

    payload = _build_analyze_payload(parsed_email)

    response = requests.post(
        ANALYZE_API_URL,
        json=payload,
        timeout=60
    )

    response.raise_for_status()

    return response.json()


def process_emails():
    """
    Fetch new emails, parse them, send them to the analysis
    API, and update the last processed UID. The backend analysis
    pipeline handles risk computation, database persistence,
    incident creation, and threat alerting.
    """

    last_uid = load_last_uid()

    logging.info(
        "Last processed UID: %d",
        last_uid
    )

    emails = fetch_emails_after_uid(last_uid)

    if not emails:

        logging.info(
            "No new emails to process."
        )

        return

    logging.info(
        "Processing %d new email(s)...",
        len(emails)
    )

    highest_processed_uid = last_uid

    for email in emails:

        uid = int(email["uid"])

        try:

            # ----------------------------------------
            # Parse email
            # ----------------------------------------

            parsed_email = parse_email(
                email["data"]
            )

            logging.info(
                "Parsed UID %d: %s",
                uid,
                parsed_email.get("subject")
            )

            # ----------------------------------------
            # Send to team's analysis pipeline
            # ----------------------------------------

            result = analyze_email(
                parsed_email
            )

            logging.info(
                "Analysis completed for UID %d",
                uid
            )

            # ----------------------------------------
            # Log verdict from analysis pipeline
            #
            # The backend analysis pipeline automatically handles
            # persistence, incident creation, and alerting for
            # elevated threats (HIGH / CRITICAL).
            # ----------------------------------------

            classification = str(
                result.get(
                    "classification",
                    "UNKNOWN"
                )
            ).upper()

            risk_score = result.get("risk_score", 0)

            logging.info(
                "UID %d verdict: %s (risk_score=%s)",
                uid,
                classification,
                risk_score
            )

            # ----------------------------------------
            # Only mark this email processed after
            # successful analysis.
            # ----------------------------------------

            if uid > highest_processed_uid:

                highest_processed_uid = uid

        except Exception as e:

            logging.error(
                "Failed to process UID %d: %s",
                uid,
                e
            )

            # Don't mark this or later emails as processed
            # if analysis failed.
            break

    # ----------------------------------------
    # Save progress
    # ----------------------------------------

    if highest_processed_uid > last_uid:

        save_last_uid(
            highest_processed_uid
        )

        logging.info(
            "Updated last processed UID to %d.",
            highest_processed_uid
        )

    logging.info(
        "Processing cycle complete."
    )


process_new_emails = process_emails


if __name__ == "__main__":
    process_emails()