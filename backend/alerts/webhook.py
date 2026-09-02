import logging
import os
from pathlib import Path

import requests
from dotenv import load_dotenv


# Load backend/.env
ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(ENV_PATH)


WEBHOOK_URL = os.getenv(
    "ALERT_WEBHOOK_URL"
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


ALERT_SEVERITIES = {
    "HIGH",
    "CRITICAL"
}


def send_alert(
    severity,
    subject,
    details
):
    """
    Send an alert when the analysis pipeline returns
    HIGH or CRITICAL.

    This function does not calculate severity.
    It only reacts to the verdict provided by the
    analysis pipeline.
    """

    severity = str(
        severity
    ).upper()

    # Only alert for HIGH / CRITICAL
    if severity not in ALERT_SEVERITIES:

        logging.info(
            "No alert required for severity: %s",
            severity
        )

        return False

    if not WEBHOOK_URL:

        logging.warning(
            "ALERT_WEBHOOK_URL is not configured."
        )

        return False

    # Convert result to readable text
    if isinstance(details, dict):

        details_text = "\n".join(
            f"**{key}:** {value}"
            for key, value in details.items()
        )

    else:

        details_text = str(details)

    payload = {
        "content": (
            "🚨 **Email Threat Alert**\n\n"
            f"**Severity:** {severity}\n"
            f"**Subject:** {subject}\n\n"
            f"{details_text}"
        )
    }

    try:

        response = requests.post(
            WEBHOOK_URL,
            json=payload,
            timeout=10
        )

        response.raise_for_status()

        logging.info(
            "%s alert sent successfully.",
            severity
        )

        return True

    except requests.RequestException as e:

        logging.error(
            "Failed to send %s alert: %s",
            severity,
            e
        )

        return False