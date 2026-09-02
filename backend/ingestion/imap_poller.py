import imaplib
import logging
import os
from pathlib import Path

from dotenv import load_dotenv


# Load backend/.env regardless of where the script is executed from
ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(ENV_PATH)


IMAP_HOST = os.getenv("IMAP_HOST", "imap.gmail.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))

EMAIL_USERNAME = os.getenv("EMAIL_USERNAME")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Fetch emails in batches to avoid downloading everything at once
BATCH_SIZE = 25


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def connect_to_mailbox():
    """
    Connect to the configured IMAP mailbox and select INBOX.
    """

    if not EMAIL_USERNAME or not EMAIL_PASSWORD:
        raise RuntimeError(
            "EMAIL_USERNAME and EMAIL_PASSWORD must be set in backend/.env"
        )

    logging.info("Connecting to IMAP server...")

    mail = imaplib.IMAP4_SSL(
        IMAP_HOST,
        IMAP_PORT
    )

    mail.login(
        EMAIL_USERNAME,
        EMAIL_PASSWORD
    )

    status, _ = mail.select("INBOX")

    if status != "OK":
        mail.logout()
        raise RuntimeError(
            "Unable to select INBOX."
        )

    logging.info(
        "Successfully connected to mailbox."
    )

    return mail


def fetch_emails_after_uid(last_uid):
    """
    Fetch only emails with a UID greater than last_uid.

    Example:
        last_uid = 367

    Search:
        368:*

    This prevents previously processed emails from being
    downloaded and processed again.
    """

    mail = connect_to_mailbox()

    try:
        # UID SEARCH automatically performs a UID-based search.
        # Do NOT put "UID" inside the search criteria.
        search_range = f"{last_uid + 1}:*"

        logging.info(
            "Searching for emails after UID %d...",
            last_uid
        )

        status, data = mail.uid(
            "search",
            None,
            search_range
        )

        if status != "OK":
            raise RuntimeError(
                "Unable to search mailbox."
            )

        if not data or not data[0]:
            logging.info(
                "No new emails found."
            )
            return []

        # Convert returned UIDs to integers and make absolutely
        # sure none are older than last_uid.
        message_uids = []

        for uid in data[0].split():

            try:
                uid_int = int(uid)

                if uid_int > last_uid:
                    message_uids.append(uid_int)

            except ValueError:
                logging.warning(
                    "Ignoring invalid UID: %s",
                    uid
                )

        if not message_uids:
            logging.info(
                "No new emails found."
            )
            return []

        logging.info(
            "Found %d new email(s) after UID %d.",
            len(message_uids),
            last_uid
        )

        emails = []

        # Fetch in batches
        for start in range(
            0,
            len(message_uids),
            BATCH_SIZE
        ):

            batch = message_uids[
                start:start + BATCH_SIZE
            ]

            logging.info(
                "Fetching batch %d-%d of %d...",
                start + 1,
                min(
                    start + BATCH_SIZE,
                    len(message_uids)
                ),
                len(message_uids)
            )

            for uid in batch:

                try:
                    status, fetch_data = mail.uid(
                        "fetch",
                        str(uid),
                        "(RFC822)"
                    )

                    if status != "OK":
                        logging.error(
                            "Failed to fetch UID %d",
                            uid
                        )
                        continue

                    raw_email = None

                    for response in fetch_data:

                        if not isinstance(
                            response,
                            tuple
                        ):
                            continue

                        if len(response) < 2:
                            continue

                        raw_email = response[1]

                        if isinstance(
                            raw_email,
                            bytes
                        ):
                            break

                    if not raw_email:
                        logging.error(
                            "No email data received for UID %d",
                            uid
                        )
                        continue

                    emails.append(
                        {
                            "uid": uid,
                            "data": raw_email
                        }
                    )

                    logging.info(
                        "Fetched UID %d (%d bytes)",
                        uid,
                        len(raw_email)
                    )

                except Exception as e:

                    logging.error(
                        "Failed to fetch UID %d: %s",
                        uid,
                        e
                    )

        return emails

    finally:

        try:
            mail.close()
        except Exception:
            pass

        try:
            mail.logout()
        except Exception:
            pass