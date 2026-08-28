from email import policy
from email.parser import BytesParser


def parse_received_headers(email_message):
    """
    Extract all Received headers from the email.
    """
    return email_message.get_all("Received", [])


def extract_body(email_message):
    """
    Extract the plain-text body of the email.
    """

    if email_message.is_multipart():
        for part in email_message.walk():

            # Ignore attachments
            if part.get_content_disposition() == "attachment":
                continue

            if part.get_content_type() == "text/plain":
                return part.get_content()

        # If no plain-text part exists, try HTML
        for part in email_message.walk():

            if part.get_content_disposition() == "attachment":
                continue

            if part.get_content_type() == "text/html":
                return part.get_content()

    else:
        if email_message.get_content_type() in (
            "text/plain",
            "text/html",
        ):
            return email_message.get_content()

    return ""


def extract_raw_headers(email_message):
    """
    Convert all email headers into a dictionary.
    """

    return {
        key: value
        for key, value in email_message.items()
    }


def parse_email(file_data: bytes):
    """
    Parse a raw .eml file and return normalized email data.
    """

    email_message = BytesParser(
        policy=policy.default
    ).parsebytes(file_data)

    return {
        "from": email_message.get("From"),
        "to": email_message.get("To"),
        "subject": email_message.get("Subject"),
        "reply_to": email_message.get("Reply-To"),
        "return_path": email_message.get("Return-Path"),
        "message_id": email_message.get("Message-ID"),
        "body": extract_body(email_message),
        "raw_headers": extract_raw_headers(email_message),
        "received_chain": parse_received_headers(email_message),
    }