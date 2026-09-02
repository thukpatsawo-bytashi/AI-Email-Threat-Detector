"""
Email Parser Module

Parses raw .eml RFC-822 file bytes into a normalized dictionary containing
sender, recipient, subject, body text (with HTML cleanup), headers, and
the Received chain.
"""

from email import policy
from email.parser import BytesParser
import email.utils
import re
import html


def clean_html_to_text(html_content: str) -> str:
    """
    Strips HTML tags, script/style blocks, and decodes HTML entities
    to produce clean readable plain text.
    """
    if not html_content:
        return ""

    # Remove script and style elements
    cleaned = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html_content, flags=re.DOTALL | re.IGNORECASE)
    # Replace block tags with newlines
    cleaned = re.sub(r"<(br|p|div|tr|li|h[1-6])[^>]*>", "\n", cleaned, flags=re.IGNORECASE)
    # Remove remaining HTML tags
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    # Unescape HTML entities (&amp;, &nbsp;, etc.)
    cleaned = html.unescape(cleaned)
    # Normalize whitespace
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in cleaned.splitlines()]
    return "\n".join(line for line in lines if line).strip()


def parse_received_headers(email_message) -> list[str]:
    """
    Extract all Received headers from the email as a list of strings.
    """
    received = email_message.get_all("Received", [])
    if not received:
        return []
    # Normalize line breaks and multiple spaces in Received headers
    return [re.sub(r"\s+", " ", str(r)).strip() for r in received]


def extract_body(email_message) -> str:
    """
    Extract the plain-text body of the email.
    If multipart, prioritizes text/plain; falls back to cleaned text/html.
    """
    plain_parts = []
    html_parts = []

    if email_message.is_multipart():
        for part in email_message.walk():
            # Ignore attachments
            content_disposition = str(part.get_content_disposition() or "").lower()
            if content_disposition == "attachment":
                continue

            content_type = part.get_content_type()
            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)
                content = payload.decode(errors="replace") if payload else ""

            if not isinstance(content, str):
                content = str(content or "")

            if content_type == "text/plain":
                plain_parts.append(content)
            elif content_type == "text/html":
                html_parts.append(content)

        if plain_parts:
            return "\n\n".join(p.strip() for p in plain_parts if p.strip())
        if html_parts:
            return clean_html_to_text("\n\n".join(html_parts))

    else:
        content_type = email_message.get_content_type()
        try:
            content = email_message.get_content()
        except Exception:
            payload = email_message.get_payload(decode=True)
            content = payload.decode(errors="replace") if payload else ""

        if not isinstance(content, str):
            content = str(content or "")

        if content_type == "text/plain":
            return content.strip()
        elif content_type == "text/html":
            return clean_html_to_text(content)

    return ""


def extract_raw_html(email_message) -> str:
    """
    Return concatenated text/html parts for URL analysis.
    """
    html_parts = []

    if email_message.is_multipart():
        for part in email_message.walk():
            content_disposition = str(part.get_content_disposition() or "").lower()
            if content_disposition == "attachment":
                continue

            if part.get_content_type() != "text/html":
                continue

            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)
                content = payload.decode(errors="replace") if payload else ""

            if content:
                html_parts.append(str(content))
    elif email_message.get_content_type() == "text/html":
        try:
            content = email_message.get_content()
        except Exception:
            payload = email_message.get_payload(decode=True)
            content = payload.decode(errors="replace") if payload else ""
        if content:
            html_parts.append(str(content))

    return "\n\n".join(html_parts)


def extract_raw_headers(email_message) -> dict[str, str]:
    """
    Convert all email headers into a dictionary of string values.
    Duplicate headers are concatenated because authentication systems often add
    more than one Authentication-Results or Received-SPF line.
    """
    headers = {}
    canonical_keys = {}
    for key, value in email_message.items():
        clean_value = re.sub(r"\s+", " ", str(value)).strip()
        lower_key = key.lower()
        existing_key = canonical_keys.get(lower_key)
        if existing_key:
            headers[existing_key] = f"{headers[existing_key]} {clean_value}".strip()
        else:
            headers[key] = clean_value
            canonical_keys[lower_key] = key
    return headers


def parse_email(file_data: bytes) -> dict:
    """
    Parse a raw .eml file byte string and return normalized email data dictionary.
    """
    if not file_data:
        raise ValueError("Empty file data provided to parser.")

    email_message = BytesParser(policy=policy.default).parsebytes(file_data)

    from_header = str(email_message.get("From", "") or "")
    to_header = str(email_message.get("To", "") or "")
    subject_header = str(email_message.get("Subject", "") or "")
    reply_to_header = str(email_message.get("Reply-To", "") or "")
    return_path_header = str(email_message.get("Return-Path", "") or "")
    message_id_header = str(email_message.get("Message-ID", "") or "")

    return {
        "from": from_header,
        "to": to_header,
        "subject": subject_header,
        "reply_to": reply_to_header,
        "return_path": return_path_header,
        "message_id": message_id_header,
        "body": extract_body(email_message),
        "raw_html": extract_raw_html(email_message),
        "raw_headers": extract_raw_headers(email_message),
        "received_chain": parse_received_headers(email_message),
    }


if __name__ == "__main__":
    sample_eml = b"""From: "PayPal Security" <service@paypa1-security.xyz>
To: victim@example.com
Subject: URGENT: Verify Your Account Immediately
Reply-To: support@gmail.com
Return-Path: <bounce@evil.xyz>
Message-ID: <12345@evil.xyz>
Content-Type: text/plain; charset="utf-8"
Received: from mail.evil.xyz (185.123.45.67) by mx.google.com with ESMTPS

Dear Customer,
Your account has been suspended due to suspicious activity.
Please verify your credentials immediately.
"""
    result = parse_email(sample_eml)
    print("Parsed email result:")
    print("From:", result["from"])
    print("Subject:", result["subject"])
    print("Body length:", len(result["body"]))
