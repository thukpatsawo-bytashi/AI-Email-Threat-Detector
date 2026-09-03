"""
Unit tests for backend/ingestion/processor.py.

Verifies that analyze_email() sends requests to /api/analyze-text with
a payload that matches the DirectEmailInput schema.
"""

from unittest.mock import MagicMock, patch
import pytest

from main import DirectEmailInput, app
from analyzers.email_parser import parse_email
from ingestion.processor import (
    ANALYZE_API_URL,
    analyze_email,
    _build_analyze_payload,
)
from fastapi.testclient import TestClient


def test_default_analyze_api_url():
    """Ensure the default ANALYZE_API_URL points to /api/analyze-text, not /api/analyze."""
    assert ANALYZE_API_URL.endswith("/api/analyze-text")


def test_analyze_email_payload_matches_direct_email_input():
    """
    Verify analyze_email() maps parse_email output fields onto DirectEmailInput
    schema fields (from_email, to_email, subject, body, raw_headers, raw_eml_text)
    and that Pydantic validates the payload without error.
    """
    parsed_email = {
        "from": "security-alert@paypal-update.com",
        "to": "target@corporate.com",
        "subject": "Urgent: Verify Your Account",
        "reply_to": "attacker@evil.com",
        "return_path": "bounce@evil.com",
        "message_id": "<12345@evil.com>",
        "body": "Please click the link below to confirm your password immediately.",
        "raw_html": "<p>Please click the link</p>",
        "raw_headers": {
            "From": "security-alert@paypal-update.com",
            "To": "target@corporate.com",
            "Subject": "Urgent: Verify Your Account",
            "X-Spam-Status": "Yes",
        },
        "received_chain": ["from mail.evil.com (185.123.45.67) by mx.google.com"],
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "classification": "HIGH",
        "risk_score": 85,
        "incident_id": 1,
    }
    mock_response.raise_for_status = MagicMock()

    with patch("ingestion.processor.requests.post", return_value=mock_response) as mock_post:
        result = analyze_email(parsed_email)

        # 1. Ensure API was called with the analyze-text endpoint
        mock_post.assert_called_once()
        call_args, call_kwargs = mock_post.call_args
        assert call_args[0] == ANALYZE_API_URL

        # 2. Extract JSON payload sent to the API
        payload = call_kwargs.get("json")
        assert payload is not None, "Payload was not sent as JSON"

        # 3. Confirm all keys match DirectEmailInput model fields
        direct_input_fields = set(DirectEmailInput.model_fields.keys())
        payload_keys = set(payload.keys())
        assert payload_keys == direct_input_fields, (
            f"Payload keys {payload_keys} do not match DirectEmailInput fields {direct_input_fields}"
        )

        # 4. Confirm field mappings
        assert payload["from_email"] == "security-alert@paypal-update.com"
        assert payload["to_email"] == "target@corporate.com"
        assert payload["subject"] == "Urgent: Verify Your Account"
        assert payload["body"] == "Please click the link below to confirm your password immediately."
        assert isinstance(payload["raw_headers"], str)
        assert "X-Spam-Status: Yes" in payload["raw_headers"]
        assert payload["raw_eml_text"] is None

        # 5. Confirm payload validates cleanly against the DirectEmailInput Pydantic model
        validated_input = DirectEmailInput.model_validate(payload)
        assert validated_input.from_email == payload["from_email"]
        assert validated_input.to_email == payload["to_email"]

        # 6. Confirm return value is returned as expected
        assert result["risk_score"] == 85


def test_analyze_email_with_real_parser_and_fastapi_compatibility():
    """
    Test the entire chain from parse_email() -> analyze_email() -> FastAPI /api/analyze-text.
    Mocks requests.post using TestClient to guarantee that /api/analyze-text accepts the
    payload without a 422 Unprocessable Entity error.
    """
    sample_eml = (
        b"From: billing@suspicious-bank.com\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Your statement is ready\r\n"
        b"Content-Type: text/plain; charset=\"utf-8\"\r\n"
        b"\r\n"
        b"Please review your latest billing statement."
    )

    parsed = parse_email(sample_eml)
    client = TestClient(app)

    # Use TestClient to mock requests.post by forwarding to the actual FastAPI app
    def mock_requests_post(url, json=None, timeout=None):
        endpoint = "/api/analyze-text"
        resp = client.post(endpoint, json=json)
        mock_resp = MagicMock()
        mock_resp.status_code = resp.status_code
        mock_resp.json = resp.json
        if resp.status_code >= 400:
            import requests
            http_err = requests.exceptions.HTTPError(f"{resp.status_code} Error: {resp.text}")
            mock_resp.raise_for_status.side_effect = http_err
        else:
            mock_resp.raise_for_status = MagicMock()
        return mock_resp

    with patch("ingestion.processor.requests.post", side_effect=mock_requests_post):
        result = analyze_email(parsed)

    # Clean up test records
    try:
        from database import SessionLocal, Incident, AnalyzedEmail
        clean_db = SessionLocal()
        try:
            if result.get("incident_id"):
                clean_db.query(Incident).filter(Incident.id == result["incident_id"]).delete()
            if result.get("analyzed_email_id"):
                clean_db.query(AnalyzedEmail).filter(AnalyzedEmail.id == result["analyzed_email_id"]).delete()
            clean_db.commit()
        finally:
            clean_db.close()
    except Exception:
        pass

    # If it was 422, it would have raised an HTTPError. Since it passed:
    assert "risk_score" in result
    assert "classification" in result
    assert result["from"] == "billing@suspicious-bank.com"


def test_process_emails_delegates_alerts_and_logs_verdict(caplog):
    """
    Ensure process_emails() does not trigger send_alert() itself (leaving
    alerting to backend's execute_analysis_pipeline) and correctly logs
    classification and risk_score.
    """
    from ingestion.processor import process_emails
    import logging

    fake_email = {
        "uid": 105,
        "data": b"From: phish@evil.xyz\nSubject: Critical alert\n\nMalicious content",
    }
    fake_parsed = {
        "from": "phish@evil.xyz",
        "to": "target@victim.com",
        "subject": "Critical alert",
        "body": "Malicious content",
        "raw_headers": {"From": "phish@evil.xyz"},
    }
    fake_analysis_result = {
        "classification": "CRITICAL",
        "risk_score": 95,
        "reasons": ["Urgent credential demand"],
    }

    with patch("ingestion.processor.load_last_uid", return_value=100), \
         patch("ingestion.processor.fetch_emails_after_uid", return_value=[fake_email]), \
         patch("ingestion.processor.parse_email", return_value=fake_parsed), \
         patch("ingestion.processor.analyze_email", return_value=fake_analysis_result), \
         patch("ingestion.processor.save_last_uid") as mock_save_uid, \
         patch("backend.alerts.webhook.send_alert") as mock_send_alert:

        with caplog.at_level(logging.INFO):
            process_emails()

        # Alert should NOT be called from processor.py
        mock_send_alert.assert_not_called()

        # Progress should be saved
        mock_save_uid.assert_called_once_with(105)

        # Logging should report classification and risk_score
        assert "UID 105 verdict: CRITICAL (risk_score=95)" in caplog.text

