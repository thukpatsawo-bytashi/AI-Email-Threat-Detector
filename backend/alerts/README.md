# 🚨 Real-Time Threat Alerting

The `alerts` module dispatches instant webhook notifications when incoming emails are classified as **HIGH** or **CRITICAL** severity threats by the threat analysis pipeline.

---

## How It Works

1. During analysis (`backend/main.py:execute_analysis_pipeline`), the composite risk engine produces a final risk score and classification (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `CLEAN`).
2. If the classification is `HIGH` or `CRITICAL`, `send_alert()` is automatically invoked.
3. A JSON payload with forensic threat metadata is formatted and dispatched via HTTP POST to the configured `ALERT_WEBHOOK_URL`.
4. If no webhook URL is configured or if the remote endpoint times out, the error is handled gracefully without disrupting the primary analysis pipeline.

---

## Configuration

Add the webhook destination URL to `backend/.env`:

```env
# Webhook URL for threat notifications (Slack, Discord, Teams, or SIEM/SOAR)
ALERT_WEBHOOK_URL=<your-slack-webhook-url>
```

---

## Alert Payload Format

The outgoing payload sent to `ALERT_WEBHOOK_URL` adheres to the following structure:

```json
{
  "text": "🚨 [CRITICAL] Threat Detected: URGENT: Verify Your Account Credentials",
  "severity": "CRITICAL",
  "subject": "URGENT: Verify Your Account Credentials",
  "details": {
    "risk_score": "92/100",
    "sender": "security@paypa1-update.com",
    "summary": "High phishing probability (94%), SPF authentication failed, and brand impersonation detected in URL."
  }
}
```

---

## Compatible Webhook Receivers

- **Slack**: Compatible out of the box with standard Slack Incoming Webhook URLs (renders the `text` and key fields).
- **Discord**: Append `/slack` to Discord webhook URLs to receive standard Slack-formatted messages.
- **Microsoft Teams**: Use Teams Workflow / Incoming Webhook connectors.
- **SIEM / SOAR Collectors**: Splunk HEC, Elastic Webhook, or custom security automation endpoints.
