# 📬 Automated Email Ingestion Engine

The `ingestion` module provides continuous, unattended monitoring of an IMAP mailbox. It automatically polls for new messages, parses `.eml` MIME data, forwards parsed payloads to the threat analysis API (`/api/analyze-text`), and tracks message state to ensure zero duplicate scans.

---

## Architecture & Data Flow

```
[ IMAP Mailbox ] (e.g., abuse@company.com)
       │
       ▼ (SSL / TLS on port 993)
[ imap_poller.py ] ─── Fetches unread emails with UID > last_saved_uid
       │
       ▼ (Raw bytes)
[ email_parser.py ] ── Parses MIME parts, headers, plain text, and HTML
       │
       ▼ (DirectEmailInput schema)
[ processor.py ] ───── POSTs to /api/analyze-text
       │
       ▼
[ Backend API ] ────── Runs header, NLP, URL & IP analyzers
       │               Persists email to database & creates SOC Incident
       │               Dispatches Webhook Alert (if HIGH or CRITICAL)
       │
       ▼ (On Success)
[ state.py ] ───────── Saves new highest UID to state.json
```

---

## Configuration

The ingestion module loads environment variables from `backend/.env`.

Add or configure the following keys:

```env
# ── IMAP Mailbox Settings ──────────────────────────────────────────
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
EMAIL_USERNAME=security-inbox@your-domain.com
EMAIL_PASSWORD=your-app-specific-password

# ── Polling Interval (in seconds) ──────────────────────────────────
POLL_INTERVAL=20

# ── Target Analysis Pipeline ───────────────────────────────────────
ANALYZE_API_URL=http://127.0.0.1:8000/api/analyze-text
```

### Provider Configuration Tips

- **Gmail / Google Workspace**:
  1. Enable 2-Step Verification on the Google Account.
  2. Navigate to **Manage Account → Security → App Passwords**.
  3. Generate a 16-character App Password and set it as `EMAIL_PASSWORD`.
  4. Ensure IMAP access is enabled in Gmail settings (**Settings → Forwarding and POP/IMAP → Enable IMAP**).
- **Microsoft 365 / Outlook**:
  - Host: `outlook.office365.com`
  - Port: `993`
  - Use an App Password if MFA is enabled on the tenant.
- **Custom IMAP / Dovecot**:
  - Ensure the IMAP server supports TLS/SSL (`IMAP4_SSL`) on port 993.

---

## Usage

### 1. Continuous Scheduled Ingestion (Recommended for Production)

Uses APScheduler's `BlockingScheduler` to run an ingestion cycle every `POLL_INTERVAL` seconds:

```bash
# Execute from the project root
python -m backend.ingestion.scheduler
```

The scheduler logs all lifecycle events:
```text
2026-09-03 17:30:00 - INFO - Continuous ingestion started.
2026-09-03 17:30:00 - INFO - Polling every 20 seconds.
2026-09-03 17:30:00 - INFO - Connecting to IMAP server...
2026-09-03 17:30:01 - INFO - Last processed UID: 42
2026-09-03 17:30:01 - INFO - Processing 2 new email(s)...
2026-09-03 17:30:02 - INFO - Parsed UID 43: Urgent payroll action required
2026-09-03 17:30:04 - INFO - UID 43 verdict: CRITICAL (risk_score=92)
2026-09-03 17:30:04 - INFO - Updated last processed UID to 43.
```

### 2. One-Off Ingestion Cycle

Fetches and analyzes all unread emails since the last processed UID, commits the high watermark, and exits:

```bash
# Execute from the project root
python -m backend.ingestion.processor
```

---

## State Tracking & Fault Tolerance

The ingestion pipeline uses a high-watermark state tracker (`state.py`):
- Progress is stored in `backend/ingestion/state.json`:
  ```json
  {
    "last_uid": 43
  }
  ```
- **Guaranteed At-Least-Once Delivery**: The UID is only advanced in `state.json` **after** the analysis API confirms successful persistence.
- **Failure Isolation**: If an email cannot be parsed or if the API returns an error, the processing loop halts without advancing past that UID. Subsequent polling attempts will retry the message once the issue or backend connectivity is resolved.

---

## Production Deployment as a Systemd Service

To run the poller as a persistent Linux daemon:

Create `/etc/systemd/system/email-threat-ingestion.service`:

```ini
[Unit]
Description=AI Email Threat Detector - Ingestion Poller
After=network.target

[Service]
Type=simple
User=appuser
WorkingDirectory=/opt/AI-Email-Threat-Detector
EnvironmentFile=/opt/AI-Email-Threat-Detector/backend/.env
ExecStart=/opt/AI-Email-Threat-Detector/backend/venv/bin/python -m backend.ingestion.scheduler
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now email-threat-ingestion.service
sudo journalctl -u email-threat-ingestion.service -f
```
