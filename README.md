# 🛡️ AI Email Threat Detector

An AI-powered email threat analysis tool that inspects `.eml` files for phishing indicators, suspicious headers, URLs, and sender infrastructure — built as a hackathon MVP.

## Architecture

```
┌──────────────┐      POST /api/analyze       ┌────────────────────┐
│  React App   │  ──────────────────────────▶  │   FastAPI (main)   │
│  (frontend)  │  ◀──────────────────────────  │                    │
└──────────────┘      flat JSON response       └────────┬───────────┘
                                                        │
                              ┌──────────────────────────┼──────────────────────────┐
                              │                          │                          │
                     ┌────────▼────────┐       ┌─────────▼─────────┐      ┌────────▼────────┐
                     │ header_analyzer │       │  phishing_model   │      │  ip_analyzer    │
                     │  (SPF/DKIM/     │       │  (NLP classify)   │      │  (IP geoloc &   │
                     │   DMARC check)  │       │                   │      │   reputation)   │
                     └────────┬────────┘       └─────────┬─────────┘      └────────┬────────┘
                              │                          │                          │
                              └──────────────────────────┼──────────────────────────┘
                                                         │
                                                ┌────────▼────────┐
                                                │   risk_engine   │
                                                │  (final score)  │
                                                └─────────────────┘
```

### Pipeline

| Step | Module | Input | Output |
|------|--------|-------|--------|
| 1 | `analyzers/email_parser.py` | Raw `.eml` bytes | `ParsedEmail` dict |
| 2 | `analyzers/header_analyzer.py` | `ParsedEmail` | `HeaderAnalysisResult` |
| 3 | `ml/phishing_model.py` | Email subject + body text | `NLPResult` |
| 4 | `analyzers/url_analyzer.py` | Parsed email body / HTML URLs | `URLAnalysisResult` |
| 5 | `analyzers/ip_analyzer.py` | Received chain | `IPResult` |
| 6 | `analyzers/risk_engine.py` | Steps 2–5 results | `FinalResult` |

> **Note:** The backend runs the live analysis pipeline: parser, header checks, NLP classification, URL analysis, IP intelligence, and evidence-aware final risk scoring.

---

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- pip & npm

### 1. Backend (API server)

```bash
# From the project root
pip install -r backend/requirements.txt

# Start the API (Terminal 1)
cd backend
uvicorn main:app --reload --port 8000
```

> The API server starts at `http://localhost:8000`.
> Interactive API docs are at [http://localhost:8000/docs](http://localhost:8000/docs).
> **This only serves JSON** — it is not the website.

### 2. Frontend (React website)

Open a **second terminal**:

```bash
# From the project root
cd frontend
npm install
npm run dev
```

> The website starts at `http://localhost:5173`.
> **Open this URL in your browser** to use the app.

### What runs where

| URL | What |
|-----|------|
| `http://localhost:8000` | Backend API — returns JSON only |
| `http://localhost:8000/docs` | Swagger interactive API docs |
| **`http://localhost:5173`** | **Website — the Upload & Dashboard UI** |

---

## API Reference

### `GET /`

Health check.

```json
{ "message": "AI Email Threat Detector API is running" }
```

### `POST /api/analyze`

Upload a `.eml` file for threat analysis.

**Request:** `multipart/form-data` with a `file` field containing the `.eml` file.

```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@suspicious_email.eml"
```

**Response** (flat JSON combining all analysis stages):

```json
{
  "from": "Billing Department <billing@company-payments.xyz>",
  "subject": "URGENT: Outstanding Invoice #INV-92841",
  "body": "Dear Valued Customer...",

  "spf": "fail",
  "dkim": "fail",
  "dmarc": "fail",
  "sender_reply_mismatch": true,
  "domain_lookalike": true,
  "domain_age_days": 3,
  "anomalies": [
    "Sender identity mismatch: From (company-payments.xyz) vs Reply-To (gmail.com)",
    "Envelope sender mismatch: From (company-payments.xyz) vs Return-Path (evil.xyz)",
    "Suspicious high-risk top-level domain (.xyz)",
    "Newly registered domain (only 3 days old)",
    "SPF authentication failed (fail)",
    "DKIM cryptographic signature verification failed",
    "DMARC policy check failed"
  ],
  "header_risk_score": 100,

  "extracted_ips": ["185.123.45.67"],
  "primary_ip": "185.123.45.67",
  "geo": { "country": "Germany", "city": "Frankfurt", "isp": "Example Hosting Provider" },
  "ip_risk_score": 60,

  "phishing_probability": 79,
  "legitimate_probability": 21,
  "flagged_terms": [
    "urgent",
    "immediately",
    "within 24 hours",
    "unauthorized access",
    "verify your account",
    "confirm your details",
    "outstanding invoice",
    "payment declined"
  ],

  "url_count": 1,
  "suspicious_url_count": 0,
  "malicious_url_count": 0,
  "url_risk_score": 8,
  "urls": [
    {
      "original_url": "https://company-payments.xyz/verify-billing",
      "hostname": "company-payments.xyz",
      "registrable_domain": "company-payments.xyz",
      "risk_score": 8,
      "classification": "SAFE"
    }
  ],
  "url_evidence": [],

  "risk_score": 100,
  "classification": "CRITICAL",
  "evidence_level": "STRONG",
  "reasons": [
    "Sender identity mismatch: From (company-payments.xyz) vs Reply-To (gmail.com)",
    "Envelope sender mismatch: From (company-payments.xyz) vs Return-Path (evil.xyz)",
    "Suspicious high-risk top-level domain (.xyz)",
    "Newly registered domain (only 3 days old)",
    "SPF authentication failed (fail)",
    "DKIM cryptographic signature verification failed",
    "DMARC policy check failed",
    "Strong phishing-language evidence (79%): urgent, immediately, within 24 hours, unauthorized access",
    "Risky sending network (185.123.45.67) associated with Example Hosting Provider"
  ],
  "breakdown": { "nlp": 79, "header": 100, "ip": 60, "url": 8 },
  "risk_metrics": {
    "content": 38,
    "authentication": 40,
    "identity": 22,
    "domain": 28,
    "network": 12,
    "url": 0,
    "synergy": 25,
    "evidence_sources": ["content", "authentication", "identity", "domain", "network"],
    "auth_passes": 0,
    "auth_failures": 3,
    "auth_missing": 0,
    "flagged_term_count": 8,
    "analysis_confidence": 100
  }
}
```

**Error responses:**

| Status | Reason |
|--------|--------|
| `400` | File is not `.eml` or is empty |

---

## CORS

The API allows cross-origin requests from:

- `http://localhost:3000` (Create React App)
- `http://localhost:5173` (Vite)

---

## Project Structure

```
AI-Email-Threat-Detector/
├── backend/
│   ├── main.py                  # FastAPI application entrypoint & API routes
│   ├── analyzers/               # Core email threat analysis engines
│   │   ├── email_parser.py      # .eml RFC-822 MIME parsing
│   │   ├── header_analyzer.py   # SPF / DKIM / DMARC & domain lookalike checks
│   │   ├── url_analyzer.py      # URL intelligence & brand spoofing detection
│   │   ├── ip_analyzer.py       # Received hop parsing, IP geo & ISP reputation
│   │   └── risk_engine.py       # Evidence-aware multi-vector risk scorer
│   ├── database/                # Persistence & ORM layer
│   │   ├── db.py                # SQLAlchemy engine & session maker
│   │   ├── models.py            # AnalyzedEmail & Incident models
│   │   └── db_seed.py           # Database seeding utilities
│   ├── ml/                      # Machine learning & NLP classification
│   │   ├── phishing_model.py    # Phishing NLP classifier (heuristics + TF-IDF)
│   │   ├── dataset_builder.py   # Dataset builder & sampler
│   │   ├── train_llm.py         # DistilBERT fine-tuning pipeline
│   │   └── push_to_hub.py       # Hugging Face hub deployment
│   ├── alerts/                  # Security notifications
│   │   └── webhook.py           # Webhook dispatcher for HIGH/CRITICAL threats
│   ├── ingestion/               # Automated email ingestion
│   │   ├── imap_poller.py       # Background IMAP mailbox poller
│   │   ├── processor.py         # Ingestion processor
│   │   ├── scheduler.py         # Periodic polling scheduler
│   │   └── state.py             # UID tracking state
│   ├── tests/                   # Integration and unit test suites
│   │   ├── test_integration.py  # End-to-end API & DB integration tests
│   │   ├── test_url_analyzer.py # Comprehensive URL analyzer test suite
│   │   └── conftest.py          # Pytest path configuration
│   ├── requirements.txt         # Python dependencies
│   └── PARSER_README.md         # Email parser documentation
└── frontend/                    # React + Vite web application
    ├── src/
    │   ├── UserPortal.jsx       # User email upload & quick text scanning
    │   ├── Dashboard.jsx        # SOC Operations Center dashboard
    │   ├── SOCSummaryCharts.jsx # Real-time verdicts & threat keyword charts
    │   ├── SOCIncidentQueue.jsx # Incident & analyzed email triage queue
    │   └── SOCDetailDrawer.jsx  # Deep forensic analysis drawer
```

---

## License

This project was built during a hackathon. License TBD.
