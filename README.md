# 🛡️ AI Email Threat Detector

An enterprise-grade email security analysis platform and SOC operations center that inspects `.eml` files and raw email text for phishing indicators, authentication spoofing, malicious URLs, and suspicious sender infrastructure.

Developed as a standalone collaborative security engineering project combining automated ingestion, multi-vector threat detection, persistence, real-time alerting, and an analyst triage dashboard.

---

## Architecture

```
┌─────────────────────────┐                                ┌───────────────────────────┐
│     React Dashboard     │       POST /api/analyze        │      FastAPI Backend      │
│  (SOC View & Queue UI)  │ ─────────────────────────────▶ │                           │
│     (Vite on :5173)     │ ◀───────────────────────────── │    (Uvicorn on :8000)     │
└────────────┬────────────┘        JSON response           └─────────────┬─────────────┘
             │                                                           │
             │                   GET /api/incidents                      │
             └───────────────────────────────────────────────────────────┤
                                                                         │
                                                               ┌─────────▼─────────┐
                                                               │  SQLite Database  │
                                                               │ (Persistent Volume│
                                                               └─────────┬─────────┘
                                                                         │
                                       ┌─────────────────────────────────┼─────────────────────────────────┐
                                       │                                 │                                 │
                              ┌────────▼────────┐               ┌────────▼────────┐               ┌────────▼────────┐
                              │ header_analyzer │               │ phishing_model  │               │   ip_analyzer   │
                              │  (SPF/DKIM/     │               │ (DistilBERT ML  │               │  (Threat Intel  │
                              │   DMARC check)  │               │  + Heuristics)  │               │   & Abuse Geo)  │
                              └────────┬────────┘               └────────┬────────┘               └────────┬────────┘
                                       │                                 │                                 │
                                       └─────────────────────────────────┼─────────────────────────────────┘
                                                                         │
                                                                ┌────────▼────────┐
                                                                │   risk_engine   │
                                                                │  (Final Score)  │
                                                                └────────┬────────┘
                                                                         │
                                                                ┌────────▼────────┐
                                                                │ Webhook Alerts  │
                                                                │ (HIGH/CRITICAL) │
                                                                └─────────────────┘
```

### Analysis Pipeline

| Step | Module | Input | Output | Purpose |
|:---:|---|---|---|---|
| **1** | `analyzers/email_parser.py` | Raw `.eml` bytes / RFC-822 text | `ParsedEmail` dict | Extracts headers, multipart bodies, HTML, and Received hops |
| **2** | `analyzers/header_analyzer.py` | `ParsedEmail` | `HeaderAnalysisResult` | Validates SPF/DKIM/DMARC, detects spoofed From/Reply-To, and flags typosquats |
| **3** | `ml/phishing_model.py` | Subject + clean body text | `NLPResult` | Scores phishing intent via fine-tuned Transformer (DistilBERT) + weighted heuristics |
| **4** | `analyzers/url_analyzer.py` | Extracted URLs & anchor text | `URLAnalysisResult` | Evaluates domain age, brand impersonation, homoglyphs, and redirect cloaking |
| **5** | `analyzers/ip_analyzer.py` | Received hop chain | `IPResult` | Isolates originating sender IP, performs reverse DNS, ISP classification & abuse checks |
| **6** | `analyzers/risk_engine.py` | Aggregated findings (2–5) | `FinalResult` | Evidence-aware risk calculation (0–100 score, severity classification, explanations) |
| **7** | `alerts/webhook.py` | Threat verdict | Webhook Dispatch | Real-time notifications for HIGH and CRITICAL threat incidents |

---

## Core Features

- **Multi-Vector Threat Analysis**: Combines RFC-822 MIME parsing, cryptographic email authentication checks, URL intelligence with registrable-domain validation, IP reputation lookups, and NLP classification.
- **Continuous Email Ingestion**: Background IMAP poller automatically ingests unread mailbox traffic, parses messages, feeds the analysis API, and tracks high-watermark UIDs to prevent duplicate scanning.
- **SOC Analyst Workspace**:
  - Sortable and filterable incident triage queue (Severity: CRITICAL, HIGH, MEDIUM, LOW, CLEAN).
  - One-click analyst actions: Escalate to Tier 2, mark False Positive, investigate, or close.
  - Deep inspection drawer revealing raw headers, extracted URLs, authentication breakdown, and threat intelligence.
  - Dynamic 7-day verdict timeline and top-flagged threat terms charts.
- **Containerized & CI-Ready**: Fully dockerized via `docker compose` with persistent SQLite volume mounting, and GitHub Actions CI workflow for test and build verification.

---

## Quick Start

### Option 1: Run with Docker Compose (Recommended)

Run both the FastAPI backend and React frontend with a single command:

```bash
# Clone the repository
git clone https://github.com/thukpatsawo-bytashi/AI-Email-Threat-Detector.git
cd AI-Email-Threat-Detector

# Build and start all services
docker compose up --build
```

- **Frontend SOC Dashboard**: [http://localhost:5173](http://localhost:5173)
- **Backend API & Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **SQLite Database**: Persisted in the `sqlite_data` Docker volume at `/app/data/threat_detector.db`.

To stop the containers:
```bash
docker compose down
```

---

### Option 2: Manual Local Setup

#### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

#### 1. Backend Setup

```bash
# From project root
cd backend

# Create and activate a virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the API server
uvicorn main:app --reload --port 8000
```

The API starts at `http://localhost:8000`. Interactive OpenAPI documentation is accessible at [http://localhost:8000/docs](http://localhost:8000/docs).

#### 2. Frontend Setup

Open a **second terminal**:

```bash
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```

Access the user interface at [http://localhost:5173](http://localhost:5173).

---

## Continuous Email Ingestion (IMAP Mail Poller)

The codebase includes an automated email ingestion engine in `backend/ingestion/` that continuously monitors a designated IMAP inbox (e.g. `abuse@company.com` or a security mailbox), parses incoming emails, submits them to `/api/analyze-text`, and updates its state so emails are never processed twice.

### 1. Configuration

Create or edit `backend/.env` (see `backend/.env.example`):

```env
# IMAP Server Configuration
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
EMAIL_USERNAME=your-security-inbox@gmail.com
EMAIL_PASSWORD=your-app-password

# Polling interval in seconds (default: 20)
POLL_INTERVAL=20

# Target Analysis API endpoint (default: http://127.0.0.1:8000/api/analyze-text)
ANALYZE_API_URL=http://127.0.0.1:8000/api/analyze-text

# Optional webhook for real-time alerting on HIGH/CRITICAL threats
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
```

> **Note for Gmail users**: Use a 16-character **Google App Password** (Account Security → 2-Step Verification → App Passwords) rather than your personal password.

### 2. Running the Mail Poller

#### Continuous Daemon (Scheduled Poller)
Runs a persistent loop checking the mailbox every `POLL_INTERVAL` seconds using an APScheduler blocking runner:

```bash
# From project root
python -m backend.ingestion.scheduler
```

#### One-Off Ingestion Cycle
Fetches and processes all new emails since the last saved UID, then exits:

```bash
# From project root
python -m backend.ingestion.processor
```

### 3. How State Tracking Works
- The poller loads the highest UID processed from `backend/ingestion/state.json`.
- Only emails with `UID > last_uid` are fetched and processed.
- If an email analysis succeeds, `state.json` updates with the new highest UID.
- If an analysis fails, execution safely stops without advancing the UID, ensuring no emails are dropped or missed.

---

## API Reference

| Method | Endpoint | Description | Request Body |
|---|---|---|---|
| `GET` | `/` | Health check | None |
| `POST` | `/api/analyze` | Multi-stage threat analysis for uploaded `.eml` files | `multipart/form-data` (`file: UploadFile`) |
| `POST` | `/api/analyze-text` | Threat analysis for direct text / pasted email headers & body | `application/json` (`DirectEmailInput`) |
| `GET` | `/api/incidents` | SOC incident & email queue with filtering | Query params: `severity`, `status`, `search` |
| `GET` | `/api/incidents/{id}` | Detailed incident and email metadata | URL parameter `id` (integer) |
| `PATCH` | `/api/incidents/{id}` | Analyst triage (escalate, false positive, close, notes) | `application/json` (`IncidentUpdatePayload`) |
| `GET` | `/api/stats/summary` | 100% dynamic SOC statistics computed from DB records | None |
| `GET` | `/api/stats/charts` | Dynamic 7-day verdicts timeline and top-flagged threat terms | None |

### Sample `POST /api/analyze-text` Payload

```json
{
  "from_email": "security@paypa1-update.com",
  "to_email": "analyst@enterprise.corp",
  "subject": "URGENT: Verify Your Account Credentials",
  "body": "Your account has been locked. Click http://185.123.45.67/login to verify.",
  "raw_headers": "From: security@paypa1-update.com\nAuthentication-Results: spf=fail dkim=fail dmarc=fail"
}
```

---

## Project Structure

```
AI-Email-Threat-Detector/
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI workflow (PR & main checks)
├── backend/
│   ├── Dockerfile               # Production container definition (Python 3.11-slim)
│   ├── main.py                  # FastAPI application entrypoint & API routes
│   ├── requirements.txt         # Pinned Python package dependencies
│   ├── analyzers/               # Core email threat analysis engines
│   │   ├── email_parser.py      # .eml RFC-822 MIME parser & HTML cleaner
│   │   ├── header_analyzer.py   # SPF / DKIM / DMARC & domain lookalike checks
│   │   ├── url_analyzer.py      # Public-suffix URL intelligence & brand spoofing
│   │   ├── ip_analyzer.py       # Received hop extraction, GeoIP & ISP abuse scoring
│   │   └── risk_engine.py       # Evidence-aware multi-vector risk aggregator
│   ├── database/                # Persistence & ORM layer
│   │   ├── db.py                # SQLAlchemy engine & session factory
│   │   ├── models.py            # AnalyzedEmail & Incident database models
│   │   └── db_seed.py           # Realistic database seeding utilities
│   ├── ml/                      # Machine learning & NLP classification
│   │   ├── phishing_model.py    # Phishing NLP classifier (DistilBERT + heuristics)
│   │   ├── dataset_builder.py   # Training dataset builder & sampler
│   │   ├── train_llm.py         # DistilBERT sequence classification training
│   │   └── push_to_hub.py       # Hugging Face hub deployment utility
│   ├── alerts/                  # Security notifications
│   │   └── webhook.py           # Webhook dispatcher for HIGH/CRITICAL threats
│   ├── ingestion/               # Automated email ingestion module
│   │   ├── imap_poller.py       # Background IMAP mailbox connection & batch fetcher
│   │   ├── processor.py         # Payload mapping & analysis execution
│   │   ├── scheduler.py         # APScheduler periodic polling loop
│   │   └── state.py             # High-watermark UID persistence (state.json)
│   └── tests/                   # Pytest test suites
│       ├── conftest.py          # Pytest module path configuration
│       ├── test_integration.py  # End-to-end API & DB integration tests
│       ├── test_processor.py    # Ingestion processor & schema validation tests
│       └── test_url_analyzer.py # Comprehensive URL analyzer unit test suite
├── frontend/
│   ├── Dockerfile               # Node 18 multi-stage build + Vite preview server
│   ├── package.json             # React dependencies and scripts
│   ├── vite.config.js           # Vite dev/preview server & API proxy configuration
│   └── src/
│       ├── App.jsx              # Navigation shell and route definitions
│       ├── Dashboard.jsx        # SOC Operations Center dashboard layout
│       ├── Upload.jsx           # User portal for .eml upload & direct text scanning
│       ├── SOCSummaryCharts.jsx # Real-time verdicts & threat keyword analytics
│       ├── SOCIncidentQueue.jsx # Incident & analyzed email triage queue
│       ├── SOCDetailDrawer.jsx  # Deep forensic analysis drawer
│       └── index.css            # Dark mode design system & styling
└── docker-compose.yml           # Multi-container orchestration & volume configuration
```

---

## Testing & Quality Assurance

Run the automated test suite locally:

```bash
# Run backend tests
pytest backend/tests/ -v

# Run frontend build check
cd frontend && npm run build
```

---

## License

This project is licensed under the [MIT License](LICENSE).
