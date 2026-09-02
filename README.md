# 🛡️ AI Email Threat Detector

An AI-powered email threat analysis tool that inspects `.eml` files for phishing indicators, suspicious headers, URLs, and sender infrastructure — built as a hackathon MV## Architecture (Phase 2 Update)

```
┌──────────────────┐                               ┌───────────────────────────┐
│ React Dashboard  │       POST /api/analyze       │      FastAPI (main)       │
│  (SOC View &     │ ────────────────────────────▶ │                           │
│   Queue UI)      │ ◀──────────────────────────── │      (API Endpoints)      │
└────────┬─────────┘       JSON response           └─────────────┬─────────────┘
         │                                                       │
         │                 GET /api/incidents                    │
         └───────────────────────────────────────────────────────┤
                                                                 │
                                                       ┌─────────▼─────────┐
                                                       │  SQLite/Postgres  │
                                                       │    (Database)     │
                                                       └─────────┬─────────┘
                                                                 │
                               ┌─────────────────────────────────┼─────────────────────────────────┐
                               │                                 │                                 │
                      ┌────────▼────────┐               ┌────────▼────────┐               ┌────────▼────────┐
                      │ header_analyzer │               │ phishing_model  │               │   ip_analyzer   │
                      │  (SPF/DKIM/     │               │ (Custom LLM/NLP)│               │  (Threat Intel  │
                      │   DMARC check)  │               │                 │               │   Integration)  │
                      └────────┬────────┘               └────────┬────────┘               └────────┬────────┘
                               │                                 │                                 │
                               └─────────────────────────────────┼─────────────────────────────────┘
                                                                 │
                                                        ┌────────▼────────┐
                                                        │   risk_engine   │
                                                        │  (Final Score)  │
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
### New Phase 2 Components Completed in `main`:
1. **Custom LLM / NLP Classification**: Transitioned from heuristic to a dedicated machine learning approach for parsing phishing language (`train_llm.py`, `dataset_builder.py`, `push_to_hub.py`).
2. **Persistence Layer**: Implemented a database layer using SQLAlchemy (`db.py`, `models.py`) to save parsed incident reports and feed the new SOC dashboard.
3. **SOC Dashboard Frontend**: Built a premium React frontend featuring a sortable/filterable incident queue (`SOCIncidentQueue.jsx`), dynamic summary charts (`SOCSummaryCharts.jsx`), and an interactive incident detail drawer (`SOCDetailDrawer.jsx`).
4. **Enhanced Threat Intel**: Extended `ip_analyzer.py` and `url_analyzer.py` with real threat intel feeds, wired into a refined `risk_engine.py`.

---

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- pip & npm

### 1. Backend (API server & Database)

```bash
# From the project root
pip install -r backend/requirements.txt

# Start the API (Terminal 1)
cd backend
uvicorn main:app --reload --port 8000
```

> The API server starts at `http://localhost:8000`.
> Interactive API docs are at [http://localhost:8000/docs](http://localhost:8000/docs).

### 2. Frontend (React SOC Dashboard)

Open a **second terminal**:

```bash
# From the project root
cd frontend
npm install
npm run dev
```

> The website starts at `http://localhost:5173`.
> **Open this URL in your browser** to access the SOC Dashboard and Upload UI.

---

## API Reference

### `GET /`

Health check.

### `POST /api/analyze`

Upload a `.eml` file for threat analysis. The result is saved to the database.

### `GET /api/incidents` (New)

Fetch the queue of all processed email incidents for the SOC Dashboard.

---

## Project Structure

```
AI-Email-Threat-Detector/
├── backend/
│   ├── main.py               # FastAPI app & endpoints
│   ├── db.py / models.py     # SQLAlchemy Persistence
│   ├── email_parser.py       # .eml parsing
│   ├── header_analyzer.py    # SPF / DKIM / DMARC analysis
│   ├── phishing_model.py     # Custom LLM phishing classification
│   ├── train_llm.py          # LLM fine-tuning scripts
│   ├── url_analyzer.py       # URL extraction and threat intel
│   ├── ip_analyzer.py        # IP geolocation & risk scoring
│   └── risk_engine.py        # Evidence-aware final risk aggregation
└── frontend/                 # React UI
    ├── package.json
    └── src/
        ├── App.jsx           # Routing & App Shell
        ├── Dashboard.jsx     # SOC Mission Control Layout
        ├── SOCIncidentQueue.jsx
        ├── SOCSummaryCharts.jsx
        ├── SOCDetailDrawer.jsx
        └── index.css         # Premium UI styling
```

---
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
