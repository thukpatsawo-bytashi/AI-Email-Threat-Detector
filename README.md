# 🛡️ AI Email Threat Detector

An AI-powered email threat analysis tool that inspects `.eml` files for phishing indicators, suspicious headers, and malicious IPs — built as a hackathon MVP.

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
| 1 | `email_parser.py` | Raw `.eml` bytes | `ParsedEmail` dict |
| 2 | `header_analyzer.py` | `ParsedEmail` | `HeaderAnalysisResult` |
| 3 | `phishing_model.py` | Email body text | `NLPResult` |
| 4 | `ip_analyzer.py` | Received chain | `IPResult` |
| 5 | `risk_engine.py` | Steps 2–4 results | `FinalResult` |

> **Note:** The backend is currently running in **stub mode** — all five analysis stages return hardcoded mock data. Real module imports will be wired in at integration time.

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
  "from": "billing@company-payments.xyz",
  "subject": "URGENT: Outstanding Invoice",
  "body": "Your account will be suspended...",

  "spf": "fail",
  "dkim": "fail",
  "dmarc": "fail",
  "sender_reply_mismatch": true,
  "domain_lookalike": false,
  "anomalies": ["Sender identity mismatch", "Multiple authentication failures"],
  "header_risk_score": 80,

  "extracted_ips": ["185.123.45.67"],
  "primary_ip": "185.123.45.67",
  "geo": { "country": "Germany", "city": "Frankfurt", "isp": "Example Hosting Provider" },
  "ip_risk_score": 60,

  "phishing_probability": 91,
  "legitimate_probability": 3,
  "flagged_terms": ["urgent", "account suspended", "click immediately"],

  "risk_score": 89,
  "classification": "CRITICAL",
  "reasons": ["SPF failed", "DKIM failed", "Sender/Reply-To mismatch", "High phishing probability (91%)"],
  "breakdown": { "nlp": 91, "header": 80, "ip": 60 }
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
│   ├── main.py               # FastAPI app & route (stub mode)
│   ├── email_parser.py        # .eml parsing
│   ├── header_analyzer.py     # SPF / DKIM / DMARC analysis
│   ├── phishing_model.py      # NLP phishing classification
│   ├── ip_analyzer.py         # IP geolocation & risk scoring
│   ├── risk_engine.py         # Final risk aggregation
│   ├── requirements.txt       # Python dependencies
│   └── PARSER_README.md       # Email parser docs
└── frontend/                  # React UI (TBD)
```

---

## Module Ownership

| Module | Owner | Status |
|--------|-------|--------|
| `main.py` | API / Integration | ✅ Stub mode ready |
| `email_parser.py` | Parser team | 🔧 In progress |
| `header_analyzer.py` | Header team | 🔧 In progress |
| `phishing_model.py` | NLP team | 🔧 In progress |
| `ip_analyzer.py` | IP team | 🔧 In progress |
| `risk_engine.py` | Risk team | 🔧 In progress |
| `frontend/` | Frontend team | 🔧 In progress |

---

## License

This project was built during a hackathon. License TBD.
