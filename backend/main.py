"""
AI Email Threat Detector – Production FastAPI Application.

POST /api/analyze  accepts a multipart .eml upload, runs it through the full
threat detection pipeline (Email Parser -> Header Analyzer -> NLP Classifier ->
IP Analyzer -> Risk Engine), and returns a single unified flat JSON response.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import traceback

from email_parser import parse_email
from header_analyzer import analyze as analyze_headers
from phishing_model import classify as classify_nlp
from url_analyzer import analyze_urls
from ip_analyzer import analyze as analyze_ip
from risk_engine import compute as compute_risk

app = FastAPI(
    title="AI Email Threat Detector",
    description="Email threat analysis API combining header analysis, NLP phishing detection, and IP reputation scoring.",
    version="1.0.0",
)

# ── CORS – allow frontend dev servers ────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


FAKE_INCIDENTS = [
    {
        "id": 1,
        "analyzed_email_id": 101,
        "title": "Credential phishing attempt",
        "severity": "critical",
        "status": "new",
        "sender": "Billing Department <billing@company-payments.xyz>",
        "subject": "URGENT: Outstanding Invoice #INV-92841",
        "risk_score": 100,
        "classification": "CRITICAL",
        "evidence_level": "STRONG",
        "assigned_to": None,
        "created_at": "2026-09-02T09:00:00Z",
        "updated_at": "2026-09-02T09:00:00Z",
    },
    {
        "id": 2,
        "analyzed_email_id": 102,
        "title": "Suspicious login URL review",
        "severity": "medium",
        "status": "investigating",
        "sender": "Security Notice <alerts@example-support.com>",
        "subject": "Review recent account activity",
        "risk_score": 52,
        "classification": "MEDIUM",
        "evidence_level": "MODERATE",
        "assigned_to": "soc-analyst@example.com",
        "created_at": "2026-09-02T10:15:00Z",
        "updated_at": "2026-09-02T10:40:00Z",
    },
]


@app.get("/")
def root():
    """Health check endpoint."""
    return {"message": "AI Email Threat Detector API is running"}


@app.get("/api/incidents")
def list_incidents():
    """Temporary SOC incident list stub; does not query persistence yet."""
    return {
        "items": FAKE_INCIDENTS,
        "total": len(FAKE_INCIDENTS),
    }


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: int):
    """Temporary SOC incident detail stub; does not query persistence yet."""
    for incident in FAKE_INCIDENTS:
        if incident["id"] == incident_id:
            return {
                **incident,
                "summary": "Mock incident detail for SOC workflow integration.",
                "reasons": [
                    "SPF authentication failed",
                    "Sender/Reply-To mismatch detected",
                    "Strong phishing-language evidence",
                ],
                "timeline": [
                    {
                        "timestamp": incident["created_at"],
                        "event": "Incident created from analysis result",
                    },
                    {
                        "timestamp": incident["updated_at"],
                        "event": f"Status is {incident['status']}",
                    },
                ],
            }

    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/api/stats/summary")
def get_stats_summary():
    """Temporary SOC summary stats stub; does not calculate from persistence yet."""
    return {
        "total_analyzed_emails": 128,
        "total_incidents": len(FAKE_INCIDENTS),
        "open_incidents": 2,
        "critical_incidents": 1,
        "high_risk_emails": 14,
        "average_risk_score": 37,
    }


@app.get("/api/stats/incidents")
def get_incident_stats():
    """Temporary incident distribution stats stub; does not query persistence yet."""
    return {
        "by_status": {
            "new": 1,
            "open": 0,
            "investigating": 1,
            "escalated": 0,
            "resolved": 0,
            "false_positive": 0,
            "closed": 0,
        },
        "by_severity": {
            "low": 0,
            "medium": 1,
            "high": 0,
            "critical": 1,
        },
        "recent_incidents": FAKE_INCIDENTS,
    }


@app.post("/api/analyze")
async def analyze_email(file: UploadFile = File(...)):
    """
    Accepts a .eml file upload, runs the live multi-stage analysis pipeline,
    and returns a unified flat JSON payload.
    """
    # 1. Validate file extension
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported."
        )

    # 2. Read file contents
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file is empty."
        )

    try:
        # Stage 1: Parse raw .eml into structured fields
        parsed = parse_email(file_bytes)

        # Stage 2: Header & Authentication Analysis
        header_res = analyze_headers(parsed)

        # Stage 3: NLP Content Phishing Classification
        nlp_input = "\n\n".join(
            part for part in (parsed.get("subject", ""), parsed.get("body", "")) if part
        )
        nlp_res = classify_nlp(nlp_input)

        # Stage 4: URL Phishing Analysis
        url_res = analyze_urls(parsed)

        # Stage 5: IP Geolocation & Network Reputation
        ip_res = analyze_ip(parsed.get("received_chain", []))

        # Stage 6: Composite Risk Calculation
        final_verdict = compute_risk(header_res, nlp_res, ip_res, url_res)

        # ── Flatten response into unified JSON ─────────────────────────
        return {
            # Email metadata & content
            "from": parsed.get("from", ""),
            "to": parsed.get("to", ""),
            "subject": parsed.get("subject", ""),
            "body": parsed.get("body", ""),
            "received_chain": parsed.get("received_chain", []),

            # Header analysis results
            **header_res,

            # IP intelligence results
            **ip_res,

            # NLP model results
            **nlp_res,

            # URL analysis results
            **url_res,

            # Risk Engine final verdict
            **final_verdict,
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"An error occurred while analyzing the email: {str(e)}"
        )
