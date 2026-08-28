"""
AI Email Threat Detector – FastAPI backend (stub mode).

POST /api/analyze  accepts a multipart .eml upload, runs it through five
analysis stages (currently returning hardcoded mock data), and returns a
single flat JSON response.

Switch to real imports at integration time by replacing the stub_* functions
with actual imports from the teammate modules.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="AI Email Threat Detector",
    description="Email upload and threat-analysis API (stub mode)",
    version="0.1.0",
)

# ── CORS – allow the React dev server ────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================================
#  STUBS — replace with real imports at integration time
# =====================================================================

def stub_parse_eml(file_bytes: bytes) -> dict:
    """Stub for email_parser.parse_email"""
    return {
        "from": "billing@company-payments.xyz",
        "to": "victim@example.com",
        "subject": "URGENT: Outstanding Invoice",
        "reply_to": "payments.help@gmail.com",
        "return_path": "bounce@evil.xyz",
        "message_id": "<12345@evil.xyz>",
        "body": "Your account will be suspended...",
        "raw_headers": {"X-Mailer": "Evil Mailer 1.0"},
        "received_chain": [
            "Received: from suspicious-server...",
            "Received: by another-mail-server...",
        ],
    }


def stub_analyze_headers(parsed_email: dict) -> dict:
    """Stub for header_analyzer.analyze"""
    return {
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
        "sender_reply_mismatch": True,
        "domain_lookalike": False,
        "domain_age_days": None,
        "anomalies": ["Sender identity mismatch", "Multiple authentication failures"],
        "header_risk_score": 80,
    }


def stub_classify(body_text: str) -> dict:
    """Stub for phishing_model.classify"""
    return {
        "phishing_probability": 91,
        "legitimate_probability": 3,
        "flagged_terms": ["urgent", "account suspended", "click immediately"],
        "method": "heuristic",
    }


def stub_analyze_ips(received_chain: list[str]) -> dict:
    """Stub for ip_analyzer.analyze"""
    return {
        "extracted_ips": ["185.123.45.67"],
        "primary_ip": "185.123.45.67",
        "geo": {
            "country": "Germany",
            "city": "Frankfurt",
            "isp": "Example Hosting Provider",
        },
        "ip_risk_score": 60,
    }


def stub_compute_risk(header_result: dict, nlp_result: dict, ip_result: dict) -> dict:
    """Stub for risk_engine.compute"""
    return {
        "risk_score": 89,
        "classification": "CRITICAL",
        "reasons": [
            "SPF failed",
            "DKIM failed",
            "Sender/Reply-To mismatch",
            "High phishing probability (91%)",
        ],
        "breakdown": {"nlp": 91, "header": 80, "ip": 60},
    }


# =====================================================================
#  Routes
# =====================================================================

@app.get("/")
def root():
    return {"message": "AI Email Threat Detector API is running"}


@app.post("/api/analyze")
async def analyze_email(file: UploadFile = File(...)):
    """Accept a .eml upload, run all analysis stages, return flat JSON."""

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    # ── Pipeline (stubs) ──────────────────────────────────────────────
    parsed       = stub_parse_eml(file_bytes)
    header_res   = stub_analyze_headers(parsed)
    nlp_res      = stub_classify(parsed["body"])
    ip_res       = stub_analyze_ips(parsed["received_chain"])
    final        = stub_compute_risk(header_res, nlp_res, ip_res)

    # ── Flat response ─────────────────────────────────────────────────
    return {
        # From ParsedEmail
        "from": parsed["from"],
        "subject": parsed["subject"],
        "body": parsed["body"],
        "received_chain": parsed["received_chain"],
        # Header analysis
        **header_res,
        # IP analysis
        **ip_res,
        # NLP
        **nlp_res,
        # Final verdict
        **final,
    }