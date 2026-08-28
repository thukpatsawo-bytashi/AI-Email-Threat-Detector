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


@app.get("/")
def root():
    """Health check endpoint."""
    return {"message": "AI Email Threat Detector API is running"}


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
        nlp_res = classify_nlp(parsed.get("body", ""))

        # Stage 4: IP Geolocation & Network Reputation
        ip_res = analyze_ip(parsed.get("received_chain", []))

        # Stage 5: Composite Risk Calculation
        final_verdict = compute_risk(header_res, nlp_res, ip_res)

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

            # Risk Engine final verdict
            **final_verdict,
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"An error occurred while analyzing the email: {str(e)}"
        )