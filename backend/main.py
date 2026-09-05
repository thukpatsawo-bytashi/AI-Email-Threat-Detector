"""
AI Email Threat Detector – Production FastAPI Application.

Provides:
- POST /api/analyze: Multi-stage email threat analysis from uploaded .eml files
- POST /api/analyze-text: Multi-stage threat analysis from direct user input / pasted text
- GET  /api/incidents: Real-time SOC incident queue with dynamic filtering
- GET  /api/incidents/{id}: Detailed incident and email metadata
- PATCH /api/incidents/{id}: Analyst triage actions (escalate, false positive, close)
- GET  /api/stats/summary: 100% dynamic SOC statistics computed from real database records
- GET  /api/stats/charts: 100% dynamic 7-day verdicts and aggregated threat terms
"""

from contextlib import asynccontextmanager
import concurrent.futures
from datetime import datetime, timedelta, timezone
import traceback
from typing import Any

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Query
from fastapi.responses import JSONResponse, Response
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

import sys
from pathlib import Path

# Ensure backend root is always on sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from database import Base, engine, get_db, AnalyzedEmail, Incident, IncidentStatus
from analyzers import (
    parse_email,
    analyze_headers,
    analyze_ip,
    analyze_urls,
    compute_risk,
)
from ml import classify_nlp
from alerts.webhook import send_alert
from imap_monitor import imap_monitor


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database schema is created cleanly with no artificial seeds
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="AI Email Threat Detector",
    description="Email threat analysis API combining header analysis, NLP phishing detection, URL intelligence, and IP reputation scoring.",
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS – allow frontend dev servers on any localhost port ───────────
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic Request Models ───────────────────────────────────────────
class IncidentUpdatePayload(BaseModel):
    status: str
    assigned_to: str | None = None
    notes: str | None = None


class DirectEmailInput(BaseModel):
    from_email: str | None = None
    to_email: str | None = None
    subject: str | None = None
    body: str | None = None
    raw_headers: str | None = None
    raw_eml_text: str | None = None


# ── Helper Formatter ──────────────────────────────────────────────────
def format_email_entry_for_frontend(email: AnalyzedEmail) -> dict[str, Any]:
    """
    Formats a database AnalyzedEmail model (along with any associated Incident)
    into the schema consumed by SOCIncidentQueue and SOCDetailDrawer.
    """
    res = (email.analysis_result or {})
    inc = email.incidents[0] if email.incidents else None

    reasons = res.get("reasons", [])
    if inc and inc.summary:
        explanation = inc.summary
    elif reasons:
        explanation = " ".join(str(r) for r in reasons[:3])
    else:
        explanation = "Standard benign email. No elevated threat patterns detected."

    spf = res.get("spf", "none")
    dkim = res.get("dkim", "none")
    dmarc = res.get("dmarc", "none")
    auth_status = {
        "SPF": spf,
        "DKIM": dkim,
        "DMARC": dmarc,
    }

    threat_intel = list(res.get("threat_intel") or [])
    if not threat_intel:
        if res.get("domain_lookalike") and email.sender:
            threat_intel.append({"type": "Domain", "value": email.sender, "source": "Domain Threat Intel"})
        if res.get("primary_ip") and res.get("ip_risk_score", 0) >= 40:
            threat_intel.append({"type": "IP", "value": res.get("primary_ip", ""), "source": "IP Abuse Check"})
        for u in res.get("urls", []):
            if isinstance(u, dict) and u.get("classification") in ("SUSPICIOUS", "MALICIOUS"):
                threat_intel.append({
                    "type": "URL",
                    "value": str(u.get("original_url", ""))[:45],
                    "source": "URL Phish Engine",
                })

    status_map = {
        IncidentStatus.NEW: "New",
        IncidentStatus.OPEN: "Open",
        IncidentStatus.IN_REVIEW: "In Review",
        IncidentStatus.INVESTIGATING: "Investigating",
        IncidentStatus.ESCALATED: "Escalated",
        IncidentStatus.RESOLVED: "Resolved",
        IncidentStatus.FALSE_POSITIVE: "False Positive",
        IncidentStatus.CLOSED: "Closed",
    }

    if inc:
        status_display = status_map.get(inc.status, inc.status.value.capitalize())
        raw_status = inc.status.value
        entry_id = f"INC-{inc.id:04d}"
        numeric_id = inc.id
    else:
        status_display = "Clean"
        raw_status = "clean"
        entry_id = f"EML-{email.id:04d}"
        numeric_id = email.id

    return {
        "id": entry_id,
        "numeric_id": numeric_id,
        "email_id": email.id,
        "has_incident": bool(inc),
        "incident_id": inc.id if inc else None,
        "date": email.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "sender": email.sender or "Unknown",
        "subject": (email.subject or "No Subject") or "No Subject",
        "severity": email.classification.upper(),
        "status": status_display,
        "raw_status": raw_status,
        "riskScore": email.risk_score,
        "explanation": explanation,
        "detailed_reasons": reasons,
        "authStatus": auth_status,
        "threatIntel": threat_intel,
        "assigned_to": inc.assigned_to if inc else None,
        "notes": inc.notes if inc else None,
        "filename": email.filename,
        "body_preview": (email.body[:400] if email.body else ""),
        "analysis_result": res,
        # Geo / IP intel
        "geo": res.get("geo", {}),
        "primary_ip": res.get("primary_ip", ""),
        "ip_risk_score": res.get("ip_risk_score", 0),
        "reputation": res.get("reputation", {}),
        # URL analysis
        "urls": res.get("urls", []),
        "url_risk_score": res.get("url_risk_score", 0),
    }


def execute_analysis_pipeline(parsed: dict, filename: str, db: Session) -> dict[str, Any]:
    """
    Shared execution engine that runs headers, NLP, URLs, IP, and risk computation,
    persisting results to the database and raising an incident if required.
    """
    nlp_input = "\n\n".join(
        part for part in (parsed.get("subject", ""), parsed.get("body", "")) if part
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        f_header = executor.submit(analyze_headers, parsed)
        f_nlp = executor.submit(classify_nlp, nlp_input)
        f_url = executor.submit(analyze_urls, parsed)
        f_ip = executor.submit(analyze_ip, parsed.get("received_chain", []))

        header_res = f_header.result()
        nlp_res = f_nlp.result()
        url_res = f_url.result()
        ip_res = f_ip.result()

    final_verdict = compute_risk(header_res, nlp_res, ip_res, url_res)

    response_payload = {
        "from": parsed.get("from", ""),
        "to": parsed.get("to", ""),
        "subject": parsed.get("subject", ""),
        "body": parsed.get("body", ""),
        "received_chain": parsed.get("received_chain", []),
        **header_res,
        **ip_res,
        **nlp_res,
        **url_res,
        **final_verdict,
    }

    # Persist to database
    analyzed_email = AnalyzedEmail(
        filename=filename,
        sender=parsed.get("from", "") or "Unknown Sender",
        recipient=parsed.get("to", ""),
        subject=parsed.get("subject", "") or "No Subject",
        body=parsed.get("body", ""),
        risk_score=final_verdict.get("risk_score", 0),
        classification=final_verdict.get("classification", "LOW"),
        evidence_level=final_verdict.get("evidence_level", "LOW"),
        phishing_probability=nlp_res.get("phishing_probability", 0),
        header_risk_score=header_res.get("header_risk_score", 0),
        ip_risk_score=ip_res.get("ip_risk_score", 0),
        url_risk_score=url_res.get("url_risk_score", 0),
        raw_headers=parsed.get("raw_headers", {}),
        received_chain=parsed.get("received_chain", []),
        analysis_result=response_payload,
        risk_metrics=final_verdict.get("risk_metrics", {}),
        created_at=utcnow(),
    )
    db.add(analyzed_email)
    db.commit()
    db.refresh(analyzed_email)

    # Dynamic Incident generation for threats
    incident_id = None
    risk_score = final_verdict.get("risk_score", 0)
    classification = final_verdict.get("classification", "LOW").upper()

    if risk_score >= 30 or classification in ("CRITICAL", "HIGH", "MEDIUM"):
        reasons = final_verdict.get("reasons", [])
        
        # Get the first reason and extract the string message if it's a dict
        primary_reason = "Elevated email threat indicators detected"
        if reasons:
            first_reason = reasons[0]
            if isinstance(first_reason, dict):
                primary_reason = first_reason.get("message", primary_reason)
            else:
                primary_reason = str(first_reason)
                
        incident = Incident(
            analyzed_email_id=analyzed_email.id,
            title=f"{classification} Threat: {(analyzed_email.subject or 'No Subject')[:75]}",
            severity=classification,
            status=IncidentStatus.NEW,
            summary=primary_reason,
            notes=f"Generated from threat analysis. Risk Score: {risk_score}/100.",
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)
        incident_id = incident.id

        # Dispatch real-time webhook alert for elevated threats
        if classification in ("CRITICAL", "HIGH"):
            try:
                send_alert(
                    severity=classification,
                    subject=analyzed_email.subject,
                    details={
                        "risk_score": f"{risk_score}/100",
                        "sender": analyzed_email.sender,
                        "summary": primary_reason,
                    }
                )
            except Exception:
                pass

    response_payload["analyzed_email_id"] = analyzed_email.id
    response_payload["incident_id"] = incident_id
    return response_payload


# ── Health Check ──────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"message": "AI Email Threat Detector API is running", "status": "healthy"}


# ── 1. Analyze Email from File Upload (.eml) ─────────────────────────
@app.post("/api/analyze")
async def analyze_email(files: list[UploadFile] = File(...), db: Session = Depends(get_db)):
    """
    Accepts uploaded .eml files, runs the multi-stage threat detection pipeline,
    persists the results, and creates dynamic incidents if risky.
    """
    results = []
    for file in files:
        if not (file.filename or "").lower().endswith(".eml"):
            continue

        file_bytes = await file.read()
        if not file_bytes:
            continue

        try:
            parsed = parse_email(file_bytes)
            safe_filename: str = file.filename or "unknown.eml"
            res = execute_analysis_pipeline(parsed, safe_filename, db)
            results.append(res)
        except Exception as e:
            traceback.print_exc()
            raise HTTPException(
                status_code=500,
                detail=f"An error occurred while analyzing the email {file.filename}: {str(e)}"
            )

    if not results and files:
        raise HTTPException(status_code=400, detail="No valid .eml files provided.")

    return results


# ── 2. Dynamic Input Analysis (Direct Text / Pasted Email) ───────────
@app.post("/api/analyze-text")
def analyze_direct_input(input_data: DirectEmailInput, db: Session = Depends(get_db)):
    """
    Accepts dynamic raw text input (raw email or separate From/Subject/Body/Headers fields),
    processes it through the complete detection pipeline, and persists real analysis records.
    """
    try:
        # If user pasted raw .eml RFC-822 text
        if input_data.raw_eml_text and input_data.raw_eml_text.strip():
            raw_bytes = input_data.raw_eml_text.encode("utf-8", errors="replace")
            parsed = parse_email(raw_bytes)
            filename = "pasted_raw_email.eml"
        else:
            # Structured fields entered dynamically by user
            raw_headers_dict = {}
            if input_data.raw_headers:
                for line in input_data.raw_headers.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        raw_headers_dict[k.strip()] = v.strip()

            parsed = {
                "from": input_data.from_email or "",
                "to": input_data.to_email or "",
                "subject": input_data.subject or "",
                "reply_to": input_data.from_email or "",
                "return_path": input_data.from_email or "",
                "message_id": "",
                "body": input_data.body or "",
                "raw_html": input_data.body if "<html" in (input_data.body or "").lower() else "",
                "raw_headers": raw_headers_dict,
                "received_chain": [],
            }
            filename = f"direct_scan_{int(utcnow().timestamp())}.eml"

        if not parsed.get("body") and not parsed.get("subject"):
            raise HTTPException(status_code=400, detail="Please provide email subject or body text to analyze.")

        return execute_analysis_pipeline(parsed, filename, db)

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing input text: {str(e)}"
        )


# ── SOC Incidents Queue ───────────────────────────────────────────────
@app.get("/api/incidents")
def list_incidents(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    search: str | None = Query(None),
    db: Session = Depends(get_db)
):
    """
    Returns all dynamically analyzed emails from the database, newest first.
    Includes active threat incidents as well as verified clean emails.
    """
    query = db.query(AnalyzedEmail).order_by(desc(AnalyzedEmail.created_at))

    if severity and severity.upper() != "ALL":
        query = query.filter(AnalyzedEmail.classification == severity.upper())

    emails = query.all()
    formatted = [format_email_entry_for_frontend(email) for email in emails]

    if status and status.upper() != "ALL":
        target_status = status.lower().replace(" ", "_")
        formatted = [e for e in formatted if e["raw_status"] == target_status]

    if search:
        s = search.lower()
        formatted = [
            e for e in formatted
            if s in e["subject"].lower()
            or s in e["sender"].lower()
            or s in e["id"].lower()
            or s in e["explanation"].lower()
        ]

    return {
        "items": formatted,
        "total": len(formatted),
    }


@app.get("/api/incidents/{item_id}")
def get_incident(item_id: int, db: Session = Depends(get_db)):
    """
    Returns full detail for an analyzed email or incident.
    """
    # 1. Try finding an Incident
    incident = db.query(Incident).filter(Incident.id == item_id).first()
    if incident and incident.analyzed_email:
        return format_email_entry_for_frontend(incident.analyzed_email)

    # 2. Try finding by AnalyzedEmail ID
    email = db.query(AnalyzedEmail).filter(AnalyzedEmail.id == item_id).first()
    if email:
        return format_email_entry_for_frontend(email)

    raise HTTPException(status_code=404, detail="Analyzed email or incident not found")


@app.get("/api/incidents/{item_id}/report")
def download_incident_report(item_id: int, db: Session = Depends(get_db)):
    """Generate a downloadable PDF threat analysis report."""
    email = db.query(AnalyzedEmail).filter(AnalyzedEmail.id == item_id).first()
    if not email:
        incident = db.query(Incident).filter(Incident.id == item_id).first()
        if incident and incident.analyzed_email:
            email = incident.analyzed_email

    if not email:
        raise HTTPException(status_code=404, detail="Incident not found")

    res = email.analysis_result or {}
    inc = email.incidents[0] if email.incidents else None

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title="AI Email Threat Analysis Report",
    )

    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "ReportTitle", parent=styles["Title"],
        alignment=TA_CENTER, fontSize=18, spaceAfter=6
    )
    subtitle = ParagraphStyle(
        "Subtitle", parent=styles["Normal"],
        alignment=TA_CENTER, fontSize=9, textColor=colors.grey, spaceAfter=14
    )
    section = ParagraphStyle(
        "Section", parent=styles["Heading2"],
        fontSize=12, spaceBefore=10, spaceAfter=6
    )
    body = ParagraphStyle(
        "ReportBody", parent=styles["BodyText"],
        fontSize=9, leading=12
    )
    small = ParagraphStyle(
        "Small", parent=body, fontSize=8, leading=10
    )

    def val(x):
        if x is None:
            return "N/A"
        return str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def para(x, style=body):
        return Paragraph(val(x), style)

    def add_table(rows, widths=(48 * mm, 132 * mm)):
        t = Table(rows, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F9FAFB")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(t)
        story.append(Spacer(1, 5))

    story = [
        Paragraph("AI Email Threat Analysis Report", title),
        Paragraph(
            f"Generated: {val(utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))}",
            subtitle
        ),
    ]

    story.append(Paragraph("1. Threat Summary", section))
    add_table([
        [para("Field", small), para("Value", small)],
        [para("Risk Score"), para(f"{email.risk_score}/100")],
        [para("Classification"), para(email.classification)],
        [para("Evidence Level"), para(email.evidence_level)],
        [para("Incident ID"), para(f"INC-{inc.id:04d}" if inc else "N/A")],
        [para("Incident Status"), para(inc.status.value if inc else "N/A")],
    ])

    story.append(Paragraph("2. Email Metadata", section))
    add_table([
        [para("Field", small), para("Value", small)],
        [para("From"), para(email.sender)],
        [para("To"), para(email.recipient)],
        [para("Subject"), para(email.subject)],
        [para("Date Analyzed"), para(email.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"))],
        [para("Filename"), para(email.filename)],
    ])

    story.append(Paragraph("3. Authentication Results", section))
    add_table([
        [para("Check", small), para("Result", small)],
        [para("SPF"), para(res.get("spf", "N/A"))],
        [para("DKIM"), para(res.get("dkim", "N/A"))],
        [para("DMARC"), para(res.get("dmarc", "N/A"))],
    ])

    story.append(Paragraph("4. Risk Score Breakdown", section))
    add_table([
        [para("Metric", small), para("Value", small)],
        [para("Header Risk Score"), para(email.header_risk_score)],
        [para("Phishing Probability"), para(email.phishing_probability)],
        [para("IP Risk Score"), para(email.ip_risk_score)],
        [para("URL Risk Score"), para(email.url_risk_score)],
    ])

    story.append(Paragraph("5. IP Intelligence", section))
    add_table([
        [para("Field", small), para("Value", small)],
        [para("Primary IP"), para(res.get("primary_ip", ""))],
        [para("Geolocation"), para(res.get("geo", {}))],
        [para("Reputation"), para(res.get("reputation", {}))],
    ])

    story.append(Paragraph("6. Key Findings", section))
    reasons = res.get("reasons", []) or []
    if reasons:
        for reason in reasons:
            story.append(Paragraph("• " + val(reason), body))
    else:
        story.append(para("No specific elevated threat findings were recorded."))

    story.append(Paragraph("7. Flagged Terms", section))
    flagged = res.get("flagged_terms", []) or []
    story.append(para(", ".join(map(str, flagged)) if flagged else "None"))

    story.append(Paragraph("8. URL Analysis", section))
    urls = res.get("urls", []) or []
    if urls:
        rows = [[para("URL", small), para("Classification / Risk", small)]]
        for item in urls[:50]:
            if isinstance(item, dict):
                url = item.get("original_url") or item.get("url") or ""
                details = str(item.get("classification", "N/A"))
                if item.get("risk_score") is not None:
                    details += f" | Risk: {item.get('risk_score')}"
                rows.append([para(url, small), para(details, small)])
            else:
                rows.append([para(item, small), para("N/A", small)])
        add_table(rows, widths=(105 * mm, 75 * mm))
    else:
        story.append(para("No URLs detected."))

    story.append(Paragraph("9. Email Body", section))
    story.append(para((email.body or "")[:12000], small))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="threat_report_{item_id}.pdf"'
        },
    )


@app.patch("/api/incidents/{item_id}")
def update_incident(
    item_id: int,
    payload: IncidentUpdatePayload,
    db: Session = Depends(get_db)
):
    """
    Allows SOC analysts to triage any email or incident in the queue:
    - Escalate to Tier 2
    - Mark as False Positive
    - Set to Investigating / Closed / Resolved
    """
    incident = db.query(Incident).filter(Incident.id == item_id).first()
    if not incident:
        # Check if item_id refers to an AnalyzedEmail that doesn't have an incident yet
        email = db.query(AnalyzedEmail).filter(AnalyzedEmail.id == item_id).first()
        if not email:
            raise HTTPException(status_code=404, detail="Incident or analyzed email not found")

        # Create an incident on-demand for this email
        incident = Incident(
            analyzed_email_id=email.id,
            title=f"Manual Triage: {(email.subject or 'No Subject')[:75]}",
            severity=email.classification.upper(),
            status=IncidentStatus.IN_REVIEW,
            summary="Manually flagged by analyst for triage.",
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

    new_status_str = payload.status.lower().strip().replace(" ", "_")

    valid_statuses = {item.value: item for item in IncidentStatus}
    if new_status_str not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{payload.status}'. Valid values: {list(valid_statuses.keys())}"
        )

    incident.status = valid_statuses[new_status_str]
    incident.updated_at = utcnow()

    if payload.assigned_to:
        incident.assigned_to = payload.assigned_to
    if payload.notes:
        incident.notes = payload.notes

    if incident.status in (IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE, IncidentStatus.RESOLVED):
        incident.closed_at = utcnow()

    db.commit()
    db.refresh(incident)

    return {
        "success": True,
        "incident": format_email_entry_for_frontend(incident.analyzed_email)
    }


class BulkDeletePayload(BaseModel):
    item_ids: list[int]


@app.delete("/api/incidents/bulk")
def delete_incidents_bulk(payload: BulkDeletePayload, db: Session = Depends(get_db)):
    """
    Deletes multiple incidents and their associated analyzed emails.
    """
    if not payload.item_ids:
        return {"success": True, "message": "No items to delete"}

    deleted_count = 0
    for item_id in payload.item_ids:
        email = db.query(AnalyzedEmail).filter(AnalyzedEmail.id == item_id).first()
        if email:
            incident = db.query(Incident).filter(Incident.analyzed_email_id == email.id).first()
            if incident:
                db.delete(incident)
            db.delete(email)
            deleted_count += 1
        else:
            incident = db.query(Incident).filter(Incident.id == item_id).first()
            if incident:
                db.delete(incident)
                deleted_count += 1

    db.commit()
    return {"success": True, "message": f"Deleted {deleted_count} incidents successfully"}


@app.delete("/api/incidents/{item_id}")
def delete_incident(item_id: int, db: Session = Depends(get_db)):
    """
    Deletes an incident and its associated analyzed email.
    """
    email = db.query(AnalyzedEmail).filter(AnalyzedEmail.id == item_id).first()
    if email:
        incident = db.query(Incident).filter(Incident.analyzed_email_id == email.id).first()
        if incident:
            db.delete(incident)
        db.delete(email)
        db.commit()
        return {"success": True, "message": "Deleted successfully"}
    
    incident = db.query(Incident).filter(Incident.id == item_id).first()
    if incident:
        db.delete(incident)
        db.commit()
        return {"success": True, "message": "Deleted successfully"}

    raise HTTPException(status_code=404, detail="Incident or analyzed email not found")


# ── SOC Summary Statistics (100% Dynamic) ─────────────────────────────
@app.get("/api/stats/summary")
def get_stats_summary(db: Session = Depends(get_db)):
    """
    Calculates dynamic SOC dashboard statistics directly from database records.
    Contains zero hardcoded values.
    """
    total_emails = db.query(AnalyzedEmail).count()
    active_incidents = db.query(Incident).filter(
        Incident.status.in_([
            IncidentStatus.NEW,
            IncidentStatus.OPEN,
            IncidentStatus.IN_REVIEW,
            IncidentStatus.INVESTIGATING,
            IncidentStatus.ESCALATED,
        ])
    ).count()

    threat_count = db.query(AnalyzedEmail).filter(
        AnalyzedEmail.classification.in_(["HIGH", "CRITICAL"])
    ).count()
    threat_rate = f"{(threat_count / total_emails * 100):.1f}%" if total_emails > 0 else "0.0%"

    # Dynamic average resolution calculation from resolved/closed incidents
    closed_incidents = db.query(Incident).filter(
        Incident.closed_at.isnot(None),
        Incident.status.in_([IncidentStatus.CLOSED, IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE])
    ).all()

    if closed_incidents:
        total_minutes = sum(
            max(1, int((inc.closed_at - inc.created_at).total_seconds() / 60))  # type: ignore[operator]
            for inc in closed_incidents
            if inc.closed_at is not None
        )
        avg_m = int(total_minutes / len(closed_incidents))
        avg_resolution = f"{avg_m}m" if avg_m < 60 else f"{avg_m // 60}h {avg_m % 60}m"
    else:
        avg_resolution = "N/A"

    return {
        "active_incidents": active_incidents,
        "avg_resolution": avg_resolution,
        "emails_scanned": total_emails,
        "threat_rate": threat_rate,
        "total_incidents": db.query(Incident).count(),
    }


# ── SOC Charts & Trends Statistics (100% Dynamic) ─────────────────────
@app.get("/api/stats/charts")
@app.get("/api/stats/trends")
def get_stats_charts(db: Session = Depends(get_db)):
    """
    Returns 100% dynamic 7-day verdicts and aggregated threat terms strictly
    from analyzed email records in the database.
    """
    now = utcnow()
    day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

    # Dynamic 7-day buckets
    verdicts = []
    for i in range(6, -1, -1):
        target_date = (now - timedelta(days=i)).date()
        day_label = day_names[target_date.weekday()]

        start_dt = datetime(target_date.year, target_date.month, target_date.day)
        end_dt = start_dt + timedelta(days=1)

        day_emails = db.query(AnalyzedEmail).filter(
            AnalyzedEmail.created_at >= start_dt,
            AnalyzedEmail.created_at < end_dt,
        ).all()

        malicious = sum(1 for e in day_emails if e.risk_score >= 60)
        clean = sum(1 for e in day_emails if e.risk_score < 60)
        verdicts.append({"name": day_label, "malicious": malicious, "clean": clean})

    # Dynamic extraction of top flagged threat terms
    all_emails = db.query(AnalyzedEmail).all()
    term_counts: dict[str, int] = {}
    for email in all_emails:
        res = email.analysis_result or {}
        terms = res.get("flagged_terms") or []
        for t in terms:
            cleaned = str(t).title()
            term_counts[cleaned] = term_counts.get(cleaned, 0) + 1

    palette = ["#6366f1", "#ef4444", "#f97316", "#eab308", "#22d3ee"]
    sorted_terms = sorted(term_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    terms_data = [
        {"name": term, "count": count, "fill": palette[idx % len(palette)]}
        for idx, (term, count) in enumerate(sorted_terms)
    ]

    return {
        "verdicts_over_time": verdicts,
        "top_terms": terms_data,
    }


# ── IMAP Live Email Monitoring ─────────────────────────────────────────
class IMAPConfig(BaseModel):
    host: str
    port: int = 993
    email: str
    password: str
    folder: str = "INBOX"
    interval: int = 15


@app.post("/api/imap/start")
def start_imap_monitor(config: IMAPConfig, db: Session = Depends(get_db)):
    """
    Starts IMAP monitoring with the provided config.
    New emails are analyzed and added to the incident queue in real time.
    """
    def analysis_callback(raw_bytes: bytes, filename: str):
        from database import SessionLocal
        local_db = SessionLocal()
        try:
            parsed = parse_email(raw_bytes)
            if parsed.get("body") or parsed.get("subject"):
                execute_analysis_pipeline(parsed, filename, local_db)
        except Exception as e:
            import traceback
            traceback.print_exc()
        finally:
            local_db.close()

    result = imap_monitor.start(config.model_dump(), analysis_callback)
    return result


@app.post("/api/imap/stop")
def stop_imap_monitor():
    """Stops the active IMAP monitor."""
    return imap_monitor.stop()


@app.get("/api/imap/status")
def get_imap_status():
    """Returns the current IMAP monitor status."""
    return imap_monitor.status
