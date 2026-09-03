"""
Database Seeding Module

Populates initial baseline analyzed emails and SOC incidents if the database
is empty, giving analysts rich data to explore on initial launch.
"""

from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

try:
    from .models import AnalyzedEmail, Incident, IncidentStatus
except ImportError:
    from database.models import AnalyzedEmail, Incident, IncidentStatus

def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def seed_initial_data_if_empty(db: Session):
    """
    Seeds initial realistic incidents and analyzed emails if none exist.
    """
    if db.query(Incident).count() > 0 or db.query(AnalyzedEmail).count() > 0:
        return

    now = utcnow()

    # 1. Critical Phishing: PayPal Spoof
    email_1 = AnalyzedEmail(
        filename="paypal_suspension_urgent.eml",
        sender="PayPal Security <admin@paypal-security-update.com>",
        recipient="user@internal-corp.com",
        subject="Action Required: Your account has been suspended",
        body="Dear customer, your account has been temporarily suspended due to multiple unauthorized login attempts. Click immediately to verify your credentials and restore access within 24 hours.",
        risk_score=98,
        classification="CRITICAL",
        evidence_level="STRONG",
        phishing_probability=96,
        header_risk_score=90,
        ip_risk_score=60,
        url_risk_score=95,
        raw_headers={"Authentication-Results": "spf=fail dkim=fail dmarc=fail"},
        received_chain=["Received: from mail.paypal-security-update.com (185.123.45.67) by mx.internal-corp.com with ESMTPS"],
        analysis_result={
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
            "sender_reply_mismatch": True,
            "domain_lookalike": True,
            "domain_age_days": 2,
            "anomalies": [
                "Sender identity mismatch: From vs Reply-To",
                "Domain lookalike detected mimicking PayPal",
                "Newly registered domain (2 days old)",
                "SPF, DKIM, and DMARC authentication all failed"
            ],
            "flagged_terms": ["account suspended", "verify credentials", "click immediately", "within 24 hours"],
            "primary_ip": "185.123.45.67",
            "geo": {"country": "Germany", "city": "Frankfurt", "isp": "Bulletproof Hosting Ltd"},
            "threat_intel": [
                {"type": "Domain", "value": "paypal-security-update.com", "source": "VirusTotal"},
                {"type": "URL", "value": "http://185.123.45.67/login/verify", "source": "PhishTank"}
            ],
            "reasons": [
                "Sender identity mismatch detected",
                "Newly registered lookalike domain mimicking PayPal",
                "Strong phishing-language evidence (96%)",
                "SPF, DKIM, and DMARC authentication all failed"
            ],
            "breakdown": {"nlp": 96, "header": 90, "ip": 60, "url": 95},
        },
        created_at=now - timedelta(hours=2, minutes=15),
    )
    db.add(email_1)
    db.flush()

    inc_1 = Incident(
        analyzed_email_id=email_1.id,
        title="Credential Harvesting: PayPal Spoof with Lookalike Domain",
        severity="CRITICAL",
        status=IncidentStatus.OPEN,
        summary="LLM detected extreme urgency combined with deceptive lookalike domain (paypal-security-update.com). Authentication failed across all protocols.",
        notes="Flagged for immediate triage and domain blocking at firewall.",
        created_at=now - timedelta(hours=2, minutes=15),
        updated_at=now - timedelta(hours=2, minutes=15),
    )
    db.add(inc_1)

    # 2. High Risk: Macro Attachment HR Spoof
    email_2 = AnalyzedEmail(
        filename="q3_bonus_schedule.eml",
        sender="HR Department <hr@internal-corp.net>",
        recipient="all-staff@internal-corp.com",
        subject="Q3 Bonus Payout Schedule - Review Document",
        body="Attached is the finalized Q3 bonus distribution spreadsheet. Please open the attachment and verify your compensation details.",
        risk_score=85,
        classification="HIGH",
        evidence_level="STRONG",
        phishing_probability=78,
        header_risk_score=85,
        ip_risk_score=50,
        url_risk_score=60,
        raw_headers={"Authentication-Results": "spf=fail dkim=pass dmarc=fail"},
        received_chain=["Received: from mail.unauthorized-vps.org (192.168.44.12) by mx.internal-corp.com"],
        analysis_result={
            "spf": "fail",
            "dkim": "pass",
            "dmarc": "fail",
            "sender_reply_mismatch": True,
            "domain_lookalike": False,
            "domain_age_days": 180,
            "anomalies": [
                "Envelope sender mismatch: From vs Return-Path",
                "SPF validation failed from sending server"
            ],
            "flagged_terms": ["open the attachment", "verify credentials", "bonus"],
            "primary_ip": "192.168.44.12",
            "geo": {"country": "Netherlands", "city": "Amsterdam", "isp": "CloudVPS B.V."},
            "threat_intel": [
                {"type": "IP", "value": "192.168.44.12", "source": "AbuseIPDB"}
            ],
            "reasons": [
                "Sender spoofed internal address but failed SPF authorization",
                "Suspicious macro-attachment phrasing detected"
            ],
            "breakdown": {"nlp": 78, "header": 85, "ip": 50, "url": 60},
        },
        created_at=now - timedelta(hours=4, minutes=30),
    )
    db.add(email_2)
    db.flush()

    inc_2 = Incident(
        analyzed_email_id=email_2.id,
        title="Internal HR Spoofing with Suspicious Attachment",
        severity="HIGH",
        status=IncidentStatus.IN_REVIEW,
        assigned_to="SOC Tier 1 Analyst",
        summary="Contains attachment masquerading as bonus schedule. Sender spoofed internal address with SPF failure.",
        notes="Quarantined attachment. Analyzing macro signature.",
        created_at=now - timedelta(hours=4, minutes=30),
        updated_at=now - timedelta(hours=3, minutes=10),
    )
    db.add(inc_2)

    # 3. Critical BEC: CEO Wire Transfer
    email_3 = AnalyzedEmail(
        filename="urgent_wire_needed.eml",
        sender="CEO Executive <ceo@exec-wire-transfer.biz>",
        recipient="cfo@internal-corp.com",
        subject="Confidential: Wire Transfer Needed Today",
        body="I am currently in an all-day confidential partner meeting. Please execute an urgent wire transfer for the vendor acquisition invoice before end of business today. Details attached.",
        risk_score=96,
        classification="CRITICAL",
        evidence_level="STRONG",
        phishing_probability=92,
        header_risk_score=95,
        ip_risk_score=65,
        url_risk_score=0,
        raw_headers={"Authentication-Results": "spf=fail dkim=fail dmarc=fail"},
        received_chain=["Received: from mail.exec-wire-transfer.biz (45.142.122.9) by mx.internal-corp.com"],
        analysis_result={
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
            "sender_reply_mismatch": True,
            "domain_lookalike": True,
            "domain_age_days": 3,
            "anomalies": [
                "Executive impersonation attempt detected",
                "Domain registered 3 days ago",
                "SPF, DKIM, and DMARC failed"
            ],
            "flagged_terms": ["wire transfer", "confidential", "urgent", "before end of day"],
            "primary_ip": "45.142.122.9",
            "geo": {"country": "Russia", "city": "Moscow", "isp": "HostPalace Web Services"},
            "threat_intel": [
                {"type": "Domain", "value": "exec-wire-transfer.biz", "source": "PhishTank"}
            ],
            "reasons": [
                "Business Email Compromise (BEC) impersonating C-suite executive",
                "Domain was registered only 3 days ago",
                "Urgent wire transfer pressure language"
            ],
            "breakdown": {"nlp": 92, "header": 95, "ip": 65, "url": 0},
        },
        created_at=now - timedelta(days=1, hours=3),
    )
    db.add(email_3)
    db.flush()

    inc_3 = Incident(
        analyzed_email_id=email_3.id,
        title="CEO Fraud / Business Email Compromise (BEC) Wire Transfer",
        severity="CRITICAL",
        status=IncidentStatus.OPEN,
        summary="C-suite impersonation demanding rapid wire transfer. Domain registered 3 days ago from offshore host.",
        notes="Notified finance department to prevent wire release.",
        created_at=now - timedelta(days=1, hours=3),
        updated_at=now - timedelta(days=1, hours=3),
    )
    db.add(inc_3)

    # 4. Medium Risk: Password Expiry Link
    email_4 = AnalyzedEmail(
        filename="it_password_notice.eml",
        sender="IT Support <it-support@internal-corp.com>",
        recipient="user@internal-corp.com",
        subject="Password Expiry Notice - Action Required",
        body="Your corporate network password will expire in 24 hours. Please click the link to reset your password and avoid losing system access.",
        risk_score=65,
        classification="MEDIUM",
        evidence_level="MODERATE",
        phishing_probability=68,
        header_risk_score=20,
        ip_risk_score=10,
        url_risk_score=70,
        raw_headers={"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
        received_chain=["Received: from internal-mail.internal-corp.com (10.0.0.5) by mx.internal-corp.com"],
        analysis_result={
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "sender_reply_mismatch": False,
            "domain_lookalike": False,
            "domain_age_days": 1200,
            "anomalies": [
                "Contains external reset link pointing outside corporate domain"
            ],
            "flagged_terms": ["password expire", "reset your password", "action required"],
            "primary_ip": "10.0.0.5",
            "geo": {"country": "United States", "city": "San Jose", "isp": "Corporate Internal Net"},
            "threat_intel": [],
            "reasons": [
                "Legitimate internal sender but points to unverified external credential form",
                "High credential harvesting language patterns"
            ],
            "breakdown": {"nlp": 68, "header": 20, "ip": 10, "url": 70},
        },
        created_at=now - timedelta(days=1, hours=7),
    )
    db.add(email_4)
    db.flush()

    inc_4 = Incident(
        analyzed_email_id=email_4.id,
        title="Unverified External Password Reset Link",
        severity="MEDIUM",
        status=IncidentStatus.OPEN,
        summary="Legitimate internal sender header, but includes link pointing to external form.",
        notes="Contacted IT admin to verify if official change campaign.",
        created_at=now - timedelta(days=1, hours=7),
        updated_at=now - timedelta(days=1, hours=7),
    )
    db.add(inc_4)

    # 5. Low Risk Clean / Closed: Marketing Newsletter
    email_5 = AnalyzedEmail(
        filename="marketing_digest.eml",
        sender="Marketing Team <newsletter@marketing-digest.com>",
        recipient="user@internal-corp.com",
        subject="Weekly Tech & Cybersecurity Digest",
        body="Hello! Here are this week's top stories in enterprise cybersecurity and software engineering trends.",
        risk_score=12,
        classification="LOW",
        evidence_level="LOW",
        phishing_probability=8,
        header_risk_score=5,
        ip_risk_score=5,
        url_risk_score=5,
        raw_headers={"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
        received_chain=["Received: from mail.marketing-digest.com (209.85.220.65) by mx.internal-corp.com"],
        analysis_result={
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "sender_reply_mismatch": False,
            "domain_lookalike": False,
            "domain_age_days": 1800,
            "anomalies": [],
            "flagged_terms": [],
            "primary_ip": "209.85.220.65",
            "geo": {"country": "United States", "city": "Mountain View", "isp": "Google LLC"},
            "threat_intel": [],
            "reasons": ["Standard promotional email with valid SPF, DKIM, and DMARC"],
            "breakdown": {"nlp": 8, "header": 5, "ip": 5, "url": 5},
        },
        created_at=now - timedelta(days=2, hours=1),
    )
    db.add(email_5)
    db.flush()

    inc_5 = Incident(
        analyzed_email_id=email_5.id,
        title="Automated Newsletter (Triage Complete)",
        severity="LOW",
        status=IncidentStatus.CLOSED,
        summary="Standard promotional newsletter. All authentication passed; no indicators found.",
        notes="Closed as clean.",
        created_at=now - timedelta(days=2, hours=1),
        updated_at=now - timedelta(days=2),
        closed_at=now - timedelta(days=2),
    )
    db.add(inc_5)

    # Additional historical clean & low emails for rich statistics
    additional_samples = [
        ("Daily Standup Notes", "alice@internal-corp.com", 8, "LOW", now - timedelta(days=3), []),
        ("Sprint Retrospective Review", "bob@internal-corp.com", 14, "LOW", now - timedelta(days=4), []),
        ("Cloud Infrastructure Invoice", "billing@aws.amazon.com", 22, "LOW", now - timedelta(days=5), ["invoice"]),
        ("GitHub Notification: PR #42 Merged", "notifications@github.com", 10, "LOW", now - timedelta(days=6), []),
    ]
    for subj, sndr, score, cls, dt, terms in additional_samples:
        db.add(AnalyzedEmail(
            filename=f"{subj.lower().replace(' ', '_')}.eml",
            sender=sndr,
            recipient="user@internal-corp.com",
            subject=subj,
            body=f"Content for {subj}",
            risk_score=score,
            classification=cls,
            evidence_level="LOW",
            phishing_probability=score,
            header_risk_score=5,
            ip_risk_score=5,
            url_risk_score=5,
            raw_headers={"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
            analysis_result={
                "spf": "pass",
                "dkim": "pass",
                "dmarc": "pass",
                "reasons": ["Benign email"],
                "flagged_terms": terms,
                "breakdown": {"nlp": score, "header": 5, "ip": 5, "url": 5},
            },
            created_at=dt,
        ))

    db.commit()
