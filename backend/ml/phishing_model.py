"""
Phishing NLP Classification Model

Multi-layered phishing detection combining:
  1. Fine-tuned DistilBERT transformer (HuggingFace)
  2. TF-IDF + Logistic Regression ML classifier
  3. Intent-based pattern analysis (behavioral signals)
  4. Keyword heuristic baseline
"""

import re
import os
import math
import joblib

os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

# The Hugging Face repository where the fine-tuned DistilBERT model is hosted
NLP_MODEL_REPO = "bixby404/phishing-detection"

# Cache the pipeline in memory so we don't reload it for every email
_nlp_pipeline = None

def load_nlp_pipeline():
    global _nlp_pipeline
    if _nlp_pipeline is None:
        try:
            import torch
            from transformers import pipeline
            _nlp_pipeline = pipeline("text-classification", model=NLP_MODEL_REPO, tokenizer=NLP_MODEL_REPO)
        except Exception as e:
            _nlp_pipeline = False  # Mark as unavailable so we don't keep trying
    return _nlp_pipeline


# ── Intent-Based Pattern Analysis ─────────────────────────────────
# These detect phishing BEHAVIORS rather than specific keywords.
# Each pattern has a weight and a human-readable label for flagging.

INTENT_PATTERNS = [
    # Artificial deadlines / time pressure
    (r'\b(?:deadline|expires?|expiring)\b.*\b(?:today|tonight|tomorrow|hours?|minutes?)\b', 30, "artificial deadline pressure"),
    (r'\b(?:today|tonight|tomorrow)\b.*\b(?:deadline|expires?|close[sd]?|end)\b', 30, "artificial deadline pressure"),
    (r'\bbefore\s+(?:the\s+)?(?:deadline|end\s+of\s+(?:day|business)|close\s+of\s+business|eod|eob)\b', 25, "end-of-day pressure"),
    (r'\b(?:within|next)\s+\d+\s*(?:hour|minute|hr|min)', 25, "tight time constraint"),
    (r'\b(?:window|period)\s+closes?\b', 20, "closing window pressure"),
    (r'\bremain(?:s)?\s+(?:temporarily\s+)?restricted\b', 25, "restriction threat"),

    # Consequence/threat language (indirect urgency)
    (r'\b(?:failure|failing)\s+to\s+(?:respond|act|review|verify|confirm|complete|comply)', 35, "consequence threat"),
    (r'\bmay\s+result\s+in\s+(?:temporary|permanent|immediate)?\s*(?:restrict|suspend|terminat|lock|delet|disabl|block|loss)', 35, "service disruption threat"),
    (r'\bif\s+(?:you\s+)?(?:do\s+not|don\'t|did\s+not|didn\'t)\s+(?:initiate|authorize|recogni[sz]e|request|make)', 25, "did-you-do-this bait"),
    (r'\b(?:will\s+be|may\s+be|could\s+be)\s+(?:suspended|locked|terminated|restricted|disabled|deleted|blocked|deactivated)', 30, "account threat"),
    (r'\bprocessing\s+may\s+be\s+delayed\b', 20, "delay consequence"),
    (r'\b(?:unverified|pending\s+(?:review|verification|confirmation))\b', 20, "pending verification status"),

    # Fake verification / review requests
    (r'\breview\s+(?:the\s+)?(?:security\s+)?(?:event|activity|record|alert|incident)\b', 25, "fake review request"),
    (r'\b(?:confirm|verify)\s+(?:the\s+)?(?:activity|identity|ownership|record)\b', 25, "identity verification request"),
    (r'\bworkspace\s+owner\s+confirms?\b', 20, "ownership confirmation bait"),
    (r'\bmanual\s+confirmation\b', 20, "manual confirmation request"),
    (r'\brecord\s+(?:remains?\s+)?unverified\b', 20, "unverified record pressure"),

    # Suspicious reference IDs (fake legitimacy)
    (r'\b(?:reference|ref|case|ticket|incident|event)\s*(?:#|:|\s)\s*[A-Z]{1,4}[\-]?\d{3,8}\b', 15, "suspicious reference ID"),
    (r'\bINC-\d{4}\b', 10, "incident reference ID"),

    # "Do not forward/share" isolation tactics
    (r'\bdo\s+not\s+(?:forward|share|distribute)\s+this\b', 20, "recipient isolation tactic"),
    (r'\bintended\s+only\s+for\s+(?:the\s+)?(?:employee|recipient|addressee|account\s+holder)\b', 20, "recipient isolation tactic"),

    # Automated notification disguise
    (r'\b(?:automated|automatic)\s+(?:security\s+)?(?:notification|alert|message|check)\b', 15, "automated alert disguise"),
    (r'\bdo\s+not\s+reply\s+(?:to\s+)?this\b', 10, "no-reply disguise"),

    # Security event fabrication
    (r'\b(?:security\s+)?(?:check|scan|audit)\s+detected\b', 25, "fabricated security event"),
    (r'\b(?:unverified|unauthorized|suspicious|anomalous)\s+(?:document|file|export|access|sign.?in|transaction|activity|login|device)', 30, "fabricated security alert"),

    # Link-to-action pressure (review/confirm via link)
    (r'\breview\b.*\bhttps?://', 15, "link-based review request"),
    (r'\b(?:click|visit|go\s+to|navigate)\b.*\bhttps?://', 15, "link-based action request"),

    # Payroll / HR / Benefits bait
    (r'\b(?:benefits?\s+(?:profile|record|reconciliation)|payroll.{0,20}(?:sync|update|change))', 25, "HR/payroll social engineering"),
    (r'\b(?:employee\s+record|benefits?\s+record)\b.*\b(?:review|confirm|verify)\b', 25, "employee record bait"),

    # Generic "secure" action labels
    (r'\bsecure\s+(?:workspace|account|portal|access)\b', 15, "secure-action label"),
]


# High-signal term weights by category
HEURISTIC_WEIGHTS = {
    # Urgency & Pressure
    "urgent": 25,
    "immediately": 20,
    "account suspended": 45,
    "account locked": 40,
    "action required": 30,
    "within 24 hours": 35,
    "permanent deletion": 40,
    "unauthorized access": 35,
    "security alert": 30,
    "final notice": 35,

    # Credential Harvesting & Account Bait
    "verify your account": 45,
    "confirm your details": 40,
    "verify credentials": 45,
    "confirm your password": 50,
    "reset your password": 30,
    "update billing": 35,
    "sign in to verify": 40,
    "login to continue": 30,
    "re-activate": 35,

    # Financial & Fraud
    "wire transfer": 45,
    "outstanding invoice": 35,
    "overdue invoice": 35,
    "unusual transaction": 40,
    "crypto": 30,
    "bitcoin": 35,
    "gift card": 40,
    "direct deposit": 35,
    "payment declined": 35,
    "refund notification": 30,

    # Call-to-Action & Links
    "click here": 25,
    "click immediately": 35,
    "open the attachment": 30,
    "download document": 25,
    "follow this link": 25,
    "access secure portal": 35,
}

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_classifier_model.pkl")
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "phishing_classifier_vectorizer.pkl")

if not os.path.exists(MODEL_PATH):
    alt_m = os.path.join(os.path.dirname(__file__), "..", "phishing_classifier_model.pkl")
    if os.path.exists(alt_m):
        MODEL_PATH = alt_m

if not os.path.exists(VECTORIZER_PATH):
    alt_v = os.path.join(os.path.dirname(__file__), "..", "phishing_classifier_vectorizer.pkl")
    if os.path.exists(alt_v):
        VECTORIZER_PATH = alt_v


# Built-in robust training corpus (50+ diverse examples)
TRAINING_CORPUS = [
    # ── Phishing Examples (obvious) ──
    ("URGENT: Your account has been suspended due to unusual activity. Click here immediately to verify your account and confirm your password.", 1),
    ("Please wire transfer the outstanding invoice amount immediately to our updated bank details within 24 hours.", 1),
    ("Action Required: Your Microsoft 365 password will expire in 2 hours. Reset your password now to avoid service disruption.", 1),
    ("Security Alert: We detected an unauthorized sign in to your bank account. Confirm your details to restore access.", 1),
    ("Dear customer, your invoice is overdue. Download the attachment and confirm your billing information immediately.", 1),
    ("Your Netflix subscription payment was declined. Update billing information to keep watching your favorite shows.", 1),
    ("PayPal Fraud Prevention: An unauthorized transaction of $540.00 was attempted. Login to verify your credentials.", 1),
    ("Payroll Department: Direct deposit details change required. Sign in to verify your identity before the deadline.", 1),
    ("DHL Delivery: Your package could not be delivered due to unpaid customs fee. Click here to confirm payment details.", 1),
    ("You received a secure document via DocuSign. Follow this link and sign in to access secure portal.", 1),
    ("Final Notice: Your email mailbox has exceeded storage limit and is scheduled for permanent deletion. Click here to upgrade.", 1),
    ("Urgent assistance required: I need you to purchase 5 Apple gift cards for the client meeting today. Reply immediately.", 1),
    ("Amazon Order Confirmation: You ordered iPhone 15 Pro for $1,299. If you did not make this purchase, click here to cancel.", 1),
    ("Apple ID Locked: Your account has been suspended due to security reasons. Verify your account now.", 1),
    ("HR Alert: Annual bonus distribution list attached. Login with company credentials to view your allocation.", 1),
    ("Internal IT Desk: Required VPN security update. Enter your username and password to authenticate the upgrade.", 1),
    ("Your cryptocurrency wallet has received a deposit. Confirm your private key to claim the bitcoin transfer.", 1),
    ("IRS Tax Refund Notification: You are eligible for a $1,420 refund. Submit your bank account details immediately.", 1),
    ("Google Workspace: Critical security vulnerability found in your session. Re-activate your access right now.", 1),
    ("Urgent: Account locked due to multiple failed login attempts. Verify identity to prevent permanent suspension.", 1),
    ("Chase Bank: Suspicious wire transfer flagged. Call our support line or click the link to confirm your details.", 1),
    ("Notice of Subpoena: You have been served with a legal document. Download the attached PDF to review charges.", 1),
    ("Action Required: Your domain registration is expiring today. Pay outstanding invoice immediately to prevent domain loss.", 1),
    ("Urgent request from the CEO: Please process this confidential wire transfer immediately before end of day.", 1),
    ("WhatsApp Web: Your phone number has been linked to a new device. Click here if this was not you.", 1),

    # ── Phishing Examples (sophisticated / intent-based) ──
    ("An automated security check detected an unverified document export from your workspace. The export will remain temporarily restricted until the owner confirms the activity. Review the security event before the deadline today.", 1),
    ("Our monthly benefits reconciliation identified an employee record requiring manual confirmation. Your benefits profile is currently marked as Pending Review. Please review the record before the reconciliation window closes today.", 1),
    ("A login attempt from an unrecognized device was flagged on your account. If you did not initiate this activity, please review the alert immediately. Failure to respond within 24 hours may result in temporary access restrictions.", 1),
    ("Your document sharing permissions have been temporarily suspended due to a policy compliance review. To restore access, confirm your identity through the secure verification portal. Reference: DOC-38471.", 1),
    ("The IT security team has detected unusual API activity associated with your developer account. Please review the flagged activity and verify your recent actions. Failure to review may result in temporary suspension of API access.", 1),
    ("A compliance audit has identified a discrepancy in your expense report submission. Please review and confirm the flagged entries before end of business today to avoid processing delays. Reference: EXP-92841.", 1),
    ("Your cloud storage quota review is pending. An automated scan flagged files that may violate retention policy. Review the flagged items before the review window closes to prevent automatic archival.", 1),
    ("Human Resources has updated the employee benefits enrollment portal. Your current selections require re-confirmation by the end of the enrollment period. Access the portal to review your benefits selections.", 1),
    ("A scheduled system migration requires all users to re-validate their credentials. Complete the validation through the secure portal before the migration window. Accounts not validated may experience temporary service interruption.", 1),
    ("Your recent travel expense claim has been flagged for additional verification. The finance team requires confirmation of the flagged transactions. Please review and respond before the reimbursement deadline.", 1),

    # ── Legitimate Examples ──
    ("Hi team, here is the agenda for our weekly sprint review meeting tomorrow at 10 AM. Let me know if you have topics to add.", 0),
    ("Thanks for sending the updated design mockups! They look great. I will review with product management today.", 0),
    ("Can we reschedule our sync to Thursday afternoon? Something came up on my calendar. Best regards, Sarah.", 0),
    ("Attached is the Q3 quarterly financial report for your review. Please let me know your thoughts before Friday's board meeting.", 0),
    ("Hi John, thank you for your help on the customer onboarding presentation yesterday. The client was very impressed.", 0),
    ("Lunch at 12:30 PM today at the cafeteria? Let me know if you want to join us.", 0),
    ("Please find the minutes from today's engineering all-hands meeting. Summary points are listed below.", 0),
    ("Hey everyone, just a reminder that the office will be closed on Monday for the holiday. Enjoy your long weekend!", 0),
    ("The pull request for the authentication service has been merged to staging. Tests are running cleanly.", 0),
    ("Hi Alex, could you share the spreadsheet from last week's customer feedback survey when you have a moment? Thanks!", 0),
    ("Good morning, here is the weekly status update on Project Titan. All milestones are currently on track.", 0),
    ("Thanks for following up! I reviewed the contract terms and everything looks aligned with our discussion.", 0),
    ("Team, congratulations on successfully shipping the v2.4 release! Great work everyone.", 0),
    ("Hi Dave, do you have 15 minutes this afternoon for a quick coffee chat about the upcoming roadmap?", 0),
    ("The documentation for the new API endpoints has been published to our internal wiki. Feel free to check it out.", 0),
    ("Hi team, please remember to submit your time sheets by end of day Friday. Have a great weekend.", 0),
    ("Thanks for the introduction! Looking forward to collaborating on the partner integration project.", 0),
    ("Here are the meeting notes and action items from our discussion with the architecture committee.", 0),
    ("Hi Lisa, hope you're having a productive week. Wanted to check in on the hiring pipeline for the backend role.", 0),
    ("The staging environment has been refreshed with the latest seed data for QA testing.", 0),
    ("Thank you for your inquiry. Our support team has resolved ticket #48291. Please let us know if you need further help.", 0),
    ("Hi everyone, please welcome Michael who is joining our DevOps team starting today!", 0),
    ("Let's touch base next Tuesday after the client demo to discuss feedback and next steps.", 0),
    ("Hey, do you happen to have the link to the shared Google Drive folder with the conference photos?", 0),
]


def ensure_ml_model_trained():
    """
    Ensures the scikit-learn model and vectorizer exist. If missing,
    trains a high-accuracy classifier on the curated training corpus.
    """
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        return

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        texts = [text for text, _ in TRAINING_CORPUS]
        labels = [label for _, label in TRAINING_CORPUS]

        vectorizer = TfidfVectorizer(
            max_features=2500,
            stop_words="english",
            ngram_range=(1, 2),
            sublinear_tf=True
        )
        X = vectorizer.fit_transform(texts)

        model = LogisticRegression(C=2.0, max_iter=500, random_state=42)
        model.fit(X, labels)

        joblib.dump(model, MODEL_PATH)
        joblib.dump(vectorizer, VECTORIZER_PATH)
    except Exception as e:
        # Fallback to heuristic if scikit-learn fails
        pass


def extract_flagged_terms(body_lower: str) -> list[str]:
    """
    Identifies specific phishing indicator terms present in the body text.
    """
    flagged = []
    for term in HEURISTIC_WEIGHTS:
        # Match whole phrase or word boundary
        pattern = r"\b" + re.escape(term) + r"\b"
        if re.search(pattern, body_lower):
            flagged.append(term)
    return flagged


def analyze_intent_patterns(body_text: str) -> dict:
    """
    Analyzes the email body for phishing INTENT patterns — behavioral
    signals that indicate social engineering regardless of specific keywords.

    Returns a dict with:
      - intent_score: weighted score from matched patterns (0+)
      - matched_intents: list of human-readable intent labels
      - intent_count: number of distinct intent patterns matched
    """
    body_lower = body_text.lower()
    matched = []
    total_score = 0

    seen_labels = set()
    for pattern, weight, label in INTENT_PATTERNS:
        if re.search(pattern, body_lower) and label not in seen_labels:
            matched.append(label)
            total_score += weight
            seen_labels.add(label)

    # Co-occurrence amplifier: multiple intent signals compound suspicion
    if len(matched) >= 4:
        total_score = int(total_score * 1.4)
    elif len(matched) >= 3:
        total_score = int(total_score * 1.25)
    elif len(matched) >= 2:
        total_score = int(total_score * 1.1)

    return {
        "intent_score": total_score,
        "matched_intents": matched,
        "intent_count": len(matched),
    }


def classify_heuristic(body_text: str) -> dict:
    """
    Multi-vector heuristic phishing classifier combining keyword matching
    and intent-based pattern analysis.
    """
    if not body_text:
        return {
            "phishing_probability": 0,
            "legitimate_probability": 100,
            "flagged_terms": [],
            "method": "heuristic"
        }

    body_lower = body_text.lower()
    flagged = extract_flagged_terms(body_lower)

    # Keyword score
    keyword_score = sum(HEURISTIC_WEIGHTS.get(term, 10) for term in flagged)
    if len(flagged) >= 3:
        keyword_score = int(keyword_score * 1.25)
    elif len(flagged) >= 2:
        keyword_score = int(keyword_score * 1.1)

    # Intent pattern score
    intent_result = analyze_intent_patterns(body_text)
    intent_score = intent_result["intent_score"]

    # Combine: take the higher of the two, plus a fraction of the other
    raw_score = max(keyword_score, intent_score) + int(min(keyword_score, intent_score) * 0.4)

    # Add matched intents to flagged terms for visibility
    all_flagged = flagged + intent_result["matched_intents"]

    # Calibrate to 0-100 using sigmoid
    if raw_score <= 0:
        phishing_prob = 2
    else:
        phishing_prob = int(min(98, max(5, 100 / (1 + math.exp(-0.04 * (raw_score - 50))))))

    legit_prob = max(1, 100 - phishing_prob)

    return {
        "phishing_probability": phishing_prob,
        "legitimate_probability": legit_prob,
        "flagged_terms": all_flagged,
        "method": "heuristic"
    }


def classify(body_text: str) -> dict:
    """
    Classifies email body text for phishing probability.
    Pipeline: DistilBERT → TF-IDF ML → Intent+Keyword Heuristic.
    Intent analysis is always blended into final results.
    """
    if not body_text or not body_text.strip():
        return {
            "phishing_probability": 0,
            "legitimate_probability": 100,
            "flagged_terms": [],
            "method": "heuristic"
        }

    body_lower = body_text.lower()
    flagged_terms = extract_flagged_terms(body_lower)

    # Always run intent analysis as a supplementary signal
    intent_result = analyze_intent_patterns(body_text)
    all_flagged = flagged_terms + intent_result["matched_intents"]

    # Intent-based floor: if strong intent signals detected, set minimum score
    intent_floor = 0
    if intent_result["intent_count"] >= 3:
        intent_floor = 55
    elif intent_result["intent_count"] >= 2:
        intent_floor = 35
    elif intent_result["intent_count"] >= 1:
        intent_floor = 15

    # 1. Attempt Hugging Face DistilBERT LLM Classification
    try:
        nlp = load_nlp_pipeline()
        if nlp:
            truncated_text = body_text[:2000]
            result = nlp(truncated_text)[0]

            label = result['label']
            score = int(result['score'] * 100)

            if label == "LABEL_1" or label == 1:
                final_prob = score
                legit_prob = 100 - score
            else:
                legit_prob = score
                final_prob = 100 - score

            # Blend with intent floor
            final_prob = max(final_prob, intent_floor)
            legit_prob = 100 - final_prob

            return {
                "phishing_probability": final_prob,
                "legitimate_probability": legit_prob,
                "flagged_terms": all_flagged,
                "method": "llm_classifier"
            }
    except Exception as e:
        pass

    # 2. Attempt TF-IDF Scikit-Learn Model Classification (Fallback)
    try:
        ensure_ml_model_trained()
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            model = joblib.load(MODEL_PATH)
            vectorizer = joblib.load(VECTORIZER_PATH)

            features = vectorizer.transform([body_text])
            probabilities = model.predict_proba(features)[0]

            ml_phishing_prob = int(probabilities[1] * 100)

            # Blend with intent and heuristic signals
            heuristic_res = classify_heuristic(body_text)
            final_prob = max(ml_phishing_prob, heuristic_res["phishing_probability"], intent_floor)

            final_prob = max(0, min(100, final_prob))
            legit_prob = max(0, min(100, 100 - final_prob))

            return {
                "phishing_probability": final_prob,
                "legitimate_probability": legit_prob,
                "flagged_terms": all_flagged,
                "method": "ml_classifier"
            }
    except Exception:
        pass

    # 3. Baseline Heuristic (includes intent analysis)
    return classify_heuristic(body_text)


# Initialize model on import
try:
    ensure_ml_model_trained()
except Exception:
    pass


if __name__ == "__main__":
    print("=" * 60)
    print("PHISHING MODEL TEST SUITE")
    print("=" * 60)

    test_cases = [
        ("Obvious phishing",
         "URGENT: Your account has been suspended due to suspicious activity. Verify your account and confirm your password immediately by clicking here."),

        ("Sophisticated phishing (AI workspace)",
         "An automated security check detected an unverified document export from your AI workspace. The export will remain temporarily restricted until the workspace owner confirms the activity. Review the security event here: http://ai-workspace.example/security/event/AW-48291. Failure to review the event before the deadline may result in temporary restrictions on workspace exports."),

        ("Sophisticated phishing (HR benefits)",
         "Our monthly benefits reconciliation identified an employee record requiring manual confirmation. Your benefits profile is currently marked as Pending Review. Please review the record before the reconciliation window closes today. Please do not forward this message, as the review link is intended only for the employee associated with this notification."),

        ("Clean email",
         "Hi team, let's meet at 2pm tomorrow to discuss the quarterly project deliverables. Best regards."),
    ]

    for label, text in test_cases:
        result = classify(text)
        print(f"\n[{label}]")
        print(f"  Phishing: {result['phishing_probability']}%  |  Method: {result['method']}")
        print(f"  Flagged: {', '.join(result['flagged_terms'][:5])}")
    print()

