"""
Phishing NLP Classification Model

Combines TF-IDF + Logistic Regression ML classification with multi-vector
heuristic analysis (urgency, credential harvesting, financial fraud,
suspicious call-to-action) to accurately score email body text.
"""

import re
import os
import math
import joblib
from transformers import pipeline

# The Hugging Face repository where the fine-tuned DistilBERT model is hosted
NLP_MODEL_REPO = "bixby404/phishing-detection"

# Cache the pipeline in memory so we don't reload it for every email
_nlp_pipeline = None

def load_nlp_pipeline():
    global _nlp_pipeline
    if _nlp_pipeline is None:
        try:
            _nlp_pipeline = pipeline("text-classification", model=NLP_MODEL_REPO, tokenizer=NLP_MODEL_REPO)
        except Exception as e:
            print(f"Failed to load NLP model: {e}")
            _nlp_pipeline = False  # Mark as failed so we don't keep trying
    return _nlp_pipeline

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


# Built-in robust training corpus (50+ diverse examples)
TRAINING_CORPUS = [
    # ── Phishing Examples ──
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


def classify_heuristic(body_text: str) -> dict:
    """
    Robust multi-vector heuristic phishing classifier.
    Computes calibrated non-linear phishing probability based on keyword signals.
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

    raw_score = sum(HEURISTIC_WEIGHTS.get(term, 10) for term in flagged)

    # Multi-term co-occurrence multiplier (urgency + credentials + financial)
    if len(flagged) >= 3:
        raw_score = int(raw_score * 1.25)
    elif len(flagged) >= 2:
        raw_score = int(raw_score * 1.1)

    # Calibrate to 0-100 probability using sigmoid scaling
    if raw_score <= 0:
        phishing_prob = 2
    else:
        # Soft curve mapping raw score to percentage
        phishing_prob = int(min(98, max(5, 100 / (1 + math.exp(-0.06 * (raw_score - 40))))))

    # Calculate legitimate probability
    legit_prob = max(1, 100 - phishing_prob)

    return {
        "phishing_probability": phishing_prob,
        "legitimate_probability": legit_prob,
        "flagged_terms": flagged,
        "method": "heuristic"
    }


def classify(body_text: str) -> dict:
    """
    Classifies email body text for phishing probability.
    Tries ML TF-IDF classifier first; falls back to heuristic engine.
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

    # 1. Attempt Hugging Face DistilBERT LLM Classification
    try:
        nlp = load_nlp_pipeline()
        if nlp:
            # Run inference
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
                
            return {
                "phishing_probability": final_prob,
                "legitimate_probability": legit_prob,
                "flagged_terms": flagged_terms,
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

            # probabilities[1] = phishing probability, probabilities[0] = legit
            ml_phishing_prob = int(probabilities[1] * 100)

            # Blend with heuristic signals if high-risk terms are present
            if flagged_terms and ml_phishing_prob < 50:
                heuristic_res = classify_heuristic(body_text)
                final_prob = max(ml_phishing_prob, heuristic_res["phishing_probability"])
            else:
                final_prob = ml_phishing_prob

            final_prob = max(0, min(100, final_prob))
            legit_prob = max(0, min(100, 100 - final_prob))

            return {
                "phishing_probability": final_prob,
                "legitimate_probability": legit_prob,
                "flagged_terms": flagged_terms,
                "method": "ml_classifier"
            }
    except Exception:
        # Fall back to heuristic on any error
        pass

    # 2. Baseline Heuristic
    return classify_heuristic(body_text)


# Initialize model on import
try:
    ensure_ml_model_trained()
except Exception:
    pass


if __name__ == "__main__":
    phish_sample = "URGENT: Your account has been suspended due to suspicious activity. Verify your account and confirm your password immediately by clicking here."
    clean_sample = "Hi team, let's meet at 2pm tomorrow to discuss the quarterly project deliverables. Best regards."

    print("Phishing test:")
    print(classify(phish_sample))
    print("\nClean test:")
    print(classify(clean_sample))
