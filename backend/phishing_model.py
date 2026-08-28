import re
import os
import urllib.request
import joblib

# Weighted term list for the heuristic baseline approach
# Higher weights indicate stronger signals of phishing.
HEURISTIC_WEIGHTS = {
    # Urgency language
    "urgent": 30,
    "immediately": 20,
    "suspended": 40,
    "verify your account": 50,
    "click here": 30,
    "act now": 30,
    
    # Credential / Financial bait
    "password": 40,
    "confirm your details": 40,
    "unusual activity": 30,
    "wire transfer": 50
}

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_classifier_model.pkl")
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "phishing_classifier_vectorizer.pkl")


def classify(body_text: str) -> dict:
    """
    Analyzes the body text of an email to determine the probability of it being phishing.
    Returns exactly the expected JSON shape required by the contract.
    """
    
    # ---------------------------------------------------------
    # STRETCH GOAL: Attempt to load and use the ML Classifier
    # ---------------------------------------------------------
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            model = joblib.load(MODEL_PATH)
            vectorizer = joblib.load(VECTORIZER_PATH)
            
            # Predict
            features = vectorizer.transform([body_text])
            probabilities = model.predict_proba(features)[0]
            
            # Assuming class 1 is phishing, class 0 is legitimate
            # This depends on how the model was trained, we enforce 1=phishing
            phishing_prob = int(probabilities[1] * 100)
            legit_prob = int(probabilities[0] * 100)
            
            # Extract flagged terms for explainability
            body_lower = body_text.lower()
            flagged_terms = []
            for term in HEURISTIC_WEIGHTS:
                if re.search(r'\b' + re.escape(term) + r'\b', body_lower):
                    flagged_terms.append(term)
                    
            return {
                "phishing_probability": phishing_prob,
                "legitimate_probability": legit_prob,
                "flagged_terms": flagged_terms,
                "method": "ml_classifier"
            }
    except Exception as e:
        # Silently fall back to heuristic on ANY error (missing file, load error, etc)
        pass


    # ---------------------------------------------------------
    # BASELINE: Heuristic Keyword Matcher (The Safety Net)
    # ---------------------------------------------------------
    if not body_text:
        body_text = ""
        
    body_lower = body_text.lower()
    score = 0
    flagged_terms = []
    
    for term, weight in HEURISTIC_WEIGHTS.items():
        if re.search(r'\b' + re.escape(term) + r'\b', body_lower):
            score += weight
            flagged_terms.append(term)
            
    # Normalize score (cap at 100)
    final_score = min(score, 100)
    legitimate_prob = 100 - final_score
    
    return {
        "phishing_probability": final_score,
        "legitimate_probability": legitimate_prob,
        "flagged_terms": flagged_terms,
        "method": "heuristic"
    }


def train_stretch_model():
    """
    STRETCH GOAL: Train a real lightweight classifier.
    This fetches a small CSV, trains a TF-IDF + LogisticRegression model,
    and saves it to disk for the classify() function to use.
    It imports ML libraries inside the function to avoid crashing the main app
    if they aren't installed (which protects the baseline).
    """
    try:
        import pandas as pd
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
    except ImportError:
        print("Missing required libraries for ML (pandas, scikit-learn). Train skipped.")
        return

    DATASET_URL = "https://raw.githubusercontent.com/nitesh-yadav/Phishing-Email-Detection/master/phishing_data.csv"
    DATASET_PATH = os.path.join(os.path.dirname(__file__), "phishing_data.csv")
    
    print(f"Downloading dataset from {DATASET_URL}...")
    try:
        urllib.request.urlretrieve(DATASET_URL, DATASET_PATH)
        print("Download complete.")
    except Exception as e:
        print(f"Failed to download dataset: {e}. Falling back to tiny dummy dataset.")
        # Create a small dummy dataset so training doesn't crash if network fails
        dummy_data = {
            "Email Text": [
                "URGENT: Your account has been suspended due to unusual activity. Please verify your account and confirm your details immediately by clicking the link. Do not share your password.",
                "Please wire transfer the money immediately to the following account.",
                "Hi John, can we schedule a meeting for next week to discuss the project?",
                "The quarterly report is attached. Please review it by Friday.",
                "Verify your account now or it will be locked.",
                "Lunch at 12? Let me know."
            ],
            "Email Type": ["Phishing Email", "Phishing Email", "Safe Email", "Safe Email", "Phishing Email", "Safe Email"]
        }
        df = pd.DataFrame(dummy_data)
        df.to_csv(DATASET_PATH, index=False)

    print("Loading data...")
    try:
        df = pd.read_csv(DATASET_PATH)
        
        # Determine text and label columns dynamically based on common names
        text_col = next((col for col in ["Email Text", "text", "email_text", "content"] if col in df.columns), df.columns[0])
        label_col = next((col for col in ["Email Type", "label", "class", "is_phishing"] if col in df.columns), df.columns[1])
            
        df = df.dropna(subset=[text_col, label_col])
        X = df[text_col].astype(str)
        y = df[label_col]
        
        # Convert labels to binary (1=phishing, 0=safe)
        if y.dtype == object:
            y = y.apply(lambda x: 1 if "phishing" in str(x).lower() or "spam" in str(x).lower() else 0)
        
        print("Training model...")
        vectorizer = TfidfVectorizer(max_features=5000, stop_words="english")
        X_vec = vectorizer.fit_transform(X)
        
        model = LogisticRegression(max_iter=1000)
        model.fit(X_vec, y)
        
        joblib.dump(model, MODEL_PATH)
        joblib.dump(vectorizer, VECTORIZER_PATH)
        
        print(f"Model saved to {MODEL_PATH}")
        print(f"Vectorizer saved to {VECTORIZER_PATH}")
    except Exception as e:
        print(f"An error occurred during training: {e}")

if __name__ == "__main__":
    # Test Fixtures to verify the exact JSON shape and behavior
    legit_email = "Hi John, can we schedule a meeting for next week to discuss the project?"
    phishing_email = "URGENT: Your account has been suspended due to unusual activity. Please verify your account and confirm your details immediately by clicking the link. Do not share your password."
    
    print("--- BASELINE Legitimate Email Test ---")
    print(classify(legit_email))
    
    print("\n--- BASELINE Phishing Email Test ---")
    print(classify(phishing_email))
    
    # Try training the model
    print("\n--- STRETCH GOAL: Training ML Model ---")
    train_stretch_model()
    
    if os.path.exists(MODEL_PATH):
        print("\n--- STRETCH GOAL Legitimate Email Test ---")
        print(classify(legit_email))
        
        print("\n--- STRETCH GOAL Phishing Email Test ---")
        print(classify(phishing_email))
