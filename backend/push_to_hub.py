import os
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from huggingface_hub import login

# 1. Provide your Hugging Face Access Token here
# You can get it from: https://huggingface.co/settings/tokens
HF_TOKEN = os.environ.get("HF_TOKEN", "your_token_here")

# 2. Set your Hugging Face username and the name you want for the model
# Example: "Bala/email-threat-detector-distilbert"
REPO_ID = "bixby404/phishing-detection"

def push_model():
    print("Logging into Hugging Face...")
    login(token=HF_TOKEN)

    model_dir = os.path.join(os.path.dirname(__file__), "nlp_model")
    
    print(f"Loading model and tokenizer from {model_dir}...")
    model = AutoModelForSequenceClassification.from_pretrained(model_dir)
    tokenizer = AutoTokenizer.from_pretrained(model_dir)

    print(f"Pushing model to https://huggingface.co/{REPO_ID} ...")
    model.push_to_hub(REPO_ID)
    tokenizer.push_to_hub(REPO_ID)

    print("Success! Your model is now in your Hugging Face account.")

if __name__ == "__main__":
    push_model()
