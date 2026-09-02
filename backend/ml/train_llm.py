import os
import torch
import numpy as np
from datasets import load_from_disk
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification, 
    TrainingArguments, 
    Trainer
)
import evaluate

DATASET_DIR = os.path.join(os.path.dirname(__file__), "merged_dataset")
MODEL_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "nlp_model")
MODEL_NAME = "distilbert-base-uncased"

def compute_metrics(eval_pred):
    metric = evaluate.load("accuracy")
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    return metric.compute(predictions=predictions, references=labels)

def train_model():
    print(f"Loading dataset from {DATASET_DIR}...")
    if not os.path.exists(DATASET_DIR):
        print(f"Dataset directory {DATASET_DIR} not found. Please run dataset_builder.py first.")
        return

    dataset = load_from_disk(DATASET_DIR)
    
    print(f"Loading tokenizer {MODEL_NAME}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    def tokenize_function(examples):
        return tokenizer(examples["text"], padding="max_length", truncation=True, max_length=128)

    print("Tokenizing dataset...")
    tokenized_datasets = dataset.map(tokenize_function, batched=True)

    print(f"Loading model {MODEL_NAME} for classification...")
    # 2 labels: 0 for legitimate, 1 for phishing
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)

    # For hackathon/demo purposes, we use minimal epochs and batch size.
    # On a local CPU this might take a few minutes. On GPU it will be very fast.
    training_args = TrainingArguments(
        output_dir=os.path.join(os.path.dirname(__file__), "training_checkpoints"),
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=2e-5,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        num_train_epochs=1,
        weight_decay=0.01,
        load_best_model_at_end=True,
        # Disable wandb reporting to keep it clean locally
        report_to="none" 
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["test"],
        compute_metrics=compute_metrics,
    )

    print("Starting fine-tuning...")
    trainer.train()

    print(f"Training complete. Saving model to {MODEL_OUTPUT_DIR}...")
    trainer.save_model(MODEL_OUTPUT_DIR)
    tokenizer.save_pretrained(MODEL_OUTPUT_DIR)
    
    print("Model successfully exported and ready to use in phishing_model.py!")

if __name__ == "__main__":
    train_model()
