import os
import pandas as pd
from datasets import load_dataset, Dataset

LOCAL_CSV = os.path.join(os.path.dirname(__file__), "phishing_data.csv")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "merged_dataset")

def build_dataset():
    print("Building merged dataset for Phase 2 LLM Fine-tuning...")
    
    # 1. Load local dataset
    print(f"Loading local data from {LOCAL_CSV}")
    try:
        local_df = pd.read_csv(LOCAL_CSV)
        # Rename columns to standard 'text' and 'label'
        text_col = next((col for col in ["Email Text", "text", "email_text", "content"] if col in local_df.columns), local_df.columns[0])
        label_col = next((col for col in ["Email Type", "label", "class", "is_phishing"] if col in local_df.columns), local_df.columns[1])
        
        local_df = local_df[[text_col, label_col]].rename(columns={text_col: "text", label_col: "label"})
        # Convert string labels to int (unconditionally)
        local_df['label'] = local_df['label'].apply(lambda x: 1 if "phishing" in str(x).lower() or "spam" in str(x).lower() or str(x) == "1" else 0)
        
        print(f"Loaded {len(local_df)} local examples.")
    except Exception as e:
        print(f"Warning: Could not load local dataset: {e}")
        local_df = pd.DataFrame(columns=["text", "label"])

    # 2. Load public dataset from HuggingFace
    # We use a small portion of a public dataset to keep demo training fast
    print("Loading public phishing dataset from Hugging Face...")
    try:
        # trust_remote_code=True is needed for some older dataset scripts
        hf_dataset = load_dataset("ealvaradob/phishing-dataset", split="train", trust_remote_code=True)
        hf_df = hf_dataset.to_pandas()
        
        # Depending on the dataset, column names might vary. Usually 'text' and 'label'
        if 'text_combined' in hf_df.columns:
            hf_df['text'] = hf_df['text_combined']
            
        hf_df = hf_df[['text', 'label']].dropna()
        hf_df['label'] = hf_df['label'].apply(lambda x: 1 if str(x) == "1" else 0)
        
        # Sample a subset to keep hackathon training time reasonable (e.g., 500 examples)
        if len(hf_df) > 500:
            hf_df = hf_df.sample(n=500, random_state=42)
            
        print(f"Loaded {len(hf_df)} public examples.")
    except Exception as e:
        print(f"Warning: Could not load public dataset: {e}")
        hf_df = pd.DataFrame(columns=["text", "label"])

    # 3. Merge and prepare
    merged_df = pd.concat([local_df, hf_df], ignore_index=True)
    
    # Ensure labels are integers
    merged_df['label'] = merged_df['label'].astype(int)
    merged_df['text'] = merged_df['text'].astype(str)
    
    # Shuffle
    merged_df = merged_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"Total merged dataset size: {len(merged_df)} examples.")
    
    # Convert to HuggingFace Dataset format
    final_dataset = Dataset.from_pandas(merged_df)
    
    # Split into train/test
    split_dataset = final_dataset.train_test_split(test_size=0.2, seed=42)
    
    # Save to disk
    print(f"Saving merged dataset to {OUTPUT_DIR}")
    split_dataset.save_to_disk(OUTPUT_DIR)
    print("Dataset build complete.")
    
    return split_dataset

if __name__ == "__main__":
    build_dataset()
