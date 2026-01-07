import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score
import argparse
import sys
import os

def load_data(filepath='dataset.csv'):
    """Load dataset from CSV file."""
    if not os.path.exists(filepath):
        print(f"Error: Dataset file '{filepath}' not found.")
        sys.exit(1)
    return pd.read_csv(filepath)

def train_model(df):
    """Train the Naive Bayes model."""
    vocabulary = ['exec', 'import', 'os', 'eval', 'subprocess', 'socket', 'system', 'connect', 'base64', 'popen', 'sys', 'urllib', 'requests']
    vectorizer = CountVectorizer(vocabulary=vocabulary)
    
    X = vectorizer.fit_transform(df['code'])
    y = df['label']
    
    # Stratified split ensures we have examples of both classes even with small data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    model = MultinomialNB()
    model.fit(X_train, y_train)
    
    return model, vectorizer

def predict_script(model, vectorizer, script_code):
    """Predict if a script is MALICIOUS or BENIGN."""
    transformed_script = vectorizer.transform([script_code])
    prediction = model.predict(transformed_script)
    # Get probability for confidence score (optional enhancement)
    return prediction[0]

def scan_file(filepath, model, vectorizer):
    """Scan a single file and return result."""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            code_content = f.read()
        
        return predict_script(model, vectorizer, code_content)
            
    except Exception as e:
        # print(f"[!] Error reading {filepath}: {e}")
        return "ERROR"

def main():
    parser = argparse.ArgumentParser(description="Real Malicious Script Detector")
    parser.add_argument('--scan', type=str, required=True, help="Path to file or directory to scan")
    parser.add_argument('--train-file', type=str, default='dataset.csv', help="Path to the training dataset CSV")
    args = parser.parse_args()

    # 1. Load and Train
    if not os.path.exists(args.train_file):
        print(f"Error: Training file '{args.train_file}' not found. Cannot start detector.")
        sys.exit(1)
        
    print(f"[*] Loading training data from {args.train_file}...")
    df = load_data(args.train_file)
    
    print(f"[*] Training model on {len(df)} signatures...")
    model, vectorizer = train_model(df)
    print("[*] Model trained and ready.")
    print("-" * 50)

    # 2. Scan Target
    target_path = args.scan
    
    if not os.path.exists(target_path):
        print(f"Error: Target '{target_path}' not found.")
        sys.exit(1)

    if os.path.isfile(target_path):
        print(f"[*] Scanning file: {target_path}")
        res = scan_file(target_path, model, vectorizer)
        print("-" * 50)
        if res == "MALICIOUS":
            print(f"\n[!] 1 MALICIOUS FILE FOUND:\n    - {target_path}")
        else:
            print("\n[+] No malicious files found.")
            
    elif os.path.isdir(target_path):
        print(f"[*] Recursively scanning directory: {target_path}")
        print("[*] progress: ", end='', flush=True)
        
        count = 0
        malicious_files = []
        
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    result = scan_file(filepath, model, vectorizer)
                    count += 1
                    
                    if result == "MALICIOUS":
                        malicious_files.append(filepath)
                        print(f"\n[!] MALICIOUS DETECTED: {filepath}")
                        print("[*] progress: ", end='', flush=True)
                    elif count % 100 == 0:
                        print(".", end='', flush=True)

        print("\n" + "=" * 50)
        print("SCAN SUMMARY")
        print("=" * 50)
        print(f"Total Files Scanned: {count}")
        print(f"Malicious Detected:  {len(malicious_files)}")
        print("-" * 50)
        
        if malicious_files:
            print(f"[!] THREATS FOUND:")
            for mf in malicious_files:
                print(f"    -> {mf}")
        else:
            print("[+] System Clean. No threats detected.")
            
    else:
        print("Error: Target is not a file or directory.")

if __name__ == "__main__":
    main()
