import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score
import argparse
import sys
import os
import time

def type_print(text, delay=0.02):
    """Print text with a typewriter effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def progress_bar(label, duration=1.0, steps=20):
    """Show a progress bar."""
    sys.stdout.write(f"{label} [")
    sys.stdout.flush()
    step_delay = duration / steps
    for i in range(steps):
        sys.stdout.write("█")
        sys.stdout.flush()
        time.sleep(step_delay)
    sys.stdout.write("] Done!\n")

def load_data(filepath='dataset.csv'):
    """Load dataset from CSV file."""
    if not os.path.exists(filepath):
        type_print(f"Error: Dataset file '{filepath}' not found.")
        sys.exit(1)
    return pd.read_csv(filepath)

def train_model(df):
    """Train the Naive Bayes model."""
    vocabulary = ['exec', 'import', 'os', 'eval', 'subprocess', 'socket', 'system', 'connect', 'base64', 'popen', 'sys', 'urllib', 'requests']
    vectorizer = CountVectorizer(vocabulary=vocabulary)
    
    X = vectorizer.fit_transform(df['code'])
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    model = MultinomialNB()
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    return model, vectorizer, accuracy

def predict_script(model, vectorizer, script_code):
    """Predict if a script is MALICIOUS or BENIGN."""
    transformed_script = vectorizer.transform([script_code])
    prediction = model.predict(transformed_script)
    return prediction[0]

def main():
    parser = argparse.ArgumentParser(description="Malicious Script Detector")
    parser.add_argument('--scan', type=str, help="Path to the python script to scan")
    parser.add_argument('--train-file', type=str, default='dataset.csv', help="Path to the training dataset CSV")
    args = parser.parse_args()

    print("\n" + "="*40)
    print("   MALICIOUS SCRIPT DETECTOR v1.0   ")
    print("="*40 + "\n")
    time.sleep(0.5)

    type_print("[*] Initializing system core...")
    time.sleep(0.5)

    progress_bar("[*] Loading knowledge base", duration=1.5)
    df = load_data(args.train_file)
    type_print(f"    -> Loaded {len(df)} signatures.")
    time.sleep(0.5)
    
    progress_bar("[*] Training neural model ", duration=2.0)
    model, vectorizer, accuracy = train_model(df)
    type_print(f"    -> Model Accuracy: {accuracy * 100:.2f}%")
    time.sleep(0.5)
    
    if args.scan:
        target_file = args.scan
        if not os.path.exists(target_file):
            type_print(f"[!] Error: File '{target_file}' not found.")
            return

        try:
            with open(target_file, 'r') as f:
                code_content = f.read()
            
            print("-" * 40)
            type_print(f"[*] Target locked: {target_file}")
            progress_bar("[*] Scanning file contents", duration=2.5)
            
            type_print("[*] Analyzing heuristics...", delay=0.05)
            time.sleep(1.0)
            
            result = predict_script(model, vectorizer, code_content)
            
            print("-" * 40)
            if result == "MALICIOUS":
                type_print(f"    >>> RESULT: {result} <<<", delay=0.1)
                print("    [!] THREAT DETECTED! IMMEDIATE ACTION REQUIRED!")
            else:
                type_print(f"    >>> RESULT: {result} <<<", delay=0.1)
                print("    [+] File appears safe.")
            print("-" * 40)
            
        except Exception as e:
            print(f"Error reading file: {e}")
    else:
        # Default demo behavior if no scan argument provided
        print("\n--- Demo Prediction ---")
        test_snippet = "import os; os.system('echo malicious')"
        progress_bar("[*] Analyzing demo snippet", duration=1.0)
        result = predict_script(model, vectorizer, test_snippet)
        print(f"Snippet: {test_snippet}")
        type_print(f"Prediction: {result}")

if __name__ == "__main__":
    main()
