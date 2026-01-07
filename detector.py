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

    print("Loading dataset...")
    df = load_data(args.train_file)
    print(f"Dataset loaded with {len(df)} entries.")
    
    print("Training model...")
    model, vectorizer, accuracy = train_model(df)
    print(f"Model Accuracy (on split test set): {accuracy * 100:.2f}%")
    
    if args.scan:
        target_file = args.scan
        if not os.path.exists(target_file):
            print(f"Error: File '{target_file}' not found.")
            return

        try:
            with open(target_file, 'r') as f:
                code_content = f.read()
            
            print(f"\nScanning: {target_file}")
            result = predict_script(model, vectorizer, code_content)
            print(f"Result: {result}")
            
        except Exception as e:
            print(f"Error reading file: {e}")
    else:
        # Default demo behavior if no scan argument provided
        print("\n--- Demo Prediction ---")
        test_snippet = "import os; os.system('echo malicious')"
        result = predict_script(model, vectorizer, test_snippet)
        print(f"Snippet: {test_snippet}")
        print(f"Prediction: {result}")

if __name__ == "__main__":
    main()
