import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt

# 1. Create a synthetic dataset
# 5 Benign scripts
benign_scripts = [
    "print('Hello World')",
    "import math\nprint(math.sqrt(16))",
    "def add(a, b):\n    return a + b",
    "import datetime\nprint(datetime.datetime.now())",
    "for i in range(10):\n    print(i)"
]

# 5 Malicious-looking scripts (simulated)
malicious_scripts = [
    "import os\nos.system('rm -rf /')",
    "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.connect(('10.0.0.1', 8080))",
    "exec(\"import subprocess; subprocess.call(['ls', '-l'])\")",
    "eval(\"__import__('os').system('echo malicious')\")",
    "import subprocess\nsubprocess.run(['cat', '/etc/shadow'])"
]

# Combine data
scripts = benign_scripts + malicious_scripts
labels = ['BENIGN'] * 5 + ['MALICIOUS'] * 5

df = pd.DataFrame({'script': scripts, 'label': labels})

print("Dataset created with", len(df), "entries.")

# 2. Feature Extraction
# Specifically target keywords as requested
vocabulary = ['exec', 'import', 'os', 'eval', 'subprocess', 'socket', 'system', 'connect']
vectorizer = CountVectorizer(vocabulary=vocabulary)

X = vectorizer.fit_transform(df['script'])
y = df['label']

# 3. Train the model
# Using a simple split, though with only 10 items, standard splits might be wonky.
# We'll use a fixed random state to ensure we get at least one of each in train/test if possible,
# but with 80/20 of 10 samples, that's 8 train, 2 test.
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

model = MultinomialNB()
model.fit(X_train, y_train)

# 4. Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# 5. Output function
def predict_script(script_code):
    """
    Takes a new string of code and labels it as 'MALICIOUS' or 'BENIGN'.
    """
    transformed_script = vectorizer.transform([script_code])
    prediction = model.predict(transformed_script)
    return prediction[0]

# Demonstration
print("-" * 30)
test_code_benign = "print('Just a normal script')"
result_benign = predict_script(test_code_benign)
print(f"Test Code:\n{test_code_benign}\nPrediction: {result_benign}")

print("-" * 30)
test_code_malicious = "import os; os.system('shutdown now')"
result_malicious = predict_script(test_code_malicious)
print(f"Test Code:\n{test_code_malicious}\nPrediction: {result_malicious}")
