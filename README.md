# Malicious Script Detector (Text-Based)

A Python-based tool that uses Machine Learning (Multinomial Naive Bayes) to detect malicious patterns in Python scripts.

## Features
- **Machine Learning Analysis**: Uses a trained `MultinomialNB` model to classify code as `BENIGN` or `MALICIOUS`.
- **Keyword Targeting**: Specifically monitors for sensitive functions and modules like `exec()`, `eval()`, `os.system()`, `subprocess`, `socket`, and `base64`.
- **Recursive Scanning**: Scan a single file or an entire directory recursively.
- **Noise-Reduced Output**: Shows progress during scans and only alerts on detected threats.
- **Detailed Summary**: Provides a final report with total files scanned and a list of detected threats.

## Installation (For your PC)

To run this tool on your computer, you need Python 3 and the `pandas`, `numpy`, and `scikit-learn` libraries. It is recommended to use a virtual environment:

1. **Open your terminal** and navigate to the project folder:
   ```bash
   cd malicious_script_detector
   ```

2. **Create a virtual environment** (optional but recommended):
   ```bash
   python3 -m venv venv
   ```

3. **Activate the environment**:
   - **Mac/Linux**: `source venv/bin/activate`
   - **Windows**: `venv\Scripts\activate`

4. **Install dependencies**:
   ```bash
   pip install pandas numpy scikit-learn
   ```

## Usage

### 1. Training the Model
The model trains automatically using `dataset.csv` every time you start a scan. You can add more malicious or benign code samples to `dataset.csv` (using the `create_dataset.py` script as a template) to improve detection accuracy.

### 2. Scanning a single file
To scan any Python script for threats:
```bash
python3 detector.py --scan path/to/your_script.py
```

### 3. Scanning an entire folder
To scan a whole directory (and all subfolders) recursively:
```bash
python3 detector.py --scan path/to/your_folder
```

## How it Works
The detector uses a **Vectorization** process to count the occurrences of "dangerous" keywords in a script. It then feeds these counts into a **Naive Bayes** classifier. 

1. **Dataset**: A CSV file (`dataset.csv`) contains samples of safe and malicious code.
2. **Training**: The model learns which keywords are most commonly associated with malicious scripts.
3. **Inference**: When a new file is scanned, the model calculates the probability of it being malicious based on the presence of those keywords.

## Scan Summary
At the end of every scan, the tool provides a summary report in the terminal:
```text
==================================================
SCAN SUMMARY
==================================================
Total Files Scanned: [Count]
Malicious Detected:  [Count]
--------------------------------------------------
[!] THREATS FOUND:
    -> path/to/malicious_file.py
```
