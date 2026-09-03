# scripts/train_model.py
import argparse
from pathlib import Path
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV

def train_and_serialize(output_path: str):
    print("Training production exploitability model...")
    
    # Example dataset representing real-world triage history:
    # Features: [internet_facing, requires_no_auth, requires_no_interaction, high_severity_vuln]
    # Label: 1 (Exploited in wild), 0 (Not exploited/remediated safely)
    X = np.array([
        [1, 1, 1, 1], [1, 1, 1, 1], [1, 1, 0, 1], [1, 0, 1, 1],
        [0, 1, 1, 1], [1, 1, 1, 0], [1, 1, 1, 0], [1, 0, 0, 0],
        [0, 0, 0, 0], [0, 1, 0, 1], [0, 1, 1, 0], [1, 0, 1, 0],
    ])
    y = np.array([1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0])

    # 1. Base Classifier
    base_model = LogisticRegression(random_state=42)
    
    # 2. Apply Calibrated Classifier to ensure model probabilities 
    # represent actual real-world likelihood
    calibrated_model = CalibratedClassifierCV(estimator=base_model, method="sigmoid", cv=2)
    calibrated_model.fit(X, y)
    
    # 3. Serialize Model
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(calibrated_model, out_file)
    print(f"Model successfully saved to {out_file.resolve()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="resources/model.joblib")
    args = parser.parse_args()
    train_and_serialize(args.output)
