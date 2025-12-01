import os
import json
import random
from datetime import datetime

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
import pickle
import csv


# -------------------------------------------------------
#  Feature extraction (must match ids_core/model.py)
# -------------------------------------------------------
def extract_features(path: str, payload: str):
    return [
        len(path),
        len(payload),
        1.0 if "admin" in payload.lower() else 0.0,
        1.0 if "select" in payload.lower() else 0.0,
    ]


# -------------------------------------------------------
#  Option A: Load CSIC-based labeled CSV if present
# -------------------------------------------------------
def load_csic_labeled():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    csic_path = os.path.join(project_root, "data", "csic_processed", "csic_labeled.csv")

    if not os.path.exists(csic_path):
        print(f"[CSIC] Labeled file not found at {csic_path}")
        return None, None

    print(f"[CSIC] Loading labeled data from {csic_path} ...")

    X = []
    y = []

    with open(csic_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            path = row.get("path", "") or ""
            payload = row.get("payload", "") or ""
            label = int(row.get("label", 0))

            X.append(extract_features(path, payload))
            y.append(label)

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)

    print(f"[CSIC] Loaded {len(X)} samples.")
    return X, y


# -------------------------------------------------------
#  Option B: Synthetic data generator (fallback)
# -------------------------------------------------------
def generate_synthetic_data(n_benign: int = 600, n_malicious: int = 600):
    print("[SYNTH] Generating synthetic training data...")
    X = []
    y = []

    benign_paths = ["/", "/home", "/login", "/products", "/profile", "/search"]
    benign_payloads = [
        "normal traffic",
        "username=user&password=test123",
        "id=42",
        "page=1&sort=asc",
        "hello world",
        "",
    ]

    for _ in range(n_benign):
        path = random.choice(benign_paths)
        payload = random.choice(benign_payloads)

        # a bit of noise
        if random.random() < 0.2:
            payload += " x" * random.randint(20, 80)

        X.append(extract_features(path, payload))
        y.append(0)

    malicious_paths = ["/admin", "/wp-admin", "/phpmyadmin", "/login"]
    malicious_payloads = [
        "' OR 1=1 --",
        "UNION SELECT password FROM users",
        "SELECT * FROM admin",
        "'; DROP TABLE users; --",
        "admin' UNION SELECT * FROM secrets",
    ]

    for _ in range(n_malicious):
        path = random.choice(malicious_paths)
        payload = random.choice(malicious_payloads)

        if random.random() < 0.7:
            payload += " " + "A" * random.randint(10, 100)

        X.append(extract_features(path, payload))
        y.append(1)

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)
    print(f"[SYNTH] Created {len(X)} synthetic samples.")
    return X, y


def main():
    # Try CSIC first
    X, y = load_csic_labeled()

    # Fallback to synthetic if CSIC not available
    if X is None or y is None or len(X) == 0:
        X, y = generate_synthetic_data()

    # Optionally downsample if CSIC is huge
    max_samples = 10000
    if len(X) > max_samples:
        print(f"[INFO] Downsampling from {len(X)} to {max_samples} samples.")
        idx = np.random.choice(len(X), size=max_samples, replace=False)
        X = X[idx]
        y = y[idx]

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"Training samples: {len(X_train)}, Test samples: {len(X_test)}")

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=6,
        random_state=42,
        n_jobs=-1,
    )

    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print("\n=== Evaluation ===")
    print(f"Accuracy: {acc:.3f}")
    print("Confusion matrix (rows=true, cols=pred):")
    print(cm)
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, digits=3))

    # Save model + metadata into ids_core
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ids_core_dir = os.path.join(project_root, "ids_core")
    os.makedirs(ids_core_dir, exist_ok=True)

    model_path = os.path.join(ids_core_dir, "model.pkl")
    info_path = os.path.join(ids_core_dir, "model_info.json")

    with open(model_path, "wb") as f:
        pickle.dump(clf, f)

    info = {
        "algorithm": "RandomForestClassifier",
        "n_estimators": 200,
        "max_depth": 6,
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
        "accuracy": float(acc),
        "confusion_matrix": cm.tolist(),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "features": [
            "path_length",
            "payload_length",
            "has_admin_in_payload",
            "has_select_in_payload",
        ],
        "data_source": "CSIC" if os.path.exists(
            os.path.join(project_root, "data", "csic_processed", "csic_labeled.csv")
        ) else "synthetic",
    }

    with open(info_path, "w") as f:
        json.dump(info, f, indent=2)

    print(f"\nSaved trained model to: {model_path}")
    print(f"Saved model metadata to: {info_path}")
    print("Training complete.")


if __name__ == "__main__":
    main()
