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
from sklearn.metrics import roc_curve, auc
import pickle
import csv

# For reproducibility
RANDOM_SEED = 42


# -------------------------------------------------------
#  Feature extraction (must match ids_core/model.py)
# -------------------------------------------------------
def extract_features(path: str, payload: str):
    """
    Returns features in a fixed order:

    0: path_length
    1: payload_length
    2: has_admin_in_payload
    3: has_select_in_payload
    """
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

            # If label is missing, default to 0 (benign)
            label_str = row.get("label", "0")
            try:
                label = int(label_str)
            except ValueError:
                label = 0

            X.append(extract_features(path, payload))
            y.append(label)

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)

    print(f"[CSIC] Loaded {len(X)} samples.")
    return X, y

def load_sample_logs():
    """
    Load the small sample_logs.csv file for evaluation.

    Expected columns:
      src_ip,dst_ip,path,method,payload,label

    If label is missing, we default to 0 (benign).
    """
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sample_path = os.path.join(project_root, "data", "sample_logs.csv")

    if not os.path.exists(sample_path):
        print(f"[SAMPLE] sample_logs.csv not found at {sample_path}")
        return None, None

    print(f"[SAMPLE] Loading labeled sample data from {sample_path} ...")

    X = []
    y = []

    with open(sample_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            path = row.get("path", "") or ""
            payload = row.get("payload", "") or ""

            label_str = row.get("label", "0")
            try:
                label = int(label_str)
            except ValueError:
                label = 0

            X.append(extract_features(path, payload))
            y.append(label)

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)

    print(f"[SAMPLE] Loaded {len(X)} sample rows.")
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
    # Reproducibility
    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

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

    # Basic class distribution (for your report)
    benign_count = int((y == 0).sum())
    malicious_count = int((y == 1).sum())
    print(f"[INFO] Class distribution: benign={benign_count}, malicious={malicious_count}")

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=RANDOM_SEED, stratify=y
    )

    print(f"Training samples: {len(X_train)}, Test samples: {len(X_test)}")

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=6,
        random_state=RANDOM_SEED,
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
    
    # ---------------------------------------------------
    # evaluate on data/sample_logs.csv if present
    # ---------------------------------------------------
    X_samp, y_samp = load_sample_logs()
    if X_samp is not None and y_samp is not None and len(X_samp) > 0:
        print("\n=== Evaluation on sample_logs.csv ===")
        y_samp_pred = clf.predict(X_samp)

        acc_samp = accuracy_score(y_samp, y_samp_pred)
        cm_samp = confusion_matrix(y_samp, y_samp_pred)

        print(f"Sample Accuracy: {acc_samp:.3f}")
        print("Confusion matrix (rows=true, cols=pred):")
        print(cm_samp)
        print("\nClassification report:")
        print(classification_report(y_samp, y_samp_pred, digits=3))


    # Save model + metadata into ids_core
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ids_core_dir = os.path.join(project_root, "ids_core")
    os.makedirs(ids_core_dir, exist_ok=True)

    model_path = os.path.join(ids_core_dir, "model.pkl")
    info_path = os.path.join(ids_core_dir, "model_info.json")

    feature_names = [
        "path_length",
        "payload_length",
        "has_admin_in_payload",
        "has_select_in_payload",
    ]

    info = {
        "algorithm": "RandomForestClassifier",
        "n_estimators": 200,
        "max_depth": 6,
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
        "accuracy": float(acc),
        "confusion_matrix": cm.tolist(),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        # This was already in your example; keep it
        "features": feature_names,
        # Add explicit feature_names so ids_core/model.py can use the right order
        "feature_names": feature_names,
        "data_source": "CSIC"
        if os.path.exists(
            os.path.join(project_root, "data", "csic_processed", "csic_labeled.csv")
        )
        else "synthetic",
        "positive_label": 1,
        "label_meaning": {"0": "benign", "1": "malicious"},
        "random_seed": RANDOM_SEED,
    }

    with open(model_path, "wb") as f:
        pickle.dump(clf, f)

    with open(info_path, "w") as f:
        json.dump(info, f, indent=2)

    print(f"\nSaved trained model to: {model_path}")
    print(f"Saved model metadata to: {info_path}")
    print("Training complete.")

    # -------------------------------------------------------
    # Visualization: Confusion Matrix + ROC Curve
    # -------------------------------------------------------
    try:
        import matplotlib.pyplot as plt

        print("[VIZ] Generating evaluation plots...")

        # --- Confusion Matrix Heatmap ---
        fig_cm, ax_cm = plt.subplots()
        cax = ax_cm.imshow(cm, cmap="Blues")
        ax_cm.set_title("Confusion Matrix")
        ax_cm.set_xlabel("Predicted")
        ax_cm.set_ylabel("True")

        # Label matrix values
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax_cm.text(j, i, str(cm[i, j]), ha="center", va="center", color="black")

        plt.colorbar(cax)
        plt.tight_layout()

        reports_dir = os.path.join(project_root, "model_training", "reports")
        os.makedirs(reports_dir, exist_ok=True)

        cm_path = os.path.join(reports_dir, "confusion_matrix.png")
        fig_cm.savefig(cm_path)
        plt.close(fig_cm)

        # --- ROC Curve ---
        if hasattr(clf, "predict_proba"):
            y_score = clf.predict_proba(X_test)[:, 1]
        else:
            y_score = y_pred

        fpr, tpr, _ = roc_curve(y_test, y_score)
        roc_auc = auc(fpr, tpr)

        fig_roc, ax_roc = plt.subplots()
        ax_roc.plot(fpr, tpr, label=f"AUC = {roc_auc:.3f}")
        ax_roc.plot([0, 1], [0, 1], linestyle="--")
        ax_roc.set_xlabel("False Positive Rate")
        ax_roc.set_ylabel("True Positive Rate")
        ax_roc.set_title("ROC Curve")
        ax_roc.legend(loc="lower right")
        plt.tight_layout()

        roc_path = os.path.join(reports_dir, "roc_curve.png")
        fig_roc.savefig(roc_path)
        plt.close(fig_roc)

        print(f"[VIZ] Saved confusion matrix: {cm_path}")
        print(f"[VIZ] Saved ROC curve: {roc_path}")

    except ImportError:
        print("[VIZ] matplotlib not installed; skipping visualizations.")


if __name__ == "__main__":
    main()