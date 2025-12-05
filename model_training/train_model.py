import os
import json
import random
import math
from datetime import datetime
from collections import Counter
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    roc_curve,
    auc,
)
from sklearn.model_selection import train_test_split
import pickle
import csv

# For reproducibility
RANDOM_SEED = 42

# -------------------------------------------------------
#  Feature extraction (must match ids_core/model.py)
# -------------------------------------------------------

def shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy of a string. Higher entropy often indicates
    more "random" or obfuscated content.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((freq / length) * math.log2(freq / length) for freq in counts.values())

def extract_features(path: str, payload: str):
    """
    Returns features in a fixed order:

    0: path_length
    1: payload_length
    2: has_admin_in_payload
    3: has_select_in_payload
    4: num_special_chars
    5: num_digits
    6: path_depth
    7: has_sql_keywords
    8: has_xss_pattern
    9: payload_entropy
    """
    payload_lower = payload.lower()

    # Basic lengths
    path_length = len(path)
    payload_length = len(payload)

    # Simple flags
    has_admin_in_payload = 1.0 if "admin" in payload_lower else 0.0
    has_select_in_payload = 1.0 if "select" in payload_lower else 0.0

    # Extra shape features
    num_special_chars = sum(
        1 for c in payload
        if not c.isalnum() and not c.isspace()
    )
    num_digits = sum(1 for c in payload if c.isdigit())

    # Path depth: number of non-empty segments
    path_depth = len([segment for segment in path.split("/") if segment])

    # SQL-ish keywords
    sql_keywords = ("union", "select", "insert", "update", "delete", "drop", "where")
    has_sql_keywords = 1.0 if any(kw in payload_lower for kw in sql_keywords) else 0.0

    # Very simple XSS patterns
    xss_tokens = ("<script", "onerror=", "onload=", "javascript:")
    has_xss_pattern = 1.0 if any(tok in payload_lower for tok in xss_tokens) else 0.0

    # Entropy of the raw payload
    payload_entropy = shannon_entropy(payload)

    return [
        float(path_length),
        float(payload_length),
        float(has_admin_in_payload),
        float(has_select_in_payload),
        float(num_special_chars),
        float(num_digits),
        float(path_depth),
        float(has_sql_keywords),
        float(has_xss_pattern),
        float(payload_entropy),
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

    # Optionally downsample if CSIC is huge.
    # Default: keep up to 60,000 samples (your full dataset size).
    # Override with IDS_TRAIN_MAX_SAMPLES (set to 0 to disable downsampling).
    max_samples_env = os.getenv("IDS_TRAIN_MAX_SAMPLES")
    max_samples = int(max_samples_env) if max_samples_env else 61065

    if max_samples > 0 and len(X) > max_samples:
        print(f"[INFO] Downsampling from {len(X)} to {max_samples} samples.")
        idx = np.random.choice(len(X), size=max_samples, replace=False)
        X = X[idx]
        y = y[idx]

    # Basic class distribution
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
        class_weight="balanced",
    )

    clf.fit(X_train, y_train)

    # ---------------------------------------------------
    # Evaluation on test set with threshold-based prediction
    # ---------------------------------------------------
    decision_threshold = 0.47  # adjust between 0.4 and 0.6 (or based on sweep below)

    if hasattr(clf, "predict_proba"):
        y_proba = clf.predict_proba(X_test)[:, 1]

        # -----------------------------------------------
        # Threshold sweep: precision/recall for many thr
        # -----------------------------------------------
        print("\n=== Threshold sweep on test set ===")
        for thr in [0.40, 0.425, 0.45, 0.475, 0.50, 0.525, 0.55, 0.725,  0.6]:
            y_thr = (y_proba >= thr).astype(int)
            prec = precision_score(y_test, y_thr, zero_division=0)
            rec = recall_score(y_test, y_thr, zero_division=0)
            print(f"  thr={thr:.2f} -> precision={prec:.3f}, recall={rec:.3f}")

        # Use the chosen decision_threshold for the main metrics
        y_pred = (y_proba >= decision_threshold).astype(int)
    else:
        # Fallback to default classifier behavior if predict_proba is unavailable
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
    # Evaluate on data/sample_logs.csv if present
    # ---------------------------------------------------
    X_samp, y_samp = load_sample_logs()
    if X_samp is not None and y_samp is not None and len(X_samp) > 0:
        print("\n=== Evaluation on sample_logs.csv ===")

        if hasattr(clf, "predict_proba"):
            y_samp_proba = clf.predict_proba(X_samp)[:, 1]
            y_samp_pred = (y_samp_proba >= decision_threshold).astype(int)
        else:
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
        "num_special_chars",
        "num_digits",
        "path_depth",
        "has_sql_keywords",
        "has_xss_pattern",
        "payload_entropy",
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
        "features": feature_names,
        "feature_names": feature_names,
        "data_source": "CSIC"
        if os.path.exists(
            os.path.join(project_root, "data", "csic_processed", "csic_labeled.csv")
        )
        else "synthetic",
        "positive_label": 1,
        "label_meaning": {"0": "benign", "1": "malicious"},
        "random_seed": RANDOM_SEED,
        # store threshold so runtime can use the same value
        "decision_threshold": float(decision_threshold),
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
