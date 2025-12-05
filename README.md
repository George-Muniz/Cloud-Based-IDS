# Cloud-Based Intrusion Detection System (IDS)

This project implements a lightweight, cloud-hosted Intrusion Detection System
designed for HTTP traffic. It combines:

- **Rule-based detection** (simple, explainable rules),
- **Machine learning** (RandomForest classifier),
- **Cloud-native deployment** on both:
  - **Google Compute Engine (GCE)** VM, and
  - **Google App Engine (GAE)** Standard.

The goal is to compare **cost**, **performance**, and **accuracy** between
the two deployment models using the same IDS logic and datasets.

---

We performed a threshold sweep at multiple values (0.40–0.72).  
We selected **threshold = 0.50** because it produced the best balance between precision (~0.658) and recall (~0.911).  
Lower thresholds increased false positives, and higher thresholds significantly reduced recall.  
Therefore 0.50 provides optimal detection performance aligned with the IDS design goal of high recall (catching most attacks).

## Architecture Overview

**Core components:**

- `api/main.py`  
  FastAPI application exposing:
  - `POST /analyze` – analyze a single HTTP-like event
  - `GET /analyze_batch` – analyze a CSV in GCS
  - `GET /summary` – basic counters for events, alerts, and errors
  - `GET /model_info` – ML model metadata

- `ids_core/detector.py`  
  Normalizes events, runs rules + ML model, fuses results, and logs structured
  detections (optionally to Cloud Logging).

- `ids_core/model.py`  
  Loads `model.pkl` and `model_info.json`, extracts features from events, and
  produces ML probabilities using a RandomForest classifier.

- `ids_core/rules.py`  
  Simple, explainable rule engine (e.g., flags `/admin` paths, suspicious
  payloads, etc.).

- `ids_core/batch.py`  
  Loads CSV logs from Google Cloud Storage, runs each row through `detect`,
  and returns a summary (flagged count, ratio, skipped rows, etc.).

- `model_training/train_model.py`  
  Training pipeline that:
  - Loads the CSIC web attack dataset (if present),
  - Extracts numeric features from path + payload,
  - Trains a RandomForest classifier,
  - Evaluates it,
  - Saves `ids_core/model.pkl` and `ids_core/model_info.json`.

---

## Datasets

The primary dataset is the **CSIC 2010 HTTP dataset**, preprocessed into:

- `data/csic_processed/csic_labeled.csv`  
  Used for training (`model_training/train_model.py`) and for synthetic
  “realistic” log CSVs in GCS.

You can also test with smaller samples such as:

- `data/sample_logs.csv`
- Any CSV you upload to your GCS bucket in the same schema.

---

## Running Locally (GCE-style)

1. Create and activate a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
