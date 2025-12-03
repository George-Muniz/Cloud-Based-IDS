import io
import csv
import logging
import pandas as pd
from typing import List, Dict
from urllib.parse import urlparse
from google.cloud import storage
from .detector import detect

logger = logging.getLogger(__name__)


def _parse_gs_path(gs_path: str):
    if not gs_path.startswith("gs://"):
        raise ValueError(f"gs_path must start with gs://, got: {gs_path}")

    rest = gs_path[len("gs://") :]
    parts = rest.split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid gs_path (missing blob name): {gs_path}")

    bucket_name, blob_name = parts
    return bucket_name, blob_name


def analyze_gcs_csv(gs_path: str) -> Dict:
    bucket_name, blob_name = _parse_gs_path(gs_path)

    # Hard limits ONLY for how many detailed entries we return in "results".
    # We now always process the *entire* file to get correct totals.
    if "csic" in blob_name.lower():
        MAX_ROWS = 200      # kept for response metadata/backwards-compat
        MAX_DETAILS = 200   # how many detailed rows we keep in "results"
    else:
        MAX_ROWS = 500
        MAX_DETAILS = 300

    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    total = 0
    flagged = 0
    skipped = 0
    details: List[Dict] = []

    # Stream the CSV directly from GCS as text, line by line.
    # newline="" is important for csv.DictReader to behave correctly.
    with blob.open("rt", newline="", encoding="utf-8", errors="replace") as text_stream:
        reader = csv.DictReader(text_stream)

        for row in reader:
            if not row:
                continue

            try:
                # --- Normalize path (handles CSIC full URLs) ---
                raw_path = (row.get("path") or "").strip()
                if raw_path.startswith("http://") or raw_path.startswith("https://"):
                    parsed = urlparse(raw_path)
                    path = parsed.path or raw_path
                else:
                    path = raw_path

                # --- Build event dict for our detector ---
                event = {
                    "src_ip": (row.get("src_ip") or "").strip(),
                    "dst_ip": (row.get("dst_ip") or "").strip(),
                    "path": path,
                    "method": (row.get("method") or "").strip(),
                    "payload": row.get("payload") or "",
                }

                det = detect(event)

            except Exception as e:
                skipped += 1
                logger.exception("Error processing row from %s, skipping: %s", gs_path, e)
                continue

            total += 1
            if det.get("is_intrusion"):
                flagged += 1

            # Only keep up to MAX_DETAILS detailed results to keep responses small.
            if len(details) < MAX_DETAILS:
                details.append(
                    {
                        "event": event,
                        "detection": det,
                    }
                )

    return {
        "total_events": total,
        "flagged": flagged,
        "flagged_ratio": (flagged / total) if total else 0.0,
        "results": details,
        "skipped": skipped,
        "max_rows": MAX_ROWS,
        "max_details": MAX_DETAILS,
    }
