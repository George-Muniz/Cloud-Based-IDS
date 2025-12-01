import io
import csv
import logging
from typing import List, Dict
from urllib.parse import urlparse
import pandas as pd
from google.cloud import storage
from .detector import detect

logger = logging.getLogger(__name__)


def _parse_gs_path(gs_path: str):
    assert gs_path.startswith("gs://")
    _, rest = gs_path.split("gs://", 1)
    bucket, blob = rest.split("/", 1)
    return bucket, blob


def analyze_gcs_csv(gs_path: str) -> Dict:
    """
    Analyze a CSV stored in GCS and return a summary.

    Supports both:
      - sample_logs.csv (small, labeled)
      - csic_logs.csv (large, HTTP-style logs with multi-line payloads)

    We:
      - Limit the number of rows read for safety (MAX_ROWS)
      - Limit the number of detailed events returned (MAX_DETAILS)
      - Handle full URLs in `path` (CSIC style)
      - Log and skip bad rows instead of crashing the whole request
    """
    # Hard limits to keep App Engine happy on large files like CSIC
    MAX_ROWS = 1000       # max rows to fully process (lower to avoid timeouts)
    MAX_DETAILS = 500     # max events to include in "results"

    bucket_name, blob_name = _parse_gs_path(gs_path)

    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    data_bytes = blob.download_as_bytes()
    text = data_bytes.decode("utf-8", errors="replace")

    # Use pandas to robustly parse CSV with potential multi-line payloads.
    # on_bad_lines="skip" (for newer pandas) prevents malformed lines from killing the whole job.
    try:
        df = pd.read_csv(
            io.StringIO(text),
            nrows=MAX_ROWS,
            engine="python",
            on_bad_lines="skip",  # pandas >= 1.3
        )
    except TypeError:
        # Fallback for older pandas that don't support on_bad_lines
        df = pd.read_csv(
            io.StringIO(text),
            nrows=MAX_ROWS,
            engine="python",
        )

    # Ensure required columns exist (create empty ones if missing)
    required_cols = ["src_ip", "dst_ip", "path", "method", "payload"]
    for col in required_cols:
        if col not in df.columns:
            df[col] = ""

    # Keep just the columns we actually use
    df = df[required_cols]

    total = 0          # rows successfully processed
    flagged = 0
    skipped = 0
    details: List[Dict] = []

    for idx, row in df.iterrows():
        try:
            # Handle CSIC-style full URLs in path
            raw_path = str(row["path"]).strip()
            if raw_path.startswith("http://") or raw_path.startswith("https://"):
                parsed = urlparse(raw_path)
                path = parsed.path or raw_path
            else:
                path = raw_path

            payload_val = row["payload"]
            if pd.isna(payload_val):
                payload_str = ""
            else:
                payload_str = str(payload_val)

            event = {
                "src_ip": str(row["src_ip"]).strip(),
                "dst_ip": str(row["dst_ip"]).strip(),
                "path": path,
                "method": str(row["method"]).strip(),
                "payload": payload_str,
            }

            det = detect(event)
        except Exception as e:
            skipped += 1
            logger.exception(
                "Error processing row %s from %s, skipping: %s",
                idx,
                gs_path,
                e,
            )
            continue

        total += 1
        if det.get("is_intrusion"):
            flagged += 1

        # Only keep a sample of detailed results to keep JSON small
        if len(details) < MAX_DETAILS:
            details.append({
                "event": event,
                "detection": det,
            })

    return {
        "total_events": total,
        "flagged": flagged,
        "flagged_ratio": (flagged / total) if total else 0.0,
        "results": details,
        "skipped": skipped,
        "max_rows": MAX_ROWS,
        "max_details": MAX_DETAILS,
    }