import io
import csv
import logging
from typing import List, Dict
from urllib.parse import urlparse

from google.cloud import storage
from .detector import detect

logger = logging.getLogger(__name__)


def _parse_gs_path(gs_path: str):
    """
    Parse a gs://bucket/path/to/file.csv string into (bucket, blob_name).
    """
    if not gs_path.startswith("gs://"):
        raise ValueError(f"gs_path must start with gs://, got: {gs_path}")

    rest = gs_path[len("gs://") :]
    parts = rest.split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid gs_path (missing blob name): {gs_path}")

    bucket_name, blob_name = parts
    return bucket_name, blob_name


def analyze_gcs_csv(gs_path: str) -> Dict:
    """
    Load a CSV from GCS and run our IDS detector on each row.

    Handles:
      - training-style csv with an extra 'label' column (ignored)
      - CSIC-style logs where 'path' is a full URL (we keep only the path)
    """
    bucket_name, blob_name = _parse_gs_path(gs_path)

    # Hard limits so CSIC doesn't blow up memory / CPU
    # Use a smaller sample if this is the huge CSIC log.
    if "csic" in blob_name.lower():
        MAX_ROWS = 200
    else:
        MAX_ROWS = 500

    MAX_DETAILS = 300  # max events to include in "results"

    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    data_bytes = blob.download_as_bytes()
    text_stream = io.StringIO(data_bytes.decode("utf-8", errors="replace"))

    reader = csv.DictReader(text_stream)

    total = 0
    flagged = 0
    skipped = 0
    details: List[Dict] = []

    for row in reader:
        if not row:
            continue

        if total >= MAX_ROWS:
            break

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
