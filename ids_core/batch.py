import io
import csv
import logging
from typing import List, Dict
from urllib.parse import urlparse

from google.cloud import storage
from .detector import detect

logger = logging.getLogger(__name__)


def _parse_gs_path(gs_path: str):
    assert gs_path.startswith("gs://")
    _, rest = gs_path.split("gs://", 1)
    bucket, blob = rest.split("/", 1)
    return bucket, blob


def analyze_gcs_csv(gs_path: str) -> Dict:
    # Hard limits to keep App Engine happy on large files like CSIC
    MAX_ROWS = 1000        # max rows to fully process
    MAX_DETAILS = 500      # max events to include in "results"

    bucket_name, blob_name = _parse_gs_path(gs_path)

    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    data_bytes = blob.download_as_bytes()
    text_stream = io.StringIO(data_bytes.decode("utf-8", errors="replace"))

    # Use DictReader but be defensive about bad CSV rows
    reader = csv.DictReader(text_stream)

    total = 0          # rows actually processed (up to MAX_ROWS)
    flagged = 0
    skipped = 0
    details: List[Dict] = []

    while True:
        # --- Safely advance the CSV reader ---
        try:
            row = next(reader)
        except StopIteration:
            break
        except csv.Error as e:
            # Badly formatted CSV row: skip and keep going
            skipped += 1
            logger.exception("CSV parse error in %s, skipping row: %s", gs_path, e)
            continue

        if total >= MAX_ROWS:
            # Stop before we blow up CPU/memory/response size
            break

        try:
            # Handle CSIC-style full URLs in path
            raw_path = (row.get("path") or "").strip()
            if raw_path.startswith("http://") or raw_path.startswith("https://"):
                parsed = urlparse(raw_path)
                path = parsed.path or raw_path
            else:
                path = raw_path

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
