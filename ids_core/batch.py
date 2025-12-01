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


def _safe_csv_reader(text: str):
    """
    A safer CSV iterator:
    - tries DictReader first
    - falls back to manual line parsing if DictReader crashes (CSIC logs)
    """
    try:
        # Normal CSV works
        return csv.DictReader(io.StringIO(text))
    except Exception:
        logger.warning("DictReader failed → using fallback parser.")

        lines = text.split("\n")
        if not lines:
            return []

        header = [h.strip() for h in lines[0].split(",")]

        for line in lines[1:]:
            if not line.strip():
                continue
            parts = line.split(",", maxsplit=len(header) - 1)
            row = dict(zip(header, parts))
            yield row


def analyze_gcs_csv(gs_path: str) -> Dict:
    MAX_ROWS = 1000
    MAX_DETAILS = 500

    bucket_name, blob_name = _parse_gs_path(gs_path)

    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    data_bytes = blob.download_as_bytes()
    text = data_bytes.decode("utf-8", errors="replace")

    reader = _safe_csv_reader(text)

    total = 0
    flagged = 0
    skipped = 0
    details: List[Dict] = []

    for row in reader:
        if total >= MAX_ROWS:
            break

        try:
            raw_path = (row.get("path") or "").strip()

            # Extract URL path for CSIC logs containing full URLs
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
