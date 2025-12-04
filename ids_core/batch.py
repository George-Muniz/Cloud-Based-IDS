import io
import csv
import logging
import os
from typing import List, Dict, Any
from urllib.parse import urlparse
from google.cloud import storage
from .detector import detect

logger = logging.getLogger(__name__)

# structured logger for batch-level metrics
try:
    from google.cloud import logging as cloud_logging

    _cloud_logging_client = cloud_logging.Client()
    _structured_logger = _cloud_logging_client.logger("ids-batch")
except Exception:
    _structured_logger = None


def _parse_gs_path(gs_path: str) -> tuple[str, str]:
    """
    Split a GCS path like gs://bucket/path/to/file.csv
    into (bucket, blob_path).
    """
    if not gs_path.startswith("gs://"):
        raise ValueError(f"gs_path must start with gs://, got: {gs_path}")

    without_scheme = gs_path[5:]
    bucket, _, blob = without_scheme.partition("/")
    if not bucket or not blob:
        raise ValueError(f"Invalid GCS path: {gs_path}")

    return bucket, blob


def _row_to_event(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a CSV row (dict) into an event dict that our detector can handle.
    This is intentionally lightweight so it works with your existing datasets.
    """
    event: Dict[str, Any] = dict(row)

    # Try to normalize request path/method if only a raw request line is present
    request_line = event.get("request")
    if isinstance(request_line, str) and " " in request_line:
        try:
            parts = request_line.split(" ")
            if len(parts) >= 2:
                method = parts[0]
                url_part = parts[1]
                event.setdefault("method", method)
                # url_part might include querystring
                parsed = urlparse(url_part)
                event.setdefault("path", parsed.path or url_part)
                if parsed.query:
                    event.setdefault("query", parsed.query)
        except Exception:
            pass

    # If there's a URL field, extract path/query from it
    if "url" in event and isinstance(event["url"], str):
        parsed = urlparse(event["url"])
        if parsed.path and "path" not in event:
            event["path"] = parsed.path
        if parsed.query and "query" not in event:
            event["query"] = parsed.query

    return event


def _log_batch_metrics(gs_path: str, summary: Dict[str, Any]) -> None:
    """
    Log aggregate metrics for the batch run, for use in dashboards.
    """
    payload = {
        "message": "ids_batch_summary",
        "ids": {
            "batch": {
                "gs_path": gs_path,
                "total_events": summary.get("total_events"),
                "flagged": summary.get("flagged"),
                "flagged_ratio": summary.get("flagged_ratio"),
                "skipped": summary.get("skipped"),
                "max_rows": summary.get("max_rows"),
                "max_details": summary.get("max_details"),
            }
        },
    }

    if _structured_logger is not None:
        try:
            _structured_logger.log_struct(payload)
        except Exception:
            logger.exception("Failed to write structured batch summary log")
    else:
        import json

        logger.info("IDS_BATCH_SUMMARY %s", json.dumps(payload))


# Caps to avoid blowing up on large files
MAX_ROWS = int(os.getenv("IDS_MAX_ROWS", "20000"))
MAX_DETAILS = int(os.getenv("IDS_MAX_DETAILS", "100"))

def analyze_batch(gs_path: str) -> Dict[str, Any]:
    """
    Load a CSV from GCS, run each row through the IDS, and return a summary.

    Return shape (backwards compatible):
        {
            "total_events": int,
            "flagged": int,
            "flagged_ratio": float,
            "results": [ ... detailed flagged events ... ],
            "skipped": int,
            "max_rows": int,
            "max_details": int,
        }
    """
    bucket_name, blob_name = _parse_gs_path(gs_path)

    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    logger.info("Downloading log file from GCS: bucket=%s, blob=%s", bucket_name, blob_name)
    data = blob.download_as_text()

    f = io.StringIO(data)
    reader = csv.DictReader(f)

    total = 0
    flagged = 0
    skipped = 0
    details: List[Dict[str, Any]] = []

    for row in reader:
        total += 1
        if total > MAX_ROWS:
            logger.info("Reached MAX_ROWS=%d, stopping further processing", MAX_ROWS)
            break

        try:
            event = _row_to_event(row)
            det = detect(event)
        except Exception:
            skipped += 1
            logger.exception("Failed to analyze row; skipping")
            continue

        if det.get("is_malicious"):
            flagged += 1
            if len(details) < MAX_DETAILS:
                details.append(
                    {
                        "row_index": total - 1,
                        "event": event,
                        "detection": det,
                    }
                )

    summary: Dict[str, Any] = {
        "total_events": total,
        "flagged": flagged,
        "flagged_ratio": (flagged / total) if total else 0.0,
        "results": details,
        "skipped": skipped,
        "max_rows": MAX_ROWS,
        "max_details": MAX_DETAILS,
    }

    # Emit structured batch metrics for dashboards (Cloud Logging, etc.)
    _log_batch_metrics(gs_path, summary)

    return summary

# Backwards-compatible alias for older code
def analyze_gcs_csv(gs_path: str) -> Dict[str, Any]:
    """
    Legacy wrapper kept for compatibility.
    Internally just calls analyze_batch(gs_path).
    """
    return analyze_batch(gs_path)
