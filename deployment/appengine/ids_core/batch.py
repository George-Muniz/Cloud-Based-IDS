import io
import csv
from typing import List, Dict
from google.cloud import storage
from .detector import detect

def _parse_gs_path(gs_path: str):
    assert gs_path.startswith("gs://")
    _, rest = gs_path.split("gs://", 1)
    bucket, blob = rest.split("/", 1)
    return bucket, blob

def analyze_gcs_csv(gs_path: str) -> Dict:
    bucket_name, blob_name = _parse_gs_path(gs_path)

    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    data_bytes = blob.download_as_bytes()
    text_stream = io.StringIO(data_bytes.decode("utf-8"))
    reader = csv.DictReader(text_stream)

    total = 0
    flagged = 0
    details: List[Dict] = []

    for row in reader:
        event = {
            "src_ip": row.get("src_ip", ""),
            "dst_ip": row.get("dst_ip", ""),
            "path": row.get("path", ""),
            "method": row.get("method", ""),
            "payload": row.get("payload", ""),
        }
        det = detect(event)
        total += 1
        if det["is_intrusion"]:
            flagged += 1

        details.append({
            "event": event,
            "detection": det,
        })

    return {
        "total_events": total,
        "flagged": flagged,
        "flagged_ratio": (flagged / total) if total else 0.0,
        "results": details,
    }
