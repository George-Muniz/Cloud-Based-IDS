from typing import Dict, Iterable
import json
import io
import datetime

PATTERNS = {
    "login_success": "LOGIN SUCCESS",
    "login_failure": "LOGIN FAILURE",
    "sql_injection": "SQL INJECTION",
    "access_denied": "ACCESS DENIED",
    "file_upload": "FILE UPLOAD",
}

def analyze_lines(lines: Iterable[str]) -> Dict[str, int]:
    counts = {k: 0 for k in PATTERNS}
    total = 0
    for line in lines:
        total += 1
        L = line.strip().upper()
        for key, token in PATTERNS.items():
            if token in L:
                counts[key] += 1
    counts["total_lines"] = total
    return counts

def analysis_to_json(blob_name: str, counts: Dict[str, int]) -> bytes:
    doc = {
        "blob": blob_name,
        "counts": counts,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "version": "w1-w2-baseline",
    }
    return json.dumps(doc, indent=2).encode("utf-8")

def analyze_blob_to_bytes(blob_name: str, downloader) -> bytes:
    raw = downloader(blob_name)
    buf = io.BytesIO(raw if isinstance(raw, (bytes, bytearray)) else raw.read())
    text = buf.getvalue().decode("utf-8", errors="replace").splitlines()
    counts = analyze_lines(text)
    return analysis_to_json(blob_name, counts)
