import logging
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, unquote_plus

logger = logging.getLogger(__name__)

# Keep your original suspicious patterns, but extend a bit
SQLI_PATTERNS = [
    "union select",
    "select ",
    " or 1=1",
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "drop table",
    "insert into",
    "update ",
    "delete from",
    "information_schema",
    "--",
    "/*",
    " xp_",
]

PATH_SUSPICIOUS_KEYWORDS = [
    "../",
    "..\\",
    "/etc/passwd",
    "/proc",
    "wp-admin",
    "admin",
    "phpmyadmin",
]

SUSPICIOUS_EXTENSIONS = [
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".cgi",
]

ADMIN_KEYWORDS = [
    "admin",
    "root",
    "superuser",
]


def _get_path_and_query(event: Dict[str, Any]) -> tuple[str, str]:
    """
    Extract path and query string from various event fields.
    """
    # Try explicit fields first
    path = event.get("path") or event.get("cs_uri_stem") or ""
    query = event.get("query") or event.get("cs_uri_query") or ""

    # Fallback to a URL field
    if not path:
        url = event.get("url") or event.get("request_uri") or ""
        if url:
            parsed = urlparse(url)
            path = parsed.path or ""
            query = query or parsed.query or ""

    # Fallback to raw request line "GET /foo?bar=1 HTTP/1.1"
    req = event.get("request")
    if not path and isinstance(req, str) and " " in req:
        try:
            parts = req.split(" ")
            if len(parts) >= 2:
                url_part = parts[1]
                parsed = urlparse(url_part)
                path = parsed.path or url_part
                query = query or parsed.query or ""
        except Exception:
            pass

    return path or "", query or ""


def _normalize_payload(payload: str) -> str:
    return unquote_plus(payload).lower()


def check_sql_injection(payload: str) -> List[str]:
    """
    Very simple SQLi check based on keyword/substring matches.
    Returns a list of rule IDs that fired.
    """
    hits: List[str] = []

    if not payload:
        return hits

    norm = _normalize_payload(payload)

    for pattern in SQLI_PATTERNS:
        if pattern in norm:
            hits.append(f"SQLI:{pattern.strip()}")

    # Also inspect query parameters individually for keywords like 'admin'
    try:
        params = parse_qs(payload)
        for key, values in params.items():
            key_norm = _normalize_payload(key)
            if any(k in key_norm for k in ADMIN_KEYWORDS):
                hits.append("SQLI:admin_param")
            for v in values:
                v_norm = _normalize_payload(v)
                if any(p in v_norm for p in SQLI_PATTERNS):
                    hits.append("SQLI:param_match")
    except Exception:
        # payload may not be a strict query string; ignore
        pass

    return list(sorted(set(hits)))


def check_path_anomaly(path: str) -> List[str]:
    """
    Heuristic checks on the request path.
    Returns a list of rule IDs that fired.
    """
    hits: List[str] = []
    if not path:
        return hits

    lower_path = path.lower()

    # Directory traversal, sensitive paths, admin panels, etc.
    for kw in PATH_SUSPICIOUS_KEYWORDS:
        if kw in lower_path:
            hits.append(f"PATH:{kw}")

    # Suspicious extensions (often used for web shells etc.)
    for ext in SUSPICIOUS_EXTENSIONS:
        if lower_path.endswith(ext):
            hits.append(f"PATH_EXT:{ext}")

    # Very long path could be an attempt to overflow/buffer issues
    if len(path) > 2000:
        hits.append("PATH:too_long")

    return list(sorted(set(hits)))


def rule_engine(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply simple rule-based checks to an event.

    Returns:
        {
            "is_intrusion": bool,
            "rules_triggered": [...],
            "reasons": [...],   # extra detail, safe for logging
        }
    """
    path, query = _get_path_and_query(event)
    body = event.get("body") or event.get("payload") or ""

    combined_payload = f"{query}&{body}" if query and body else (query or body)

    sql_hits = check_sql_injection(combined_payload)
    path_hits = check_path_anomaly(path)

    rules_triggered: List[str] = []
    reasons: List[str] = []

    if sql_hits:
        rules_triggered.extend(sql_hits)
        reasons.append(f"SQLi patterns detected: {sql_hits}")

    if path_hits:
        rules_triggered.extend(path_hits)
        reasons.append(f"Suspicious path patterns detected: {path_hits}")

    # Simple status-based rule (optional, backwards compatible)
    status = event.get("status")
    try:
        status_int = int(status) if status is not None else None
    except ValueError:
        status_int = None

    if status_int and status_int >= 500:
        rules_triggered.append("HTTP:server_error")
        reasons.append(f"High HTTP status code: {status_int}")

    is_intrusion = len(rules_triggered) > 0

    return {
        "is_intrusion": is_intrusion,
        "rules_triggered": list(sorted(set(rules_triggered))),
        "reasons": reasons,
    }
