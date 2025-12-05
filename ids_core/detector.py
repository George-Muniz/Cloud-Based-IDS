import logging
import json
from typing import Dict, Any
from .model import ml_score, get_decision_threshold
from .rules import rule_engine
from .apis import geoip_lookup
#Contains the detection rules, ML model loading, and single-event detection logic.
logger = logging.getLogger(__name__)

# structured logging to Cloud Logging
try:
    from google.cloud import logging as cloud_logging

    _cloud_logging_client = cloud_logging.Client()
    _structured_logger = _cloud_logging_client.logger("ids-detector")
except Exception:
    _structured_logger = None


def _normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Light normalization so rules + ML can work across different CSV schemas
    without breaking existing behavior.
    """
    normalized = dict(event)

    # Normalize IP
    if "src_ip" not in normalized:
        for key in ("ip", "client_ip", "remote_addr", "c_ip"):
            if key in normalized:
                normalized.setdefault("src_ip", normalized.get(key))
                break

    # Normalize path / url
    if "path" not in normalized:
        for key in ("path", "url", "cs_uri_stem", "request_uri"):
            if key in normalized and normalized[key]:
                normalized["path"] = normalized[key]
                break

    # Normalize method
    if "method" not in normalized:
        for key in ("method", "cs_method", "http_method"):
            if key in normalized:
                normalized["method"] = normalized[key]
                break

    # Normalize query / payload
    if "query" not in normalized:
        for key in ("query", "cs_uri_query"):
            if key in normalized:
                normalized["query"] = normalized[key]
                break

    if "body" not in normalized:
        for key in ("body", "payload", "request_body"):
            if key in normalized:
                normalized["body"] = normalized[key]
                break

    return normalized


def _log_structured_detection(
    raw_event: Dict[str, Any],
    normalized_event: Dict[str, Any],
    result: Dict[str, Any],
) -> None:
    """
    Send a structured log to Cloud Logging if available,
    otherwise log JSON to standard logging.
    """
    src_ip = normalized_event.get("src_ip") or raw_event.get("ip")
    path = normalized_event.get("path") or raw_event.get("url")
    method = normalized_event.get("method")
    status = normalized_event.get("status") or raw_event.get("status")

    payload = {
        "message": "ids_detection",
        "ids": {
            "event": {
                "src_ip": src_ip,
                "method": method,
                "path": path,
                "status": status,
            },
            "detection": {
                "is_malicious": result.get("is_malicious"),
                "score": result.get("score"),
                "rule_score": result.get("rule_score"),
                "ml_score": result.get("ml_score"),
                "rules_triggered": result.get("rules_triggered", []),
                "severity": result.get("severity"),
                "geo": result.get("geo", {}),
            },
        },
    }

    if _structured_logger is not None:
        try:
            _structured_logger.log_struct(payload)
        except Exception:
            logger.exception("Failed to write structured detection log")
    else:
        logger.info("IDS_DETECTION %s", json.dumps(payload))

def detect(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main detection entrypoint.

    Returns a dict (backwards compatible):
        {
            "is_malicious": bool,
            "is_intrusion": bool,
            "score": float,
            "rule_score": float,
            "ml_score": float,
            "ml_probability": float,
            "rules_triggered": [...],
            "severity": "low|medium|high",
            "geo": {...},  # optional
        }
    """
    normalized = _normalize_event(event)

    # 1) Rule-based detection
    rule_result = rule_engine(normalized)
    rule_hit = bool(rule_result.get("is_intrusion"))
    rule_score = 1.0 if rule_hit else 0.0
    rules_triggered = rule_result.get("rules_triggered", [])

    # 2) ML-based detection
    ml_prob = ml_score(normalized)
    ml_threshold = get_decision_threshold()
    ml_hit = ml_prob >= ml_threshold

    # 3) Fusion
    combined_score = 0.6 * ml_prob + 0.4 * rule_score

    # Final decision: rules OR ML
    suspicious = rule_hit or ml_hit

    # Severity heuristic
    if combined_score >= 0.9 or len(rules_triggered) >= 3:
        severity = "high"
    elif combined_score >= 0.7 or len(rules_triggered) >= 1:
        severity = "medium"
    elif suspicious:
        severity = "low"
    else:
        severity = "none"

    result: Dict[str, Any] = {
        # Backwards-compatible booleans
        "is_intrusion": bool(suspicious),
        "is_malicious": bool(suspicious),
        "malicious": bool(suspicious),  

        # Scores
        "score": float(combined_score),
        "rule_score": float(rule_score),
        "ml_score": float(ml_prob),
        "ml_probability": float(ml_prob),

        # Extras
        "rules_triggered": rules_triggered,
        "normalized_event": normalized,
        "severity": severity,
        "source": "ids_v1",
    }

    # GeoIP lookup for malicious events
    src_ip = normalized.get("src_ip")
    if suspicious and src_ip:
        try:
            geo = geoip_lookup(src_ip)
        except Exception:
            logger.exception("GeoIP lookup failed for %s", src_ip)
            geo = {}
        result["geo"] = geo

    # Structured logging
    _log_structured_detection(event, normalized, result)

    return result
