from __future__ import annotations
import os
import json
import logging
from typing import Dict, Any, List
import math
import numpy as np
import pickle
from collections import Counter
logger = logging.getLogger(__name__)

_MODEL = None
_MODEL_INFO: Dict[str, Any] | None = None

# Threshold used to decide "malicious" vs "benign" at runtime.
# This will be loaded from model_info.json if present.
_DECISION_THRESHOLD: float = 0.5

# Where to look for the model file
_MODEL_PATH_CANDIDATES: List[str | None] = [
    os.environ.get("IDS_MODEL_PATH"),
    os.path.join(os.path.dirname(__file__), "model.pkl"),
    os.path.join(os.path.dirname(__file__), "..", "model.pkl"),
]

_MODEL_INFO_PATH = os.path.join(os.path.dirname(__file__), "model_info.json")


def _load_model():
    """
    Lazy-load the trained ML model and optional metadata.
    """
    global _MODEL, _MODEL_INFO, _DECISION_THRESHOLD

    if _MODEL is not None:
        return _MODEL

    model_path = None
    for candidate in _MODEL_PATH_CANDIDATES:
        if candidate and os.path.exists(candidate):
            model_path = candidate
            break

    if not model_path:
        raise FileNotFoundError(
            f"Could not find model.pkl in any of: {_MODEL_PATH_CANDIDATES}"
        )

    with open(model_path, "rb") as f:
        _MODEL = pickle.load(f)

    # Optional metadata (feature names etc.)
    try:
        with open(_MODEL_INFO_PATH, "r") as f:
            _MODEL_INFO = json.load(f)
    except FileNotFoundError:
        _MODEL_INFO = None

    # Load decision threshold from metadata if present
    if _MODEL_INFO is not None:
        try:
            # train_model.py writes this key
            _DECISION_THRESHOLD = float(_MODEL_INFO.get("decision_threshold", 0.5))
        except Exception:
            _DECISION_THRESHOLD = 0.5
    else:
        _DECISION_THRESHOLD = 0.5

    logger.info(
        "Loaded IDS ML model from %s (decision_threshold=%.3f)",
        model_path,
        _DECISION_THRESHOLD,
    )
    return _MODEL


def _get_path(event: Dict[str, Any]) -> str:
    """
    Try to derive a request path from several possible fields.
    """
    # direct path/url
    for key in ("path", "url", "request_uri", "cs_uri_stem"):
        val = event.get(key)
        if isinstance(val, str) and val:
            return val

    # "request" like: "GET /foo/bar?x=1 HTTP/1.1"
    req = event.get("request")
    if isinstance(req, str) and " " in req:
        try:
            parts = req.split(" ")
            if len(parts) >= 2:
                return parts[1]
        except Exception:
            pass

    return ""


def _get_payload(event: Dict[str, Any]) -> str:
    """
    Combine query/body/payload-ish fields into a single string.
    """
    for key in ("body", "payload", "request_body", "query", "cs_uri_query"):
        val = event.get(key)
        if isinstance(val, str) and val:
            return val

    # Sometimes full "request" contains query string
    req = event.get("request")
    if isinstance(req, str):
        return req

    return ""

def shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy of a string. Must match training-side definition.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((freq / length) * math.log2(freq / length) for freq in counts.values())

def _extract_features(event: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract features consistent with model_info.json / training:

    - path_length
    - payload_length
    - has_admin_in_payload
    - has_select_in_payload
    - num_special_chars
    - num_digits
    - path_depth
    - has_sql_keywords
    - has_xss_pattern
    - payload_entropy
    """
    path = _get_path(event)
    payload = _get_payload(event)
    payload_lower = payload.lower()

    path_length = len(path)
    payload_length = len(payload)

    has_admin_in_payload = 1.0 if "admin" in payload_lower else 0.0
    has_select_in_payload = 1.0 if "select" in payload_lower else 0.0

    num_special_chars = sum(
        1 for c in payload
        if not c.isalnum() and not c.isspace()
    )
    num_digits = sum(1 for c in payload if c.isdigit())

    path_depth = len([segment for segment in path.split("/") if segment])

    sql_keywords = ("union", "select", "insert", "update", "delete", "drop", "where")
    has_sql_keywords = 1.0 if any(kw in payload_lower for kw in sql_keywords) else 0.0

    xss_tokens = ("<script", "onerror=", "onload=", "javascript:")
    has_xss_pattern = 1.0 if any(tok in payload_lower for tok in xss_tokens) else 0.0

    payload_entropy = shannon_entropy(payload)

    features: Dict[str, float] = {
        "path_length": float(path_length),
        "payload_length": float(payload_length),
        "has_admin_in_payload": float(has_admin_in_payload),
        "has_select_in_payload": float(has_select_in_payload),
        "num_special_chars": float(num_special_chars),
        "num_digits": float(num_digits),
        "path_depth": float(path_depth),
        "has_sql_keywords": float(has_sql_keywords),
        "has_xss_pattern": float(has_xss_pattern),
        "payload_entropy": float(payload_entropy),
    }

    return features

def ml_score(event: Dict[str, Any]) -> float:
    """
    Score an event with the ML model.

    Returns a probability in [0, 1]. On failure, returns 0.0.
    """
    try:
        model = _load_model()
    except Exception:
        logger.exception("Failed to load ML model; returning 0.0")
        return 0.0

    features = _extract_features(event)

    global _MODEL_INFO

    # Determine feature order
    if _MODEL_INFO:
        if "feature_names" in _MODEL_INFO:
            # Preferred key written by train_model.py
            feature_order = list(_MODEL_INFO["feature_names"])
        elif "features" in _MODEL_INFO:
            # Backwards-compatible key (same order)
            feature_order = list(_MODEL_INFO["features"])
        else:
            # Fall back to hard-coded order that matches training
            feature_order = [
                "path_length",
                "payload_length",
                "has_admin_in_payload",
                "has_select_in_payload",
                "num_special_chars",
                "num_digits",
                "path_depth",
                "has_sql_keywords",
                "has_xss_pattern",
                "payload_entropy",
            ]
    else:
        # No metadata at all: use the same hard-coded order
        feature_order = [
            "path_length",
            "payload_length",
            "has_admin_in_payload",
            "has_select_in_payload",
            "num_special_chars",
            "num_digits",
            "path_depth",
            "has_sql_keywords",
            "has_xss_pattern",
            "payload_entropy",
        ]

    x = np.array([[features.get(name, 0.0) for name in feature_order]], dtype=float)

    try:
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(x)[0, 1]
            score = float(proba)
        elif hasattr(model, "decision_function"):
            raw = float(model.decision_function(x)[0])
            # Simple logistic squashing
            score = 1.0 / (1.0 + np.exp(-raw))
        else:
            # As a last resort, treat model.predict output as a score
            pred = float(model.predict(x)[0])
            # Clamp to [0, 1]
            score = max(0.0, min(1.0, pred))
    except Exception:
        logger.exception("Error scoring event with ML model; returning 0.0")
        return 0.0

    # Clamp to [0, 1] for safety
    return max(0.0, min(1.0, score))


def get_model_info() -> Dict[str, Any] | None:
    """
    Optional helper: return the model metadata (e.g., for debugging or
    exposing in a /model_info endpoint if you want).
    """
    global _MODEL_INFO
    if _MODEL is None:
        _load_model()
    return _MODEL_INFO


def get_decision_threshold() -> float:
    """
    Return the decision threshold being used to classify events as malicious.
    This value is loaded from model_info.json (decision_threshold) or
    defaults to 0.5.
    """
    global _MODEL, _DECISION_THRESHOLD
    if _MODEL is None:
        _load_model()
    return _DECISION_THRESHOLD


def classify_with_threshold(event: Dict[str, Any]) -> bool:
    """
    Convenience helper: classify an event using the learned decision threshold.

    Returns True if the event should be considered malicious, False otherwise.
    """
    score = ml_score(event)
    threshold = get_decision_threshold()
    return score >= threshold
