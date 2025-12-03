import os
import json
import logging
from typing import Dict, Any, List

import numpy as np
import pickle

logger = logging.getLogger(__name__)

_MODEL = None
_MODEL_INFO: Dict[str, Any] | None = None

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
    global _MODEL, _MODEL_INFO

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

    logger.info("Loaded IDS ML model from %s", model_path)
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


def _extract_features(event: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract features consistent with model_info.json / training:

    - path_length
    - payload_length
    - has_admin_in_payload
    - has_select_in_payload
    """
    path = _get_path(event)
    payload = _get_payload(event)
    payload_lower = payload.lower()

    features: Dict[str, float] = {
        "path_length": float(len(path)),
        "payload_length": float(len(payload)),
        "has_admin_in_payload": 1.0 if "admin" in payload_lower else 0.0,
        "has_select_in_payload": 1.0 if "select" in payload_lower else 0.0,
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
            ]
    else:
        # No metadata at all: use the same hard-coded order
        feature_order = [
            "path_length",
            "payload_length",
            "has_admin_in_payload",
            "has_select_in_payload",
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
