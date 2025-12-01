import os
import pickle
import numpy as np

_MODEL = None

def _load_model():
    global _MODEL
    if _MODEL is not None:
        return _MODEL

    possible_paths = [
        os.path.join(os.path.dirname(__file__), "model.pkl"),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "model.pkl"),
    ]

    model_path = None
    for p in possible_paths:
        if os.path.exists(p):
            model_path = p
            break

    if model_path is None:
        _MODEL = None
        return None

    with open(model_path, "rb") as f:
        _MODEL = pickle.load(f)
    return _MODEL

def ml_score(event: dict) -> float:
    """
    Returns anomaly/probability score in [0, 1].
    If no model is available, fall back to 0.0.
    """
    model = _load_model()
    if model is None:
        return 0.0

    path = event.get("path", "") or ""
    payload = event.get("payload", "") or ""

    x = np.array([
        len(path),
        len(payload),
        1.0 if "admin" in payload.lower() else 0.0,
        1.0 if "select" in payload.lower() else 0.0,
    ]).reshape(1, -1)

    try:
        if hasattr(model, "predict_proba"):
            prob = model.predict_proba(x)[0][1]
        elif hasattr(model, "decision_function"):
            raw = float(model.decision_function(x)[0])
            prob = 1.0 / (1.0 + np.exp(-raw))
        else:
            pred = model.predict(x)[0]
            prob = float(pred)
    except Exception:
        prob = 0.0

    return float(prob)
