# ids_core/rules.py

SUSPICIOUS_PATTERNS = [
    "' OR 1=1",
    "UNION SELECT",
    "/etc/passwd",
    "<script>",
]

def analyze_event(event: dict) -> dict:
    """
    event example:
    {
      "src_ip": "1.2.3.4",
      "path": "/login",
      "method": "POST",
      "payload": "username=admin&password=' OR 1=1"
    }
    """
    payload = (event.get("payload") or "").lower()
    triggered = [p for p in SUSPICIOUS_PATTERNS if p.lower() in payload]

    is_intrusion = len(triggered) > 0

    return {
        "is_intrusion": is_intrusion,
        "rules_triggered": triggered,
    }
