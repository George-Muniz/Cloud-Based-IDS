SUSPICIOUS_PATTERNS = [
    "' OR 1=1",
    "UNION SELECT",
    "DROP TABLE",
    "INSERT INTO",
    "/etc/passwd",
]

SUSPICIOUS_PATHS = [
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
    "/etc/passwd",
]

def check_sql_injection(payload: str):
    payload_low = (payload or "").lower()
    return [p for p in SUSPICIOUS_PATTERNS if p.lower() in payload_low]

def check_path_anomaly(path: str):
    path_low = (path or "").lower()
    return [p for p in SUSPICIOUS_PATHS if p.lower() in path_low]

def rule_engine(event: dict) -> dict:
    """
    event example:
    {
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "path": "/login",
        "method": "POST",
        "payload": "username=admin&password=' OR 1=1"
    }
    """
    rules_triggered = []

    sql_trigs = check_sql_injection(event.get("payload", ""))
    if sql_trigs:
        rules_triggered.append(f"SQL_INJECTION:{','.join(sql_trigs)}")

    path_trigs = check_path_anomaly(event.get("path", ""))
    if path_trigs:
        rules_triggered.append(f"SUSPICIOUS_PATH:{','.join(path_trigs)}")

    is_intrusion = len(rules_triggered) > 0

    return {
        "is_intrusion": is_intrusion,
        "rules_triggered": rules_triggered
    }
