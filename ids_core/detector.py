from .rules import rule_engine
from .model import ml_score
from .apis import geoip_lookup

def detect(event: dict) -> dict:
    rule_result = rule_engine(event)
    rule_score = 1.0 if rule_result["is_intrusion"] else 0.0

    prob = ml_score(event)
    combined = max(rule_score, prob)

    suspicious = combined >= 0.5
    geo = None

    if suspicious:
        src_ip = event.get("src_ip")
        geo = geoip_lookup(src_ip)

    return {
        "is_intrusion": suspicious,
        "score": combined,
        "rule_score": rule_score,
        "ml_score": prob,
        "rules_triggered": rule_result["rules_triggered"],
        "geoip": geo,
    }
