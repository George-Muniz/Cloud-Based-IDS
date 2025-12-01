import os
import requests

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

def geoip_lookup(ip: str) -> dict:
    """
    Simple IP geo lookup using ipinfo.io.
    Set IPINFO_TOKEN in environment or app.yaml.
    """
    if not ip or not IPINFO_TOKEN:
        return {
            "provider": "ipinfo",
            "country": "unknown",
            "org": "",
            "error": "no_token_or_ip",
        }

    url = f"https://ipinfo.io/{ip}"
    params = {"token": IPINFO_TOKEN}

    try:
        resp = requests.get(url, params=params, timeout=2)
    except Exception as e:
        return {
            "provider": "ipinfo",
            "country": "unknown",
            "org": "",
            "error": f"request_failed:{e}",
        }

    if not resp.ok:
        return {
            "provider": "ipinfo",
            "country": "unknown",
            "org": "",
            "error": f"http_{resp.status_code}",
        }

    data = resp.json()
    return {
        "provider": "ipinfo",
        "country": data.get("country", "NA"),
        "org": data.get("org", ""),
        "city": data.get("city", ""),
        "region": data.get("region", ""),
    }
