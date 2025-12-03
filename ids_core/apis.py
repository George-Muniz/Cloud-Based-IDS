import logging
import os
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Optional: IPinfo token for higher rate limits / more fields
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")

try:
    import requests  # type: ignore
except Exception:  # requests may not be installed in some environments
    requests = None  # type: ignore[assignment]


def geoip_lookup(ip: str) -> Dict[str, Any]:
    """
    Basic GeoIP lookup using ipinfo.io.

    Returns a small dict with location info.
    If requests is not available or something fails, returns {}.
    """
    if not ip:
        return {}

    if requests is None:
        logger.debug("requests library not available; skipping GeoIP lookup")
        return {}

    url = f"https://ipinfo.io/{ip}"
    params = {}
    if IPINFO_TOKEN:
        params["token"] = IPINFO_TOKEN

    try:
        resp = requests.get(url, params=params, timeout=2.0)
    except Exception:
        logger.warning("GeoIP HTTP request failed for %s", ip, exc_info=True)
        return {}

    if resp.status_code != 200:
        logger.warning(
            "GeoIP lookup failed for %s with status %s", ip, resp.status_code
        )
        return {}

    try:
        data = resp.json()
    except Exception:
        logger.warning("Failed to parse GeoIP JSON for %s", ip, exc_info=True)
        return {}

    # Only return fields we actually care about
    return {
        "ip": data.get("ip"),
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "loc": data.get("loc"),
        "org": data.get("org"),
    }
