import ipaddress

import httpx

from app.config import settings


def _configured() -> bool:
    return bool(
        settings.ABUSEIPDB_API_KEY
        and settings.ABUSEIPDB_API_KEY != "your_abuseipdb_api_key_here"
    )


async def check_ip_abuse(ip: str) -> dict:
    ipaddress.ip_address(ip)
    if not _configured():
        return {"available": False, "reason": "AbuseIPDB is not configured"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Accept": "application/json", "Key": settings.ABUSEIPDB_API_KEY},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
            )
            response.raise_for_status()
            data = response.json().get("data", {})
    except (httpx.HTTPError, ValueError, AttributeError, TypeError) as exc:
        return {"available": False, "reason": f"AbuseIPDB lookup failed: {exc}"}

    reports = data.pop("reports", []) or []
    data["recentReports"] = reports[:20]
    data["ip"] = data.get("ipAddress", ip)
    data["available"] = True
    return data
