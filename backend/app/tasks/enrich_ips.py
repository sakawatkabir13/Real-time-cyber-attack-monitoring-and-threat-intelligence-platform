import json
import httpx
import redis
from app.tasks.celery_app import celery_app
from app.config import settings
import logging

logger = logging.getLogger(__name__)
sync_redis = redis.from_url(settings.REDIS_URL, decode_responses=True)

@celery_app.task(
    bind=True,
    autoretry_for=(httpx.HTTPError,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 4},
    name="enrich_ip_task",
)
def enrich_ip_task(self, ip: str):
    """
    Background worker task to fetch AbuseIPDB reputation data.
    """
    cache_key = f"ip_data:{ip}"
    if sync_redis.get(cache_key):
        return

    api_key = settings.ABUSEIPDB_API_KEY
    if not api_key or api_key == "your_abuseipdb_api_key_here":
        return

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    resp = httpx.get(url, headers=headers, params=params, timeout=10.0)
    resp.raise_for_status()
    d = resp.json().get("data", {})
    data = {
        "reputation_score": d.get("abuseConfidenceScore", 0),
        "number_of_reporters": d.get("numDistinctUsers", 0),
        "community_reports": d.get("totalReports", 0),
    }

    # Cache for 24 hours
    sync_redis.setex(cache_key, 86400, json.dumps(data))
