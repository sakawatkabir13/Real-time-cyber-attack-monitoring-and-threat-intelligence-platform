"""All-request map telemetry, separate from durable detections and ML labels.

Keep a bounded seven-day/latest-N recovery buffer in Redis, not a second copy
of every access log in PostgreSQL. Live delivery is not sampled. Atomic Redis
storage + publication makes stable-ID ingestion retries safe.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from urllib.parse import urlsplit

from app.config import settings
from app.redis_client import redis_client
from app.schemas.event import ThreatEventCreate
from app.schemas.ingest import LogEntry
from app.services.geo_lookup import geo_lookup
from app.websocket_manager import WEBSOCKET_EVENT_CHANNEL


TRAFFIC_INDEX = "map:http:index:v1"
TRAFFIC_DATA = "map:http:data:v1"
TRAFFIC_TTL = 7 * 86400
STORE_AND_PUBLISH = """
local fresh = {}
for i=4,#ARGV,3 do
    if redis.call('HSETNX', KEYS[2], ARGV[i], ARGV[i+2]) == 1 then
        redis.call('ZADD', KEYS[1], ARGV[i+1], ARGV[i])
        table.insert(fresh, ARGV[i+2])
    end
end
local expired = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
local excess = redis.call('ZCARD', KEYS[1]) - tonumber(ARGV[1])
if excess > 0 then
    for _,id in ipairs(redis.call('ZRANGE', KEYS[1], 0, excess - 1)) do
        table.insert(expired, id)
    end
end
for _,id in ipairs(expired) do
    redis.call('ZREM', KEYS[1], id)
    redis.call('HDEL', KEYS[2], id)
end
redis.call('EXPIRE', KEYS[1], ARGV[3])
redis.call('EXPIRE', KEYS[2], ARGV[3])
if #fresh > 0 then
    redis.call('PUBLISH', KEYS[3], '{"type":"HTTP_TRAFFIC","data":[' .. table.concat(fresh, ',') .. ']}')
end
return #fresh
"""


@dataclass(frozen=True)
class HttpObservation:
    log: LogEntry
    detection: ThreatEventCreate | None = None


async def publish_http_requests(observations: list[HttpObservation]) -> int:
    if not observations:
        return 0
    semaphore = asyncio.Semaphore(20)

    async def lookup(ip):
        async with semaphore:
            return await geo_lookup.lookup(ip)

    # One enrichment per distinct source, not per request in a scan burst.
    ips = list(dict.fromkeys(item.log.source_ip for item in observations))
    geographies = dict(zip(ips, await asyncio.gather(*(lookup(ip) for ip in ips))))
    payloads = []
    for item in observations:
        log, finding = item.log, item.detection
        geo = geographies[log.source_ip]
        stamp = datetime.fromisoformat(log.timestamp)
        identity = hashlib.sha256(f"{log.server_id}:{log.event_id}".encode()).hexdigest()[:32]
        payloads.append({
            "id": "http:" + identity, "kind": "http_request", "server_id": log.server_id,
            "source_ip": log.source_ip, "country": geo.get("country") or "Unknown",
            "lat": geo.get("lat"), "lng": geo.get("lon"),
            "dest_lat": settings.TARGET_LATITUDE, "dest_lng": settings.TARGET_LONGITUDE,
            "dest_port": None, "method": log.method,
            # Do not publish credentials, tokens, or personal data from query strings.
            "path": urlsplit(log.path or "/").path, "status_code": log.status_code,
            "host": log.host, "timestamp": stamp.isoformat(), "epoch": stamp.timestamp(),
            "attack_type": finding.attack_type if finding else "http_request",
            "severity": finding.severity if finding else "normal",
        })
    now = datetime.now(timezone.utc).timestamp()
    arguments = [value for event in payloads for value in (event["id"], event["epoch"], json.dumps(event))]
    return int(await redis_client._require_client().eval(
        STORE_AND_PUBLISH, 3, TRAFFIC_INDEX, TRAFFIC_DATA, WEBSOCKET_EVENT_CHANNEL,
        settings.MAP_TRAFFIC_LIMIT, now - TRAFFIC_TTL, TRAFFIC_TTL, *arguments,
    ))


async def recent_http_requests(*, limit: int = 500, hours: int = 24, server_id: str | None = None) -> list[dict]:
    client = redis_client._require_client()
    cutoff = datetime.now(timezone.utc).timestamp() - hours * 3600
    ids = await client.zrevrangebyscore(TRAFFIC_INDEX, "+inf", cutoff, start=0, num=settings.MAP_TRAFFIC_LIMIT)
    if not ids:
        return []
    result = []
    for raw in await client.hmget(TRAFFIC_DATA, ids):
        if raw:
            event = json.loads(raw)
            if not server_id or event["server_id"] == server_id:
                result.append(event)
                if len(result) >= limit:
                    break
    return result
