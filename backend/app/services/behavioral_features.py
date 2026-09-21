"""Atomic, retry-safe event-time aggregation; scoring is scheduled separately."""

from datetime import datetime
import re
import time
from urllib.parse import urlsplit
import uuid

from app.config import settings
from app.redis_client import redis_client
from app.services.ml_features import temporal_features
from app.services.privacy import hash_ip


PENDING_WINDOWS = "ml:pending-windows:v3"
WINDOW_TTL = 8 * 86_400
AUTH_PATH_RE = re.compile(r"/(?:api/)?(?:login|signin|auth|token|session)|/user/login|/account/(?:login|signin)|/wp-login\.php|/admin/login|/panel/login", re.I)

# Atomic updates prevent partial snapshots and duplicate aggregation on retries.
# Track at most 128 paths individually; HLL still counts overall path diversity.
OBSERVE_FIELDS = ("event_id", "now", "due_at", "bytes_sent", "status_family", "request_time",
                  "rule_threat", "auth_failure", "ip_hash", "path_hash", "path", "ua_hash", "seen_key", "second", "next_base", "grace")
METADATA_FIELDS = ("scope", "server_id", "entity_key", "source_ip_hash", "source_ip", "window_start",
                   "window_seconds", "feature_schema", "reputation_score", "reporter_count", "community_reports")
OBSERVE_SCRIPT = "local b, p = KEYS[1], {metadata={}}\n" + "\n".join(
    f"p.{name} = ARGV[{index}]" for index, name in enumerate(
        (*OBSERVE_FIELDS, *(f"metadata.{field}" for field in METADATA_FIELDS)), start=1,
    )
) + """
local ttl = tonumber(ARGV[#ARGV])
if redis.call('SADD', b .. ':events', p.event_id) == 0 then return 0 end
if redis.call('EXISTS', b) == 0 then
    for k,v in pairs(p.metadata) do redis.call('HSET', b, k, v) end
end
redis.call('HINCRBY', b, 'request_count', 1)
redis.call('HINCRBY', b, 'bytes_total', p.bytes_sent)
redis.call('HINCRBY', b, 'status_' .. p.status_family .. 'xx', 1)
if p.request_time ~= '' then
    redis.call('HINCRBYFLOAT', b, 'request_time_total', p.request_time)
    redis.call('HINCRBY', b, 'timed_request_count', 1)
end
if p.rule_threat == '1' then redis.call('HINCRBY', b, 'rule_threat_count', 1) end
if p.auth_failure == '1' then redis.call('HINCRBY', b, 'failed_auth_count', 1) end
if p.metadata.scope == 'server' then
    if redis.call('SET', p.seen_key, '1', 'EX', 2592000, 'NX') then
        redis.call('HINCRBY', b, 'new_ip_count', 1)
    end
end
redis.call('PFADD', b .. ':ips', p.ip_hash)
redis.call('PFADD', b .. ':paths', p.path_hash)
redis.call('PFADD', b .. ':uas', p.ua_hash)
local peak = redis.call('HINCRBY', b .. ':seconds', p.second, 1)
if peak > tonumber(redis.call('HGET', b, 'peak_second_requests') or '0') then
    redis.call('HSET', b, 'peak_second_requests', peak)
end
if redis.call('ZSCORE', b .. ':path_counts', p.path_hash) or
   redis.call('ZCARD', b .. ':path_counts') < 128 then
    redis.call('ZINCRBY', b .. ':path_counts', 1, p.path_hash)
    redis.call('HSET', b .. ':path_names', p.path_hash, p.path)
    if p.metadata.scope == 'server' then
        redis.call('PFADD', b .. ':path_ips:' .. p.path_hash, p.ip_hash)
        redis.call('EXPIRE', b .. ':path_ips:' .. p.path_hash, ttl)
    end
end
redis.call('HSET', b, 'updated_at', p.now)
redis.call('ZADD', KEYS[2], p.due_at, b)
-- Late data also changes the following window's rate-change feature.
if redis.call('EXISTS', p.next_base) == 1 then
    local finish = tonumber(redis.call('HGET', p.next_base, 'window_start')) +
                   tonumber(redis.call('HGET', p.next_base, 'window_seconds'))
    redis.call('ZADD', KEYS[2], math.max(finish, tonumber(p.now)) + tonumber(p.grace), p.next_base)
    redis.call('HSET', p.next_base, 'updated_at', p.now)
end
for _,suffix in ipairs({'', ':events', ':ips', ':paths', ':uas', ':seconds', ':path_counts', ':path_names'}) do
    redis.call('EXPIRE', b .. suffix, ttl)
end
return 1
"""

# The scorer and persistence task consume the same atomic snapshot.
SNAPSHOT_SCRIPT = """
local b = KEYS[1]
if redis.call('EXISTS', b) == 0 then return '' end
local a, data = redis.call('HGETALL', b), {}
for i=1,#a,2 do data[a[i]] = a[i+1] end
local paths = redis.call('ZREVRANGE', b .. ':path_counts', 0, -1, 'WITHSCORES')
local top, max_ips = 0, 0
if #paths > 0 then
    top = tonumber(paths[2])
    data.top_path = redis.call('HGET', b .. ':path_names', paths[1]) or ''
end
if data.scope == 'server' then
    for i=1,#paths,2 do
        max_ips = math.max(max_ips, redis.call('PFCOUNT', b .. ':path_ips:' .. paths[i]))
    end
end
data.max_path_unique_ips = tostring(max_ips)
local previous = redis.call('HGET', KEYS[2], 'request_count')
data.previous_window_present = previous and '1' or '0'
data.previous_request_count = previous or '0'
return {a, {redis.call('PFCOUNT', b .. ':ips'), redis.call('PFCOUNT', b .. ':paths'),
            redis.call('PFCOUNT', b .. ':uas')}, tostring(top), tostring(max_ips),
        previous or '', data.top_path or ''}
"""


def _window_start(timestamp: datetime, seconds: int) -> int:
    epoch = int(timestamp.timestamp())
    return epoch - epoch % seconds


def _base_key(scope: str, server_hash: str, entity_key: str, start: int) -> str:
    return f"ml:window:{scope}:{server_hash}:{entity_key}:{start}"


def previous_key(base: str, seconds: int) -> str:
    prefix, start = base.rsplit(":", 1)
    return f"{prefix}:{int(start) - seconds}"


def decode_snapshot(raw):
    if not raw:
        return None
    fields, counts, top, max_ips, previous, top_path = raw
    data = dict(zip(fields[::2], fields[1::2]))
    data.update(max_path_unique_ips=max_ips, previous_request_count=previous or "0",
                previous_window_present="1" if previous else "0", top_path=top_path)
    return data, dict(zip(("unique_ips", "unique_paths", "unique_user_agents"), counts)), float(top)


def values_from_snapshot(data: dict[str, str], cardinalities: dict[str, int], top: float) -> dict:
    count = max(1, int(data.get("request_count", 0)))
    seconds = max(1, int(data.get("window_seconds", 1)))
    timed = int(data.get("timed_request_count", 0))
    peak = int(data.get("peak_second_requests", 0))
    previous_present = int(data.get("previous_window_present", 0))
    previous_count = int(data.get("previous_request_count", 0))
    values = {
        "request_rate": count / seconds,
        "unique_ips": float(cardinalities.get("unique_ips", 0)),
        "new_ip_ratio": int(data.get("new_ip_count", 0)) / count,
        "unique_paths": float(cardinalities.get("unique_paths", 0)),
        "top_path_share": top / count,
        "status_4xx_ratio": int(data.get("status_4xx", 0)) / count,
        "status_5xx_ratio": int(data.get("status_5xx", 0)) / count,
        "avg_bytes": int(data.get("bytes_total", 0)) / count,
        "avg_request_time": float(data.get("request_time_total", 0)) / timed if timed else None,
        "request_time_coverage": timed / count,
        "peak_second_requests": float(peak),
        "burst_ratio": peak / count,
        "rate_change_ratio": count / max(1, previous_count) if previous_present else 0.0,
        "previous_window_present": float(previous_present),
        "failed_auth_ratio": int(data.get("failed_auth_count", 0)) / count,
        "max_path_unique_ips": float(data.get("max_path_unique_ips", 0)),
        "unique_user_agents": float(cardinalities.get("unique_user_agents", 0)),
        "reputation_score": float(data.get("reputation_score", 0)),
        "reporter_count": float(data.get("reporter_count", 0)),
        "community_reports": float(data.get("community_reports", 0)),
    }
    values.update(temporal_features(int(data.get("window_start", 0))))
    return values


class BehavioralFeatureService:
    ttl_seconds = WINDOW_TTL

    @staticmethod
    async def _snapshot(base: str):
        client = redis_client._require_client()
        seconds = await client.hget(base, "window_seconds")
        if not seconds:
            return None
        return decode_snapshot(await client.eval(
            SNAPSHOT_SCRIPT, 2, base, previous_key(base, int(seconds)),
        ))

    async def observe(self, *, log: object, timestamp: datetime, rule_threat: bool,
                      reputation_score: float, reporter_count: int, community_reports: int) -> None:
        client = redis_client._require_client()
        server_hash = hash_ip(f"v3:server:{log.server_id}")
        ip_hash = hash_ip(log.source_ip)
        path = (urlsplit(log.path or "/").path or "/")[:512]
        now = time.time()
        event_id = log.event_id or uuid.uuid4().hex
        pipe = client.pipeline()
        for scope in ("server", "source"):
            seconds = settings.ML_SERVER_WINDOW_SECONDS if scope == "server" else settings.ML_SOURCE_WINDOW_SECONDS
            start = _window_start(timestamp, seconds)
            # Preserve schema-2 DB rows if an upgrade occurs mid-window.
            entity_key = "v3-server" if scope == "server" else f"v3-{ip_hash}"
            base = _base_key(scope, server_hash, entity_key, start)
            payload = {
                "event_id": event_id, "now": now,
                # Quiet grace also lets delayed/replayed batches finish before scoring.
                "due_at": max(start + seconds, now) + settings.ML_WINDOW_GRACE_SECONDS,
                "metadata": {
                    "scope": scope, "server_id": log.server_id, "entity_key": entity_key,
                    "source_ip_hash": ip_hash if scope == "source" else "",
                    "source_ip": log.source_ip if scope == "source" else "",
                    "window_start": start, "window_seconds": seconds, "feature_schema": 3,
                    "reputation_score": max(0.0, reputation_score),
                    "reporter_count": max(0, reporter_count), "community_reports": max(0, community_reports),
                },
                "bytes_sent": max(0, log.bytes_sent), "status_family": log.status_code // 100,
                "request_time": log.request_time, "rule_threat": rule_threat,
                "auth_failure": bool(AUTH_PATH_RE.search(path)) and log.status_code in (401, 403),
                "ip_hash": ip_hash, "path_hash": hash_ip(f"path:{path}"), "path": path,
                "ua_hash": hash_ip(f"ua:{log.user_agent}"),
                "seen_key": f"ml:seen:{server_hash}:{ip_hash}",
                "second": int(timestamp.timestamp()) - start,
                "next_base": _base_key(scope, server_hash, entity_key, start + seconds),
                "grace": settings.ML_WINDOW_GRACE_SECONDS,
            }
            values = [payload[field] for field in OBSERVE_FIELDS] + [payload["metadata"][field] for field in METADATA_FIELDS]
            arguments = ["" if value is None else int(value) if isinstance(value, bool) else value for value in values]
            pipe.eval(OBSERVE_SCRIPT, 2, base, PENDING_WINDOWS, *arguments, self.ttl_seconds)
        # Fail the batch if aggregation fails; stable IDs make retry safe.
        await pipe.execute()


behavioral_features = BehavioralFeatureService()
