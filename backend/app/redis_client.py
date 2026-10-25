"""
Redis client — async connection wrapper with a true sliding-window counter.

The sliding window uses a Redis sorted set (ZSET):
  - Each request is stored as a member with the current timestamp as its score
  - Old entries (outside the window) are removed before counting
  - This gives an accurate count of requests in the last N seconds

The previous implementation used INCR + EXPIRE which was NOT a true sliding
window — it reset the TTL on every request, so a continuously active IP
would never expire its counter. This implementation is correct.
"""

import hashlib
import time
import uuid
import redis.asyncio as redis
from app.config import settings


# Adjacent event-time buckets cover (timestamp - window, timestamp]. Expiry
# uses receipt time so historical batches never mix with present-day traffic.
EVENT_COUNT_SCRIPT = """
if ARGV[5] == '1' then
    redis.call('ZADD', KEYS[1], 'NX', ARGV[1], ARGV[4])
    redis.call('EXPIRE', KEYS[1], ARGV[3])
end
return redis.call('ZCOUNT', KEYS[1], '(' .. ARGV[2], ARGV[1]) +
       redis.call('ZCOUNT', KEYS[2], '(' .. ARGV[2], ARGV[1])
"""


# Register all contextual counters atomically, then revisit the latest observed
# five-minute context affected by this request. Unlike a global high-water mark,
# the endpoint is strictly less than event_time + window: unrelated later traffic
# cannot absorb historical batches. Three adjacent buckets bound the lookup.
# This deliberately revisits one latest affected context, not every historical
# endpoint. Cross-batch late delivery is supported while these receipt-TTL keys
# remain available. Stable IDs make registration retry-safe.
CONTEXT_COUNT_SCRIPT = """
local stamp, window, ttl = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local fresh = redis.call('ZADD', KEYS[2], 'NX', ARGV[1], ARGV[4])
for i=1,#KEYS/3 do
    local current = KEYS[(i-1)*3+2]
    if ARGV[4+i] == '1' then
        if fresh == 1 then redis.call('ZADD', current, 'NX', ARGV[1], ARGV[4]) end
        redis.call('EXPIRE', current, ttl)
    end
end
local finish = stamp
local upper = '(' .. string.format('%.17g', stamp + window)
for _,key in ipairs({KEYS[2], KEYS[3]}) do
    local latest = redis.call('ZREVRANGEBYSCORE', key, upper, ARGV[1], 'WITHSCORES', 'LIMIT', 0, 1)
    if #latest > 0 then finish = math.max(finish, tonumber(latest[2])) end
end
local lower = '(' .. string.format('%.17g', finish - window)
local result = {string.format('%.17g', finish)}
for i=1,#KEYS/3 do
    local total = 0
    for offset=1,3 do
        total = total + redis.call('ZCOUNT', KEYS[(i-1)*3+offset], lower, string.format('%.17g', finish))
    end
    table.insert(result, total)
end
return result
"""


class RedisClient:
    def __init__(self):
        self.redis = None

    async def connect(self):
        self.redis = redis.from_url(settings.REDIS_URL, decode_responses=True)
        await self.redis.ping()

    async def close(self):
        if self.redis:
            await self.redis.aclose()
            self.redis = None

    def _require_client(self):
        if self.redis is None:
            raise RuntimeError("Redis client is not connected")
        return self.redis

    @staticmethod
    def _key_part(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]

    async def increment_window(
        self,
        ip: str,
        window_size: int = 60,
        *,
        server_id: str = "global",
        scope: str = "requests",
    ) -> int:
        """
        True sliding window counter.

        Returns the number of requests from `ip` in the last `window_size` seconds.
        Uses a Redis sorted set keyed by rate:{ip}:
          score  = Unix timestamp of the request
          member = unique ID per request (prevents overwrites on same timestamp)
        """
        client = self._require_client()
        key = (
            f"rate:{self._key_part(server_id)}:{self._key_part(scope)}:"
            f"{self._key_part(ip)}"
        )
        now = time.time()
        window_start = now - window_size

        pipe = client.pipeline()

        # 1. Remove entries older than the window start
        pipe.zremrangebyscore(key, "-inf", window_start)

        # 2. Add this request (unique member so concurrent requests don't collide)
        pipe.zadd(key, {f"{now}:{uuid.uuid4().hex[:8]}": now})

        # 3. Count requests remaining in the window
        pipe.zcard(key)

        # 4. Set key expiry slightly longer than the window for automatic cleanup
        pipe.expire(key, window_size + 10)

        results = await pipe.execute()

        # results[2] is the zcard (count after add)
        return int(results[2])

    async def event_counts(
        self, ip: str, *, server_id: str, timestamp: float,
        event_id: str, counters: dict[str, bool], window_size: int = 300,
    ) -> dict[str, int]:
        """Detection counts; API security limits intentionally use wall time."""
        bucket = int(timestamp // window_size)
        prefix = f"event-rate:{self._key_part(server_id)}:{self._key_part(ip)}"
        pipe = self._require_client().pipeline()
        for scope, add in counters.items():
            key = f"{prefix}:{self._key_part(scope)}"
            pipe.eval(
                EVENT_COUNT_SCRIPT, 2, f"{key}:{bucket}", f"{key}:{bucket - 1}",
                timestamp, timestamp - window_size,
                max(settings.EVENT_COUNTER_TTL_SECONDS, window_size * 2),
                event_id, "1" if add else "0",
            )
        return dict(zip(counters, map(int, await pipe.execute())))

    async def allow_request(
        self, scope: str, identity: str, *, limit: int, window_size: int
    ) -> bool:
        count = await self.increment_window(
            identity,
            window_size,
            server_id="api",
            scope=f"limit:{scope}",
        )
        return count <= limit

    async def contextual_event_counts(
        self, ip: str, *, server_id: str, timestamp: float,
        event_id: str, counters: dict[str, bool], window_size: int = 300,
    ) -> tuple[dict[str, int], float]:
        """Count the latest affected event-time context, including bounded late data.

        A late request may use already observed later requests, but never an
        endpoint >= timestamp + window_size, which would exclude that request.
        Historical intervals separated by five minutes are not combined.
        """
        if not counters.get("requests"):
            raise ValueError("Contextual counting requires the requests counter")
        scopes = ["requests", *(scope for scope in counters if scope != "requests")]
        bucket = int(timestamp // window_size)
        prefix = f"event-rate:{self._key_part(server_id)}:{self._key_part(ip)}"
        keys = [
            f"{prefix}:{self._key_part(scope)}:{period}"
            for scope in scopes for period in (bucket - 1, bucket, bucket + 1)
        ]
        result = await self._require_client().eval(
            CONTEXT_COUNT_SCRIPT, len(keys), *keys,
            timestamp, window_size,
            max(settings.EVENT_COUNTER_TTL_SECONDS, window_size * 2), event_id,
            *("1" if counters[scope] else "0" for scope in scopes),
        )
        return dict(zip(scopes, map(int, result[1:]))), float(result[0])

    async def claim_ingest_event(self, server_id: str, event_id: str) -> str:
        client = self._require_client()
        key = f"ingest:event:{self._key_part(server_id)}:{self._key_part(event_id)}"
        claimed = await client.set(key, "processing", ex=600, nx=True)
        if claimed:
            return "claimed"
        return await client.get(key) or "processing"

    async def complete_ingest_event(self, server_id: str, event_id: str) -> None:
        client = self._require_client()
        key = f"ingest:event:{self._key_part(server_id)}:{self._key_part(event_id)}"
        await client.set(key, "done", ex=604_800)

    async def release_ingest_event(self, server_id: str, event_id: str) -> None:
        client = self._require_client()
        key = f"ingest:event:{self._key_part(server_id)}:{self._key_part(event_id)}"
        if await client.get(key) == "processing":
            await client.delete(key)

    async def ping(self) -> bool:
        client = self._require_client()
        return bool(await client.ping())


redis_client = RedisClient()
