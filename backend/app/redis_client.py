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
