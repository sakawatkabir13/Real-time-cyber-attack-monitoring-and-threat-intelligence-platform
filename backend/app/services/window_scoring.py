"""Durable scheduled scoring, independent of further traffic from a source."""

import asyncio
from datetime import datetime, timezone
import hashlib
import logging
import time
import uuid

from sqlalchemy import select

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.threat_event import ThreatEvent
from app.redis_client import redis_client
from app.schemas.event import ThreatEventCreate
from app.services.behavioral_features import PENDING_WINDOWS, behavioral_features, values_from_snapshot
from app.services.event_pipeline import PendingThreat, persist_threats
from app.services.ml_engine import ml_engine

logger = logging.getLogger(__name__)

RELEASE_LOCK = """
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end
return 0
"""

FINISH_WINDOW = """
if redis.call('HGET', KEYS[1], 'request_count') ~= ARGV[1] then return 0 end
if redis.call('HGET', KEYS[1], 'updated_at') ~= ARGV[7] then return 0 end
if redis.call('GET', KEYS[3]) ~= ARGV[2] then return 0 end
redis.call('HSET', KEYS[1], 'scored_revision', ARGV[1], 'updated_at', ARGV[3])
if ARGV[4] ~= '' then
    redis.call('HSET', KEYS[1], 'anomaly_score', ARGV[4],
               'model_version', ARGV[5], 'anomaly_explanation', ARGV[6])
end
redis.call('ZREM', KEYS[2], KEYS[1])
return 1
"""


def window_event_id(base: str) -> str:
    return "ml:" + hashlib.sha256(base.encode()).hexdigest()[:60]


async def score_window(base: str) -> bool:
    client = redis_client._require_client()
    lock = f"ml:scoring-lock:{base}"
    token = uuid.uuid4().hex
    if not await client.set(lock, token, ex=120, nx=True):
        return False
    try:
        due = await client.zscore(PENDING_WINDOWS, base)
        if due is None or due > time.time():
            return False
        snapshot = await behavioral_features._snapshot(base)
        if snapshot is None:
            await client.zrem(PENDING_WINDOWS, base)
            return False
        data, cardinalities, top = snapshot
        revision = int(data["request_count"])
        minimum = settings.ML_MIN_SERVER_REQUESTS if data["scope"] == "server" else settings.ML_MIN_SOURCE_REQUESTS
        prediction = None
        if revision >= minimum:
            prediction = await asyncio.to_thread(
                ml_engine.score, data["scope"], data["server_id"],
                values_from_snapshot(data, cardinalities, top),
            )
            if prediction is None:
                # Retain pending work through model warm-up/restart. Expired
                # Redis windows are removed on the next pass, not retried forever.
                await client.zadd(PENDING_WINDOWS, {base: time.time() + 60}, gt=True)
                return False

        # A log arrived while the model was running: leave the newer window queued.
        if await client.hget(base, "request_count") != str(revision):
            return False
        if await client.hget(base, "updated_at") != data["updated_at"]:
            return False
        if await client.get(lock) != token:
            return False
        if prediction is not None:
            actionable = (int(data.get("rule_threat_count", 0)) == 0
                          and prediction.score >= settings.ML_ALERT_SCORE)
            identity = window_event_id(base)
            async with AsyncSessionLocal() as db:
                prior = await db.scalar(select(ThreatEvent.id).where(
                    ThreatEvent.server_id == data["server_id"],
                    ThreatEvent.ingest_event_id == identity,
                ))
                # Keep earlier findings as reviewable history if late data changes
                # the assessment; do not silently delete alerts or human verdicts.
                if actionable or prior is not None:
                    start = int(data["window_start"])
                    end = start + int(data["window_seconds"])
                    period = (f"Window {datetime.fromtimestamp(start, timezone.utc).isoformat()} "
                              f"to {datetime.fromtimestamp(end, timezone.utc).isoformat()}; "
                              f"{revision} requests. ")
                    explanation = period + prediction.explanation
                    if not actionable:
                        explanation += " Revised after late data: no longer an independent ML alert; prior finding retained for review."
                    event = ThreatEventCreate(
                        server_id=data["server_id"],
                        timestamp=datetime.fromtimestamp(start, timezone.utc),
                        source_ip=data.get("source_ip") or None,
                        path=data.get("top_path") or None,
                        attack_type="server_traffic_anomaly" if data["scope"] == "server" else "source_behavior_anomaly",
                        severity=("high" if prediction.score >= 95 else "medium") if actionable else "low",
                        anomaly_score=prediction.score, explanation=explanation,
                    )
                    await persist_threats(db, [PendingThreat(event, identity, replace_existing=True)])

        return bool(await client.eval(
            FINISH_WINDOW, 3, base, PENDING_WINDOWS, lock, revision, token, time.time(),
            prediction.score if prediction else "", prediction.model_version if prediction else "",
            prediction.explanation if prediction else "",
            data["updated_at"],
        ))
    finally:
        await client.eval(RELEASE_LOCK, 1, lock, token)


async def score_due_windows() -> int:
    client = redis_client._require_client()
    bases = await client.zrangebyscore(
        PENDING_WINDOWS, "-inf", time.time(), start=0, num=settings.ML_SCORING_BATCH_SIZE,
    )
    completed = 0
    for base in bases:
        try:
            completed += int(await score_window(base))
        except Exception:
            logger.exception("Completed-window scoring failed for %s", base)
            # A bad item cannot permanently starve the bounded work queue.
            await client.zadd(PENDING_WINDOWS, {base: time.time() + 60}, gt=True)
    await client.set("ml:scorer:heartbeat", str(time.time()), ex=120)
    return completed


async def scoring_loop() -> None:
    while True:
        try:
            await score_due_windows()
        except Exception:
            logger.exception("Window scoring worker failed; retrying")
        await asyncio.sleep(settings.ML_SCORING_INTERVAL_SECONDS)
