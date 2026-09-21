"""Durable Celery-backed processing for manually uploaded access logs."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

from app.config import settings
from app.database import AsyncSessionLocal, engine
from app.redis_client import redis_client
from app.services.detection_engine import detection_engine
from app.services.event_pipeline import PendingThreat, persist_threats
from app.services.geo_lookup import geo_lookup
from app.services.log_parser import parse_event
from app.tasks.celery_app import celery_app


logger = logging.getLogger(__name__)
ACTIVE_ANALYSIS_KEY = "analysis:active"
LATEST_ANALYSIS_KEY = "analysis:latest"
ANALYSIS_STATUS_TTL = 7 * 86_400


def analysis_status_key(job_id: str) -> str:
    return f"analysis:job:{job_id}"


async def save_analysis_status(job_id: str, **values: object) -> dict[str, object]:
    client = redis_client._require_client()
    current_raw = await client.get(analysis_status_key(job_id))
    current: dict[str, object] = json.loads(current_raw) if current_raw else {"jobId": job_id}
    current.update(values)
    encoded = json.dumps(current)
    await client.setex(analysis_status_key(job_id), ANALYSIS_STATUS_TTL, encoded)
    await client.setex(LATEST_ANALYSIS_KEY, ANALYSIS_STATUS_TTL, encoded)
    return current


async def release_active_analysis(job_id: str) -> None:
    client = redis_client._require_client()
    if await client.get(ACTIVE_ANALYSIS_KEY) == job_id:
        await client.delete(ACTIVE_ANALYSIS_KEY)


async def _process_file(job_id: str, path: str, total: int) -> dict[str, object]:
    await redis_client.connect()
    processed = 0
    rejected = 0
    try:
        await save_analysis_status(
            job_id,
            state="running",
            processed=0,
            total=total,
            rejected=0,
            error=None,
        )
        pending: list[PendingThreat] = []
        with open(path, "r", encoding="utf-8", errors="ignore") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                event_id = f"upload-{job_id[:24]}-{line_number}"
                log_entry = parse_event(
                    {"raw_log": line.rstrip("\n"), "event_id": event_id},
                    "manual-upload",
                )
                if log_entry is None:
                    rejected += 1
                else:
                    detected = await detection_engine.process_log(log_entry)
                    if detected:
                        pending.append(PendingThreat(detected, event_id))
                processed += 1
                if len(pending) >= 100 or processed % 100 == 0:
                    async with AsyncSessionLocal() as db:
                        await persist_threats(db, pending)
                    pending.clear()
                    await save_analysis_status(
                        job_id,
                        state="running",
                        processed=processed,
                        total=total,
                        rejected=rejected,
                    )
            if pending:
                async with AsyncSessionLocal() as db:
                    await persist_threats(db, pending)
        return await save_analysis_status(
            job_id,
            state="complete",
            processed=processed,
            total=total,
            rejected=rejected,
            error=None,
        )
    except Exception as exc:
        logger.exception("Uploaded log analysis failed for job %s", job_id)
        await save_analysis_status(
            job_id,
            state="error",
            processed=processed,
            total=total,
            rejected=rejected,
            error=str(exc)[:2000],
        )
        raise
    finally:
        await release_active_analysis(job_id)
        await geo_lookup.close()
        await redis_client.close()
        await engine.dispose()
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


@celery_app.task(
    name="analyze_log_file_task",
    acks_late=True,
    reject_on_worker_lost=True,
)
def analyze_log_file_task(job_id: str, path: str, total: int) -> dict[str, object]:
    upload_root = Path(path).resolve().parent
    configured_root = Path(settings.ANALYSIS_UPLOAD_DIR).resolve()
    if upload_root != configured_root:
        raise ValueError("Analysis path is outside the configured upload directory")
    return asyncio.run(_process_file(job_id, path, total))
