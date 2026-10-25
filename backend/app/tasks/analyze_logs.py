"""Durable Celery-backed processing for manually uploaded access logs."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
import time

import httpx
from redis import exceptions as redis_errors
from sqlalchemy import exc as database_errors

from app.config import settings
from app.database import AsyncSessionLocal, engine
from app.redis_client import redis_client
from app.services.detection_engine import detection_engine
from app.services.event_pipeline import PendingThreat, persist_threats
from app.services.geo_lookup import geo_lookup
from app.services.log_parser import parse_event
from app.services.http_traffic import HttpObservation, publish_http_requests
from app.tasks.celery_app import celery_app


logger = logging.getLogger(__name__)
ACTIVE_ANALYSIS_KEY = "analysis:active"
LATEST_ANALYSIS_KEY = "analysis:latest"
ANALYSIS_STATUS_TTL = 7 * 86_400
ANALYSIS_UPLOAD_RETENTION_SECONDS = 2 * 86_400
ANALYSIS_MAX_RETRIES = 5
ANALYSIS_RETRY_DELAY_SECONDS = 30


class AnalysisInputError(ValueError):
    """A missing, expired, or invalid upload cannot recover through retry."""


def _retryable_failure(exc: Exception) -> bool:
    return isinstance(exc, (
        redis_errors.ConnectionError, redis_errors.TimeoutError,
        database_errors.OperationalError, database_errors.InterfaceError,
        database_errors.TimeoutError, database_errors.DisconnectionError,
        httpx.TransportError, ConnectionError, TimeoutError,
    )) or isinstance(exc, database_errors.DBAPIError) and exc.connection_invalidated


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
    processed = 0
    rejected = 0
    detections = 0
    try:
        await redis_client.connect()
        await save_analysis_status(
            job_id,
            state="running",
            processed=0,
            total=total,
            rejected=0,
            detections=0,
            error=None,
            retryDelaySeconds=None,
        )
        pending: list[PendingThreat] = []
        traffic: list[HttpObservation] = []
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
                    traffic.append(HttpObservation(log_entry, detected))
                    if detected:
                        pending.append(PendingThreat(detected, event_id))
                        detections += 1
                processed += 1
                if len(pending) >= 100 or processed % 100 == 0:
                    async with AsyncSessionLocal() as db:
                        await persist_threats(db, pending)
                    await publish_http_requests(traffic)
                    traffic.clear()
                    pending.clear()
                    await save_analysis_status(
                        job_id,
                        state="running",
                        processed=processed,
                        total=total,
                        rejected=rejected,
                        detections=detections,
                    )
            if pending or traffic:
                async with AsyncSessionLocal() as db:
                    await persist_threats(db, pending)
                await publish_http_requests(traffic)
        result = await save_analysis_status(
            job_id,
            state="complete",
            processed=processed,
            total=total,
            rejected=rejected,
            detections=detections,
            error=None,
        )
        await release_active_analysis(job_id)
        return result
    finally:
        # A retry/redelivery must still have its original input. The task
        # removes the private upload only after success or terminal failure.
        for close in (geo_lookup.close, redis_client.close, engine.dispose):
            try:
                await close()
            except Exception:
                logger.warning("Could not close log-analysis resource", exc_info=True)


async def _record_failure(job_id: str, total: int, *, retrying: bool,
                          retries: int, delay: int) -> None:
    try:
        await redis_client.connect()
        # Keep the last durable checkpoint; a stable-ID replay starts at line
        # one and fills any missing detection/telemetry writes safely.
        await save_analysis_status(
            job_id, state="retrying" if retrying else "error", total=total,
            retries=retries, retryDelaySeconds=delay if retrying else None,
            error=("A temporary dependency failure interrupted processing. Retrying automatically."
                   if retrying else
                   "Log analysis could not complete. Check server logs and upload the file again."),
        )
        if retrying:
            client = redis_client._require_client()
            if await client.get(ACTIVE_ANALYSIS_KEY) == job_id:
                await client.expire(ACTIVE_ANALYSIS_KEY, 86_400)
        else:
            await release_active_analysis(job_id)
    except Exception:
        # Redis itself may be the failed dependency. A status-write failure
        # must not suppress the Celery retry or expose raw exception details.
        logger.warning("Could not record analysis recovery state for %s", job_id,
                       exc_info=True)
    finally:
        try:
            await redis_client.close()
        except Exception:
            logger.warning("Could not close analysis status connection", exc_info=True)


def _remove_upload(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        # Daily orphan cleanup enforces the same two-day retention bound.
        logger.warning("Could not remove terminal log upload", exc_info=True)


async def _completed_analysis(job_id: str) -> dict[str, object] | None:
    """A worker can finish/unlink and die before its late acknowledgement."""
    try:
        await redis_client.connect()
        raw = await redis_client._require_client().get(analysis_status_key(job_id))
        try:
            status = json.loads(raw) if raw else None
        except (ValueError, TypeError):
            return None
        if isinstance(status, dict) and status.get("state") == "complete":
            await release_active_analysis(job_id)
            return status
        return None
    finally:
        try:
            await redis_client.close()
        except Exception:
            logger.warning("Could not close analysis completion connection", exc_info=True)


@celery_app.task(
    name="analyze_log_file_task",
    bind=True,
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=ANALYSIS_MAX_RETRIES,
)
def analyze_log_file_task(self, job_id: str, path: str, total: int) -> dict[str, object]:
    upload_root = Path(path).resolve().parent
    configured_root = Path(settings.ANALYSIS_UPLOAD_DIR).resolve()
    if upload_root != configured_root:
        raise ValueError("Analysis path is outside the configured upload directory")
    try:
        completed = asyncio.run(_completed_analysis(job_id))
        if completed is not None:
            _remove_upload(path)
            return completed
        upload = Path(path)
        if time.time() - upload.stat().st_mtime >= ANALYSIS_UPLOAD_RETENTION_SECONDS:
            raise AnalysisInputError("Analysis upload has expired")
        upload.chmod(0o600)
        result = asyncio.run(_process_file(job_id, path, total))
    except Exception as exc:
        retries = self.request.retries
        retrying = _retryable_failure(exc) and retries < self.max_retries
        delay = min(ANALYSIS_RETRY_DELAY_SECONDS * 2**retries, 300)
        logger.exception("Uploaded log analysis attempt failed for job %s", job_id)
        asyncio.run(_record_failure(job_id, total, retrying=retrying,
                                    retries=retries + int(retrying), delay=delay))
        if retrying:
            # Keep provider/database exception text out of the task's public
            # result as well as the dashboard status document.
            raise self.retry(exc=RuntimeError("Temporary log-analysis dependency failure"),
                             countdown=delay)
        _remove_upload(path)
        raise RuntimeError("Log analysis failed; see the private server logs") from None
    _remove_upload(path)
    return result
