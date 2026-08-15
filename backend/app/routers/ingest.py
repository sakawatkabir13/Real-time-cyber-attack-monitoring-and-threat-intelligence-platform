"""Authenticated, idempotent ingestion for remote log collectors."""

import ipaddress
import json
import logging
import re
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.config import settings
from app.database import AsyncSessionLocal
from app.redis_client import redis_client
from app.security import verify_collector_token
from app.schemas.ingest import LogEntry
from app.services.detection_engine import detection_engine
from app.services.event_pipeline import PendingThreat, persist_threats

logger = logging.getLogger(__name__)
router = APIRouter()

LOG_PATTERN = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+)[^"]*" (\d{3}) (\d+|-)(?:\s+"[^"]*"\s+"([^"]*)")?'
)


class AgentBatch(BaseModel):
    server_id: str = Field(default="unknown-agent", min_length=1, max_length=64)
    events: list[dict[str, Any]] = Field(
        min_length=1, max_length=settings.MAX_INGEST_BATCH_SIZE
    )


def parse_event(event: dict[str, Any], server_id: str) -> LogEntry | None:
    if len(json.dumps(event, default=str)) > 16_384:
        return None

    raw = event.get("raw_log")
    if isinstance(raw, str):
        match = LOG_PATTERN.match(raw)
        if not match:
            return None
        ip, timestamp, method, path, status_code, bytes_sent, user_agent = match.groups()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        return LogEntry(
            server_id=server_id,
            timestamp=timestamp,
            source_ip=ip,
            method=method,
            path=path[:8192],
            status_code=int(status_code),
            bytes_sent=0 if bytes_sent == "-" else int(bytes_sent),
            request_time=0.0,
            user_agent=(user_agent or "Unknown")[:2048],
            host="unknown",
        )

    ip = event.get("source_ip") or event.get("ip")
    if not isinstance(ip, str):
        return None
    try:
        ipaddress.ip_address(ip)
        return LogEntry(
            server_id=server_id,
            timestamp=str(event.get("timestamp") or ""),
            source_ip=ip,
            method=str(event.get("method") or "GET")[:10],
            path=str(event.get("path") or "/")[:8192],
            status_code=int(event.get("status_code", 200)),
            bytes_sent=int(event.get("bytes_sent") or 0),
            request_time=float(event.get("request_time") or 0.0),
            user_agent=str(event.get("user_agent") or "Unknown")[:2048],
            host=str(event.get("host") or "unknown")[:255],
        )
    except (TypeError, ValueError):
        return None


@router.post("/ingest/batch", status_code=status.HTTP_202_ACCEPTED, tags=["Ingestion"])
async def ingest_batch(batch: AgentBatch, authorization: str | None = Header(None)):
    verify_collector_token(authorization)

    accepted = 0
    rejected = 0
    duplicates = 0
    claimed: list[str] = []
    completed: list[str] = []
    threats: list[PendingThreat] = []
    seen_event_ids: set[str] = set()

    try:
        for raw_event in batch.events:
            event_id_value = raw_event.get("event_id")
            event_id = None
            if event_id_value is not None:
                if not isinstance(event_id_value, str) or not re.fullmatch(
                    r"[A-Za-z0-9._:-]{1,64}", event_id_value
                ):
                    rejected += 1
                    continue
                event_id = event_id_value
            if event_id:
                if event_id in seen_event_ids:
                    accepted += 1
                    duplicates += 1
                    continue
                seen_event_ids.add(event_id)
                claim = await redis_client.claim_ingest_event(batch.server_id, event_id)
                if claim == "done":
                    accepted += 1
                    duplicates += 1
                    continue
                if claim != "claimed":
                    raise HTTPException(503, "A duplicate batch is still being processed")
                claimed.append(event_id)

            log_entry = parse_event(raw_event, batch.server_id)
            if log_entry is None:
                rejected += 1
                if event_id:
                    completed.append(event_id)
                continue

            detected = await detection_engine.process_log(log_entry)
            if detected is not None:
                threats.append(PendingThreat(detected, event_id))
            accepted += 1
            if event_id:
                completed.append(event_id)

        async with AsyncSessionLocal() as db:
            await persist_threats(db, threats)

        for event_id in completed:
            await redis_client.complete_ingest_event(batch.server_id, event_id)

    except HTTPException:
        for event_id in claimed:
            await redis_client.release_ingest_event(batch.server_id, event_id)
        raise
    except Exception as exc:
        logger.exception("Ingest batch failed")
        for event_id in claimed:
            await redis_client.release_ingest_event(batch.server_id, event_id)
        raise HTTPException(503, "Batch processing failed; retry the same event IDs") from exc

    return {
        "accepted": accepted,
        "rejected": rejected,
        "duplicates": duplicates,
        "status": "processed",
    }
