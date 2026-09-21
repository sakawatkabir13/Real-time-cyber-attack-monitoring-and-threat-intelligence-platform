"""Authenticated, idempotent ingestion for remote log collectors."""

import logging
import re
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.config import settings
from app.database import AsyncSessionLocal
from app.redis_client import redis_client
from app.security import verify_collector_token
from app.services.log_parser import parse_event
from app.services.detection_engine import detection_engine
from app.services.event_pipeline import PendingThreat, persist_threats

logger = logging.getLogger(__name__)
router = APIRouter()

class AgentBatch(BaseModel):
    server_id: str = Field(default="unknown-agent", min_length=1, max_length=64)
    events: list[dict[str, Any]] = Field(
        min_length=1, max_length=settings.MAX_INGEST_BATCH_SIZE
    )


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
