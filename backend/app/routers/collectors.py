from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Path
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.collector_agent import CollectorAgent
from app.redis_client import redis_client
from app.security import require_dashboard_auth, verify_collector_token

router = APIRouter(tags=["Collectors"])


class CollectorHeartbeat(BaseModel):
    server_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    reported_state: Literal["running", "paused"]
    spool_depth: int = Field(ge=0, le=10_000_000)
    agent_version: str = Field(default="unknown", max_length=32)
    last_error: str | None = Field(default=None, max_length=2000)


class CollectorCommand(BaseModel):
    desired_state: Literal["running", "paused"]


def serialize_collector(agent: CollectorAgent) -> dict:
    last_seen = agent.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    offline = last_seen < datetime.now(timezone.utc) - timedelta(
        seconds=settings.COLLECTOR_OFFLINE_SECONDS
    )
    return {
        "serverId": agent.server_id,
        "desiredState": agent.desired_state,
        "reportedState": "offline" if offline else agent.reported_state,
        "commandVersion": agent.command_version,
        "spoolDepth": agent.spool_depth,
        "agentVersion": agent.agent_version,
        "lastError": agent.last_error,
        "lastSeen": last_seen.isoformat(),
    }


@router.post("/collector/heartbeat")
async def collector_heartbeat(
    heartbeat: CollectorHeartbeat,
    authorization: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
):
    verify_collector_token(authorization)
    if not await redis_client.allow_request(
        "collector_heartbeat", heartbeat.server_id, limit=30, window_size=60
    ):
        raise HTTPException(429, "Collector heartbeat rate limit exceeded")
    now = datetime.now(timezone.utc)
    statement = insert(CollectorAgent).values(
        server_id=heartbeat.server_id,
        desired_state="running",
        reported_state=heartbeat.reported_state,
        spool_depth=heartbeat.spool_depth,
        agent_version=heartbeat.agent_version,
        last_error=heartbeat.last_error,
        last_seen=now,
        command_version=0,
    )
    statement = statement.on_conflict_do_update(
        index_elements=[CollectorAgent.server_id],
        set_={
            "reported_state": statement.excluded.reported_state,
            "spool_depth": statement.excluded.spool_depth,
            "agent_version": statement.excluded.agent_version,
            "last_error": statement.excluded.last_error,
            "last_seen": now,
            "updated_at": now,
        },
    ).returning(CollectorAgent)
    agent = (await db.execute(statement)).scalar_one()
    await db.commit()
    return {
        "desiredState": agent.desired_state,
        "commandVersion": agent.command_version,
    }


@router.get("/collectors", dependencies=[Depends(require_dashboard_auth)])
async def list_collectors(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(CollectorAgent).order_by(desc(CollectorAgent.last_seen)).limit(200)
    )
    return [serialize_collector(agent) for agent in result.scalars()]


@router.post(
    "/collectors/{server_id}/command",
    dependencies=[Depends(require_dashboard_auth)],
)
async def command_collector(
    server_id: Annotated[
        str, Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    ],
    command: CollectorCommand,
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    statement = insert(CollectorAgent).values(
        server_id=server_id,
        desired_state=command.desired_state,
        reported_state="paused",
        spool_depth=0,
        last_seen=now - timedelta(days=365),
        command_version=1,
    )
    statement = statement.on_conflict_do_update(
        index_elements=[CollectorAgent.server_id],
        set_={
            "desired_state": command.desired_state,
            "command_version": CollectorAgent.command_version + 1,
            "updated_at": now,
        },
    ).returning(CollectorAgent)
    agent = (await db.execute(statement)).scalar_one()
    await db.commit()
    return serialize_collector(agent)
