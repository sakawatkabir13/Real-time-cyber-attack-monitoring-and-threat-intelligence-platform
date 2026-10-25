from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.ddos_alert import DdosAlert
from app.models.incident_group import IncidentGroup
from app.security import require_dashboard_auth
from app.services.incident_grouping import serialize_group

router = APIRouter(prefix="/incidents", tags=["Related incidents"], dependencies=[Depends(require_dashboard_auth)])


@router.get("")
async def list_incidents(
    limit: int = Query(default=50, ge=1, le=100),
    server_id: str | None = None,
    attack_type: str | None = None,
    minimum_severity: Literal["low", "medium", "high", "critical"] = "low",
    verdict: Literal["unreviewed", "confirmed_malicious", "legitimate", "misconfiguration", "uncertain"] | None = None,
    since: datetime | None = None,
    search: str = Query(default="", max_length=256),
    db: AsyncSession = Depends(get_db),
):
    # Match the same member alert across every filter. Separate EXISTS clauses
    # could incorrectly combine one member's severity with another's verdict.
    member = select(DdosAlert.id).where(DdosAlert.incident_group_id == IncidentGroup.id)
    if isinstance(server_id, str) and server_id:
        member = member.where(DdosAlert.server_id == server_id)
    if isinstance(attack_type, str) and attack_type:
        member = member.where(DdosAlert.attack_type == attack_type)
    ranks = ["low", "medium", "high", "critical"]
    member = member.where(DdosAlert.severity.in_(ranks[ranks.index(minimum_severity):]))
    if isinstance(verdict, str) and verdict:
        member = member.where(DdosAlert.verdict == verdict)
    if isinstance(since, datetime):
        if since.tzinfo is None:
            raise HTTPException(422, "since must include a timezone")
        member = member.where(DdosAlert.last_seen >= since.astimezone(timezone.utc))
    if isinstance(search, str) and search:
        escaped = search.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        evidence = (func.coalesce(DdosAlert.source_ip, "Multiple sources") + " "
                    + DdosAlert.server_id + " " + DdosAlert.attack_type + " "
                    + func.coalesce(DdosAlert.trigger_reason, ""))
        member = member.where(func.lower(evidence).like(f"%{escaped}%", escape="\\"))
    groups = await db.scalars(select(IncidentGroup).where(exists(member))
                             .order_by(desc(IncidentGroup.last_seen)).limit(limit))
    return [serialize_group(group) for group in groups]
