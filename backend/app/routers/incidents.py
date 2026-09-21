from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.ddos_alert import DdosAlert
from app.models.incident_group import IncidentGroup
from app.security import require_dashboard_auth
from app.services.incident_grouping import serialize_group

router = APIRouter(prefix="/incidents", tags=["Related incidents"], dependencies=[Depends(require_dashboard_auth)])


@router.get("")
async def list_incidents(limit: int = Query(default=50, ge=1, le=100), db: AsyncSession = Depends(get_db)):
    groups = await db.scalars(select(IncidentGroup).where(exists().where(
        DdosAlert.incident_group_id == IncidentGroup.id,
    )).order_by(desc(IncidentGroup.last_seen)).limit(limit))
    return [serialize_group(group) for group in groups]
