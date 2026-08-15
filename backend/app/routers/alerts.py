from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.ddos_alert import DdosAlert
from app.security import require_dashboard_auth
from app.services.alert_service import serialize_alert
from app.websocket_manager import manager

router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"],
    dependencies=[Depends(require_dashboard_auth)],
)


@router.get("")
async def list_alerts(
    limit: int = Query(default=200, ge=1, le=500),
    status: str | None = Query(default=None, pattern="^(new|acknowledged|resolved)$"),
    db: AsyncSession = Depends(get_db),
):
    query = select(DdosAlert)
    if status:
        query = query.where(DdosAlert.status == status)
    result = await db.execute(query.order_by(desc(DdosAlert.last_seen)).limit(limit))
    return [serialize_alert(alert) for alert in result.scalars()]


@router.patch("/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: UUID, db: AsyncSession = Depends(get_db)):
    alert = await db.get(DdosAlert, alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    if alert.status != "acknowledged":
        alert.status = "acknowledged"
        alert.acknowledged_at = datetime.now(timezone.utc)
        await db.commit()
    payload = serialize_alert(alert)
    await manager.broadcast_json({"type": "ALERT_UPDATED", "data": payload})
    return payload
