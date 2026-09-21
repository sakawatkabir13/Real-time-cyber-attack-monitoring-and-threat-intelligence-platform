from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.ddos_alert import DdosAlert
from app.models.alert_review import AlertReview
from app.schemas.alert import AlertReviewRequest
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
    await manager.publish_json({"type": "ALERT_UPDATED", "data": payload})
    return payload


@router.patch("/{alert_id}/resolve")
async def resolve_alert(alert_id: UUID, db: AsyncSession = Depends(get_db)):
    alert = await db.get(DdosAlert, alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    if alert.status != "resolved":
        now = datetime.now(timezone.utc)
        alert.status = "resolved"
        alert.end_time = now
        if alert.acknowledged_at is None:
            alert.acknowledged_at = now
        await db.commit()
    payload = serialize_alert(alert)
    await manager.publish_json({"type": "ALERT_UPDATED", "data": payload})
    return payload


@router.patch("/{alert_id}/review")
async def review_alert(alert_id: UUID, review: AlertReviewRequest, db: AsyncSession = Depends(get_db)):
    alert = await db.scalar(select(DdosAlert).where(DdosAlert.id == alert_id).with_for_update())
    if alert is None:
        raise HTTPException(404, "Alert not found")
    if alert.review_version != review.expected_version:
        raise HTTPException(409, "Another review was saved. Reload before submitting again.")
    alert.verdict = review.verdict
    alert.notes = review.notes.strip()
    alert.review_version += 1
    alert.reviewed_at = datetime.now(timezone.utc)
    db.add(AlertReview(alert_id=alert.id, version=alert.review_version, verdict=review.verdict,
                       notes=alert.notes, reviewed_at=alert.reviewed_at))
    # Verdicts do not silently acknowledge alerts, change training, or become
    # evaluation ground truth. Those are separate decisions/workflows.
    await db.commit()
    payload = serialize_alert(alert)
    await manager.publish_json({"type": "ALERT_UPDATED", "data": payload})
    return payload


@router.get("/{alert_id}/reviews")
async def review_history(alert_id: UUID, db: AsyncSession = Depends(get_db)):
    if await db.get(DdosAlert, alert_id) is None:
        raise HTTPException(404, "Alert not found")
    rows = await db.scalars(select(AlertReview).where(AlertReview.alert_id == alert_id)
                            .order_by(desc(AlertReview.version)).limit(100))
    return [{"version": row.version, "verdict": row.verdict, "notes": row.notes,
             "reviewedBy": row.reviewed_by, "reviewedAt": row.reviewed_at.isoformat()}
            for row in rows]
