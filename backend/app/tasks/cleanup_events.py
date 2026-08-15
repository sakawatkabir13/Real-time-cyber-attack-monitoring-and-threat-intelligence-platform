import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import settings
from app.models.threat_event import ThreatEvent
from app.models.traffic_window import TrafficWindow
from app.models.ddos_alert import DdosAlert
from app.models.ml_model_run import MlModelRun
from app.tasks.celery_app import celery_app


async def _delete_expired_events() -> dict[str, int]:
    engine = create_async_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,
        connect_args={"ssl": settings.DATABASE_SSL},
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.EVENT_RETENTION_DAYS)
    try:
        async with sessions() as session:
            result = await session.execute(delete(ThreatEvent).where(ThreatEvent.timestamp < cutoff))
            windows = await session.execute(
                delete(TrafficWindow).where(TrafficWindow.window_start < cutoff)
            )
            alerts = await session.execute(
                delete(DdosAlert).where(DdosAlert.last_seen < cutoff)
            )
            model_runs = await session.execute(
                delete(MlModelRun).where(
                    MlModelRun.trained_at < datetime.now(timezone.utc) - timedelta(days=90)
                )
            )
            await session.commit()
            return {
                "events": result.rowcount or 0,
                "windows": windows.rowcount or 0,
                "alerts": alerts.rowcount or 0,
                "model_runs": model_runs.rowcount or 0,
            }
    finally:
        await engine.dispose()


@celery_app.task(name="cleanup_events_task")
def cleanup_events_task() -> dict[str, int]:
    return asyncio.run(_delete_expired_events())
