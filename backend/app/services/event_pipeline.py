import asyncio
from dataclasses import dataclass
from typing import Iterable

from sqlalchemy import select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_event import ThreatEvent
from app.config import settings
from app.schemas.event import ThreatEventCreate
from app.services.geo_lookup import geo_lookup
from app.services.alert_service import serialize_alert, upsert_alerts
from app.websocket_manager import manager


@dataclass(frozen=True)
class PendingThreat:
    event: ThreatEventCreate
    ingest_event_id: str | None = None


def serialize_event(event: ThreatEvent) -> dict:
    return {
        "id": str(event.id),
        "server_id": event.server_id,
        "source_ip": event.source_ip,
        "dest_ip": event.dest_ip,
        "dest_lat": event.dest_lat if event.dest_lat is not None else settings.TARGET_LATITUDE,
        "dest_lng": event.dest_lon if event.dest_lon is not None else settings.TARGET_LONGITUDE,
        "dest_port": 80,
        "attack_type": event.attack_type,
        "severity": event.severity,
        "country": event.source_country or "Unknown",
        "lat": event.source_lat,
        "lng": event.source_lon,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "anomaly_score": event.anomaly_score,
        "explanation": event.explanation,
    }


async def persist_threats(
    db: AsyncSession, pending: Iterable[PendingThreat]
) -> list[ThreatEvent]:
    """Enrich and persist a threat batch atomically, then publish it."""
    items = list(pending)
    if not items:
        return []

    event_keys = [
        (item.event.server_id, item.ingest_event_id)
        for item in items
        if item.ingest_event_id
    ]
    existing: set[tuple[str, str]] = set()
    if event_keys:
        result = await db.execute(
            select(ThreatEvent.server_id, ThreatEvent.ingest_event_id).where(
                tuple_(ThreatEvent.server_id, ThreatEvent.ingest_event_id).in_(event_keys)
            )
        )
        existing = {(server_id, event_id) for server_id, event_id in result if event_id}
        items = [
            item
            for item in items
            if (item.event.server_id, item.ingest_event_id) not in existing
        ]
    if not items:
        return []

    semaphore = asyncio.Semaphore(20)

    async def lookup(ip: str) -> dict:
        async with semaphore:
            return await geo_lookup.lookup(ip)

    geographies = await asyncio.gather(*(lookup(item.event.source_ip) for item in items))
    records: list[ThreatEvent] = []
    for item, geo in zip(items, geographies):
        event = item.event
        record = ThreatEvent(
            ingest_event_id=item.ingest_event_id,
            server_id=event.server_id,
            timestamp=event.timestamp,
            source_ip=event.source_ip,
            method=event.method,
            path=event.path,
            status_code=event.status_code,
            bytes_sent=event.bytes_sent,
            request_time=event.request_time,
            user_agent=event.user_agent,
            host=event.host,
            attack_type=event.attack_type,
            severity=event.severity,
            anomaly_score=event.anomaly_score,
            explanation=event.explanation,
            source_lat=geo.get("lat"),
            source_lon=geo.get("lon"),
            source_country=geo.get("country"),
        )
        db.add(record)
        records.append(record)

    try:
        await db.flush()
        payloads = [serialize_event(record) for record in records]
        alerts = await upsert_alerts(db, records)
        alert_payloads = [serialize_alert(alert) for alert in alerts]
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    for payload in payloads:
        await manager.broadcast_json({"type": "NEW_THREAT", "data": payload})
    for payload in alert_payloads:
        await manager.broadcast_json({"type": "ALERT_CREATED", "data": payload})
    return records
