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
    replace_existing: bool = False


def serialize_event(event: ThreatEvent) -> dict:
    return {
        "id": str(event.id),
        "server_id": event.server_id,
        "source_ip": event.source_ip or "Multiple sources",
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
    existing: dict[tuple[str, str], ThreatEvent] = {}
    if event_keys:
        result = await db.execute(
            select(ThreatEvent).where(
                tuple_(ThreatEvent.server_id, ThreatEvent.ingest_event_id).in_(event_keys)
            )
        )
        existing = {(row.server_id, row.ingest_event_id): row for row in result.scalars()}
        items = [
            item
            for item in items
            if item.replace_existing or (item.event.server_id, item.ingest_event_id) not in existing
        ]
    if not items:
        return []

    semaphore = asyncio.Semaphore(20)

    async def lookup(ip: str | None) -> dict:
        if not ip:
            return {}
        async with semaphore:
            return await geo_lookup.lookup(ip)

    geographies = await asyncio.gather(*(lookup(item.event.source_ip) for item in items))
    records: list[ThreatEvent] = []
    revised_ids: set[int] = set()
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
        prior = existing.get((event.server_id, item.ingest_event_id))
        if prior is not None:
            # Re-scoring late data updates the same window finding, not a second incident.
            for field in ("path", "severity", "anomaly_score", "explanation"):
                setattr(prior, field, getattr(record, field))
            record = prior
            revised_ids.add(record.id)
        else:
            db.add(record)
        records.append(record)

    try:
        await db.flush()
        payloads = [serialize_event(record) for record in records]
        alerts = await upsert_alerts(db, records, revised_event_ids=revised_ids)
        alert_payloads = [serialize_alert(alert) for alert in alerts]
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    for payload in payloads:
        await manager.publish_json({"type": "NEW_THREAT", "data": payload})
    for payload in alert_payloads:
        await manager.publish_json({"type": "ALERT_CREATED", "data": payload})
    return records
