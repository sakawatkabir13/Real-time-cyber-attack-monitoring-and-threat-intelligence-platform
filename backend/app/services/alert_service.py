"""Create deduplicated backend-owned security incidents from threat events."""

from __future__ import annotations

from datetime import timezone
import hashlib

from sqlalchemy import case, func, or_
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.ddos_alert import DdosAlert
from app.models.threat_event import ThreatEvent


ML_INCIDENT_TYPES = {"server_traffic_anomaly", "source_behavior_anomaly"}


def should_create_alert(event: ThreatEvent) -> bool:
    return event.severity in {"high", "critical"} or event.attack_type in ML_INCIDENT_TYPES


def _dedupe_key(event: ThreatEvent) -> str:
    timestamp = event.timestamp
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    bucket = int(timestamp.timestamp()) // settings.ALERT_DEDUPE_SECONDS
    source = "distributed" if event.attack_type == "server_traffic_anomaly" else event.source_ip
    material = f"{event.server_id}|{source}|{event.attack_type}|{bucket}"
    if event.attack_type in ML_INCIDENT_TYPES and event.ingest_event_id:
        # One reviewable finding per completed window. An old-window revision
        # must never downgrade a different, newer anomalous window's alert.
        material += f"|{event.ingest_event_id}"
    return hashlib.sha256(material.encode()).hexdigest()


def serialize_alert(alert: DdosAlert) -> dict:
    return {
        "id": str(alert.id),
        "serverId": alert.server_id,
        "sourceIp": alert.source_ip or "Multiple sources",
        "targetIp": alert.server_id,
        "type": alert.attack_type,
        "severity": alert.severity,
        "status": alert.status,
        "message": f"{alert.attack_type.replace('_', ' ').title()} detected",
        "explanation": alert.trigger_reason,
        "anomaly_score": alert.confidence,
        "occurrenceCount": alert.occurrence_count,
        "acknowledged": alert.status in {"acknowledged", "resolved"},
        "acknowledgedAt": alert.acknowledged_at.isoformat()
        if alert.acknowledged_at
        else None,
        "timestamp": alert.start_time.isoformat(),
        "lastSeen": alert.last_seen.isoformat(),
        "verdict": alert.verdict or "unreviewed",
        "reviewVersion": alert.review_version or 0,
        "reviewedAt": alert.reviewed_at.isoformat() if alert.reviewed_at else None,
        "reviewNotes": alert.notes or "",
        "incidentGroupId": str(alert.incident_group_id) if alert.incident_group_id else None,
    }


async def upsert_alerts(
    db: AsyncSession, events: list[ThreatEvent], *, revised_event_ids: set[int] | None = None,
) -> list[DdosAlert]:
    alerts: dict[str, DdosAlert] = {}
    table = DdosAlert.__table__
    revised_event_ids = revised_event_ids or set()
    for event in events:
        if not should_create_alert(event):
            continue
        key = _dedupe_key(event)
        statement = insert(DdosAlert).values(
            server_id=event.server_id,
            source_ip=None
            if event.attack_type == "server_traffic_anomaly"
            else event.source_ip,
            dedupe_key=key,
            first_event_id=event.id,
            latest_event_id=event.id,
            start_time=event.timestamp,
            last_seen=event.timestamp,
            attack_type=event.attack_type or "unknown",
            severity=event.severity or "medium",
            status="new",
            detection_method="ml"
            if event.attack_type in ML_INCIDENT_TYPES
            else "rule",
            trigger_reason=event.explanation or "Threat detected",
            top_source_ips=[event.source_ip] if event.source_ip else [],
            top_paths=[event.path] if event.path else [],
            confidence=event.anomaly_score,
            occurrence_count=1,
        )
        incoming = statement.excluded
        latest = or_(incoming.last_seen > table.c.last_seen,
                     (incoming.last_seen == table.c.last_seen) & (incoming.latest_event_id >= table.c.latest_event_id))
        revised = event.id in revised_event_ids
        statement = statement.on_conflict_do_update(
            constraint="uq_ddos_alerts_dedupe_key",
            set_={
                "first_event_id": case((incoming.start_time < table.c.start_time, incoming.first_event_id), else_=table.c.first_event_id),
                "start_time": func.least(table.c.start_time, incoming.start_time),
                "latest_event_id": case((latest, incoming.latest_event_id), else_=table.c.latest_event_id),
                "last_seen": func.greatest(table.c.last_seen, incoming.last_seen),
                "severity": case((latest, incoming.severity), else_=table.c.severity),
                "trigger_reason": case((latest, incoming.trigger_reason), else_=table.c.trigger_reason),
                "top_paths": case((latest, incoming.top_paths), else_=table.c.top_paths),
                "confidence": case((latest, incoming.confidence), else_=table.c.confidence) if revised else func.greatest(
                    func.coalesce(table.c.confidence, 0.0),
                    func.coalesce(statement.excluded.confidence, 0.0),
                ),
                "occurrence_count": table.c.occurrence_count + (0 if revised else 1),
                "updated_at": func.now(),
            },
        ).returning(DdosAlert).execution_options(populate_existing=True)
        alert = (await db.execute(statement)).scalar_one()
        alerts[str(alert.id)] = alert
    return list(alerts.values())
