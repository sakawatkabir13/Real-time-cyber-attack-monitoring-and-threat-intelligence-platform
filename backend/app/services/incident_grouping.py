"""Bounded background clustering of related observations, never attribution."""

import asyncio
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
from urllib.parse import urlsplit
import uuid

import numpy as np
from sklearn.cluster import DBSCAN
from sqlalchemy import desc, select, tuple_

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.ddos_alert import DdosAlert
from app.models.incident_group import IncidentGroup
from app.models.traffic_window import TrafficWindow
from app.redis_client import redis_client
from app.services.privacy import hash_ip
from app.services.window_scoring import RELEASE_LOCK

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Observation:
    alert_id: uuid.UUID
    server_id: str
    attack_type: str
    source_ip: str
    path: str
    timestamp: datetime
    score: float
    behavior: tuple[float, ...] = ()


def related_clusters(observations: list[Observation]) -> list[list[Observation]]:
    """Do not mix servers, attack families, paths, or measured/unmeasured data."""
    partitions = defaultdict(list)
    for observation in observations:
        if observation.path:
            partitions[(observation.server_id, observation.attack_type, observation.path,
                        bool(observation.behavior))].append(observation)
    clusters = []
    for members in partitions.values():
        if len(members) < settings.INCIDENT_GROUPING_MIN_SOURCES:
            continue
        origin = min(item.timestamp.timestamp() for item in members)
        vectors = np.asarray([
            [(item.timestamp.timestamp() - origin) / settings.INCIDENT_GROUPING_TIME_SECONDS,
             item.score / 25.0, *item.behavior] for item in members
        ])
        labels = DBSCAN(eps=1.0, min_samples=settings.INCIDENT_GROUPING_MIN_SOURCES,
                        metric="chebyshev", n_jobs=1).fit_predict(vectors)
        for label in set(labels) - {-1}:
            cluster = [item for item, assigned in zip(members, labels) if assigned == label]
            if len({item.source_ip for item in cluster}) >= settings.INCIDENT_GROUPING_MIN_SOURCES:
                clusters.append(cluster)
    return clusters


def serialize_group(group: IncidentGroup) -> dict:
    return {"id": str(group.id), "serverId": group.server_id, "type": group.attack_type,
            "path": group.path, "sourceCount": group.source_count, "alertCount": group.alert_count,
            "sourceIps": group.source_ips, "startTime": group.start_time.isoformat(),
            "lastSeen": group.last_seen.isoformat(), "explanation": group.explanation}


async def group_recent_incidents() -> int:
    client = redis_client._require_client()
    key, token = "incidents:grouping-lock", uuid.uuid4().hex
    if not await client.set(key, token, nx=True, ex=120):
        return 0
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.INCIDENT_GROUPING_LOOKBACK_SECONDS)
        async with AsyncSessionLocal() as db:
            alerts = list(await db.scalars(select(DdosAlert).where(
                DdosAlert.last_seen >= cutoff,
                DdosAlert.source_ip.is_not(None),
            ).order_by(desc(DdosAlert.last_seen)).limit(settings.INCIDENT_GROUPING_MAX_ALERTS)))
            windows = {}
            identities = [(a.server_id, a.start_time, hash_ip(a.source_ip)) for a in alerts
                          if a.attack_type == "source_behavior_anomaly"]
            if identities:
                rows = await db.scalars(select(TrafficWindow).where(
                    TrafficWindow.scope == "source", TrafficWindow.feature_schema == 3,
                    tuple_(TrafficWindow.server_id, TrafficWindow.window_start, TrafficWindow.source_ip_hash).in_(identities),
                ))
                windows = {(row.server_id, row.window_start, row.source_ip_hash): row for row in rows}
            observations = []
            for alert in alerts:
                if alert.verdict in {"legitimate", "misconfiguration"}:
                    continue
                path = (alert.top_paths or [""])[0]
                try:
                    path = urlsplit(path).path
                except ValueError:
                    continue
                window = windows.get((alert.server_id, alert.start_time, hash_ip(alert.source_ip)))
                behavior = ()
                if window is not None:
                    # A difference above 0.25 in any ratio prevents direct neighbors.
                    behavior = tuple(float(getattr(window, name) or 0) / 0.25 for name in
                                     ("burst_ratio", "status_4xx_ratio", "status_5xx_ratio", "top_path_share"))
                observations.append(Observation(alert.id, alert.server_id, alert.attack_type,
                                                alert.source_ip, path, alert.start_time,
                                                alert.confidence or 0, behavior))
            clusters = await asyncio.to_thread(related_clusters, observations)
            if await client.get(key) != token:
                return 0
            by_id = {alert.id: alert for alert in alerts}
            assigned = set()
            used_groups = set()
            for members in clusters:
                existing = sorted({by_id[m.alert_id].incident_group_id for m in members
                                   if by_id[m.alert_id].incident_group_id}, key=str)
                # Reuse identity as new members arrive; a split gets a new group.
                group_id = next((identity for identity in existing if identity not in used_groups), uuid.uuid4())
                used_groups.add(group_id)
                group = await db.get(IncidentGroup, group_id)
                if group is None:
                    group = IncidentGroup(id=group_id)
                    db.add(group)
                sources = sorted({m.source_ip for m in members})
                first = members[0]
                group.server_id, group.attack_type, group.path = first.server_id, first.attack_type, first.path
                group.source_count, group.alert_count = len(sources), len(members)
                group.source_ips = sources[:50]
                group.start_time = min(m.timestamp for m in members)
                group.last_seen = max(by_id[m.alert_id].last_seen for m in members)
                evidence = " and similar traffic-window ratios" if first.behavior else ""
                group.explanation = (f"Possible related incident: {len(sources)} sources, {len(members)} alerts "
                                     f"with the same server, detection family and path, nearby timing and scores{evidence}. "
                                     "DBSCAN groups observations for investigation; similarity does not prove a common attacker. "
                                     f"Bounded to the latest {settings.INCIDENT_GROUPING_MAX_ALERTS} source alerts "
                                     f"in {settings.INCIDENT_GROUPING_LOOKBACK_SECONDS // 60} minutes.")
                # Ensure the referenced group exists before assigning FK values.
                await db.flush()
                for member in members:
                    by_id[member.alert_id].incident_group_id = group.id
                    assigned.add(member.alert_id)
            for alert in alerts:
                if alert.id not in assigned:
                    alert.incident_group_id = None
            await db.commit()
        return len(clusters)
    finally:
        await client.eval(RELEASE_LOCK, 1, key, token)


async def grouping_loop() -> None:
    while True:
        try:
            await group_recent_incidents()
        except Exception:
            logger.exception("Incident grouping failed; retrying")
        await asyncio.sleep(settings.INCIDENT_GROUPING_INTERVAL_SECONDS)
