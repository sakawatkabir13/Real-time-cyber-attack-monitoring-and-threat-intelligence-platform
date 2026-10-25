"""Shared sample selection for training and dashboard readiness reporting."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import desc, select, or_

from app.config import settings
from app.models.traffic_window import TrafficWindow
from app.services.scanner_detection import is_directory_enumeration


def snapshot_training_eligible(data: dict, *, enumeration: bool, anomaly_score: float | None) -> bool:
    """A low anomaly score must never override independent exclusion evidence."""
    return (
        int(data.get("rule_threat_count", 0)) == 0
        and int(data.get("scanner_request_count", 0)) == 0
        and int(data.get("baseline_excluded_count", 0)) == 0
        and int(data.get("demonstration_request_count", 0)) == 0
        and not enumeration
        and (anomaly_score is None or anomaly_score < settings.ML_ALERT_SCORE)
    )


def training_query(scope: str, server_id: str | None = None):
    minimum = settings.ML_MIN_SERVER_REQUESTS if scope == "server" else settings.ML_MIN_SOURCE_REQUESTS
    query = select(TrafficWindow).where(
        TrafficWindow.scope == scope,
        TrafficWindow.feature_schema == 3,
        TrafficWindow.window_start >= datetime.now(timezone.utc) - timedelta(days=settings.ML_TRAINING_DAYS),
        TrafficWindow.is_training_eligible.is_(True),
        TrafficWindow.rule_threat_count == 0,
        or_(TrafficWindow.anomaly_score.is_(None), TrafficWindow.anomaly_score < settings.ML_ALERT_SCORE),
        TrafficWindow.request_count >= minimum,
    )
    if server_id is not None:
        query = query.where(TrafficWindow.server_id == server_id)
    return query.order_by(desc(TrafficWindow.window_start)).limit(settings.ML_MAX_TRAINING_WINDOWS * 4)


def select_training_candidates(candidates: list[TrafficWindow], scope: str):
    per_entity_limit = settings.ML_MAX_TRAINING_WINDOWS if scope == "server" else max(50, settings.ML_MAX_TRAINING_WINDOWS // 20)
    counts = defaultdict(int)
    selected = []
    scanner_excluded = 0
    for row in candidates:
        score = getattr(row, "anomaly_score", None)
        if (getattr(row, "is_training_eligible", True) is False
                or (getattr(row, "rule_threat_count", 0) or 0) > 0
                or (score is not None and score >= settings.ML_ALERT_SCORE)):
            scanner_excluded += 1
            continue
        if is_directory_enumeration(
            request_count=row.request_count or 0, unique_paths=row.unique_paths or 0,
            top_path_share=row.top_path_share if row.top_path_share is not None else 1.0,
            request_rate=row.request_rate or 0, peak_second_requests=row.peak_second_requests or 0,
        ):
            scanner_excluded += 1
            continue
        identity = (row.server_id, row.entity_key)
        if counts[identity] >= per_entity_limit:
            continue
        counts[identity] += 1
        selected.append(row)
        if len(selected) >= settings.ML_MAX_TRAINING_WINDOWS:
            break
    return list(reversed(selected)), scanner_excluded
