"""Persist completed Redis traffic aggregations to PostgreSQL."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import time

import redis
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.config import settings
from app.database import sync_database_url
from app.models.traffic_window import TrafficWindow
from app.services.behavioral_features import (
    SNAPSHOT_SCRIPT, decode_snapshot, previous_key, values_from_snapshot,
)
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


def _snapshot(client: redis.Redis, base: str) -> tuple[dict[str, str], dict[str, int], float] | None:
    seconds = client.hget(base, "window_seconds")
    if not seconds:
        return None
    return decode_snapshot(client.eval(SNAPSHOT_SCRIPT, 2, base, previous_key(base, int(seconds))))


@celery_app.task(name="flush_traffic_windows_task")
def flush_traffic_windows_task() -> int:
    client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    engine = create_engine(
        sync_database_url(),
        pool_pre_ping=True,
        connect_args={"sslmode": "require" if settings.DATABASE_SSL else "disable"},
    )
    now = time.time()
    rows: list[tuple[str, dict]] = []
    try:
        for base in client.scan_iter(match="ml:window:*"):
            parts = base.split(":")
            if len(parts) != 6 or parts[2] not in {"server", "source"}:
                continue
            snapshot = _snapshot(client, base)
            if not snapshot:
                continue
            data, cardinalities, top_count = snapshot
            start = int(data.get("window_start", 0))
            seconds = int(data.get("window_seconds", 0))
            updated_at = float(data.get("updated_at", 0))
            persisted_at = float(data.get("persisted_at", 0))
            if start + seconds + settings.ML_WINDOW_GRACE_SECONDS > now:
                continue
            if persisted_at >= updated_at:
                continue
            values = values_from_snapshot(data, cardinalities, top_count)
            count = int(data.get("request_count", 0))
            scope = data["scope"]
            anomaly_score = (
                float(data["anomaly_score"]) if data.get("anomaly_score") else None
            )
            rule_threat_count = int(data.get("rule_threat_count", 0))
            row = {
                "feature_schema": int(data.get("feature_schema", 2)),
                "server_id": data["server_id"],
                "scope": scope,
                "entity_key": data["entity_key"],
                "window_start": datetime.fromtimestamp(start, tz=timezone.utc),
                "window_seconds": seconds,
                "source_ip_hash": data.get("source_ip_hash") or None,
                "request_count": count,
                "bytes_total": int(data.get("bytes_total", 0)),
                "status_2xx": int(data.get("status_2xx", 0)),
                "status_3xx": int(data.get("status_3xx", 0)),
                "status_4xx": int(data.get("status_4xx", 0)),
                "status_5xx": int(data.get("status_5xx", 0)),
                "avg_request_time": values["avg_request_time"],
                "unique_user_agents": cardinalities["unique_user_agents"],
                "unique_ips": cardinalities["unique_ips"],
                "unique_paths": cardinalities["unique_paths"],
                "new_ip_ratio": values["new_ip_ratio"],
                "top_path_share": values["top_path_share"],
                "request_rate": values["request_rate"],
                "status_4xx_ratio": values["status_4xx_ratio"],
                "status_5xx_ratio": values["status_5xx_ratio"],
                "avg_bytes": values["avg_bytes"],
                "reputation_score": values["reputation_score"],
                "reporter_count": int(values["reporter_count"]),
                "community_reports": int(values["community_reports"]),
                "rule_threat_count": rule_threat_count,
                "is_training_eligible": rule_threat_count == 0
                and (anomaly_score is None or anomaly_score < settings.ML_ALERT_SCORE),
                "anomaly_score": anomaly_score,
                "model_version": data.get("model_version") or None,
                "anomaly_explanation": data.get("anomaly_explanation") or None,
            }
            for name in ("request_time_coverage", "peak_second_requests", "burst_ratio",
                         "rate_change_ratio", "previous_window_present", "failed_auth_ratio",
                         "max_path_unique_ips"):
                row[name] = values[name] if row["feature_schema"] == 3 else None
            if row["feature_schema"] < 3:
                # Preserve legacy measurement semantics; never label them schema 3.
                row["avg_request_time"] = float(data.get("request_time_total", 0)) / max(1, count)
            row["path"] = data.get("top_path") or None
            rows.append((base, row))

        if not rows:
            return 0
        table = TrafficWindow.__table__
        with Session(engine) as session:
            for _, row in rows:
                statement = insert(table).values(**row)
                update_values = {
                    column.name: getattr(statement.excluded, column.name)
                    for column in table.columns
                    if column.name not in {"id", "created_at"}
                }
                session.execute(
                    statement.on_conflict_do_update(
                        constraint="uq_traffic_window_entity_period",
                        set_=update_values,
                    )
                )
            session.commit()
        pipe = client.pipeline()
        for base, _ in rows:
            # Never mark a newer concurrent observation as already persisted.
            pipe.hset(base, "persisted_at", now)
        pipe.execute()
        return len(rows)
    except Exception:
        logger.exception("Traffic-window persistence failed")
        raise
    finally:
        engine.dispose()
        client.close()
