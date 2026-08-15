"""Evaluate the active model against held-out persisted traffic windows."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import sync_database_url
from app.models.traffic_window import TrafficWindow
from app.services.ml_engine import ml_engine
from app.services.ml_features import window_values


def evaluate(days: int) -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    engine = create_engine(
        sync_database_url(),
        pool_pre_ping=True,
        connect_args={"sslmode": "require" if settings.DATABASE_SSL else "disable"},
    )
    output: dict[str, dict] = {}
    try:
        with Session(engine) as session:
            for scope in ("server", "source"):
                rows = list(
                    session.scalars(
                        select(TrafficWindow).where(
                            TrafficWindow.scope == scope,
                            TrafficWindow.window_start >= cutoff,
                        )
                    )
                )
                tp = fp = tn = fn = 0
                scores: list[float] = []
                for row in rows:
                    prediction = ml_engine.score(scope, row.server_id, window_values(row))
                    if prediction is None:
                        continue
                    scores.append(prediction.score)
                    predicted = prediction.score >= settings.ML_ALERT_SCORE
                    known_incident = (row.rule_threat_count or 0) > 0
                    if predicted and known_incident:
                        tp += 1
                    elif predicted:
                        fp += 1
                    elif known_incident:
                        fn += 1
                    else:
                        tn += 1
                evaluated = tp + fp + tn + fn
                output[scope] = {
                    "evaluated_windows": evaluated,
                    "known_rule_incidents": tp + fn,
                    "precision_against_rule_incidents": tp / (tp + fp) if tp + fp else None,
                    "recall_against_rule_incidents": tp / (tp + fn) if tp + fn else None,
                    "false_positive_rate": fp / (fp + tn) if fp + tn else None,
                    "false_alerts_per_day": fp / max(1, days),
                    "average_score": sum(scores) / len(scores) if scores else None,
                }
        return {"model": ml_engine.status(), "period_days": days, "scopes": output}
    finally:
        engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=7)
    arguments = parser.parse_args()
    print(json.dumps(evaluate(max(1, arguments.days)), indent=2))
