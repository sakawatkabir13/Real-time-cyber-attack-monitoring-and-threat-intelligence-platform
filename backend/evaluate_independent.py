"""Evaluate rules, ML, and their union against independently reviewed windows.

Export candidates first, add labels from controlled exercises or human review, then
score only windows strictly later than the model's training period.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from statistics import mean

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import sync_database_url
from app.models.traffic_window import TrafficWindow
from app.services.ml_engine import ml_engine
from app.services.ml_features import window_values


def parse_time(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamps must include a timezone")
    return result.astimezone(timezone.utc)


def export_candidates(path: Path, days: int) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    engine = create_engine(
        sync_database_url(),
        pool_pre_ping=True,
        connect_args={"sslmode": "require" if settings.DATABASE_SSL else "disable"},
    )
    count = 0
    try:
        with Session(engine) as session, path.open("x", encoding="utf-8") as target:
            rows = session.scalars(
                select(TrafficWindow)
                .where(TrafficWindow.feature_schema == 3, TrafficWindow.window_start >= cutoff)
                .order_by(TrafficWindow.window_start)
            )
            for row in rows:
                item = {
                    "record_id": row.id,
                    "label": None,
                    "scope": row.scope,
                    "server_id": row.server_id,
                    "window_start": row.window_start.isoformat(),
                    "window_seconds": row.window_seconds,
                    "features": window_values(row),
                    "rule_detected": bool(row.rule_threat_count),
                    "attack_start": None,
                    "rule_alert_at": None,
                    "ml_alert_at": None,
                }
                target.write(json.dumps(item) + "\n")
                count += 1
    finally:
        engine.dispose()
    return count


def measures(truth: list[bool], predictions: list[bool], period_days: float,
             delays: list[float]) -> dict:
    tp = sum(t and p for t, p in zip(truth, predictions))
    fp = sum(not t and p for t, p in zip(truth, predictions))
    tn = sum(not t and not p for t, p in zip(truth, predictions))
    fn = sum(t and not p for t, p in zip(truth, predictions))
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "false_alerts_per_day": fp / period_days,
        "mean_detection_delay_seconds": mean(delays) if delays else None,
        "timed_detections": len(delays),
    }


def evaluate(records: list[dict], period_start: datetime, period_end: datetime) -> dict:
    if period_end <= period_start:
        raise ValueError("Evaluation period must have positive duration")
    status = ml_engine.status()
    if status["state"] != "ready":
        raise ValueError("No trained model is available; evaluation cannot run")
    truth: list[bool] = []
    rules: list[bool] = []
    ml: list[bool] = []
    delays: dict[str, list[float]] = {"rules": [], "ml": [], "combined": []}
    for row in records:
        if row.get("label") not in ("attack", "benign"):
            raise ValueError(f"Record {row.get('record_id')} needs independent attack/benign label")
        if type(row.get("rule_detected")) is not bool:
            raise ValueError("rule_detected must be an observed boolean")
        scope, server_id = row["scope"], row["server_id"]
        component = status["models"].get(scope, {}).get("servers", {}).get(server_id)
        if component is None:
            raise ValueError(f"No model for {scope}/{server_id}; do not silently omit windows")
        start = parse_time(row["window_start"])
        if not period_start <= start < period_end:
            raise ValueError("Record lies outside the declared observation period")
        if start <= parse_time(component["window_end"]):
            raise ValueError("Evaluation window overlaps model training; use later held-out windows")
        score = ml_engine.score(scope, server_id, row["features"])
        if score is None:
            raise ValueError(f"Model could not score {scope}/{server_id}")
        is_attack = row["label"] == "attack"
        rule_positive = row["rule_detected"]
        ml_positive = score.score >= settings.ML_ALERT_SCORE
        truth.append(is_attack)
        rules.append(rule_positive)
        ml.append(ml_positive)
        if is_attack and row.get("attack_start"):
            attack_start = parse_time(row["attack_start"])
            observed: dict[str, datetime] = {}
            for name, positive, field in (
                ("rules", rule_positive, "rule_alert_at"),
                ("ml", ml_positive, "ml_alert_at"),
            ):
                if positive and row.get(field):
                    alert_at = parse_time(row[field])
                    if alert_at < attack_start:
                        raise ValueError("Alert timestamp precedes attack start")
                    observed[name] = alert_at
                    delays[name].append((alert_at - attack_start).total_seconds())
            # Earliest combined detection is unknowable if a positive detector
            # has no observed alert timestamp.
            if observed and (not rule_positive or "rules" in observed) and (
                not ml_positive or "ml" in observed
            ):
                delays["combined"].append(
                    (min(observed.values()) - attack_start).total_seconds()
                )
    if not records:
        raise ValueError("No labeled windows to evaluate")
    days = (period_end - period_start).total_seconds() / 86400
    return {
        "model_version": status["version"],
        "threshold": settings.ML_ALERT_SCORE,
        "observation_days": days,
        "labeled_windows": len(records),
        "metrics_unit": "window; false alerts count positive benign windows, not deduplicated incidents",
        "rules": measures(truth, rules, days, delays["rules"]),
        "ml": measures(truth, ml, days, delays["ml"]),
        "combined": measures(truth, [a or b for a, b in zip(rules, ml)],
                             days, delays["combined"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    export = sub.add_parser("export", help="Export unlabeled candidate windows for independent review")
    export.add_argument("path", type=Path)
    export.add_argument("--days", type=int, default=7)
    run = sub.add_parser("evaluate", help="Score independently labeled, held-out JSONL")
    run.add_argument("path", type=Path)
    run.add_argument("--period-start", required=True)
    run.add_argument("--period-end", required=True)
    args = parser.parse_args()
    if args.action == "export":
        print(json.dumps({"exported_windows": export_candidates(args.path, args.days)}))
    else:
        with args.path.open(encoding="utf-8") as source:
            records = [json.loads(line) for line in source if line.strip()]
        print(json.dumps(evaluate(records, parse_time(args.period_start),
                                  parse_time(args.period_end)), indent=2))


if __name__ == "__main__":
    main()
