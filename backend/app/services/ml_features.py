"""Shared behavioral feature definitions used by inference and training."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Mapping

import numpy as np


FEATURE_NAMES: dict[str, tuple[str, ...]] = {
    "server": (
        "request_rate",
        "unique_ips",
        "new_ip_ratio",
        "unique_paths",
        "top_path_share",
        "status_4xx_ratio",
        "status_5xx_ratio",
        "avg_bytes",
        "avg_request_time",
        "unique_user_agents",
        "hour_sin",
        "hour_cos",
        "weekday_sin",
        "weekday_cos",
    ),
    "source": (
        "request_rate",
        "unique_paths",
        "status_4xx_ratio",
        "status_5xx_ratio",
        "avg_bytes",
        "avg_request_time",
        "unique_user_agents",
        "reputation_score",
        "reporter_count",
        "community_reports",
        "hour_sin",
        "hour_cos",
        "weekday_sin",
        "weekday_cos",
    ),
}

LOG_FEATURES = {
    "request_rate",
    "unique_ips",
    "unique_paths",
    "avg_bytes",
    "avg_request_time",
    "unique_user_agents",
    "reporter_count",
    "community_reports",
}

FEATURE_LABELS = {
    "request_rate": "request rate",
    "unique_ips": "unique source IPs",
    "new_ip_ratio": "new-source ratio",
    "unique_paths": "unique paths",
    "top_path_share": "top-path concentration",
    "status_4xx_ratio": "HTTP 4xx ratio",
    "status_5xx_ratio": "HTTP 5xx ratio",
    "avg_bytes": "average response bytes",
    "avg_request_time": "average request time",
    "unique_user_agents": "user-agent diversity",
    "reputation_score": "IP abuse reputation",
    "reporter_count": "AbuseIPDB reporter count",
    "community_reports": "AbuseIPDB report count",
    "hour_sin": "time-of-day pattern",
    "hour_cos": "time-of-day pattern",
    "weekday_sin": "day-of-week pattern",
    "weekday_cos": "day-of-week pattern",
}


def calibrate_anomaly_score(
    raw_score: float, quantiles: Mapping[str, float]
) -> float:
    """Map an Isolation Forest score to an interpretable baseline percentile band."""
    q50 = float(quantiles["q50"])
    q95 = max(float(quantiles["q95"]), q50 + 1e-9)
    q99 = max(float(quantiles["q99"]), q95 + 1e-9)
    q999 = max(float(quantiles["q999"]), q99 + 1e-9)
    if raw_score <= q50:
        return max(0.0, 50.0 * raw_score / max(q50, 1e-9))
    if raw_score <= q95:
        return 50.0 + 30.0 * (raw_score - q50) / (q95 - q50)
    if raw_score <= q99:
        return 80.0 + 15.0 * (raw_score - q95) / (q99 - q95)
    return min(100.0, 95.0 + 5.0 * (raw_score - q99) / (q999 - q99))


def raw_vector(scope: str, values: Mapping[str, float | int | None]) -> np.ndarray:
    return np.asarray(
        [float(values.get(name) or 0.0) for name in FEATURE_NAMES[scope]],
        dtype=float,
    )


def transform_vector(scope: str, values: Mapping[str, float | int | None]) -> np.ndarray:
    vector = raw_vector(scope, values)
    for index, name in enumerate(FEATURE_NAMES[scope]):
        if name in LOG_FEATURES:
            vector[index] = math.log1p(max(0.0, vector[index]))
    return vector


def window_values(window: object) -> dict[str, float]:
    values = {
        name: float(getattr(window, name, 0) or 0.0)
        for name in set(FEATURE_NAMES["server"] + FEATURE_NAMES["source"])
    }
    timestamp = getattr(window, "window_start", None)
    if timestamp is not None:
        values.update(temporal_features(timestamp))
    return values


def temporal_features(timestamp: datetime | int | float) -> dict[str, float]:
    if isinstance(timestamp, (int, float)):
        timestamp = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    elif timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc)
    hour = timestamp.hour + timestamp.minute / 60.0
    weekday = float(timestamp.weekday())
    return {
        "hour_sin": math.sin(2.0 * math.pi * hour / 24.0),
        "hour_cos": math.cos(2.0 * math.pi * hour / 24.0),
        "weekday_sin": math.sin(2.0 * math.pi * weekday / 7.0),
        "weekday_cos": math.cos(2.0 * math.pi * weekday / 7.0),
    }
