"""Train behavioral models from real, rule-clean traffic windows."""

from __future__ import annotations

from datetime import datetime, timezone
from bisect import bisect_left
import logging
import os
import tempfile
import uuid

import joblib
import numpy as np
import redis
from sklearn.ensemble import IsolationForest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import sync_database_url
from app.models.ml_model_run import MlModelRun
from app.models.traffic_window import TrafficWindow
from app.services.ml_features import (
    BINARY_FEATURES,
    FEATURE_NAMES,
    calibrate_anomaly_score,
    raw_vector,
    transform_vector,
    window_values,
)
from app.services.training_data import training_query, select_training_candidates
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


def _select_training_rows(
    session: Session, scope: str, server_id: str
) -> list[TrafficWindow]:
    candidates = list(session.scalars(training_query(scope, server_id)))
    return select_training_candidates(candidates, scope)[0]


def _fit_scope(scope: str, rows: list[TrafficWindow]) -> tuple[dict | None, str | None]:
    if len(rows) < settings.ML_MIN_TRAINING_WINDOWS:
        return None, "insufficient clean traffic windows"
    rows = sorted(rows, key=lambda row: row.window_start)
    raw = np.vstack([raw_vector(scope, window_values(row)) for row in rows])
    # Reject malformed data in *any* period, including validation. Do not drop
    # invalid validation rows or let transformations mask non-finite inputs.
    if not np.isfinite(raw).all():
        return None, "non-finite traffic feature values"
    binary_columns = [name in BINARY_FEATURES for name in FEATURE_NAMES[scope]]
    if not np.isin(raw[:, binary_columns], (0.0, 1.0)).all():
        return None, "invalid binary traffic feature values"
    transformed = np.vstack(
        [transform_vector(scope, window_values(row)) for row in rows]
    )

    # Fit, calibration and validation are disjoint chronological periods. Keep
    # all sources from one timestamp together to avoid leaking one burst across
    # partitions. Training-set scores are optimistically biased and must not be
    # used to calibrate the scores of unseen production traffic.
    boundaries = [index for index in range(1, len(rows))
                  if rows[index].window_start != rows[index - 1].window_start]
    if len(boundaries) < 2:
        return None, "three distinct traffic periods are required for fit, calibration and validation"
    fit_index = min(bisect_left(boundaries, int(len(rows) * 0.6)), len(boundaries) - 2)
    fit_end = boundaries[fit_index]
    calibration_index = min(max(fit_index + 1, bisect_left(boundaries, int(len(rows) * 0.8))), len(boundaries) - 1)
    calibration_end = boundaries[calibration_index]
    fit_values = transformed[:fit_end]
    # Learn the poisoning guard only from the fitting period. Never discard
    # difficult validation observations to make a candidate pass promotion.
    median = np.median(fit_values, axis=0)
    mad = np.median(np.abs(fit_values - median), axis=0)
    safe_mad = np.maximum(mad, 0.05)
    continuous_columns = np.logical_not(binary_columns)
    # A rare but valid binary flip is not a 20-MAD poisoned measurement. Its
    # domain was checked above; retain it for model fitting and scoring while
    # preserving the existing 12-MAD guard for every continuous feature.
    keep = np.all(
        np.abs((transformed[:, continuous_columns] - median[continuous_columns])
               / safe_mad[continuous_columns]) < 12.0,
        axis=1,
    )
    training = transformed[:fit_end][keep[:fit_end]]
    calibration = transformed[fit_end:calibration_end][keep[fit_end:calibration_end]]
    validation = transformed[calibration_end:]
    if len(training) < 3 or len(calibration) < 2 or len(validation) < 2:
        return None, "insufficient independent fit, calibration or validation samples after quarantine"
    if len(training) + len(calibration) + len(validation) < settings.ML_MIN_TRAINING_WINDOWS:
        return None, "too many extreme or potentially poisoned windows"

    model = IsolationForest(
        n_estimators=250,
        contamination=settings.ML_CONTAMINATION,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(training)
    anomaly_values = -model.score_samples(calibration)
    quantiles = np.quantile(anomaly_values, [0.50, 0.95, 0.99, 0.999])
    if float(quantiles[3] - quantiles[0]) < 1e-6:
        return None, "degenerate feature distribution"
    validation_scores = -model.score_samples(validation)
    validation_q99_fraction = float(np.mean(validation_scores > quantiles[2]))
    if validation_q99_fraction > 0.25:
        return None, "validation traffic drift is too high for safe promotion"
    quantile_mapping = {
        "q50": float(quantiles[0]),
        "q95": float(quantiles[1]),
        "q99": float(quantiles[2]),
        "q999": float(quantiles[3]),
    }
    validation_alert_fraction = float(
        np.mean(
            [
                calibrate_anomaly_score(float(score), quantile_mapping)
                >= settings.ML_ALERT_SCORE
                for score in validation_scores
            ]
        )
    )
    if validation_alert_fraction > settings.ML_MAX_VALIDATION_ALERT_FRACTION:
        return None, "validation alert fraction is too high for safe promotion"
    return {
        "model": model,
        "features": list(FEATURE_NAMES[scope]),
        "median": np.median(training, axis=0).tolist(),
        "mad": np.maximum(
            np.median(np.abs(training - np.median(training, axis=0)), axis=0),
            0.05,
        ).tolist(),
        "raw_median": np.median(raw[:fit_end][keep[:fit_end]], axis=0).tolist(),
        "score_quantiles": quantile_mapping,
        "sample_count": len(training) + len(calibration) + len(validation),
        "fit_samples": len(training),
        "calibration_samples": len(calibration),
        "validation_samples": len(validation),
        "calibration_method": "chronological_holdout_v1",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "window_start": rows[0].window_start.isoformat(),
        "window_end": rows[-1].window_start.isoformat(),
        "training_outlier_fraction": float(np.mean(model.predict(training) == -1)),
        "validation_q99_fraction": validation_q99_fraction,
        "validation_alert_fraction": validation_alert_fraction,
    }, None


def _atomic_dump(bundle: dict) -> None:
    directory = os.path.dirname(settings.MODEL_PATH) or "."
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(prefix="behavioral-", suffix=".joblib", dir=directory)
    os.close(descriptor)
    try:
        joblib.dump(bundle, temporary_path)
        with open(temporary_path, "rb") as stream:
            os.fsync(stream.fileno())
        # The API and worker deliberately run as an unprivileged user. A model may
        # also be trained from an administrative one-off command, so make the shared
        # volume artifact readable by every service before atomically promoting it.
        os.chmod(temporary_path, 0o644)
        os.replace(temporary_path, settings.MODEL_PATH)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


@celery_app.task(name="train_model_task")
def train_model_task() -> dict:
    client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    lock = client.lock("ml:training-lock", timeout=3600, blocking_timeout=0)
    if not lock.acquire(blocking=False):
        client.close()
        return {"status": "already_running"}

    engine = create_engine(
        sync_database_url(),
        pool_pre_ping=True,
        connect_args={"sslmode": "require" if settings.DATABASE_SSL else "disable"},
    )
    version = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    try:
        trained: dict[str, dict[str, dict]] = {"server": {}, "source": {}}
        results: dict[str, dict] = {"server": {}, "source": {}}
        existing_models: dict[str, dict] = {}
        if os.path.exists(settings.MODEL_PATH):
            try:
                existing = joblib.load(settings.MODEL_PATH)
                if isinstance(existing, dict) and existing.get("schema_version") == 3:
                    existing_models = dict(existing.get("models", {}))
                    # Retaining one scope while replacing another must not
                    # freshen its timestamp or relabel detections as the new
                    # component version.
                    for group in existing_models.values():
                        for component in group.get("servers", {}).values():
                            component.setdefault("trained_at", existing.get("trained_at"))
                            component.setdefault("model_version", existing.get("version"))
            except Exception:
                logger.warning("Existing model could not be retained", exc_info=True)
        with Session(engine, expire_on_commit=False) as session:
            for scope in ("server", "source"):
                server_ids = list(
                    session.scalars(
                        select(TrafficWindow.server_id)
                        .where(TrafficWindow.scope == scope)
                        .distinct()
                    )
                )
                for server_id in server_ids:
                    rows = _select_training_rows(session, scope, server_id)
                    component, rejection_reason = _fit_scope(scope, rows)
                    if component is None:
                        state = (
                            "warming_up"
                            if len(rows) < settings.ML_MIN_TRAINING_WINDOWS
                            else "rejected"
                        )
                        results[scope][server_id] = {
                            "status": state,
                            "samples": len(rows),
                            "reason": rejection_reason,
                        }
                        session.add(
                            MlModelRun(
                                model_version=version,
                                scope=scope,
                                server_id=server_id,
                                status="skipped" if state == "warming_up" else "rejected",
                                sample_count=len(rows),
                                contamination=settings.ML_CONTAMINATION,
                                error=rejection_reason,
                            )
                        )
                        continue
                    component["model_version"] = version
                    trained[scope][server_id] = component
                    results[scope][server_id] = {
                        "status": "trained",
                        "samples": component["sample_count"],
                    }
                    session.add(
                        MlModelRun(
                            model_version=version,
                            scope=scope,
                            server_id=server_id,
                            status="trained",
                            sample_count=component["sample_count"],
                            contamination=settings.ML_CONTAMINATION,
                            window_start=datetime.fromisoformat(component["window_start"]),
                            window_end=datetime.fromisoformat(component["window_end"]),
                            metrics={
                                "training_outlier_fraction": component[
                                    "training_outlier_fraction"
                                ],
                                "validation_q99_fraction": component[
                                    "validation_q99_fraction"
                                ],
                                "validation_alert_fraction": component[
                                    "validation_alert_fraction"
                                ],
                                "score_quantiles": component["score_quantiles"],
                                "calibration_method": component["calibration_method"],
                                "fit_samples": component["fit_samples"],
                                "calibration_samples": component["calibration_samples"],
                                "validation_samples": component["validation_samples"],
                            },
                        )
                    )
            trained_any = any(trained[scope] for scope in trained)
            if trained_any:
                models: dict[str, dict] = {}
                for scope in ("server", "source"):
                    retained = dict(
                        existing_models.get(scope, {}).get("servers", {})
                    )
                    retained.update(trained[scope])
                    if retained:
                        models[scope] = {"servers": retained}
                bundle = {
                    "schema_version": 3,
                    "version": version,
                    "trained_at": datetime.now(timezone.utc).isoformat(),
                    "models": models,
                }
                _atomic_dump(bundle)
            session.commit()
        logger.info("Behavioral training %s completed: %s", version, results)
        return {
            "status": "trained" if trained_any else (
                "rejected" if any(result["status"] == "rejected" for group in results.values() for result in group.values())
                else "warming_up"
            ),
            "version": version,
            "scopes": results,
        }
    except Exception as exc:
        logger.exception("Behavioral model training failed")
        try:
            with Session(engine) as session:
                for scope in ("server", "source"):
                    session.add(
                        MlModelRun(
                            model_version=version,
                            scope=scope,
                            server_id="unknown",
                            status="failed",
                            error=str(exc)[:2000],
                        )
                    )
                session.commit()
        except Exception:
            logger.exception("Could not record failed training run")
        raise
    finally:
        engine.dispose()
        try:
            lock.release()
        except redis.exceptions.LockError:
            pass
        client.close()
