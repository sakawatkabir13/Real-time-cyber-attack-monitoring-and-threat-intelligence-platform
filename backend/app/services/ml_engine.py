"""Versioned behavioral anomaly models with atomic hot reload and explanations."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
from typing import Any, Mapping

import joblib
import numpy as np

from app.config import settings
from app.services.ml_features import (
    FEATURE_LABELS,
    FEATURE_NAMES,
    calibrate_anomaly_score,
    transform_vector,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MLPrediction:
    scope: str
    score: float
    explanation: str
    model_version: str


class MLEngine:
    """Load a two-scope model bundle and score completed traffic windows."""

    def __init__(self) -> None:
        self.bundle: dict[str, Any] | None = None
        self._last_mtime = 0.0
        self.load_model()

    def load_model(self) -> None:
        if not os.path.exists(settings.MODEL_PATH):
            if self.bundle is None:
                self._last_mtime = 0.0
            logger.info("Behavioral model is warming up; no model artifact exists yet")
            return
        try:
            candidate = joblib.load(settings.MODEL_PATH)
            if not isinstance(candidate, dict) or candidate.get("schema_version") != 2:
                raise ValueError("unsupported model artifact; real-window schema v2 required")
            self.bundle = candidate
            self._last_mtime = os.path.getmtime(settings.MODEL_PATH)
            logger.info(
                "Loaded behavioral model %s with scopes %s",
                candidate.get("version"),
                sorted(candidate.get("models", {})),
            )
        except Exception as exc:
            logger.error("Could not load behavioral model: %s", exc)
            # Keep serving the last successfully loaded model if a new artifact is
            # temporarily unreadable or corrupt. Atomic promotion means this should
            # be rare, but losing a known-good model would be the unsafe response.

    def reload_if_updated(self) -> None:
        if not os.path.exists(settings.MODEL_PATH):
            return
        try:
            mtime = os.path.getmtime(settings.MODEL_PATH)
            if mtime != self._last_mtime:
                self.load_model()
        except OSError as exc:
            logger.warning("Could not stat behavioral model: %s", exc)

    @staticmethod
    def _explanation(
        scope: str,
        score: float,
        vector: np.ndarray,
        component: Mapping[str, Any],
    ) -> str:
        medians = np.asarray(component["median"], dtype=float)
        mads = np.maximum(np.asarray(component["mad"], dtype=float), 1e-6)
        deviations = np.abs((vector - medians) / mads)
        reasons: list[str] = []
        for index in np.argsort(deviations)[::-1]:
            if len(reasons) == 3:
                break
            if deviations[index] < 2.0:
                continue
            name = FEATURE_NAMES[scope][int(index)]
            if name.endswith(("_sin", "_cos")):
                continue
            direction = "above" if vector[index] > medians[index] else "below"
            reasons.append(
                f"{FEATURE_LABELS[name]} {direction} its learned baseline "
                f"({deviations[index]:.1f} robust deviations)"
            )
        evidence = "; ".join(reasons) or "an unusual multivariate feature combination"
        label = "server traffic" if scope == "server" else "source behavior"
        return f"ML {label} anomaly score {score:.1f}/100: {evidence}."

    def score(
        self,
        scope: str,
        server_id: str,
        values: Mapping[str, float | int | None],
    ) -> MLPrediction | None:
        self.reload_if_updated()
        if not self.bundle or scope not in self.bundle.get("models", {}):
            return None
        component = self.bundle["models"][scope].get("servers", {}).get(server_id)
        if component is None:
            return None
        vector = transform_vector(scope, values)
        model = component["model"]
        raw_score = float(-model.score_samples(vector.reshape(1, -1))[0])
        score = calibrate_anomaly_score(raw_score, component["score_quantiles"])
        return MLPrediction(
            scope=scope,
            score=score,
            explanation=self._explanation(scope, score, vector, component),
            model_version=str(self.bundle["version"]),
        )

    def status(self) -> dict[str, Any]:
        self.reload_if_updated()
        if not self.bundle:
            return {"state": "warming_up", "version": None, "models": {}}
        return {
            "state": "ready",
            "version": self.bundle.get("version"),
            "trained_at": self.bundle.get("trained_at"),
            "models": {
                scope: {
                    "samples": sum(
                        model.get("sample_count", 0)
                        for model in component.get("servers", {}).values()
                    ),
                    "servers": {
                        server_id: {
                            "samples": model.get("sample_count", 0),
                            "window_start": model.get("window_start"),
                            "window_end": model.get("window_end"),
                        }
                        for server_id, model in component.get("servers", {}).items()
                    },
                }
                for scope, component in self.bundle.get("models", {}).items()
            },
        }


ml_engine = MLEngine()
