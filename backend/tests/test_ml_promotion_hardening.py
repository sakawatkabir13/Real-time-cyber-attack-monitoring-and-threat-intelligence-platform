from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
import time

import fakeredis.aioredis
import fakeredis
import numpy as np
import pytest

from app import main
from app.config import settings
from app.redis_client import redis_client
from app.services.behavioral_features import PENDING_WINDOWS, behavioral_features
from app.services.log_parser import parse_event
from app.services.ml_features import FEATURE_NAMES
from app.services.ml_engine import MLEngine
from app.services.training_data import snapshot_training_eligible
from app.services import window_scoring
from app.tasks import train_model
from quarantine_demo_windows import demo_windows


def candidate_rows(scope="server"):
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    return [SimpleNamespace(**{**{name: .5 + index / 1000 for name in FEATURE_NAMES[scope]},
                              "previous_window_present": 0,
                              "window_start": start + timedelta(minutes=index // 3)})
            for index in range(15)]


def fake_forest(monkeypatch):
    captured = {}
    class Forest:
        def __init__(self, **kwargs):
            captured["arguments"] = kwargs
        def fit(self, x):
            captured["fit"] = x.copy()
        def score_samples(self, x):
            calls = captured.setdefault("score_calls", [])
            calls.append(x.copy())
            return -np.array(np.linspace(.3, .5, len(x)) if len(calls) == 1 else
                             captured.get("validation_scores", np.linspace(.31, .33, len(x))))
        def predict(self, x):
            return np.ones(len(x))
    monkeypatch.setattr(train_model, "IsolationForest", Forest)
    monkeypatch.setattr(settings, "ML_MIN_TRAINING_WINDOWS", 5)
    return captured


def test_calibration_uses_disjoint_chronological_periods_without_timestamp_leakage(monkeypatch):
    captured = fake_forest(monkeypatch)
    component, reason = train_model._fit_scope("server", list(reversed(candidate_rows())))
    assert reason is None
    assert len(captured["fit"]) == 9
    assert [len(x) for x in captured["score_calls"]] == [3, 3]
    assert captured["fit"][:, 0].max() < captured["score_calls"][0][:, 0].min()
    assert captured["score_calls"][0][:, 0].max() < captured["score_calls"][1][:, 0].min()
    assert component["score_quantiles"]["q50"] == pytest.approx(.4)
    assert component["fit_samples"] == 9
    assert component["calibration_samples"] == component["validation_samples"] == 3
    assert component["calibration_method"] == "chronological_holdout_v1"


@pytest.mark.parametrize("scope", ["server", "source"])
def test_validation_outliers_are_not_discarded_to_pass_promotion(monkeypatch, scope):
    captured = fake_forest(monkeypatch)
    rows = candidate_rows(scope)
    rows[-1].avg_bytes = 1e20
    component, reason = train_model._fit_scope(scope, rows)
    assert reason is None
    assert component["validation_samples"] == 3
    assert captured["score_calls"][1].max() > 40


@pytest.mark.parametrize("scope", ["server", "source"])
@pytest.mark.parametrize("majority", [0, 1])
def test_valid_binary_changes_remain_in_all_training_periods(monkeypatch, scope, majority):
    captured = fake_forest(monkeypatch)
    rows = candidate_rows(scope)
    for index, row in enumerate(rows):
        row.previous_window_present = 1 - majority if index in (7, 8, 9, 12) else majority
    component, reason = train_model._fit_scope(scope, rows)
    assert reason is None
    assert component["sample_count"] == len(rows)
    column = FEATURE_NAMES[scope].index("previous_window_present")
    assert np.array_equal(captured["fit"][:, column], [row.previous_window_present for row in rows[:9]])
    for actual, expected in zip(captured["score_calls"], (rows[9:12], rows[12:])):
        assert np.array_equal(actual[:, column], [row.previous_window_present for row in expected])


@pytest.mark.parametrize("scope", ["server", "source"])
@pytest.mark.parametrize("index", [0, 9, 12])
@pytest.mark.parametrize("value", [-1, .5, 2, float("nan"), float("inf"), -float("inf")])
def test_invalid_binary_values_reject_candidate_including_validation(monkeypatch, scope, index, value):
    captured = fake_forest(monkeypatch)
    rows = candidate_rows(scope)
    rows[index].previous_window_present = value
    component, reason = train_model._fit_scope(scope, rows)
    assert component is None
    assert reason == ("invalid binary traffic feature values" if np.isfinite(value)
                      else "non-finite traffic feature values")
    assert "fit" not in captured


@pytest.mark.parametrize("scope", ["server", "source"])
@pytest.mark.parametrize("index", [0, 9, 12])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_non_finite_continuous_values_reject_before_transform(monkeypatch, scope, index, value):
    captured = fake_forest(monkeypatch)
    rows = candidate_rows(scope)
    rows[index].avg_bytes = value
    component, reason = train_model._fit_scope(scope, rows)
    assert component is None and reason == "non-finite traffic feature values"
    assert "fit" not in captured


@pytest.mark.parametrize("scope", ["server", "source"])
@pytest.mark.parametrize("index,partition", [(0, "fit"), (9, "calibration")])
def test_continuous_extremes_are_still_quarantined(monkeypatch, scope, index, partition):
    captured = fake_forest(monkeypatch)
    rows = candidate_rows(scope)
    rows[index].avg_bytes = 1e20
    component, reason = train_model._fit_scope(scope, rows)
    assert reason is None
    assert component["sample_count"] == len(rows) - 1
    assert component[partition + "_samples"] == (8 if partition == "fit" else 2)
    column = FEATURE_NAMES[scope].index("avg_bytes")
    assert captured["fit"][:, column].max() < 40
    assert captured["score_calls"][0][:, column].max() < 40
    assert component["validation_samples"] == 3


def test_continuous_quarantine_cannot_bypass_minimum_samples(monkeypatch):
    captured = fake_forest(monkeypatch)
    rows = candidate_rows()
    rows[0].avg_bytes = 1e20
    monkeypatch.setattr(settings, "ML_MIN_TRAINING_WINDOWS", len(rows))
    component, reason = train_model._fit_scope("server", rows)
    assert component is None and reason == "too many extreme or potentially poisoned windows"
    assert "fit" not in captured


def test_repeated_same_period_cannot_be_split_into_fake_holdout(monkeypatch):
    fake_forest(monkeypatch)
    rows = candidate_rows()
    for row in rows:
        row.window_start = rows[0].window_start
    component, reason = train_model._fit_scope("server", rows)
    assert component is None and "distinct traffic periods" in reason


@pytest.mark.parametrize("scores,reason_fragment", [([1., 1., 1.], "drift"),
                                                       ([.497, .497, .497], "alert fraction")])
@pytest.mark.parametrize("scope", ["server", "source"])
def test_validation_gates_still_reject_unsafe_candidates(monkeypatch, scope, scores, reason_fragment):
    captured = fake_forest(monkeypatch)
    captured["validation_scores"] = scores
    monkeypatch.setattr(settings, "ML_ALERT_SCORE", 90)
    component, reason = train_model._fit_scope(scope, candidate_rows(scope))
    assert component is None and reason_fragment in reason


def test_retained_component_predictions_use_original_version(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "MODEL_PATH", str(tmp_path / "absent-model.joblib"))
    engine = MLEngine()
    size = len(FEATURE_NAMES["server"])
    component = {"model": SimpleNamespace(score_samples=lambda _: np.array([-.4])),
                 "median": [0] * size, "mad": [1] * size,
                 "score_quantiles": {"q50": .4, "q95": .5, "q99": .6, "q999": .7},
                 "trained_at": "2026-10-20T00:00:00+00:00", "model_version": "old-component"}
    engine.bundle = {"version": "new-sibling-bundle", "models": {"server": {"servers": {"site": component}}}}
    assert engine.score("server", "site", {}).model_version == "old-component"
    assert engine.status()["models"]["server"]["servers"]["site"]["trained_at"] == component["trained_at"]


def test_fresh_sibling_cannot_hide_stale_model_component():
    now = datetime.now(timezone.utc)
    payload = {"state": "ready", "trained_at": now.isoformat(), "models": {
        "server": {"servers": {"site": {"trained_at": now.isoformat()}}},
        "source": {"servers": {"site": {"trained_at": (now - timedelta(days=4)).isoformat()}}},
    }}
    assert main._model_is_fresh(payload) is False
    payload["models"]["source"]["servers"]["site"]["trained_at"] = now.isoformat()
    assert main._model_is_fresh(payload) is True


def test_historical_demo_quarantine_requires_exact_provenance_and_server():
    client = fakeredis.FakeRedis(decode_responses=True)
    for number, (server, event) in enumerate([("site", "demo-ml-burst-one"),
                                              ("site", "real-agent-event"),
                                              ("other", "demo-ml-burst-other")]):
        base = f"ml:window:source:hash:entity{number}:100"
        client.hset(base, mapping={"server_id": server, "scope": "source", "entity_key": f"entity{number}",
                                   "window_start": "100", "window_seconds": "300"})
        client.sadd(base + ":events", event)
    assert list(demo_windows(client, "site")) == ["ml:window:source:hash:entity0:100"]
    client.close()


@pytest.mark.asyncio
async def test_demo_windows_are_excluded_from_training_but_still_score_and_alert(monkeypatch):
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(redis_client, "redis", client)
    monkeypatch.setattr(settings, "ML_MIN_SERVER_REQUESTS", 1)
    start = int(time.time() // 60) * 60 - 120
    log = parse_event(dict(event_id="demo-ml-burst-001", source_ip="203.0.113.7",
                           timestamp=datetime.fromtimestamp(start, timezone.utc).isoformat(),
                           path="/", status_code=200, bytes_sent=100, user_agent="Mozilla/5.0"), "site")
    try:
        await behavioral_features.observe(log=log, timestamp=datetime.fromtimestamp(start, timezone.utc),
                                         rule_threat=False, reputation_score=0, reporter_count=0, community_reports=0)
        base = next(b for b in await client.zrange(PENDING_WINDOWS, 0, -1) if ":server:" in b)
        snapshot = await client.hgetall(base)
        assert snapshot["demonstration_request_count"] == "1"
        assert snapshot.get("baseline_excluded_count", "0") == "0"
        assert not snapshot_training_eligible(snapshot, enumeration=False, anomaly_score=10)
        await client.zadd(PENDING_WINDOWS, {base: time.time() - 1})
        monkeypatch.setattr(window_scoring.ml_engine, "score", lambda *args: SimpleNamespace(
            score=99, model_version="test", explanation="test"))
        monkeypatch.setattr(window_scoring, "AsyncSessionLocal", lambda: AsyncMock())
        persist = AsyncMock()
        monkeypatch.setattr(window_scoring, "persist_threats", persist)
        assert await window_scoring.score_window(base)
        assert persist.await_args.args[1][0].event.attack_type == "server_traffic_anomaly"
    finally:
        await client.aclose()
