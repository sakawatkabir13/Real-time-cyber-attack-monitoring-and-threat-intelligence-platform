"""Regression tests, not independent model-accuracy evaluation (point 6)."""

import asyncio
from datetime import datetime, timedelta, timezone
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid

import fakeredis.aioredis
import numpy as np
import pytest
import pytest_asyncio
from pydantic import ValidationError

from app.config import DetectionProfile, settings
from app.redis_client import redis_client
from app.schemas.alert import AlertReviewRequest
from app.services.behavioral_features import PENDING_WINDOWS, behavioral_features, values_from_snapshot
from app.services.detection_engine import DetectionEngine
from app.services.incident_grouping import Observation, related_clusters
from app.services.log_parser import parse_event
from app.services.ml_features import FEATURE_NAMES, transform_vector
from app.services import window_scoring
from app.services.ml_engine import MLEngine
from app.services.ml_features import window_values
from app.tasks import train_model


@pytest_asyncio.fixture
async def redis(monkeypatch):
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(redis_client, "redis", client)
    yield client
    await client.aclose()


def entry(path="/", status=200, timestamp=None, duration=None, ip="203.0.113.7", server="web-a", event_id=None, ua="curl/8.0"):
    return parse_event(dict(source_ip=ip, timestamp=timestamp or "2026-08-05T00:00:01Z",
                           path=path, status_code=status, request_time=duration,
                           user_agent=ua, bytes_sent=100, event_id=event_id or uuid.uuid4().hex), server)


def test_parser_preserves_missing_timing_and_accepts_json_lines_and_rt_suffix():
    log = '203.0.113.7 - - [05/Aug/2026:00:00:01 +0000] "GET / HTTP/1.1" 200 100 "-" "curl/8.0"'
    assert parse_event({"raw_log": log}, "web").request_time is None
    assert parse_event({"raw_log": log + " rt=0.123"}, "web").request_time == 0.123
    assert parse_event({"raw_log": log + " rt_us=123000"}, "web").request_time == 0.123
    data = dict(ip="203.0.113.7", timestamp="2026-08-05T06:00:01+06:00", request_time=5.0)
    parsed = parse_event({"raw_log": json.dumps(data)}, "web")
    assert parsed.timestamp == "2026-08-05T00:00:01+00:00"
    assert parsed.request_time == 5.0


@pytest.mark.parametrize("timestamp", ["", "yesterday", "2026-08-05T00:00:01", "2999-01-01T00:00:00Z"])
def test_bad_timestamps_are_rejected_not_replaced_with_arrival_time(timestamp):
    assert parse_event({"ip": "203.0.113.7", "timestamp": timestamp}, "web") is None


@pytest.mark.parametrize("duration", [-1, float("nan"), float("inf"), "bad"])
def test_bad_measurements_are_rejected(duration):
    assert entry(duration=duration) is None


@pytest.mark.asyncio
async def test_event_time_replay_boundaries_out_of_order_and_retry(redis):
    async def count(stamp, identity, server="a"):
        return (await redis_client.event_counts("203.0.113.7", server_id=server,
                timestamp=stamp, event_id=identity, counters={"requests": True}))["requests"]
    # Replaying an hour of traffic immediately does not turn it into a flood.
    observed = [await count(10000 + i * 18, str(i)) for i in range(200)]
    assert max(observed) <= 17
    assert await count(20000, "new") == 1
    assert await count(20000, "new") == 1
    assert await count(20000, "same-id-other-server", "b") == 1
    assert await count(19990, "late") == 1  # Future events aren't counted backward.
    assert await count(20001, "after-late") == 3
    assert await count(20301, "boundary") == 1  # lower boundary is exclusive


@pytest.mark.asyncio
async def test_busy_clean_traffic_and_curl_are_not_attacks():
    engine = DetectionEngine()
    log = entry()
    now = datetime.now(timezone.utc)
    assert await engine._detect_rule(log, now, 1000, {"requests": 1000, "same_path": 1000}) is None
    bad = entry(status=503)
    finding = await engine._detect_rule(bad, now, 200, {"same_path": 180, "server_errors": 150})
    assert finding.attack_type == "http_flood"
    assert finding.severity == "high"
    # SQL indicators retain their explanation rather than being masked by volume.
    finding = await engine._detect_rule(entry("/?id=1+UNION+SELECT+1"), now, 200,
                                       {"same_path": 180, "server_errors": 150})
    assert finding.attack_type == "sql_injection"


@pytest.mark.asyncio
async def test_slow_response_requires_timing_coverage_and_server_profiles(monkeypatch):
    engine, log, now = DetectionEngine(), entry(duration=5), datetime.now(timezone.utc)
    assert await engine._detect_rule(log, now, 200, {"same_path": 200, "timed": 1, "slow": 1}) is None
    assert (await engine._detect_rule(log, now, 200, {"same_path": 200, "timed": 200, "slow": 190})).attack_type == "http_flood"
    monkeypatch.setattr(settings, "DETECTION_PROFILES", {"web-a": DetectionProfile(request_threshold=1000)})
    assert await engine._detect_rule(log, now, 200, {"same_path": 200, "server_errors": 200}) is None


@pytest.mark.asyncio
async def test_auth_failures_need_failure_ratio():
    engine, log, now = DetectionEngine(), entry("/api/login/demo", 401), datetime.now(timezone.utc)
    assert await engine._detect_rule(log, now, 100, {"failed_auth": 16, "auth": 100}) is None
    event = await engine._detect_rule(log, now, 20, {"failed_auth": 16, "auth": 20})
    assert event.attack_type == "brute_force"


async def observe(log):
    await behavioral_features.observe(log=log, timestamp=datetime.fromisoformat(log.timestamp),
                                     rule_threat=False, reputation_score=0, reporter_count=0, community_reports=0)


@pytest.mark.asyncio
async def test_atomic_windows_retry_missingness_bursts_and_coordination(redis):
    start = int(time.time() // 300) * 300 - 900
    for i in range(20):
        stamp = datetime.fromtimestamp(start + i, timezone.utc).isoformat()
        log = entry("/shared", timestamp=stamp, duration=0.2 if i < 10 else None,
                    ip=f"203.0.113.{i + 1}", event_id=f"steady-{i}")
        await observe(log)
        await observe(log)  # Duplicate delivery must not change counts.
    bases = await redis.zrange(PENDING_WINDOWS, 0, -1)
    server = next(base for base in bases if ":server:" in base)
    data, cards, top = await behavioral_features._snapshot(server)
    values = values_from_snapshot(data, cards, top)
    assert int(data["request_count"]) == 20
    assert values["avg_request_time"] == pytest.approx(0.2)
    assert values["request_time_coverage"] == 0.5
    assert values["burst_ratio"] == 0.05
    assert values["max_path_unique_ips"] == 20
    assert values["previous_window_present"] == 0
    # Same count/rate, different rhythm.
    stamp = datetime.fromtimestamp(start + 60, timezone.utc).isoformat()
    for i in range(20):
        await observe(entry("/shared", timestamp=stamp, event_id=f"burst-{i}"))
    bases = await redis.zrange(PENDING_WINDOWS, 0, -1)
    newest = sorted(base for base in bases if ":server:" in base)[-1]
    data, cards, top = await behavioral_features._snapshot(newest)
    values = values_from_snapshot(data, cards, top)
    assert values["burst_ratio"] == 1.0
    assert values["previous_window_present"] == 1
    assert values["rate_change_ratio"] == 1.0
    assert values["avg_request_time"] is None
    assert len(transform_vector("server", values)) == len(FEATURE_NAMES["server"])


@pytest.mark.asyncio
async def test_quiet_source_is_scored_without_another_request(redis, monkeypatch):
    stamp = datetime.fromtimestamp(int(time.time() // 300) * 300 - 600, timezone.utc).isoformat()
    for i in range(5):
        await observe(entry(timestamp=stamp, event_id=f"quiet-{i}"))
    bases = await redis.zrange(PENDING_WINDOWS, 0, -1)
    base = next(base for base in bases if ":source:" in base)
    await redis.zadd(PENDING_WINDOWS, {base: time.time() - 1})
    calls = []
    def predict(scope, server_id, values):
        calls.append((scope, server_id, values))
        return SimpleNamespace(score=10, model_version="test", explanation="test normal window")
    monkeypatch.setattr(window_scoring.ml_engine, "score", predict)
    db = AsyncMock()
    db.scalar.return_value = None
    manager = AsyncMock()
    manager.__aenter__.return_value = db
    monkeypatch.setattr(window_scoring, "AsyncSessionLocal", lambda: manager)
    assert await window_scoring.score_window(base)
    assert calls[0][0:2] == ("source", "web-a")
    assert await redis.zscore(PENDING_WINDOWS, base) is None
    assert await redis.hget(base, "scored_revision") == "5"
    assert not await window_scoring.score_window(base)


@pytest.mark.asyncio
async def test_missing_model_and_worker_failure_keep_window_retryable(redis, monkeypatch):
    stamp = datetime.fromtimestamp(int(time.time() // 300) * 300 - 600, timezone.utc).isoformat()
    for i in range(5):
        await observe(entry(timestamp=stamp, event_id=f"retry-{i}"))
    base = next(b for b in await redis.zrange(PENDING_WINDOWS, 0, -1) if ":source:" in b)
    await redis.zadd(PENDING_WINDOWS, {base: time.time() - 1})
    monkeypatch.setattr(window_scoring.ml_engine, "score", lambda *args: None)
    assert not await window_scoring.score_window(base)
    assert await redis.zscore(PENDING_WINDOWS, base) > time.time()
    assert await redis.get(f"ml:scoring-lock:{base}") is None


@pytest.mark.asyncio
async def test_changed_window_is_not_acknowledged_from_an_old_snapshot(redis, monkeypatch):
    stamp = datetime.fromtimestamp(int(time.time() // 300) * 300 - 600, timezone.utc).isoformat()
    for i in range(5):
        await observe(entry(timestamp=stamp, event_id=f"racing-{i}"))
    base = next(b for b in await redis.zrange(PENDING_WINDOWS, 0, -1) if ":source:" in b)
    await redis.zadd(PENDING_WINDOWS, {base: time.time() - 1})
    snapshot = behavioral_features._snapshot
    async def changed_snapshot(key):
        result = await snapshot(key)
        await observe(entry(timestamp=stamp, event_id="arrived-during-snapshot"))
        return result
    monkeypatch.setattr(behavioral_features, "_snapshot", changed_snapshot)
    monkeypatch.setattr(window_scoring.ml_engine, "score", lambda *args: SimpleNamespace(score=99))
    assert not await window_scoring.score_window(base)
    assert await redis.zscore(PENDING_WINDOWS, base) is not None
    assert await redis.hget(base, "scored_revision") is None


@pytest.mark.asyncio
async def test_late_preceding_period_requeues_rate_change_context(redis):
    start = int(time.time() // 300) * 300 - 900
    first = datetime.fromtimestamp(start, timezone.utc).isoformat()
    following = datetime.fromtimestamp(start + 60, timezone.utc).isoformat()
    await observe(entry(timestamp=first, event_id="first"))
    await observe(entry(timestamp=following, event_id="following"))
    base = next(b for b in await redis.zrange(PENDING_WINDOWS, 0, -1)
                if ":server:" in b and b.endswith(str(start + 60)))
    await redis.zrem(PENDING_WINDOWS, base)
    await observe(entry(timestamp=first, event_id="late-preceding"))
    assert await redis.zscore(PENDING_WINDOWS, base) is not None
    data, cards, top = await behavioral_features._snapshot(base)
    assert values_from_snapshot(data, cards, top)["rate_change_ratio"] == 0.5


@pytest.mark.asyncio
async def test_snapshot_failure_releases_lock_and_delays_retry(redis, monkeypatch):
    base = "ml:window:source:test:entity:1000"
    await redis.zadd(PENDING_WINDOWS, {base: time.time() - 1})
    monkeypatch.setattr(behavioral_features, "_snapshot", AsyncMock(side_effect=RuntimeError("temporary failure")))
    assert await window_scoring.score_due_windows() == 0
    assert await redis.zscore(PENDING_WINDOWS, base) > time.time()
    assert await redis.get(f"ml:scoring-lock:{base}") is None


def test_review_requires_a_verdict_evidence_and_concurrency_version():
    valid = AlertReviewRequest(verdict="legitimate", notes="Reviewed launch traffic", expected_version=0)
    assert valid.verdict == "legitimate"
    for invalid in [dict(verdict="acknowledged", notes="seen", expected_version=0),
                    dict(verdict="legitimate", notes=" ", expected_version=0),
                    dict(verdict="uncertain", notes="checking", expected_version=-1)]:
        with pytest.raises(ValidationError):
            AlertReviewRequest(**invalid)


def test_clustering_requires_distinct_sources_and_never_mixes_servers_or_paths():
    now = datetime.now(timezone.utc)
    def item(i, source=None, server="a", path="/login", seconds=0):
        return Observation(uuid.uuid4(), server, "brute_force", source or f"203.0.113.{i}",
                           path, now + timedelta(seconds=seconds), 82)
    nearby = [item(1), item(2, seconds=20), item(3, seconds=40)]
    assert len(related_clusters(nearby)) == 1
    assert not related_clusters([item(1, source="203.0.113.1") for _ in range(4)])
    assert not related_clusters([item(1), item(2, server="b"), item(3, path="/different")])
    assert not related_clusters([item(1), item(2, seconds=1000), item(3, seconds=2000)])


@pytest.mark.parametrize("scope", ["server", "source"])
def test_schema_three_training_artifact_and_inference_are_compatible(scope, tmp_path, monkeypatch):
    # Numerical interface smoke test only: fixture values are not production
    # training data, attack labels, or an accuracy evaluation.
    rng = np.random.default_rng(17)
    rows = []
    for _ in range(250):
        fields = {name: float(rng.uniform(0.4, 0.6)) for name in FEATURE_NAMES[scope]}
        fields["window_start"] = datetime(2026, 8, 5, tzinfo=timezone.utc)
        rows.append(SimpleNamespace(**fields))
    constructor = train_model.IsolationForest
    monkeypatch.setattr(train_model, "IsolationForest", lambda **kwargs: constructor(**{**kwargs, "n_jobs": 1}))
    # Reach the serialization/inference path with this artificial fixture;
    # production promotion limits and validation logic remain unchanged.
    monkeypatch.setattr(settings, "ML_MAX_VALIDATION_ALERT_FRACTION", 0.5)
    component, reason = train_model._fit_scope(scope, rows)
    assert component is not None, reason
    monkeypatch.setattr(settings, "MODEL_PATH", str(tmp_path / "schema-three.joblib"))
    train_model._atomic_dump({"schema_version": 3, "version": "interface-test", "models": {
        scope: {"servers": {"test": component}},
    }})
    prediction = MLEngine().score(scope, "test", window_values(rows[0]))
    assert prediction is not None and 0 <= prediction.score <= 100
    assert component["features"] == list(FEATURE_NAMES[scope])
