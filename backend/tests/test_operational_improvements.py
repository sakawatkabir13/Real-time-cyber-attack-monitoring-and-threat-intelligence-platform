from types import SimpleNamespace
import asyncio
import os

import geoip2.database
import pytest

import evaluate_independent as independent
from app.services.geo_lookup import GeoLookup
from app.config import settings
from app.websocket_manager import ConnectionManager
from app import websocket_manager


def sample_records():
    base = {
        "scope": "server", "server_id": "spandan-web",
        "window_seconds": 60, "features": {}, "rule_detected": False,
        "attack_start": None, "rule_alert_at": None, "ml_alert_at": None,
    }
    return [
        {**base, "record_id": 1, "label": "attack", "window_start": "2026-09-20T01:00:00Z",
         "rule_detected": True, "attack_start": "2026-09-20T01:00:00Z",
         "rule_alert_at": "2026-09-20T01:01:00Z", "features": {"score": 10}},
        {**base, "record_id": 2, "label": "attack", "window_start": "2026-09-20T02:00:00Z",
         "attack_start": "2026-09-20T02:00:00Z",
         "ml_alert_at": "2026-09-20T02:00:20Z", "features": {"score": 95}},
        {**base, "record_id": 3, "label": "benign", "window_start": "2026-09-20T03:00:00Z",
         "features": {"score": 96}},
        {**base, "record_id": 4, "label": "benign", "window_start": "2026-09-20T04:00:00Z",
         "features": {"score": 5}},
    ]


def stub_model(monkeypatch):
    monkeypatch.setattr(independent.ml_engine, "status", lambda: {
        "state": "ready", "version": "test-model",
        "models": {"server": {"servers": {"spandan-web": {
            "window_end": "2026-09-01T00:00:00Z",
        }}}},
    })
    monkeypatch.setattr(independent.ml_engine, "score", lambda _scope, _server, features:
                        SimpleNamespace(score=features["score"]))


def test_independent_metrics_compare_rules_ml_and_combined(monkeypatch):
    stub_model(monkeypatch)
    result = independent.evaluate(
        sample_records(),
        independent.parse_time("2026-09-20T00:00:00Z"),
        independent.parse_time("2026-09-21T00:00:00Z"),
    )
    assert result["rules"]["tp"] == 1 and result["rules"]["fp"] == 0
    assert result["ml"]["tp"] == 1 and result["ml"]["fp"] == 1
    assert result["combined"]["tp"] == 2 and result["combined"]["fn"] == 0
    assert result["combined"]["false_alerts_per_day"] == 1
    assert result["combined"]["mean_detection_delay_seconds"] == 40


def test_independent_evaluation_rejects_unreviewed_and_training_overlap(monkeypatch):
    stub_model(monkeypatch)
    rows = sample_records()
    rows[0]["label"] = None
    with pytest.raises(ValueError, match="independent"):
        independent.evaluate(rows, independent.parse_time("2026-09-20T00:00:00Z"),
                             independent.parse_time("2026-09-21T00:00:00Z"))
    rows[0]["label"] = "attack"
    rows[0]["window_start"] = "2026-08-31T00:00:00Z"
    with pytest.raises(ValueError):
        independent.evaluate(rows, independent.parse_time("2026-08-30T00:00:00Z"),
                             independent.parse_time("2026-09-21T00:00:00Z"))


def test_combined_delay_requires_timestamps_for_each_positive_detector(monkeypatch):
    stub_model(monkeypatch)
    rows = sample_records()
    rows[1]["rule_detected"] = True
    result = independent.evaluate(
        rows,
        independent.parse_time("2026-09-20T00:00:00Z"),
        independent.parse_time("2026-09-21T00:00:00Z"),
    )
    assert result["combined"]["timed_detections"] == 1
    assert result["ml"]["timed_detections"] == 1


@pytest.mark.asyncio
async def test_websocket_relay_reconnects_after_redis_error(monkeypatch):
    delivered = asyncio.Event()
    manager = ConnectionManager()

    async def broadcast(payload):
        assert payload == "new-event"
        delivered.set()

    monkeypatch.setattr(manager, "broadcast", broadcast)

    class Subscription:
        def __init__(self, failing):
            self.failing = failing
            self.received = False

        async def subscribe(self, _channel):
            pass

        async def get_message(self, **_kwargs):
            if self.failing:
                raise ConnectionError("Redis restarted")
            if not self.received:
                self.received = True
                return {"type": "message", "data": "new-event"}
            await asyncio.sleep(0.1)
            return None

        async def aclose(self):
            pass

    class Client:
        attempts = 0
        heartbeats = []

        def pubsub(self):
            self.attempts += 1
            return Subscription(self.attempts == 1)

        async def set(self, key, value, ex):
            self.heartbeats.append((key, value, ex))

    client = Client()
    monkeypatch.setattr(websocket_manager.redis_client, "_require_client", lambda: client)
    task = asyncio.create_task(manager.relay_published())
    try:
        await asyncio.wait_for(delivered.wait(), timeout=3)
        assert client.attempts == 2
        assert client.heartbeats[0][0] == websocket_manager.WEBSOCKET_RELAY_HEARTBEAT
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

@pytest.mark.asyncio
async def test_local_geoip_database_reloads_and_invalidates_cache(tmp_path, monkeypatch):
    database = tmp_path / "GeoLite2-City.mmdb"
    database.write_bytes(b"test")
    monkeypatch.setattr(settings, "MAXMIND_DB_PATH", str(database))
    created = []

    class Reader:
        def __init__(self, _path):
            self.generation = len(created) + 1
            self.closed = False
            created.append(self)

        def city(self, _ip):
            country = "US" if self.generation == 1 else "GB"
            return SimpleNamespace(
                country=SimpleNamespace(iso_code=country),
                location=SimpleNamespace(latitude=1.0, longitude=2.0),
            )

        def close(self):
            self.closed = True

    monkeypatch.setattr(geoip2.database, "Reader", Reader)
    lookup = GeoLookup()
    try:
        assert (await lookup.lookup("8.8.8.8"))["country"] == "US"
        first_mtime = os.stat(database).st_mtime_ns
        os.utime(database, ns=(first_mtime + 1_000_000_000,
                               first_mtime + 1_000_000_000))
        assert (await lookup.lookup("8.8.8.8"))["country"] == "GB"
        assert len(created) == 2 and created[0].closed
    finally:
        await lookup.close()
