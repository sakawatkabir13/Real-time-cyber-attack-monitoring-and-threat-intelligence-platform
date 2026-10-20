"""All-request map delivery must never turn ordinary requests into threats."""

from datetime import datetime, timezone
import json
from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest
import pytest_asyncio

from app.config import settings
from app.redis_client import redis_client
from app.services import http_traffic
from app.services.http_traffic import HttpObservation, publish_http_requests, recent_http_requests
from app.services.detection_engine import DetectionEngine
from app.services.log_parser import parse_event
from app.services.behavioral_features import PENDING_WINDOWS, behavioral_features
from app.services.training_data import snapshot_training_eligible, select_training_candidates
from app.routers import ingest
from quarantine_scanner_windows import affected_windows
from types import SimpleNamespace


@pytest_asyncio.fixture
async def redis(monkeypatch):
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(redis_client, "redis", client)
    monkeypatch.setattr(http_traffic.geo_lookup, "lookup", AsyncMock(return_value={"lat": 23.8, "lon": 90.4, "country": "BD"}))
    yield client
    await client.aclose()


def log(identity="one", path="/", status=200, ua="Mozilla/5.0", server="spandan-web", ip="203.0.113.7"):
    return parse_event(dict(event_id=identity, source_ip=ip, path=path, status_code=status,
                           user_agent=ua, bytes_sent=100,
                           timestamp=datetime.now(timezone.utc).isoformat()), server)


@pytest.mark.asyncio
async def test_neutral_and_detected_requests_are_delivered_once_with_separate_classification(redis):
    normal, scanner = log(path="/?token=private-value"), log("two", ua="Fuzz Faster U Fool v2.1.0-dev")
    finding = await DetectionEngine()._detect_rule(scanner, datetime.now(timezone.utc), 1)
    assert finding.attack_type == "scanner"
    async with redis.pubsub() as subscription:
        await subscription.subscribe(http_traffic.WEBSOCKET_EVENT_CHANNEL)
        await subscription.get_message()
        observations = [HttpObservation(normal), HttpObservation(scanner, finding)]
        assert await publish_http_requests(observations) == 2
        message = await subscription.get_message(ignore_subscribe_messages=True, timeout=1)
        body = json.loads(message["data"])
        assert body["type"] == "HTTP_TRAFFIC"
        assert len(body["data"]) == 2
        assert {row["severity"] for row in body["data"]} == {"normal", "medium"}
        assert "private-value" not in message["data"]
        assert await publish_http_requests(observations) == 0
    recent = await recent_http_requests()
    assert len(recent) == 2
    assert all(row["kind"] == "http_request" for row in recent)
    assert all(row["lat"] == 23.8 for row in recent)
    # Duplicate sources use one enrichment per batch.
    assert http_traffic.geo_lookup.lookup.await_count == 2


@pytest.mark.asyncio
async def test_snapshot_is_bounded_and_scoped_without_sampling_live_publication(redis, monkeypatch):
    monkeypatch.setattr(settings, "MAP_TRAFFIC_LIMIT", 3)
    observations = [HttpObservation(log(str(i), server="other" if i == 3 else "spandan-web")) for i in range(4)]
    assert await publish_http_requests(observations) == 4
    assert await redis.zcard(http_traffic.TRAFFIC_INDEX) == 3
    assert await redis.hlen(http_traffic.TRAFFIC_DATA) == 3
    assert len(await recent_http_requests(server_id="other")) == 1
    assert len(await recent_http_requests(server_id="spandan-web")) == 2
    assert len(await recent_http_requests(limit=1)) == 1


@pytest.mark.asyncio
async def test_normal_requests_publish_without_creating_threats_or_replaying_retries(redis, monkeypatch):
    await redis.set("ip_data:203.0.113.7", "{}")
    monkeypatch.setattr(ingest, "verify_collector_token", lambda _: None)
    monkeypatch.setattr(ingest, "AsyncSessionLocal", lambda: AsyncMock())
    persist = AsyncMock(return_value=[])
    monkeypatch.setattr(ingest, "persist_threats", persist)
    batch = ingest.AgentBatch(server_id="spandan-web", events=[log().model_dump()])
    assert (await ingest.ingest_batch(batch))["accepted"] == 1
    assert persist.await_args.args[1] == []
    assert len(await recent_http_requests()) == 1
    assert (await ingest.ingest_batch(batch))["duplicates"] == 1
    assert len(await recent_http_requests()) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("ua", ["ffuf/2.1.0", "Fuzz Faster U Fool v2.1.0-dev", "fUzZ fAsTeR u FoOl v2"])
async def test_ffuf_is_detected_and_taints_both_baseline_scopes_even_without_a_rule_result(redis, ua):
    request = log(ua=ua)
    finding = await DetectionEngine()._detect_rule(request, datetime.now(timezone.utc), 1)
    assert finding.attack_type == "scanner"
    # Defense in depth: baseline guards do not depend on the rule return value.
    await behavioral_features.observe(log=request, timestamp=datetime.fromisoformat(request.timestamp),
                                     rule_threat=False, reputation_score=0, reporter_count=0, community_reports=0)
    for base in await redis.zrange(PENDING_WINDOWS, 0, -1):
        data = await redis.hgetall(base)
        assert data["scanner_request_count"] == "1"
        assert data["baseline_excluded_count"] == "1"
        assert not snapshot_training_eligible(data, enumeration=False, anomaly_score=1)


@pytest.mark.asyncio
async def test_rate_limited_auth_is_not_normal_training_data_before_detection_threshold(redis):
    request = log(path="/api/v1/auth/login", status=429)
    await behavioral_features.observe(log=request, timestamp=datetime.fromisoformat(request.timestamp),
                                     rule_threat=False, reputation_score=0, reporter_count=0, community_reports=0)
    for base in await redis.zrange(PENDING_WINDOWS, 0, -1):
        assert not snapshot_training_eligible(await redis.hgetall(base), enumeration=False, anomaly_score=None)
    # Ordinary endpoint rate limits are not called authentication brute force.
    finding = await DetectionEngine()._detect_rule(log(path="/api/search", status=429), datetime.now(timezone.utc), 100,
                                                 {"auth": 30, "limited_auth": 30})
    assert finding is None


@pytest.mark.asyncio
async def test_auth_rejection_rule_includes_throttling_without_claiming_password_failure():
    engine, stamp = DetectionEngine(), datetime.now(timezone.utc)
    request = log(path="/api/v1/auth/login", status=429)
    finding = await engine._detect_rule(request, stamp, 100, {"auth": 100, "failed_auth": 3, "limited_auth": 97})
    assert finding.attack_type == "brute_force"
    assert "3 authentication failures" in finding.explanation
    assert "97 rate-limited" in finding.explanation
    assert "not an invalid password" in finding.explanation
    assert await engine._detect_rule(request, stamp, 100, {"auth": 100, "limited_auth": 2}) is None


def test_training_selection_rechecks_quarantine_and_current_alert_threshold():
    def row(**changes):
        fields = dict(server_id="web", entity_key="v3-server", request_count=50,
                      unique_paths=5, request_rate=0.8, peak_second_requests=3, top_path_share=0.8,
                      is_training_eligible=True, rule_threat_count=0, anomaly_score=None)
        fields.update(changes)
        return SimpleNamespace(**fields)
    clean = row()
    selected, _ = select_training_candidates([
        row(is_training_eligible=False), row(rule_threat_count=1),
        row(anomaly_score=settings.ML_ALERT_SCORE), clean,
    ], "server")
    assert selected == [clean]


def test_log_evidence_quarantines_source_and_server_without_replaying_requests(tmp_path):
    path = tmp_path / "access.log"
    base = dict(timestamp=1792505743.464, source_ip="103.129.210.42", method="POST",
                path="/api/v1/auth/login", status_code=200, bytes_sent=100,
                user_agent="Mozilla/5.0")
    path.write_text("\n".join(json.dumps(row) for row in (
        base, {**base, "user_agent": "Fuzz Faster U Fool v2.1.0-dev"},
        {**base, "status_code": 429},
    )))
    counts, evidence = affected_windows([str(path), str(path)], "spandan-web")
    assert evidence == 2
    assert len(counts) == 2
    assert {key[0] for key in counts} == {"server", "source"}
    assert set(counts.values()) == {2}
