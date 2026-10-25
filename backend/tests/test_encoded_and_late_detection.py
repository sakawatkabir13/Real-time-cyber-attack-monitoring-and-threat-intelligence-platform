"""Bounded URL views and late-context regressions; no external services or DB."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest
import pytest_asyncio

from app.redis_client import redis_client
from app.routers import ingest
from app.services.behavioral_features import PENDING_WINDOWS
from app.services.detection_engine import DetectionEngine
from app.services.log_parser import parse_event, percent_decoded_views, signature_views
from app.services.scanner_detection import scanner_indicator


START = 1_785_891_600  # An event-time bucket boundary, independent of arrival time.


def entry(index=0, *, path="/", status=200, source="203.0.113.7", server="late-test", second=None):
    result = parse_event({
        "event_id": f"request-{index}",
        "timestamp": datetime.fromtimestamp(START + (index if second is None else second), timezone.utc).isoformat(),
        "source_ip": source, "method": "POST", "path": path,
        "status_code": status, "bytes_sent": 100,
        "request_time": 0.2, "user_agent": "Mozilla/5.0",
    }, server)
    assert result is not None
    return result


@pytest_asyncio.fixture
async def fake_redis(monkeypatch):
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(redis_client, "redis", client)
    # Prevent reputation fetch dispatch, including in direct process_log tests.
    for ip in ("203.0.113.7", "203.0.113.8"):
        await client.set(f"ip_data:{ip}", "{}")
    yield client
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("path,kind", [
    ("/search?q=1%27%20UNION%20SELECT%201--", "sql_injection"),
    ("/search?q=%55NION%09SELECT%201", "sql_injection"),
    ("/search?q=%2555NION%2520SELECT%25201", "sql_injection"),
    ("/search?q=1%27+UNION+SELECT+1--", "sql_injection"),
    ("/download?file=%2e%2e/%2e%2e/settings.json", "path_traversal"),
    ("/%2e%2e%2fsettings.json", "path_traversal"),
    ("/search?q=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E", "xss"),
    ("/%2eenv", "scanner"),
    ("/%252egit/config", "scanner"),
])
async def test_encoded_signatures_preserve_original_evidence(path, kind):
    log = entry(path=path)
    finding = await DetectionEngine()._detect_rule(log, datetime.now(timezone.utc), 1)
    assert finding is not None and finding.attack_type == kind
    assert finding.path == path and log.path == path


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [
    "/exp%5fplus", "/Back4WinXP_v3", "/assets/C%2B%2B.pdf",
    "/assets/union+select.txt", "/assets/union%2Bselect.txt",
    "/search?q=union%2Bselect", "/search?q=union%252Bselect",
    "/wordlists/selection_from.txt", "/wordlists/select_from.txt",
    "/docs?next=/admin/login", "/docs?file=.env",
    "/notes?name=select&action=update", "/notes?text=union+meeting",
])
async def test_harmless_encoded_filenames_and_literal_pluses_are_not_attacks(path):
    assert await DetectionEngine()._detect_rule(entry(path=path), datetime.now(timezone.utc), 1) is None


def test_signature_decoding_has_fixed_work_and_query_only_plus_handling():
    raw = "%25252e" * 4000
    views = percent_decoded_views(raw)
    assert len(views) == 3 and all(len(view) <= 8192 for view in views)
    assert percent_decoded_views("%25252e")[-1] == "%2e"  # Not an unbounded decode loop.
    assert "/union+select" in signature_views("/union+select?q=union+select")
    assert "q=union select" in signature_views("/union+select?q=union+select")
    assert "q=union+select" in signature_views("/?q=union%2Bselect")
    assert scanner_indicator("/%2eenv", "Mozilla/5.0")
    assert not scanner_indicator("/download?file=%2eenv", "Mozilla/5.0")


@pytest.mark.asyncio
@pytest.mark.parametrize("order", ["chronological", "reverse", "split_reverse"])
@pytest.mark.parametrize("path,status,total,expected,kind", [
    ("/login", 401, 20, 6, "brute_force"),
    ("/api/expensive", 503, 120, 20, "http_flood"),
])
async def test_contextual_findings_survive_reverse_and_split_batches(
    fake_redis, monkeypatch, order, path, status, total, expected, kind,
):
    monkeypatch.setattr(ingest, "verify_collector_token", lambda _authorization: None)
    monkeypatch.setattr(ingest, "AsyncSessionLocal", lambda: AsyncMock())
    persist = AsyncMock(return_value=[])
    publish = AsyncMock(return_value=0)
    monkeypatch.setattr(ingest, "persist_threats", persist)
    monkeypatch.setattr(ingest, "publish_http_requests", publish)
    records = [entry(i, path=path, status=status).model_dump() for i in range(total)]
    if order != "chronological":
        records.reverse()
    chunks = [records] if order != "split_reverse" else [records[:total // 2], records[total // 2:]]
    findings = []
    for chunk in chunks:
        batch = ingest.AgentBatch(server_id="late-test", events=chunk)
        response = await ingest.ingest_batch(batch, authorization="test")
        assert response["accepted"] == len(chunk) and response["duplicates"] == 0
        findings.extend(persist.await_args.args[1])
    assert len(findings) == expected
    assert {item.event.attack_type for item in findings} == {kind}
    assert len({item.ingest_event_id for item in findings}) == expected
    if order != "chronological":
        assert all("late delivery" in item.event.explanation for item in findings)

    # Stable-ID replay must not classify/publish/aggregate the same requests again.
    retry = await ingest.ingest_batch(ingest.AgentBatch(server_id="late-test", events=records), authorization="test")
    assert retry["duplicates"] == total and persist.await_args.args[1] == []
    assert publish.await_args.args[0] == []
    for base in await fake_redis.zrange(PENDING_WINDOWS, 0, -1):
        if ":source:" in base:
            assert int(await fake_redis.hget(base, "request_count")) == total


@pytest.mark.asyncio
async def test_late_context_is_bounded_in_event_time_and_isolated(fake_redis):
    async def count(second, identity, *, source="203.0.113.7", server="late-test", failed=True):
        return await redis_client.contextual_event_counts(
            source, server_id=server, timestamp=START + second, event_id=identity,
            counters={"requests": True, "failed_auth": failed},
        )

    assert (await count(299, "latest"))[0]["requests"] == 1
    counts, finish = await count(0, "late")
    assert counts == {"requests": 2, "failed_auth": 2} and finish == START + 299
    assert (await count(0, "late"))[0] == counts  # Atomic ID registration is retry-safe.
    assert (await count(300, "boundary"))[0]["requests"] == 2  # Lower endpoint excludes t=0.
    counts, finish = await count(0, "late-again")
    assert counts["requests"] == 3 and finish == START + 299  # t=300 is not folded backward.
    assert (await count(0, "other-source", source="203.0.113.8"))[0]["requests"] == 1
    assert (await count(0, "other-server", server="different"))[0]["requests"] == 1
    assert (await count(3600, "one-hour-later"))[0]["requests"] == 1
    await count(301, "next-bucket", server="bucket-edge")
    counts, finish = await count(299, "previous-bucket", server="bucket-edge")
    assert counts["requests"] == 2 and finish == START + 301
    await count(10, "unchanged-payload", server="idempotent", failed=False)
    counts, _ = await count(10, "unchanged-payload", server="idempotent", failed=True)
    assert counts == {"requests": 1, "failed_auth": 0}


@pytest.mark.asyncio
async def test_late_context_preserves_path_concentration_and_failure_ratios(fake_redis):
    engine = DetectionEngine()
    for index in range(120):
        # Heavy total volume across distinct ordinary paths is not a flood.
        assert await engine.process_log(entry(index, path=f"/ordinary-{index}", status=503)) is None
    for index in range(200, 220):
        # A different source's successful authentication is not a brute force.
        assert await engine.process_log(entry(index, path="/login", status=200, source="203.0.113.8")) is None
    for index in range(300, 310):
        # These late rejections share a window with 20 successful auth requests.
        assert await engine.process_log(entry(index, path="/login", status=401, source="203.0.113.8", second=190 + index - 300)) is None


@pytest.mark.asyncio
async def test_encoded_auth_path_and_query_only_auth_do_not_mix(fake_redis):
    engine = DetectionEngine()
    for index in range(20):
        assert await engine.process_log(entry(index, path="/docs?next=/login", status=401)) is None
    findings = [await engine.process_log(entry(index, path="/%6cogin", status=401)) for index in range(30, 50)]
    assert sum(item is not None and item.attack_type == "brute_force" for item in findings) == 6


@pytest.mark.asyncio
async def test_encoded_throttled_login_quarantines_baseline_without_false_query_auth(fake_redis):
    engine = DetectionEngine()
    assert await engine.process_log(entry(path="/%6cogin", status=429)) is None
    for base in await fake_redis.zrange(PENDING_WINDOWS, 0, -1):
        assert await fake_redis.hget(base, "baseline_excluded_count") == "1"
    await fake_redis.flushall()
    await fake_redis.set("ip_data:203.0.113.7", "{}")
    assert await engine.process_log(entry(path="/docs?next=/login", status=429)) is None
    for base in await fake_redis.zrange(PENDING_WINDOWS, 0, -1):
        assert await fake_redis.hget(base, "baseline_excluded_count") is None
