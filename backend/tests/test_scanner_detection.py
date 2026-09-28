"""Regressions for HTTP reconnaissance and scanner-safe ML baselines."""

from datetime import datetime, timezone
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import fakeredis.aioredis
import pytest

from app.redis_client import redis_client
from app.services.behavioral_features import PENDING_WINDOWS, behavioral_features
from app.services.detection_engine import DetectionEngine
from app.services.log_parser import parse_event
from app.services.scanner_detection import is_directory_enumeration
from app.services import window_scoring
from app.tasks.train_model import _select_training_rows


def entry(path: str, *, event_id: str = "one", ua: str = "curl/8.0"):
    return parse_event(
        dict(source_ip="203.0.113.7", timestamp="2026-09-28T09:51:00Z",
             path=path, status_code=200, bytes_sent=565,
             user_agent=ua, event_id=event_id),
        "spandan-web",
    )


@pytest.mark.asyncio
async def test_wordlist_filenames_are_not_sql_injection():
    engine = DetectionEngine()
    now = datetime.now(timezone.utc)
    for path in ("/exp_plus", "/assets/exp_minus", "/Back4WinXP_v3", "/CachemanXP_1"):
        assert await engine._detect_rule(entry(path), now, 1) is None
    assert (await engine._detect_rule(entry("/?id=1+UNION+SELECT+1"), now, 1)).attack_type == "sql_injection"
    assert (await engine._detect_rule(entry("/?cmd=xp_cmdshell"), now, 1)).attack_type == "sql_injection"
    assert (await engine._detect_rule(entry("/exp_plus", ua="feroxbuster/2.13.1"), now, 1)).attack_type == "scanner"


@pytest.mark.asyncio
async def test_feroxbuster_is_bounded_but_all_requests_taint_windows(monkeypatch):
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(redis_client, "redis", client)
    await client.set("ip_data:203.0.113.7", json.dumps({}))
    engine = DetectionEngine()
    try:
        first = entry("/exp_plus", ua="feroxbuster/2.13.1")
        second = entry("/another-file", event_id="two", ua="feroxbuster/2.13.1")
        assert (await engine.process_log(first)).attack_type == "scanner"
        assert await engine.process_log(second) is None
        assert (await engine.process_log(first)).attack_type == "scanner"
        bases = await client.zrange(PENDING_WINDOWS, 0, -1)
        assert len(bases) == 2
        for base in bases:
            assert await client.hget(base, "rule_threat_count") == "2"
    finally:
        await client.aclose()


def test_directory_enumeration_requires_speed_and_path_diversity():
    def probe(**changes):
        values = dict(request_count=500, unique_paths=480, top_path_share=0.01,
                      request_rate=8.3, peak_second_requests=30)
        values.update(changes)
        return is_directory_enumeration(**values)
    assert probe()  # Works even when an SPA rewrites nonexistent paths to 200.
    assert not probe(unique_paths=10, top_path_share=0.6)
    assert not probe(request_count=90, unique_paths=85)
    assert not probe(request_rate=0.5, peak_second_requests=2)


@pytest.mark.asyncio
async def test_completed_enumeration_is_detected_without_model(monkeypatch):
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(redis_client, "redis", client)
    start = int(time.time() // 300) * 300 - 600
    stamp = datetime.fromtimestamp(start, timezone.utc)
    try:
        for index in range(130):
            log = entry(f"/word-{index}", event_id=f"enumeration-{index}")
            await behavioral_features.observe(
                log=log, timestamp=stamp, rule_threat=False,
                reputation_score=0, reporter_count=0, community_reports=0,
            )
        base = next(b for b in await client.zrange(PENDING_WINDOWS, 0, -1) if ":source:" in b)
        await client.zadd(PENDING_WINDOWS, {base: time.time() - 1})
        monkeypatch.setattr(window_scoring.ml_engine, "score", lambda *args: None)
        manager = AsyncMock()
        monkeypatch.setattr(window_scoring, "AsyncSessionLocal", lambda: manager)
        persist = AsyncMock(return_value=[])
        monkeypatch.setattr(window_scoring, "persist_threats", persist)
        assert not await window_scoring.score_window(base)  # ML stays pending.
        assert persist.await_count == 1
        assert persist.await_args.args[1][0].event.attack_type == "scanner"
        assert await client.hget(base, "scanner_scored_revision") == "130"
        await client.zadd(PENDING_WINDOWS, {base: time.time() - 1})
        assert not await window_scoring.score_window(base)
        assert persist.await_count == 1
    finally:
        await client.aclose()


def test_historical_enumeration_window_is_not_selected_for_training():
    def row(count, paths, rate, peak, top):
        return SimpleNamespace(server_id="spandan-web", entity_key="v3-server",
                               request_count=count, unique_paths=paths,
                               request_rate=rate, peak_second_requests=peak,
                               top_path_share=top)
    scan = row(41_297, 41_023, 688, 747, 0.001)
    normal = row(200, 5, 3.3, 10, 0.9)
    session = Mock()
    session.scalars.return_value = [scan, normal]
    assert _select_training_rows(session, "server", "spandan-web") == [normal]
