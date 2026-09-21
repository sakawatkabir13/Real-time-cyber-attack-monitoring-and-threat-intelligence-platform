"""Opt-in functional integration test against a migrated disposable PostgreSQL DB.

Set VANGUARD_TEST_DATABASE_URL to a database named vanguard_test*.
The test creates uniquely named test records; never point it at production.
Model predictions and external geolocation are stubbed, not evaluated here.
"""

from datetime import datetime, timezone
import os
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid

import fakeredis
import fakeredis.aioredis
import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import settings
from app.database import get_db
from app.main import app
from app.models import DdosAlert, ThreatEvent, TrafficWindow
from app.redis_client import redis_client
from app.routers import ingest
from app.security import require_dashboard_auth
from app.services import event_pipeline, incident_grouping, window_scoring
from app.services.behavioral_features import PENDING_WINDOWS
from app.tasks import flush_traffic_windows


@pytest.mark.asyncio
@pytest.mark.skipif(not os.getenv("VANGUARD_TEST_DATABASE_URL"), reason="Disposable PostgreSQL URL not supplied")
async def test_ingest_quiet_windows_reviews_groups_and_late_revisions(monkeypatch):
    dsn = os.environ["VANGUARD_TEST_DATABASE_URL"]
    assert (make_url(dsn).database or "").startswith("vanguard_test"), "Test-only database required"
    engine = create_async_engine(dsn)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    fake_server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=fake_server, decode_responses=True)
    monkeypatch.setattr(redis_client, "redis", client)
    monkeypatch.setattr(settings, "DATABASE_URL", dsn)
    monkeypatch.setattr(settings, "COLLECTOR_TOKEN", "test-only-collector-token")
    monkeypatch.setattr(settings, "ML_WINDOW_GRACE_SECONDS", 0)
    monkeypatch.setattr(settings, "ML_MIN_SERVER_REQUESTS", 10)
    for module in (ingest, window_scoring, incident_grouping):
        monkeypatch.setattr(module, "AsyncSessionLocal", sessions)
    monkeypatch.setattr(event_pipeline.geo_lookup, "lookup", AsyncMock(return_value={}))
    monkeypatch.setattr(window_scoring.ml_engine, "score", lambda *args: SimpleNamespace(
        score=99.0, model_version="functional-test", explanation="Stubbed prediction for workflow test"))
    monkeypatch.setattr(flush_traffic_windows.redis, "from_url", lambda *args, **kwargs:
                        fakeredis.FakeRedis(server=fake_server, decode_responses=True))

    async def database():
        async with sessions() as db:
            yield db

    app.dependency_overrides[get_db] = database
    server_id = "test-" + uuid.uuid4().hex[:12]
    start = int(time.time() // 300) * 300 - 600
    stamp = datetime.fromtimestamp(start, timezone.utc).isoformat()
    events = []
    for source in range(1, 4):
        ip = f"203.0.113.{source}"
        await client.set(f"ip_data:{ip}", "{}")
        for index in range(5):
            events.append(dict(event_id=f"request-{source}-{index}", source_ip=ip,
                               timestamp=stamp, path="/shared", status_code=200,
                               request_time=0.2, user_agent="curl/8.0"))
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as http:
            assert (await http.get("/api/incidents")).status_code == 401
            app.dependency_overrides[require_dashboard_auth] = lambda: None
            response = await http.post("/api/ingest/batch", json={"server_id": server_id, "events": events},
                                       headers={"Authorization": f"Bearer {settings.COLLECTOR_TOKEN}"})
            assert response.status_code == 202, response.text
            assert response.json()["accepted"] == 15
            # No further requests arrive: the timer still scores all completed windows.
            assert await window_scoring.score_due_windows() == 4
            assert not await client.zrange(PENDING_WINDOWS, 0, -1)
            async with sessions() as db:
                stored = list(await db.scalars(select(ThreatEvent).where(ThreatEvent.server_id == server_id)))
                assert len(stored) == 4
                assert {e.timestamp for e in stored} == {datetime.fromtimestamp(start, timezone.utc)}
                server_event = next(e for e in stored if e.attack_type == "server_traffic_anomaly")
                assert server_event.source_ip is None
            assert flush_traffic_windows.flush_traffic_windows_task.run() == 4
            async with sessions() as db:
                windows = list(await db.scalars(select(TrafficWindow).where(TrafficWindow.server_id == server_id)))
                assert len(windows) == 4
                assert all(w.feature_schema == 3 and w.request_time_coverage == 1 for w in windows)

            await incident_grouping.group_recent_incidents()
            first_groups = [g for g in (await http.get("/api/incidents")).json() if g["serverId"] == server_id]
            assert len(first_groups) == 1 and first_groups[0]["sourceCount"] == 3
            await incident_grouping.group_recent_incidents()
            groups = [g for g in (await http.get("/api/incidents")).json() if g["serverId"] == server_id]
            assert groups[0]["id"] == first_groups[0]["id"]
            alerts = [a for a in (await http.get("/api/alerts")).json() if a["serverId"] == server_id]
            reviewed = next(a for a in alerts if a["sourceIp"] == "203.0.113.1")
            review = dict(verdict="legitimate", notes="Verified an authorized traffic exercise", expected_version=0)
            saved = await http.patch(f"/api/alerts/{reviewed['id']}/review", json=review)
            assert saved.status_code == 200, saved.text
            assert saved.json()["verdict"] == "legitimate"
            assert not saved.json()["acknowledged"]
            assert (await http.patch(f"/api/alerts/{reviewed['id']}/review", json=review)).status_code == 409
            history = (await http.get(f"/api/alerts/{reviewed['id']}/reviews")).json()
            assert len(history) == 1 and history[0]["version"] == 1
            resolved = await http.patch(f"/api/alerts/{reviewed['id']}/resolve")
            assert resolved.status_code == 200
            assert resolved.json()["status"] == "resolved"
            assert resolved.json()["acknowledged"] is True
            await incident_grouping.group_recent_incidents()
            assert not [g for g in (await http.get("/api/incidents")).json() if g["serverId"] == server_id]

            late = {**events[0], "event_id": "late-request"}
            response = await http.post("/api/ingest/batch", json={"server_id": server_id, "events": [late]},
                                       headers={"Authorization": f"Bearer {settings.COLLECTOR_TOKEN}"})
            assert response.status_code == 202
            assert await window_scoring.score_due_windows() == 2
            async with sessions() as db:
                count = await db.scalar(select(func.count(ThreatEvent.id)).where(ThreatEvent.server_id == server_id))
                assert count == 4, "Late revisions must not create duplicate window events"
                result = await db.get(DdosAlert, uuid.UUID(reviewed["id"]))
                assert result.occurrence_count == 1
                assert result.verdict == "legitimate" and result.review_version == 1
                assert result.status == "resolved"
    finally:
        app.dependency_overrides.clear()
        await client.aclose()
        await engine.dispose()
