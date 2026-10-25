from datetime import datetime, timedelta, timezone
import os
from types import SimpleNamespace
import uuid

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import delete
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import get_db
from app.main import app
from app.models.ddos_alert import DdosAlert
from app.models.incident_group import IncidentGroup
from app.routers.incidents import list_incidents
from app.security import require_dashboard_auth


@pytest.mark.asyncio
async def test_incident_filters_apply_to_one_member_and_escape_search():
    class Db:
        async def scalars(self, query):
            self.sql = str(query.compile(compile_kwargs={"literal_binds": True}))
            return []
    db = Db()
    await list_incidents(limit=50, server_id="site-a", attack_type="http_flood",
                         minimum_severity="high", verdict="confirmed_malicious",
                         since=datetime(2026, 10, 20, tzinfo=timezone.utc), search="100%_test", db=db)
    for fragment in ("EXISTS", "site-a", "http_flood", "critical", "confirmed_malicious", "2026-10-20", "ESCAPE"):
        assert fragment in db.sql
    assert db.sql.count("EXISTS") == 1
    with pytest.raises(HTTPException) as error:
        await list_incidents(limit=50, since=datetime(2026, 10, 20), db=db)
    assert error.value.status_code == 422


@pytest.mark.asyncio
@pytest.mark.skipif(not os.getenv("VANGUARD_TEST_DATABASE_URL"), reason="Disposable PostgreSQL URL not supplied")
async def test_incident_api_filters_real_postgres_members_without_cross_matching():
    dsn = os.environ["VANGUARD_TEST_DATABASE_URL"]
    assert (make_url(dsn).database or "").startswith("vanguard_test")
    engine = create_async_engine(dsn)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    server = "test-groups-" + uuid.uuid4().hex[:10]
    now = datetime.now(timezone.utc)
    groups = [IncidentGroup(id=uuid.uuid4(), server_id=server, attack_type="http_flood",
                            path="/", source_count=3, alert_count=2, source_ips=[],
                            start_time=now, last_seen=now, explanation="test group") for _ in range(2)]
    def alert(group, severity, verdict, offset=0):
        return DdosAlert(id=uuid.uuid4(), server_id=server, source_ip="203.0.113.1",
                         dedupe_key=uuid.uuid4().hex, start_time=now, last_seen=now - timedelta(days=offset),
                         attack_type="http_flood", severity=severity, status="new", detection_method="rule",
                         trigger_reason="100%_test", occurrence_count=1, verdict=verdict,
                         incident_group_id=group.id)
    async def database():
        async with sessions() as db:
            yield db
    old_overrides = dict(app.dependency_overrides)
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[require_dashboard_auth] = lambda: None
    try:
        async with sessions() as db:
            db.add_all(groups)
            await db.flush()
            db.add_all([alert(groups[0], "high", "legitimate"),
                        alert(groups[0], "low", "confirmed_malicious"),
                        alert(groups[1], "high", "confirmed_malicious")])
            await db.commit()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            params = {"server_id": server, "minimum_severity": "high", "verdict": "confirmed_malicious",
                      "since": (now - timedelta(hours=1)).isoformat(), "search": "100%_test"}
            response = await client.get("/api/incidents", params=params)
            assert response.status_code == 200, response.text
            assert [g["id"] for g in response.json()] == [str(groups[1].id)]
            assert (await client.get("/api/incidents", params={**params, "attack_type": "scanner"})).json() == []
            assert (await client.get("/api/incidents", params={**params, "search": "100X_test"})).json() == []
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(old_overrides)
        async with sessions() as db:
            await db.execute(delete(DdosAlert).where(DdosAlert.server_id == server))
            await db.execute(delete(IncidentGroup).where(IncidentGroup.server_id == server))
            await db.commit()
        await engine.dispose()
