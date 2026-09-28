from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app import main
from app.models.ddos_alert import DdosAlert
from app.models.threat_event import ThreatEvent
from app.services.alert_service import serialize_alert
from app.services.event_pipeline import serialize_event


def test_event_payload_has_real_http_context_and_no_invented_port():
    event = ThreatEvent(
        id=7,
        server_id="spandan-web",
        source_ip="203.0.113.7",
        method="GET",
        path="/admin",
        status_code=404,
        host="spandan.cuetinsights.dev",
        timestamp=datetime(2026, 9, 29, tzinfo=timezone.utc),
        attack_type="scanner",
        severity="medium",
    )
    payload = serialize_event(event)
    assert payload["dest_port"] is None
    assert (payload["method"], payload["path"], payload["status_code"], payload["host"]) == (
        "GET", "/admin", 404, "spandan.cuetinsights.dev"
    )


def test_alert_payload_does_not_pretend_server_id_is_target_ip():
    alert = DdosAlert(
        server_id="spandan-web",
        source_ip="203.0.113.7",
        attack_type="scanner",
        severity="high",
        status="new",
        trigger_reason="test",
        occurrence_count=1,
        start_time=datetime(2026, 9, 29, tzinfo=timezone.utc),
        last_seen=datetime(2026, 9, 29, tzinfo=timezone.utc),
    )
    payload = serialize_alert(alert)
    assert payload["targetIp"] is None
    assert payload["serverId"] == "spandan-web"


@pytest.mark.asyncio
async def test_stats_use_rolling_hour_bins_and_preserve_other_types(monkeypatch):
    now = datetime(2026, 9, 29, 10, 23, 12, tzinfo=timezone.utc)
    cutoff = now - timedelta(hours=24)

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr(main, "datetime", FrozenDatetime)
    client = SimpleNamespace(get=AsyncMock(return_value=None), setex=AsyncMock())
    monkeypatch.setattr(main.redis_client, "_require_client", lambda: client)

    class Result:
        def __init__(self, scalar=None, rows=None):
            self.value = scalar
            self.rows = rows or []

        def scalar(self):
            return self.value

        def all(self):
            return self.rows

    results = iter([
        Result(scalar=100), Result(scalar=15), Result(scalar=2),
        Result(rows=[("scanner", 5), ("sql_injection", 4), ("xss", 3),
                     ("path_traversal", 2), ("http_flood", 1), ("brute_force", 1)]),
        Result(rows=[(cutoff, 2), (cutoff + timedelta(hours=23), 3)]),
        Result(scalar=6),
    ])
    statements = []

    class Db:
        async def execute(self, statement):
            statements.append(str(statement.compile(compile_kwargs={"literal_binds": True})))
            return next(results)

    payload = await main.get_stats(Db())
    assert len(payload["threatsByHour"]) == 24
    assert payload["threatsByHour"][0] == {"hour": cutoff.isoformat(), "count": 2}
    assert payload["threatsByHour"][-1]["count"] == 3
    assert sum(row["count"] for row in payload["threatsByHour"]) == 5
    assert payload["topAttackTypes"][-1] == {"type": "other", "count": 1}
    assert "date_bin" in statements[4]
    assert "threat_events.timestamp <" in statements[4]


@pytest.mark.asyncio
async def test_ml_only_events_query_excludes_rule_detections():
    class Result:
        def scalars(self):
            return []

    class Db:
        async def execute(self, statement):
            self.sql = str(statement.compile(compile_kwargs={"literal_binds": True}))
            return Result()

    db = Db()
    assert await main.get_events(limit=20, ml_only=True, db=db) == []
    assert "server_traffic_anomaly" in db.sql
    assert "source_behavior_anomaly" in db.sql
    assert "scanner" not in db.sql
