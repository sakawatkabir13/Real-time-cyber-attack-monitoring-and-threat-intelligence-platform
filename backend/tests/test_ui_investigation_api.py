from datetime import datetime, timezone
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app import main
from app.services.training_data import select_training_candidates, training_query


@pytest.mark.asyncio
async def test_event_drilldown_filters_source_server_type_and_time():
    class Db:
        async def execute(self, query):
            self.sql = str(query.compile(compile_kwargs={"literal_binds": True}))
            return SimpleNamespace(scalars=lambda: [])
    db = Db()
    await main.get_events(limit=50, ml_only=False, db=db, hours=24, server_id="spandan-web", source_ip="203.0.113.9", attack_type="scanner", since=datetime(2026, 10, 5, 10, tzinfo=timezone.utc), until=datetime(2026, 10, 5, 11, tzinfo=timezone.utc))
    for value in ("spandan-web", "203.0.113.9", "scanner", "2026-10-05 10:00", "2026-10-05 11:00"):
        assert value in db.sql
    assert "timestamp <" in db.sql
    with pytest.raises(HTTPException) as error:
        await main.get_events(db=db, since=datetime(2026, 10, 5))
    assert error.value.status_code == 422


@pytest.mark.asyncio
async def test_analysis_status_is_isolated_by_job_id(monkeypatch):
    id_a, id_b = "a" * 32, "b" * 32
    values = {main.analysis_status_key(id_a): json.dumps({"jobId": id_a, "state": "running"}), main.LATEST_ANALYSIS_KEY: json.dumps({"jobId": id_b, "state": "complete"})}
    client = SimpleNamespace(get=AsyncMock(side_effect=lambda key: values.get(key)))
    monkeypatch.setattr(main.redis_client, "_require_client", lambda: client)
    assert (await main.analysis_status(job_id=id_a))["state"] == "running"
    assert (await main.analysis_status())["jobId"] == id_b
    with pytest.raises(HTTPException) as error:
        await main.analysis_status(job_id="c" * 32)
    assert error.value.status_code == 404


def test_status_and_training_share_scan_and_sample_selection():
    clean = SimpleNamespace(server_id="spandan-web", entity_key="server", request_count=40, unique_paths=4, top_path_share=.8, request_rate=.67, peak_second_requests=3)
    scan = SimpleNamespace(server_id="spandan-web", entity_key="server", request_count=400, unique_paths=390, top_path_share=.01, request_rate=6.67, peak_second_requests=15)
    selected, excluded = select_training_candidates([scan, clean], "server")
    assert selected == [clean] and excluded == 1
    sql = str(training_query("server", "spandan-web").compile(compile_kwargs={"literal_binds": True}))
    assert "window_start >=" in sql and "request_count >= 20" in sql
    assert "is_training_eligible IS true" in sql
