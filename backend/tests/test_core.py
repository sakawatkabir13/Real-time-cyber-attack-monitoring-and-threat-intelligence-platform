from datetime import timezone
import stat

import pytest
from pydantic import ValidationError

from app.config import settings
from app.models.threat_event import ThreatEvent
from app.models.traffic_window import TrafficWindow
from app.routers.ingest import AgentBatch, parse_event
from app.security import create_session_token, is_valid_session
from app.services.abuseipdb import check_ip_abuse
from app.services.detection_engine import DetectionEngine
from app.services.alert_service import should_create_alert
from app.services.behavioral_features import values_from_snapshot
from app.services.ml_features import temporal_features
from app.services.ml_engine import MLEngine
from app.tasks.train_model import _atomic_dump
from app.websocket_manager import ConnectionManager


def test_combined_log_parser_accepts_apache_dash_bytes():
    parsed = parse_event(
        {
            "raw_log": '203.0.113.7 - - [05/Aug/2026:01:02:03 +0000] '
            '"GET /login HTTP/1.1" 401 - "-" "curl/8.0"'
        },
        "server-a",
    )
    assert parsed is not None
    assert parsed.bytes_sent == 0
    assert parsed.source_ip == "203.0.113.7"


def test_parser_rejects_invalid_ip_and_oversized_batch():
    assert parse_event(
        {"raw_log": 'not-an-ip - - [05/Aug/2026:01:02:03 +0000] "GET / HTTP/1.1" 200 1'},
        "server-a",
    ) is None
    with pytest.raises(ValidationError):
        AgentBatch(server_id="server-a", events=[{}] * (settings.MAX_INGEST_BATCH_SIZE + 1))


def test_timestamp_parser_preserves_iso_timestamp():
    parsed = DetectionEngine._parse_timestamp("2026-08-05T01:02:03Z")
    assert parsed.isoformat() == "2026-08-05T01:02:03+00:00"
    assert parsed.tzinfo == timezone.utc


def test_ingest_idempotency_is_scoped_to_each_server():
    constraints = {
        constraint.name: tuple(column.name for column in constraint.columns)
        for constraint in ThreatEvent.__table__.constraints
        if constraint.name
    }
    assert constraints["uq_threat_events_server_ingest_event"] == (
        "server_id",
        "ingest_event_id",
    )


def test_behavioral_window_identity_is_unique_and_features_are_aggregated():
    constraints = {
        constraint.name: tuple(column.name for column in constraint.columns)
        for constraint in TrafficWindow.__table__.constraints
        if constraint.name
    }
    assert constraints["uq_traffic_window_entity_period"] == (
        "server_id",
        "scope",
        "entity_key",
        "window_start",
        "window_seconds",
    )
    values = values_from_snapshot(
        {
            "request_count": "20",
            "window_seconds": "60",
            "window_start": "1785891600",
            "new_ip_count": "5",
            "status_4xx": "4",
            "status_5xx": "2",
            "bytes_total": "2000",
            "request_time_total": "10",
        },
        {"unique_ips": 10, "unique_paths": 3, "unique_user_agents": 4},
        8,
    )
    assert values["request_rate"] == pytest.approx(1 / 3)
    assert values["new_ip_ratio"] == 0.25
    assert values["top_path_share"] == 0.4
    assert values["status_4xx_ratio"] == 0.2
    assert values["avg_request_time"] == 0.5
    assert set(temporal_features(1785891600)) == {
        "hour_sin",
        "hour_cos",
        "weekday_sin",
        "weekday_cos",
    }


def test_only_actionable_or_ml_threats_create_alerts():
    def event(severity: str, attack_type: str):
        return ThreatEvent(severity=severity, attack_type=attack_type)

    assert should_create_alert(event("high", "sql_injection"))
    assert should_create_alert(event("medium", "server_traffic_anomaly"))
    assert not should_create_alert(event("medium", "scanner"))


def test_session_token_is_signed_and_tamper_evident():
    token = create_session_token()
    assert is_valid_session(token)
    assert not is_valid_session(token + "tampered")


def test_production_rejects_non_secure_session_cookie(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "COLLECTOR_TOKEN", "collector-token")
    monkeypatch.setattr(settings, "DASHBOARD_PASSWORD", "dashboard-password")
    monkeypatch.setattr(settings, "SECRET_KEY", "session-signing-key")
    monkeypatch.setattr(settings, "COOKIE_SECURE", False)
    with pytest.raises(RuntimeError, match="COOKIE_SECURE"):
        settings.validate_production_secrets()


@pytest.mark.asyncio
async def test_unconfigured_abuseipdb_is_not_reported_as_clean(monkeypatch):
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "")
    result = await check_ip_abuse("8.8.8.8")
    assert result["available"] is False
    assert "abuseConfidenceScore" not in result


@pytest.mark.asyncio
async def test_websocket_broadcast_prunes_dead_connections():
    class Socket:
        def __init__(self, fail=False):
            self.fail = fail
            self.messages = []

        async def send_text(self, message):
            if self.fail:
                raise RuntimeError("closed")
            self.messages.append(message)

    manager = ConnectionManager()
    live = Socket()
    dead = Socket(fail=True)
    manager.active_connections = [live, dead]
    await manager.broadcast_json({"type": "test"})
    assert len(live.messages) == 1
    assert manager.active_connections == [live]


def test_model_artifact_is_cross_service_readable_and_bad_reload_keeps_last_good(
    tmp_path, monkeypatch
):
    path = tmp_path / "behavioral_models.joblib"
    monkeypatch.setattr(settings, "MODEL_PATH", str(path))
    _atomic_dump(
        {
            "schema_version": 2,
            "version": "test-version",
            "trained_at": "2026-08-05T00:00:00+00:00",
            "models": {},
        }
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o644

    engine = MLEngine()
    assert engine.status()["version"] == "test-version"
    path.write_bytes(b"not a joblib model")
    engine.load_model()
    assert engine.status()["version"] == "test-version"
