import io
import json

from ops import monitor


class Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def test_monitor_checks_background_disk_and_warmup(monkeypatch):
    payload = {
        "checks": {"database": True, "redis": True},
        "background": {
            "windowScorer": True, "incidentGrouping": True,
            "celeryBeatWorker": True, "collectorFresh": True,
            "websocketRelay": True, "diskUsedPercent": 45,
            "modelState": "warming_up", "modelFresh": None,
        },
    }
    monkeypatch.setattr(monitor, "urlopen",
                        lambda *_args, **_kwargs: Response(json.dumps(payload).encode()))
    assert monitor.check_health() == []
    payload["background"]["websocketRelay"] = False
    payload["background"]["diskUsedPercent"] = 93
    assert "websocketRelay unhealthy or stale" in monitor.check_health()
    assert "disk usage 93%" in monitor.check_health()


def test_monitor_emails_only_on_failure_and_recovery_transitions(monkeypatch):
    issue = {"number": 12, "title": monitor.ISSUE_TITLE}
    state = {"issue": None, "errors": ["database unhealthy"]}
    calls = []

    monkeypatch.setattr(monitor, "check_health", lambda: state["errors"])
    monkeypatch.setattr(monitor, "active_issue", lambda: state["issue"])

    def github(method, path, payload):
        calls.append((method, path, payload))
        if method == "POST":
            state["issue"] = issue
        elif payload.get("state") == "closed":
            state["issue"] = None

    monkeypatch.setattr(monitor, "github_request", github)
    monkeypatch.setattr(monitor, "send_email",
                        lambda subject, body: calls.append(("email", subject, body)))
    assert monitor.main() == 1
    assert monitor.main() == 1
    state["errors"] = []
    assert monitor.main() == 0
    assert [call for call in calls if call[0] == "email"] == [
        ("email", monitor.ISSUE_TITLE,
         f"External check: {monitor.HEALTH_URL}\n\n- database unhealthy\n"),
        ("email", "Vanguard production health recovered",
         f"All checks passed: {monitor.HEALTH_URL}"),
    ]
