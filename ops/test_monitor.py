import io
import json
import smtplib
from http.client import IncompleteRead
from urllib.error import HTTPError, URLError

import pytest

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
    issue = {"number": 12, "title": monitor.ISSUE_TITLE, "body": ""}
    state = {"issue": None, "errors": ["database unhealthy"]}
    calls = []

    monkeypatch.setattr(monitor, "check_health", lambda: state["errors"])
    monkeypatch.setattr(monitor, "active_issue", lambda: state["issue"])

    def github(method, path, payload):
        calls.append((method, path, payload))
        if method == "POST":
            issue["body"] = payload["body"]
            state["issue"] = issue
            return issue
        else:
            issue.update(payload)
            if payload.get("state") == "closed":
                state["issue"] = None
        return issue

    monkeypatch.setattr(monitor, "github_request", github)
    def send(subject, body):
        calls.append(("email", subject, body))
        return True

    monkeypatch.setattr(monitor, "send_email", send)
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


@pytest.mark.parametrize("status,body", [
    (502, b"<html>Bad Gateway</html>"),
    (503, b"not json"),
])
def test_http_error_html_still_produces_an_outage_condition(monkeypatch, status, body):
    def unavailable(*_args, **_kwargs):
        raise HTTPError(monitor.HEALTH_URL, status, "unavailable", {}, io.BytesIO(body))

    monkeypatch.setattr(monitor, "urlopen", unavailable)
    errors = monitor.check_health()
    assert f"HTTP {status}" in errors
    assert "Health endpoint returned invalid or oversized JSON" in errors


@pytest.mark.parametrize("body", [b"not json", b"[]", b"null", b"\xff",
                                  b"x" * (monitor.MAX_HEALTH_RESPONSE_BYTES + 1)])
def test_malformed_success_response_is_bounded_and_does_not_crash(monkeypatch, body):
    monkeypatch.setattr(monitor, "urlopen", lambda *_a, **_k: Response(body))
    assert monitor.check_health() == ["Health endpoint returned invalid or oversized JSON"]


@pytest.mark.parametrize("failure", [URLError("private-password-in-provider-response"),
                                     TimeoutError("private provider response"),
                                     IncompleteRead(b"private partial response")])
def test_connection_failure_does_not_publish_sensitive_exception_details(monkeypatch, failure):
    def unavailable(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(monitor, "urlopen", unavailable)
    assert monitor.check_health() == [f"Health endpoint unreachable ({type(failure).__name__})"]


def test_malformed_nested_payload_does_not_crash(monkeypatch):
    monkeypatch.setattr(monitor, "urlopen", lambda *_a, **_k:
                        Response(b'{"checks":[],"background":null}'))
    errors = monitor.check_health()
    assert "database unhealthy" in errors
    assert "websocketRelay unhealthy or stale" in errors


def test_failure_email_is_retried_then_durably_deduplicated(monkeypatch):
    issue = {"number": 12, "body": monitor.FAILURE_EMAIL_PENDING}
    attempts = []
    patches = []
    monkeypatch.setattr(monitor, "check_health", lambda: ["database unhealthy"])
    monkeypatch.setattr(monitor, "active_issue", lambda: issue)

    def github(method, path, payload):
        assert method == "PATCH" and path == "issues/12"
        patches.append(payload)
        issue.update(payload)
        return issue

    def send(*_args):
        attempts.append(1)
        if len(attempts) == 1:
            raise smtplib.SMTPServerDisconnected("private provider error")
        return True

    monkeypatch.setattr(monitor, "github_request", github)
    monkeypatch.setattr(monitor, "send_email", send)
    assert monitor.main() == 1
    assert monitor.FAILURE_EMAIL_PENDING in issue["body"]
    assert monitor.main() == 1
    assert monitor.FAILURE_EMAIL_SENT in issue["body"]
    assert monitor.main() == 1
    assert len(attempts) == 2
    assert len(patches) == 2


def test_missing_smtp_configuration_keeps_failure_notification_retryable(monkeypatch):
    issue = {"number": 12, "body": monitor.FAILURE_EMAIL_PENDING}
    attempts = []
    monkeypatch.setattr(monitor, "check_health", lambda: ["database unhealthy"])
    monkeypatch.setattr(monitor, "active_issue", lambda: issue)
    monkeypatch.setattr(monitor, "github_request", lambda _m, _p, payload: issue.update(payload))
    monkeypatch.setattr(monitor, "send_email", lambda *_a: attempts.append(1) or False)
    assert monitor.main() == 1
    assert monitor.main() == 1
    assert len(attempts) == 2
    assert monitor.FAILURE_EMAIL_SENT not in issue["body"]


def test_recovery_email_is_retried_before_closing_incident(monkeypatch):
    issue = {"number": 12, "body": monitor.FAILURE_EMAIL_SENT, "state": "open"}
    attempts = []
    monkeypatch.setattr(monitor, "check_health", lambda: [])
    monkeypatch.setattr(monitor, "active_issue", lambda: issue)
    monkeypatch.setattr(monitor, "github_request", lambda _m, _p, payload: issue.update(payload))

    def send(*_args):
        attempts.append(1)
        if len(attempts) == 1:
            raise TimeoutError("SMTP timed out")
        return True

    monkeypatch.setattr(monitor, "send_email", send)
    assert monitor.main() == 1
    assert issue["state"] == "open"
    assert monitor.RECOVERY_EMAIL_PENDING in issue["body"]
    assert monitor.main() == 0
    assert issue["state"] == "closed"
    assert len(attempts) == 2
