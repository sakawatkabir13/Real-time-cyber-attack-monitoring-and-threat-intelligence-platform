"""External Vanguard health monitor for a scheduled GitHub Actions runner."""
from __future__ import annotations

import json
import math
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HEALTH_URL = os.getenv("VANGUARD_HEALTH_URL", "https://vanguard.cuetinsights.dev/api/health")
ISSUE_TITLE = "Vanguard production health check failed"
REQUIRED_BACKGROUND = ("windowScorer", "incidentGrouping", "celeryBeatWorker",
                       "collectorFresh", "websocketRelay")
MAX_HEALTH_RESPONSE_BYTES = 64 * 1024
FAILURE_EMAIL_SENT = "<!-- vanguard:failure-email-sent -->"
FAILURE_EMAIL_PENDING = "<!-- vanguard:failure-email-pending -->"
RECOVERY_EMAIL_PENDING = "<!-- vanguard:recovery-email-pending -->"


def _health_payload(response) -> dict:
    raw = response.read(MAX_HEALTH_RESPONSE_BYTES + 1)
    if len(raw) > MAX_HEALTH_RESPONSE_BYTES:
        raise ValueError("Health response exceeds the size limit")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Health response must be an object")
    return data


def check_health() -> list[str]:
    errors = []
    try:
        with urlopen(HEALTH_URL, timeout=12) as response:
            status = response.status
            try:
                data = _health_payload(response)
            except (ValueError, UnicodeError, RecursionError):
                data = None
    except HTTPError as exc:
        status = exc.code
        # Reverse proxies commonly return HTML for 502/503 responses. The
        # outage must still reach issue/email handling instead of crashing.
        try:
            with exc:
                data = _health_payload(exc)
        except (ValueError, UnicodeError, OSError, HTTPException, RecursionError):
            data = None
    except (URLError, TimeoutError, OSError, HTTPException, ValueError) as exc:
        # Do not publish provider responses, URLs with credentials, or other
        # exception details into a public GitHub issue.
        return [f"Health endpoint unreachable ({type(exc).__name__})"]
    if status != 200:
        errors.append(f"HTTP {status}")
    if data is None:
        return errors + ["Health endpoint returned invalid or oversized JSON"]
    checks = data.get("checks")
    if not isinstance(checks, dict):
        checks = {}
    for name in ("database", "redis"):
        if checks.get(name) is not True:
            errors.append(f"{name} unhealthy")
    background = data.get("background")
    if not isinstance(background, dict):
        background = {}
    for name in REQUIRED_BACKGROUND:
        if background.get(name) is not True:
            errors.append(f"{name} unhealthy or stale")
    disk = background.get("diskUsedPercent")
    if isinstance(disk, bool) or not isinstance(disk, (int, float)) or not math.isfinite(disk):
        errors.append("disk usage unavailable")
    elif disk >= float(os.getenv("VANGUARD_DISK_ALERT_PERCENT", "90")):
        errors.append(f"disk usage {disk}%")
    if background.get("modelState") == "ready" and background.get("modelFresh") is not True:
        errors.append("trained model stale")
    return errors


def github_request(method: str, path: str, payload: dict | None = None):
    repo = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GITHUB_TOKEN"]
    request = Request(
        f"https://api.github.com/repos/{repo}/{path}",
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={"Accept": "application/vnd.github+json",
                 "Authorization": f"Bearer {token}", "User-Agent": "vanguard-health-monitor",
                 "X-GitHub-Api-Version": "2022-11-28"},
    )
    with urlopen(request, timeout=12) as response:
        return json.load(response)


def active_issue() -> dict | None:
    for item in github_request("GET", "issues?state=open&per_page=100"):
        if "pull_request" not in item and item.get("title") == ISSUE_TITLE:
            return item
    return None


def _notify(subject: str, body: str) -> bool:
    try:
        return bool(send_email(subject, body))
    except (smtplib.SMTPException, OSError) as exc:
        print(f"Email delivery failed ({type(exc).__name__}); will retry next run.",
              file=sys.stderr)
        return False


def _update_issue(issue: dict, body: str, **values) -> None:
    if body != (issue.get("body") or "") or values:
        github_request("PATCH", f"issues/{issue['number']}", {"body": body, **values})
        issue["body"] = body


def send_email(subject: str, body: str) -> bool:
    sender = os.getenv("MONITOR_EMAIL_FROM")
    recipient = os.getenv("MONITOR_EMAIL_TO")
    username = os.getenv("MONITOR_SMTP_USER")
    password = os.getenv("MONITOR_SMTP_APP_PASSWORD")
    if not all((sender, recipient, username, password)):
        print("Email not configured; set the four MONITOR_* email secrets.", file=sys.stderr)
        return False
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        smtp.login(username, password)
        smtp.send_message(message)
    return True


def main() -> int:
    errors = check_health()
    issue = active_issue()
    if errors:
        detail = "\n".join(f"- {error}" for error in errors)
        body = f"External check: {HEALTH_URL}\n\n{detail}\n"
        print(body, file=sys.stderr)
        if issue is None:
            issue = github_request("POST", "issues", {
                "title": ISSUE_TITLE, "body": body + "\n" + FAILURE_EMAIL_PENDING,
            })
        delivered = FAILURE_EMAIL_SENT in (issue.get("body") or "")
        if not delivered:
            delivered = _notify(ISSUE_TITLE, body)
        # A marker in the incident issue survives ephemeral Actions runners.
        # Retry failed SMTP delivery, but never mail every five minutes once
        # this incident's failure notification has been sent successfully.
        marker = FAILURE_EMAIL_SENT if delivered else FAILURE_EMAIL_PENDING
        _update_issue(issue, body + "\n" + marker)
        return 1
    if issue is not None:
        body = f"All checks passed: {HEALTH_URL}"
        if not _notify("Vanguard production health recovered", body):
            marker = FAILURE_EMAIL_SENT if FAILURE_EMAIL_SENT in (issue.get("body") or "") else FAILURE_EMAIL_PENDING
            _update_issue(issue, body + "\n\n" + marker + "\n" + RECOVERY_EMAIL_PENDING)
            print("Health recovered; keeping the incident open until its recovery email is delivered.", file=sys.stderr)
            return 1
        _update_issue(issue, body, state="closed")
    print("Vanguard production health OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
