"""External Vanguard health monitor for a scheduled GitHub Actions runner."""
from __future__ import annotations

import json
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HEALTH_URL = os.getenv("VANGUARD_HEALTH_URL", "https://vanguard.cuetinsights.dev/api/health")
ISSUE_TITLE = "Vanguard production health check failed"
REQUIRED_BACKGROUND = ("windowScorer", "incidentGrouping", "celeryBeatWorker",
                       "collectorFresh", "websocketRelay")


def check_health() -> list[str]:
    errors = []
    try:
        with urlopen(HEALTH_URL, timeout=12) as response:
            status = response.status
            data = json.load(response)
    except HTTPError as exc:
        status = exc.code
        data = json.load(exc)
    except (URLError, TimeoutError, ValueError) as exc:
        return [f"Health endpoint unreachable or invalid: {exc}"]
    if status != 200:
        errors.append(f"HTTP {status}")
    checks = data.get("checks", {})
    for name in ("database", "redis"):
        if checks.get(name) is not True:
            errors.append(f"{name} unhealthy")
    background = data.get("background", {})
    for name in REQUIRED_BACKGROUND:
        if background.get(name) is not True:
            errors.append(f"{name} unhealthy or stale")
    disk = background.get("diskUsedPercent")
    if not isinstance(disk, (int, float)):
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
            github_request("POST", "issues", {"title": ISSUE_TITLE, "body": body})
            send_email(ISSUE_TITLE, body)
        else:
            github_request("PATCH", f"issues/{issue['number']}",
                           {"body": body})
        return 1
    if issue is not None:
        github_request("PATCH", f"issues/{issue['number']}", {"state": "closed"})
        send_email("Vanguard production health recovered", f"All checks passed: {HEALTH_URL}")
    print("Vanguard production health OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
