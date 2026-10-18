"""Generate safe, controlled HTTP-detection demonstrations.

The default mode only writes JSONL fixtures.  ``--send`` posts those fixtures
to an explicitly configured Vanguard ingestion endpoint and should only be used
against infrastructure the operator owns or is authorized to test.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid


SCENARIOS = (
    "ml-burst",
    "single-dos",
    "distributed-dos",
    "scanner",
    "sql-injection",
    "xss",
    "path-traversal",
    "brute-force",
)

# RFC 5737 documentation addresses are safe synthetic identities.  They may
# not geolocate, so callers can provide authorized public source IPs with
# --source-ips when they want visible map origins.
DEFAULT_SOURCE_IPS = [
    "192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13",
    "198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13",
]


def _iso(stamp: datetime) -> str:
    return stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _window_start(seconds: int, now: datetime | None = None) -> datetime:
    current = now or datetime.now(timezone.utc)
    epoch = int(current.timestamp()) // seconds * seconds
    return datetime.fromtimestamp(epoch + 5, timezone.utc)


def _event(
    *, scenario: str, index: int, stamp: datetime, source_ip: str,
    path: str, status: int = 200, duration: float | None = 0.2,
    user_agent: str = "Mozilla/5.0 Vanguard-Demo", bytes_sent: int = 1200,
    server_id: str,
) -> dict[str, object]:
    return {
        "event_id": f"demo-{scenario}-{index:05d}-{uuid.uuid4().hex[:8]}",
        "timestamp": _iso(stamp),
        "source_ip": source_ip,
        "method": "GET",
        "path": path,
        "status_code": status,
        "bytes_sent": bytes_sent,
        "request_time": duration,
        "user_agent": user_agent,
        "host": server_id,
    }


def generate_events(
    scenario: str,
    *,
    server_id: str = "spandan-web",
    source_ips: list[str] | None = None,
    now: datetime | None = None,
) -> list[dict[str, object]]:
    """Return a deterministic scenario shape with unique event IDs."""
    ips = source_ips or DEFAULT_SOURCE_IPS
    if not ips:
        raise ValueError("At least one source IP is required")

    events: list[dict[str, object]] = []
    if scenario == "ml-burst":
        # Each source stays below the 100-request HTTP-flood rule.  The
        # aggregate burst is deliberately unusual for the server-level model.
        start = _window_start(60, now)
        for index in range(32 * 12):
            source = ips[index % min(32, len(ips))]
            stamp = start + timedelta(seconds=5 + index % 50)
            events.append(_event(
                scenario=scenario, index=index, stamp=stamp, source_ip=source,
                path="/", server_id=server_id,
                user_agent=f"Mozilla/5.0 Vanguard-Demo-{index % 4}",
            ))
        return events

    if scenario == "single-dos":
        start = _window_start(300, now)
        source = ips[0]
        for index in range(120):
            events.append(_event(
                scenario=scenario, index=index,
                stamp=start + timedelta(seconds=5 + index), source_ip=source,
                path="/api/expensive", status=503, duration=4.5,
                user_agent="Mozilla/5.0 Vanguard-Demo", server_id=server_id,
            ))
        return events

    if scenario == "distributed-dos":
        if len(ips) < 8:
            raise ValueError("distributed-dos requires at least 8 source IPs")
        start = _window_start(300, now)
        for source_index, source in enumerate(ips[:8]):
            for offset in range(120):
                index = source_index * 120 + offset
                events.append(_event(
                    scenario=scenario, index=index,
                    stamp=start + timedelta(seconds=5 + offset), source_ip=source,
                    path="/api/expensive", status=503, duration=4.5,
                    user_agent="Mozilla/5.0 Vanguard-Demo", server_id=server_id,
                ))
        return events

    start = _window_start(300, now)
    if scenario == "scanner":
        paths = [
            "/.env", "/.git/config", "/wp-admin", "/wp-login.php", "/server-status",
            "/phpmyadmin", "/backup.zip", "/config.yml", "/actuator/env", "/admin",
        ]
        for index in range(20):
            events.append(_event(
                scenario=scenario, index=index,
                stamp=start + timedelta(seconds=5 + index), source_ip=ips[0],
                path=paths[index % len(paths)], status=404, duration=0.05,
                user_agent="feroxbuster/2.13.1", server_id=server_id,
            ))
        return events

    paths = {
        "sql-injection": "/search?q=1%27+UNION+SELECT+1--",
        "xss": "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "path-traversal": "/download?file=../../etc/passwd",
    }
    if scenario in paths:
        return [_event(
            scenario=scenario, index=0, stamp=start + timedelta(seconds=5),
            source_ip=ips[0], path=paths[scenario], status=400,
            duration=0.1, user_agent="Mozilla/5.0 Vanguard-Demo", server_id=server_id,
        )]

    if scenario == "brute-force":
        for index in range(20):
            events.append(_event(
                scenario=scenario, index=index,
                stamp=start + timedelta(seconds=5 + index), source_ip=ips[0],
                path="/login", status=401, duration=0.2,
                user_agent="Mozilla/5.0 Vanguard-Demo", server_id=server_id,
            ))
        return events

    raise ValueError(f"Unknown scenario: {scenario}")


def send_events(events: list[dict[str, object]], backend_url: str, token: str,
                server_id: str, batch_size: int) -> None:
    if not token:
        raise ValueError("--send requires --token or COLLECTOR_TOKEN")
    url = f"{backend_url.rstrip('/')}/api/ingest/batch"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    for start in range(0, len(events), batch_size):
        batch = {"server_id": server_id, "events": events[start:start + batch_size]}
        request = Request(url, data=json.dumps(batch).encode(), headers=headers, method="POST")
        try:
            with urlopen(request, timeout=30) as response:
                payload = json.loads(response.read())
        except (HTTPError, URLError) as exc:
            raise RuntimeError(f"ingestion batch failed: {exc}") from exc
        print(f"sent {min(start + batch_size, len(events))}/{len(events)}: {payload}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument("--server-id", default="spandan-web")
    parser.add_argument("--source-ips", default=", ".join(DEFAULT_SOURCE_IPS),
                        help="comma-separated authorized/synthetic source IPs")
    parser.add_argument("--source-ips-file",
                        help="read one public IP per line from a private local file")
    parser.add_argument("--output", help="JSONL output path; defaults to /tmp/vanguard-demo-<scenario>.jsonl")
    parser.add_argument("--send", action="store_true", help="send to the authenticated ingestion API")
    parser.add_argument("--backend-url", default=os.getenv("BACKEND_URL", "http://localhost"))
    parser.add_argument("--token", default=os.getenv("COLLECTOR_TOKEN", ""))
    parser.add_argument("--batch-size", type=int, default=200, choices=range(1, 251))
    args = parser.parse_args()

    try:
        if args.source_ips_file:
            source_ips = []
            for line in Path(args.source_ips_file).read_text(encoding="utf-8").splitlines():
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                try:
                    address = ipaddress.ip_address(value)
                except ValueError as exc:
                    raise ValueError(f"invalid source IP in file: {value}") from exc
                if not address.is_global:
                    raise ValueError(f"source IP is not public/global: {value}")
                source_ips.append(str(address))
        else:
            source_ips = [item.strip() for item in args.source_ips.split(",") if item.strip()]
        source_ips = list(dict.fromkeys(source_ips))
        events = generate_events(args.scenario, server_id=args.server_id, source_ips=source_ips)
        output = Path(args.output or f"/tmp/vanguard-demo-{args.scenario}.jsonl")
        output.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
        print(f"wrote {len(events)} events to {output}")
        if args.send:
            send_events(events, args.backend_url, args.token, args.server_id, args.batch_size)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"demo generation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
