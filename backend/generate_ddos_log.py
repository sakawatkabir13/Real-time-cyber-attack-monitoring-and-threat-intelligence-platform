"""Generate a repeatable demo log and optionally ingest it through the real API."""

import argparse
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx


def generate_lines(count: int = 3000) -> list[str]:
    rng = random.Random(360)
    current_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    attackers = [
        "185.15.20.11", "103.45.10.22", "88.200.10.45", "45.22.19.100",
        "220.11.9.81", "193.10.5.5", "5.100.20.30", "110.40.2.1",
    ]
    normal_ips = [
        f"{rng.randint(1, 220)}.{rng.randint(1, 255)}.{rng.randint(1, 255)}.{rng.randint(1, 255)}"
        for _ in range(50)
    ]
    lines = []
    for index in range(count):
        if count // 6 < index < count * 5 // 6 and rng.random() < 0.9:
            ip = rng.choice(attackers)
            path = "/"
            code = "503" if rng.random() < 0.1 else "200"
            current_time += timedelta(milliseconds=rng.randint(5, 50))
        else:
            ip = rng.choice(normal_ips)
            path = rng.choice(["/index.html", "/images/logo.png", "/about", "/contact"])
            code = "200" if rng.random() < 0.95 else "404"
            current_time += timedelta(seconds=rng.randint(1, 4))
        timestamp = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" {code} '
            f'{rng.randint(200, 5000)} "-" "Mozilla/5.0"'
        )
    return lines


def send(lines: list[str], backend_url: str, token: str) -> None:
    if not token:
        raise SystemExit("Set COLLECTOR_TOKEN or pass --token when using --send")
    url = f"{backend_url.rstrip('/')}/api/ingest/batch"
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(timeout=30.0) as client:
        for start in range(0, len(lines), 200):
            events = [
                {"event_id": uuid.uuid4().hex, "raw_log": line, "type": "combined_log"}
                for line in lines[start : start + 200]
            ]
            response = client.post(
                url,
                headers=headers,
                json={"server_id": "demo-simulator", "events": events},
            )
            response.raise_for_status()
            print(f"Sent {min(start + len(events), len(lines))}/{len(lines)} events")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=3000)
    parser.add_argument("--output", default="demo_ddos_attack.log")
    parser.add_argument("--send", action="store_true", help="also POST events to the ingestion API")
    parser.add_argument("--backend-url", default=os.getenv("BACKEND_URL", "http://localhost"))
    parser.add_argument("--token", default=os.getenv("COLLECTOR_TOKEN", ""))
    args = parser.parse_args()
    lines = generate_lines(max(1, args.count))
    Path(args.output).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Generated {args.output} with {len(lines):,} requests")
    if args.send:
        send(lines, args.backend_url, args.token)


if __name__ == "__main__":
    main()
