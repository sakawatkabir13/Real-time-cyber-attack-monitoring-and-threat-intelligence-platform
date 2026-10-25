"""Exclude historical bundled-demo windows from training without deleting them.

Dry-run by default. Evidence is an actual demo-* event identifier retained in
the Redis window, not an assumption about its IP, rate, path or anomaly score.
Run on the deployment after backing up PostgreSQL and the model. No traffic or
feature values are exported, and no existing model is reset or promoted.
"""

import argparse
from datetime import datetime, timezone
import json
import time

import redis
from sqlalchemy import create_engine, select, tuple_
from sqlalchemy.orm import Session

from app.config import settings
from app.database import sync_database_url
from app.models.traffic_window import TrafficWindow


def demo_windows(client, server_id: str) -> dict[str, tuple]:
    result = {}
    for base in client.scan_iter(match="ml:window:*"):
        parts = base.split(":")
        if len(parts) != 6 or parts[2] not in {"server", "source"}:
            continue
        data = client.hgetall(base)
        if data.get("server_id") != server_id:
            continue
        if next(client.sscan_iter(base + ":events", match="demo-*", count=100), None) is None:
            continue
        result[base] = (data["scope"], data["entity_key"],
                        datetime.fromtimestamp(int(data["window_start"]), timezone.utc),
                        int(data["window_seconds"]))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-id", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    engine = create_engine(sync_database_url(), connect_args={
        "sslmode": "require" if settings.DATABASE_SSL else "disable"})
    try:
        windows = demo_windows(client, args.server_id)
        keys = list(windows.values())
        with Session(engine) as db:
            rows = []
            for offset in range(0, len(keys), 500):
                rows.extend(db.scalars(select(TrafficWindow).where(
                    TrafficWindow.server_id == args.server_id,
                    tuple_(TrafficWindow.scope, TrafficWindow.entity_key,
                           TrafficWindow.window_start, TrafficWindow.window_seconds)
                    .in_(keys[offset:offset + 500]))))
            result = {"mode": "apply" if args.apply else "dry_run", "demo_windows": len(windows),
                      "database_windows": len(rows), "previously_eligible": sum(bool(r.is_training_eligible) for r in rows)}
            if args.apply:
                # Redis first: a stale flush must not re-enable the DB rows.
                script = """
                if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
                local count = tonumber(redis.call('HGET', KEYS[1], 'demonstration_request_count') or '0')
                redis.call('HSET', KEYS[1], 'demonstration_request_count', math.max(1, count), 'updated_at', ARGV[1])
                return 1
                """
                pipe = client.pipeline()
                for base in windows:
                    pipe.eval(script, 1, base, time.time())
                result["redis_windows_quarantined"] = sum(pipe.execute())
                for row in rows:
                    row.is_training_eligible = False
                db.commit()
            print(json.dumps(result))
    finally:
        client.close()
        engine.dispose()


if __name__ == "__main__":
    main()
