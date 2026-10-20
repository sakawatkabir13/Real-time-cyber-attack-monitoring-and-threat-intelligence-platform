"""Quarantine existing baseline windows using actual access-log evidence.

Dry-run by default. Does not replay requests, fabricate events, delete alerts,
reset a model, or change its learned data. Redis guards prevent a later flush
from re-enabling a quarantined PostgreSQL window. Use the same deployment
settings/secret as ingestion so source hashes and event-time buckets match.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import time

import redis
from sqlalchemy import create_engine, select, tuple_
from sqlalchemy.orm import Session

from app.config import settings
from app.database import sync_database_url
from app.models.traffic_window import TrafficWindow
from app.services.behavioral_features import AUTH_PATH_RE, _base_key, _window_start
from app.services.log_parser import parse_event, parse_timestamp
from app.services.privacy import hash_ip
from app.services.scanner_detection import scanner_indicator


def affected_windows(paths: list[str], server_id: str) -> tuple[Counter, int]:
    counts = Counter()
    evidence = 0
    seen_files = set()
    for name in paths:
        path = Path(name).resolve()
        if path in seen_files:
            continue
        seen_files.add(path)
        opener = gzip.open if str(path).endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as stream:
            for raw in stream:
                entry = parse_event({"raw_log": raw.strip()}, server_id)
                if entry is None:
                    continue
                scanner = scanner_indicator(entry.path, entry.user_agent)
                if not scanner and not (AUTH_PATH_RE.search(entry.path) and entry.status_code == 429):
                    continue
                evidence += 1
                stamp = parse_timestamp(entry.timestamp)
                for scope, seconds in (("server", settings.ML_SERVER_WINDOW_SECONDS),
                                       ("source", settings.ML_SOURCE_WINDOW_SECONDS)):
                    entity = "v3-server" if scope == "server" else "v3-" + hash_ip(entry.source_ip)
                    counts[(scope, entity, _window_start(stamp, seconds), seconds)] += 1
    return counts, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-id", required=True)
    parser.add_argument("--logs", nargs="+", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    counts, evidence = affected_windows(args.logs, args.server_id)
    engine = create_engine(sync_database_url(), connect_args={"sslmode": "require" if settings.DATABASE_SSL else "disable"})
    client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        with Session(engine) as session:
            keys = [(scope, entity, datetime.fromtimestamp(start, timezone.utc), seconds)
                    for scope, entity, start, seconds in counts]
            rows = []
            # Chunk SQL parameters for long rotated-log histories.
            for offset in range(0, len(keys), 500):
                rows.extend(session.scalars(select(TrafficWindow).where(
                    TrafficWindow.server_id == args.server_id,
                    tuple_(TrafficWindow.scope, TrafficWindow.entity_key, TrafficWindow.window_start,
                           TrafficWindow.window_seconds).in_(keys[offset:offset + 500]),
                )))
            summary = {"mode": "apply" if args.apply else "dry_run", "evidence_requests": evidence,
                       "affected_log_windows": len(counts), "existing_database_windows": len(rows),
                       "previously_eligible": sum(row.is_training_eligible for row in rows)}
            if args.apply:
                # First persist monotonic Redis flags; fail closed if Redis is down.
                server_hash = hash_ip("v3:server:" + args.server_id)
                script = """
                if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
                local previous = tonumber(redis.call('HGET', KEYS[1], 'baseline_excluded_count') or '0')
                redis.call('HSET', KEYS[1], 'baseline_excluded_count', math.max(previous, tonumber(ARGV[1])),
                           'updated_at', ARGV[2])
                return 1
                """
                pipe = client.pipeline()
                for (scope, entity, start, _), count in counts.items():
                    pipe.eval(script, 1, _base_key(scope, server_hash, entity, start), count, time.time())
                summary["redis_windows_quarantined"] = sum(pipe.execute())
                for row in rows:
                    row.is_training_eligible = False
                session.commit()
            print(json.dumps(summary))
    finally:
        client.close()
        engine.dispose()


if __name__ == "__main__":
    main()
