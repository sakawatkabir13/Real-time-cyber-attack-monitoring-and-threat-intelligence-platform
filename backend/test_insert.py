"""Manual smoke test for the detection-to-database pipeline."""

import asyncio

from app.database import AsyncSessionLocal
from app.redis_client import redis_client
from app.schemas.ingest import LogEntry
from app.services.detection_engine import detection_engine
from app.services.event_pipeline import PendingThreat, persist_threats
from app.services.geo_lookup import geo_lookup


async def test_insert() -> None:
    await redis_client.connect()
    try:
        log_entry = LogEntry(
            server_id="manual-smoke-test",
            timestamp="26/Jul/2026:12:00:03 +0000",
            source_ip="100.12.30.8",
            method="GET",
            path="/?id=1+UNION+SELECT+password+FROM+users",
            status_code=403,
            bytes_sent=4707,
            request_time=0.1,
            user_agent="smoke-test",
            host="localhost",
        )
        detected = await detection_engine.process_log(log_entry)
        if detected is None:
            raise RuntimeError("Smoke-test event was not detected")
        async with AsyncSessionLocal() as db:
            records = await persist_threats(db, [PendingThreat(detected)])
        print(f"Successfully inserted event {records[0].id}")
    finally:
        await geo_lookup.close()
        await redis_client.close()


if __name__ == "__main__":
    asyncio.run(test_insert())
