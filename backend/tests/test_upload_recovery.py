"""Upload retries never require a live broker, database, or external provider."""

from contextlib import asynccontextmanager
import json
import os
import stat
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest
import pytest_asyncio
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import OperationalError

from app.config import settings
from app.tasks import analyze_logs


class RetryScheduled(Exception):
    def __init__(self, countdown, exc):
        self.countdown = countdown
        self.exc = exc


@pytest.fixture
def upload(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "ANALYSIS_UPLOAD_DIR", str(tmp_path))
    job_id = "a" * 32
    path = tmp_path / f"{job_id}.log"
    path.write_text("uploaded log\n")
    monkeypatch.setattr(analyze_logs, "_completed_analysis", AsyncMock(return_value=None))
    monkeypatch.setattr(analyze_logs, "_record_failure", AsyncMock())
    return job_id, path


def run_task(upload, *, retries=0):
    job_id, path = upload
    task = analyze_logs.analyze_log_file_task
    task.push_request(retries=retries)
    try:
        return task.run(job_id, str(path), 1)
    finally:
        task.pop_request()


@pytest.mark.parametrize("failure", [
    RedisConnectionError("private Redis password"),
    OperationalError("SELECT", {}, Exception("private database password")),
    TimeoutError("private provider response"),
])
def test_transient_failure_retains_private_upload_and_schedules_retry(upload, monkeypatch, failure):
    job_id, path = upload
    monkeypatch.setattr(analyze_logs, "_process_file", AsyncMock(side_effect=failure))

    def retry(*, exc, countdown):
        raise RetryScheduled(countdown, exc)

    monkeypatch.setattr(analyze_logs.analyze_log_file_task, "retry", retry)
    with pytest.raises(RetryScheduled) as scheduled:
        run_task(upload)
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert scheduled.value.countdown == 30
    assert "private" not in str(scheduled.value.exc)
    analyze_logs._record_failure.assert_awaited_once_with(
        job_id, 1, retrying=True, retries=1, delay=30,
    )


def test_retry_backoff_is_bounded(upload, monkeypatch):
    monkeypatch.setattr(analyze_logs, "_process_file", AsyncMock(side_effect=TimeoutError()))

    def retry(*, exc, countdown):
        raise RetryScheduled(countdown, exc)

    monkeypatch.setattr(analyze_logs.analyze_log_file_task, "retry", retry)
    with pytest.raises(RetryScheduled) as scheduled:
        run_task(upload, retries=4)
    assert scheduled.value.countdown == 300
    assert upload[1].exists()


def test_retry_exhaustion_releases_job_and_removes_upload(upload, monkeypatch):
    monkeypatch.setattr(analyze_logs, "_process_file", AsyncMock(side_effect=TimeoutError("secret")))
    retry = AsyncMock()
    monkeypatch.setattr(analyze_logs.analyze_log_file_task, "retry", retry)
    with pytest.raises(RuntimeError, match="private server logs") as error:
        run_task(upload, retries=analyze_logs.ANALYSIS_MAX_RETRIES)
    assert "secret" not in str(error.value)
    assert not upload[1].exists()
    assert analyze_logs._record_failure.await_args.kwargs["retrying"] is False
    retry.assert_not_called()


def test_permanent_failure_does_not_retry_or_expose_exception(upload, monkeypatch):
    monkeypatch.setattr(analyze_logs, "_process_file", AsyncMock(side_effect=ValueError("secret")))
    with pytest.raises(RuntimeError) as error:
        run_task(upload)
    assert "secret" not in str(error.value)
    assert not upload[1].exists()
    assert analyze_logs._record_failure.await_args.kwargs["retrying"] is False


def test_expired_upload_is_removed_without_processing(upload, monkeypatch):
    old = time.time() - analyze_logs.ANALYSIS_UPLOAD_RETENTION_SECONDS - 1
    os.utime(upload[1], (old, old))
    process = AsyncMock()
    monkeypatch.setattr(analyze_logs, "_process_file", process)
    with pytest.raises(RuntimeError):
        run_task(upload)
    process.assert_not_called()
    assert not upload[1].exists()


def test_success_removes_upload(upload, monkeypatch):
    result = {"state": "complete", "processed": 1}
    monkeypatch.setattr(analyze_logs, "_process_file", AsyncMock(return_value=result))
    assert run_task(upload) == result
    assert not upload[1].exists()
    analyze_logs._record_failure.assert_not_called()


def test_redelivery_after_success_accepts_missing_input_without_overwriting_completion(upload, monkeypatch):
    result = {"jobId": upload[0], "state": "complete", "processed": 1}
    upload[1].unlink()
    monkeypatch.setattr(analyze_logs, "_completed_analysis", AsyncMock(return_value=result))
    process = AsyncMock()
    monkeypatch.setattr(analyze_logs, "_process_file", process)
    assert run_task(upload) == result
    process.assert_not_called()
    analyze_logs._record_failure.assert_not_called()


@pytest_asyncio.fixture
async def redis(monkeypatch):
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(analyze_logs.redis_client, "redis", client)
    monkeypatch.setattr(analyze_logs.redis_client, "connect", AsyncMock())
    monkeypatch.setattr(analyze_logs.redis_client, "close", AsyncMock())
    monkeypatch.setattr(analyze_logs.geo_lookup, "close", AsyncMock())
    monkeypatch.setattr(analyze_logs, "engine", SimpleNamespace(dispose=AsyncMock()))
    yield client
    await client.aclose()


@pytest.mark.asyncio
async def test_replay_after_partial_persistence_reuses_stable_line_ids(redis, tmp_path, monkeypatch):
    job_id = "b" * 32
    path = tmp_path / f"{job_id}.log"
    path.write_text("\n".join(json.dumps({
        "ip": "203.0.113.7", "timestamp": "2026-08-05T00:00:01Z",
        "path": f"/example/{i}", "status_code": 200,
    }) for i in range(101)))
    await redis.set(analyze_logs.ACTIVE_ANALYSIS_KEY, job_id)
    detected_ids, stored_ids, published_ids = [], set(), set()

    async def detect(log):
        detected_ids.append(log.event_id)
        return object()

    @asynccontextmanager
    async def session():
        yield object()

    async def persist(_db, pending):
        stored_ids.update(item.ingest_event_id for item in pending)

    attempts = 0

    async def publish(traffic):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RedisConnectionError("connection interrupted after database commit")
        published_ids.update(item.log.event_id for item in traffic)

    monkeypatch.setattr(analyze_logs.detection_engine, "process_log", detect)
    monkeypatch.setattr(analyze_logs, "AsyncSessionLocal", session)
    monkeypatch.setattr(analyze_logs, "persist_threats", persist)
    monkeypatch.setattr(analyze_logs, "publish_http_requests", publish)
    with pytest.raises(RedisConnectionError):
        await analyze_logs._process_file(job_id, str(path), 101)
    assert path.exists()
    assert await redis.get(analyze_logs.ACTIVE_ANALYSIS_KEY) == job_id
    first_ids = list(detected_ids)
    assert len(first_ids) == 100
    result = await analyze_logs._process_file(job_id, str(path), 101)
    assert result["state"] == "complete" and result["processed"] == 101
    assert detected_ids[100:200] == first_ids
    assert len(stored_ids) == len(published_ids) == 101
    assert await redis.get(analyze_logs.ACTIVE_ANALYSIS_KEY) is None
    # The synchronous task is responsible for terminal input removal.
    assert path.exists()


@pytest.mark.asyncio
async def test_invalid_log_lines_are_rejected_once_without_transient_retry(redis, tmp_path):
    path = tmp_path / "invalid.log"
    path.write_text("this is not an access log\n\ninvalid again\n")
    result = await analyze_logs._process_file("c" * 32, str(path), 2)
    assert result["state"] == "complete"
    assert result["processed"] == result["rejected"] == 2
    assert result["detections"] == 0


@pytest.mark.asyncio
async def test_failure_status_preserves_checkpoint_sanitizes_error_and_releases_only_terminal(redis):
    job_id = "d" * 32
    await redis.set(analyze_logs.ACTIVE_ANALYSIS_KEY, job_id)
    await analyze_logs.save_analysis_status(job_id, processed=100, rejected=3, detections=4)
    await analyze_logs._record_failure(job_id, 200, retrying=True, retries=1, delay=30)
    status = json.loads(await redis.get(analyze_logs.analysis_status_key(job_id)))
    assert status["state"] == "retrying" and status["processed"] == 100
    assert status["retryDelaySeconds"] == 30
    assert await redis.get(analyze_logs.ACTIVE_ANALYSIS_KEY) == job_id
    await analyze_logs._record_failure(job_id, 200, retrying=False, retries=5, delay=300)
    status = json.loads(await redis.get(analyze_logs.analysis_status_key(job_id)))
    assert status["state"] == "error" and status["processed"] == 100
    assert status["retryDelaySeconds"] is None
    assert await redis.get(analyze_logs.ACTIVE_ANALYSIS_KEY) is None


@pytest.mark.asyncio
async def test_completed_lookup_is_durable_and_releases_stranded_active_job(redis):
    job_id = "e" * 32
    await redis.set(analyze_logs.ACTIVE_ANALYSIS_KEY, job_id)
    result = await analyze_logs.save_analysis_status(job_id, state="complete", processed=12)
    assert await analyze_logs._completed_analysis(job_id) == result
    assert await redis.get(analyze_logs.ACTIVE_ANALYSIS_KEY) is None
