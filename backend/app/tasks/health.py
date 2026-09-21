"""Background-pipeline heartbeat proving that Beat can reach a worker."""

import time

import redis

from app.config import settings
from app.tasks.celery_app import celery_app


CELERY_PIPELINE_HEARTBEAT = "system:celery-pipeline:heartbeat"


@celery_app.task(name="pipeline_heartbeat_task")
def pipeline_heartbeat_task() -> float:
    timestamp = time.time()
    client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        client.set(CELERY_PIPELINE_HEARTBEAT, str(timestamp), ex=120)
    finally:
        client.close()
    return timestamp
