from celery import Celery
from app.config import settings

from celery.schedules import crontab

celery_app = Celery(
    "vanguard_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.tasks.enrich_ips",
        "app.tasks.train_model",
        "app.tasks.cleanup_events",
        "app.tasks.flush_traffic_windows",
    ]
)

celery_app.conf.beat_schedule = {
    'train-model-daily': {
        'task': 'train_model_task',
        'schedule': crontab(minute=30, hour=3),
    },
    'persist-traffic-windows-every-minute': {
        'task': 'flush_traffic_windows_task',
        'schedule': 60.0,
    },
    'delete-expired-events-daily': {
        'task': 'cleanup_events_task',
        'schedule': crontab(minute=15, hour=2),
    },
}
celery_app.conf.timezone = 'UTC'
celery_app.conf.broker_connection_retry_on_startup = True
