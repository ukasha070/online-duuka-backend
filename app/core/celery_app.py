from __future__ import annotations

from celery import Celery

from app.config import settings

celery_app = Celery(
    "online_duuka",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.email_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    result_expires=settings.CELERY_EXPIRY_SECONDS,
)
