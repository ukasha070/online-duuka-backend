from celery import Celery

from .config import settings

celery_app = Celery(
    "celery_app",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["apps.auth.tasks", "apps.auth.password_reset.tasks"],
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
