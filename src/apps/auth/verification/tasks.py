from __future__ import annotations

from urllib.parse import quote
from typing import Optional

from celery import Task


from apps.auth.tasks import (
    build_frontend_link,
    email_task,
    send_templated_email_with_retry,
)
from core.config import settings

DEFAULT_FULL_NAME = "there"


@email_task("emails.send_verification_email")
def send_verification_email(
    self: Task,
    to_email: str,
    token: str,
    full_name: Optional[str] = None,
) -> None:
    verification_link = build_frontend_link(
        path="verify-email",
        token=token,
    )

    context = {
        "app_name": settings.APP_NAME,
        "full_name": full_name or DEFAULT_FULL_NAME,
        "verification_link": verification_link,
        "expiry_minutes": settings.EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES,
    }

    send_templated_email_with_retry(
        self,
        to_email=to_email,
        subject="Verify your email address",
        template_base="emails/email_verification",
        context=context,
    )
