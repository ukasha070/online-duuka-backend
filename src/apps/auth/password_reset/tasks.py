from __future__ import annotations

from typing import Optional

from celery import Task


from apps.auth.tasks import (
    DEFAULT_FULL_NAME,
    build_frontend_link,
    email_task,
    send_templated_email_with_retry,
)
from core.config import settings


@email_task("email.send_password_changed_email")
def send_password_changed_email(
    self: Task,
    to_email: str,
    full_name: Optional[str] = None,
) -> None:
    context = {
        "app_name": settings.APP_NAME,
        "full_name": full_name or DEFAULT_FULL_NAME,
    }

    send_templated_email_with_retry(
        self,
        to_email=to_email,
        subject="Your password was changed",
        template_base="emails/password_changed",
        context=context,
    )


@email_task("emails.send_password_reset_email")
def send_password_reset_email(
    self: Task,
    to_email: str,
    token: str,
    full_name: Optional[str] = None,
) -> None:
    reset_link = build_frontend_link(
        path="reset-password",
        token=token,
    )

    context = {
        "app_name": settings.APP_NAME,
        "full_name": full_name or DEFAULT_FULL_NAME,
        "reset_link": reset_link,
        "expiry_minutes": settings.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES,
    }

    send_templated_email_with_retry(
        self,
        to_email=to_email,
        subject="Reset your password",
        template_base="emails/password_reset",
        context=context,
    )
