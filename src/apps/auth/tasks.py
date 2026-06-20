from __future__ import annotations

import asyncio
from urllib.parse import quote
from typing import Any, Optional
from datetime import datetime, timezone

from celery import Task


from core.config import settings
from core.celery_app import celery_app
from core.mailers import email_service

DEFAULT_FULL_NAME = "there"
TWO_FACTOR_ACTIONS = {
    "enabled": {
        "subject": "Two-factor authentication was enabled",
        "heading": "Two-factor authentication enabled",
        "description": "Authenticator app two-factor authentication was enabled on your account.",
    },
    "disabled": {
        "subject": "Two-factor authentication was disabled",
        "heading": "Two-factor authentication disabled",
        "description": "Authenticator app two-factor authentication was disabled on your account.",
    },
    "recovery_codes_regenerated": {
        "subject": "Your recovery codes were regenerated",
        "heading": "Recovery codes regenerated",
        "description": "New two-factor recovery codes were generated for your account.",
    },
    "recovery_code_used": {
        "subject": "A recovery code was used",
        "heading": "Recovery code used",
        "description": "A recovery code was used to complete two-factor sign-in to your account.",
    },
    "otp_email_sent": {
            "subject": "Two-factor Authentication Code",
            "heading": "Two-factor Authentication Code",
            "description": "Use the code to verify inorder to login.",
    }
}


def get_frontend_url() -> str:
    return settings.FRONTEND_URL.rstrip("/")


def build_frontend_link(path: str, token: str) -> str:
    safe_token = quote(token, safe="")
    return f"{get_frontend_url()}/{path.lstrip('/')}?token={safe_token}"


def run_async_email(coro: Any) -> Any:
    """
    Celery tasks are synchronous, but email_service.send_email is async.
    This helper safely runs the async email function inside the sync Celery task.
    """
    return asyncio.run(coro)


def render_email_template(
    template_base: str,
    context: dict[str, Any],
) -> tuple[str, str]:
    """
    Example:
        template_base='emails/welcome'

    This renders:
        emails/welcome.txt
        emails/welcome.html
    """
    plain_body = email_service.render_template(
        f"{template_base}.txt",
        context,
    )

    html_body = email_service.render_template(
        f"{template_base}.html",
        context,
    )

    return plain_body, html_body


def send_templated_email(
    *,
    to_email: str,
    subject: str,
    template_base: str,
    context: dict[str, Any],
) -> None:
    plain_body, html_body = render_email_template(
        template_base=template_base,
        context=context,
    )

    run_async_email(
        email_service.send_email(
            to_email=to_email,
            subject=subject,
            plain_body=plain_body,
            html_body=html_body,
        )
    )


def send_templated_email_with_retry(
    task: Task,
    *,
    to_email: str,
    subject: str,
    template_base: str,
    context: dict[str, Any],
) -> None:
    try:
        send_templated_email(
            to_email=to_email,
            subject=subject,
            template_base=template_base,
            context=context,
        )
    except Exception as exc:
        raise task.retry(exc=exc) from exc


def email_task(
    name: str,
    max_retries: int = settings.MAX_EMAIL_RETRIES,
    retry_delay: int = settings.DEFAULT_RETRY_DELAY_SECONDS,
):
    return celery_app.task(
        name=name,
        bind=True,
        max_retries=max_retries,
        default_retry_delay=retry_delay,
    )


@email_task("emails.send_welcome_email")
def send_welcome_email(
    self: Task,
    to_email: str,
    full_name: Optional[str] = None,
) -> None:
    context = {
        "app_name": settings.APP_NAME,
        "full_name": full_name or DEFAULT_FULL_NAME,
        "frontend_url": get_frontend_url(),
    }

    send_templated_email_with_retry(
        self,
        to_email=to_email,
        subject=f"Welcome to {settings.APP_NAME}",
        template_base="emails/welcome",
        context=context,
    )


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


@email_task("emails.send_new_login_alert_email")
def send_new_login_alert_email(
    self: Task,
    to_email: str,
    full_name: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    location: Optional[str] = None,
    login_time: Optional[str] = None,
) -> None:
    """
    login_time is a string instead of datetime because Celery task arguments
    should preferably be JSON-serializable.
    """
    current_login_time = login_time or datetime.now(timezone.utc).isoformat()

    context = {
        "app_name": settings.APP_NAME,
        "full_name": full_name or DEFAULT_FULL_NAME,
        "ip_address": ip_address or "Unknown",
        "user_agent": user_agent or "Unknown device",
        "location": location or "Unknown location",
        "login_time": current_login_time,
    }

    send_templated_email_with_retry(
        self,
        to_email=to_email,
        subject="New login to your account",
        template_base="emails/new_login_alert",
        context=context,
    )


@email_task("emails.send_two_factor_security_email")
def send_two_factor_security_email(
    self: Task,
    to_email: str,
    action: str,
    full_name: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    occurred_at: Optional[str] = None,
) -> None:
    action_details = TWO_FACTOR_ACTIONS.get(
        action,
        {
            "subject": "Two-factor authentication update",
            "heading": "Two-factor authentication update",
            "description": "A two-factor authentication setting changed on your account.",
        },
    )

    context = {
        "app_name": settings.APP_NAME,
        "full_name": full_name or DEFAULT_FULL_NAME,
        "heading": action_details["heading"],
        "description": action_details["description"],
        "ip_address": ip_address or "Unknown",
        "user_agent": user_agent or "Unknown device",
        "occurred_at": occurred_at or datetime.now(timezone.utc).isoformat(),
    }

    send_templated_email_with_retry(
        self,
        to_email=to_email,
        subject=action_details["subject"],
        template_base="emails/two_factor_security",
        context=context,
    )



@email_task("emails.send_two_factor_otp_code_email")
def send_two_factor_otp_code_email(
    self: Task,
    to_email: str,
    action: str,
    otp_code: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    occurred_at: Optional[str] = None,
) -> None:
    action_details = TWO_FACTOR_ACTIONS.get(
        action,
        {
            "subject": "Two-factor Authentication Code",
            "heading": "Two-factor Authentication Code",
            "description": "Use the code to verify inorder to login.",
        },
    )

    context = {
        "app_name": settings.APP_NAME,
        "heading": action_details["heading"],
        "description": action_details["description"],
        "ip_address": ip_address or "Unknown",
        "user_agent": user_agent or "Unknown device",
        "otp_code": otp_code,
        "occurred_at": occurred_at or datetime.now(timezone.utc).isoformat(),
    }

    send_templated_email_with_retry(
        self,
        to_email=to_email,
        subject=action_details["subject"],
        template_base="emails/two_factor_security",
        context=context,
    )
