from __future__ import annotations

from typing import Any

import httpx
from fastapi import HTTPException, status

from app.config import settings

TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


async def verify_turnstile_token(
    token: str | None,
    *,
    remote_ip: str | None = None,
    expected_hostname: str | None = None,
    expected_action: str | None = None,
    timeout_seconds: float | None = None,
) -> bool:
    """Verify a Cloudflare Turnstile token.

    Local mode skips verification unless TURNSTILE_FORCE_VERIFY=true.
    """
    if settings.ENV == "local" and not settings.TURNSTILE_FORCE_VERIFY:
        return True

    if not token:
        return False

    if not settings.TURNSTILE_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Turnstile is not configured.",
        )

    payload: dict[str, str] = {
        "secret": settings.TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds or settings.HTTP_TIMEOUT_SECONDS) as client:
            response = await client.post(TURNSTILE_SITEVERIFY_URL, data=payload)
            response.raise_for_status()
            data: Any = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Turnstile verification failed.",
        ) from exc

    if not isinstance(data, dict) or data.get("success") is not True:
        return False

    hostname = expected_hostname or settings.TURNSTILE_EXPECTED_HOSTNAME
    if hostname and data.get("hostname") != hostname:
        return False

    action = expected_action
    if action and data.get("action") not in {action, None}:
        return False

    return True


async def validate_turnstile_token(
    token: str | None,
    *,
    remote_ip: str | None = None,
    expected_action: str,
) -> None:
    valid = await verify_turnstile_token(
        token,
        remote_ip=remote_ip,
        expected_action=expected_action,
    )

    if not valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Turnstile token.",
        )
