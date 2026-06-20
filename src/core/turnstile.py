from __future__ import annotations

import os
from typing import NotRequired, Optional, TypedDict

from fastapi import HTTPException
import httpx


TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


class TurnstileResponse(TypedDict, total=False):
    success: bool
    challenge_ts: str
    hostname: str
    action: str
    cdata: str
    error_codes: NotRequired[list[str]]


async def verify_turnstile_token(
    token: str,
    *,
    secret_key: Optional[str] = None,
    remote_ip: Optional[str] = None,
    expected_hostname: Optional[str] = None,
    expected_action: Optional[str] = None,
    timeout_seconds: float = 10.0,
) -> bool | None:
    """
    Verify a Cloudflare Turnstile token.

    Returns:
        True  -> token is valid
        False -> token is invalid
        None  -> config error, network error, bad API response, or hostname/action mismatch
    """

    secret = secret_key or os.getenv("TURNSTILE_SECRET_KEY")

    if not secret:
        return None

    if not token or not isinstance(token, str):
        return False

    payload: dict[str, str] = {
        "secret": secret,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.post(
                TURNSTILE_SITEVERIFY_URL,
                json=payload,
            )

        response.raise_for_status()
        data = response.json()

    except (httpx.HTTPError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    success = data.get("success")

    if success is not True:
        return False

    hostname = data.get("hostname")
    action = data.get("action")

    if expected_hostname and hostname != expected_hostname:
        return None

    if expected_action and action != expected_action:
        return None

    return True


async def validate_turnstile_token(
        turnstile_token:str, 
        ip_address:str | None, 
        expected_action:str
    ):
    is_valid = await verify_turnstile_token(
        turnstile_token,
        remote_ip=ip_address,
        expected_action=expected_action,
    )

    if is_valid is not True:
        raise HTTPException(status_code=400, detail="Invalid Turnstile token")