"""
Replace / extend the two-factor section of your existing tokens.py with the
functions below.  Everything else in that file stays exactly as-is.

Changes vs your original:
  - TokenType.twofactor value is now consistently "two-factor"
  - create_two_factor_token  accepts device + client info and remember_me
  - decode_two_factor_token  checks for the corrected type string
  - TwoFactorTokenPayload    typed Pydantic model for the decoded claims
"""

from datetime import timedelta
from typing import Any
from uuid import uuid4

import jwt
from pydantic import BaseModel

from core.config import settings
from core.utils import utc_now
from apps.auth.schema import DeviceInfoPayload
from apps.auth.utils import ClientContext

# ── keep your existing TokenType enum but make sure twofactor = "two-factor" ──
# class TokenType(StrEnum):
#     access      = "access"
#     refresh     = "refresh"
#     twofactor   = "two-factor"      # ← was "two_factor" — fix this in your enum
#     googletoken = "google-token"


# ---------------------------------------------------------------------------
# Typed payload model (optional but handy for callers)
# ---------------------------------------------------------------------------


class TwoFactorTokenPayload(BaseModel):
    sub: str  # user_id
    device_id: str | None = None
    device_name: str | None = None
    device_type: str | None = None
    os_name: str | None = None
    browser_name: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    remember_me: bool = False


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


def create_two_factor_token(
    *,
    user_id: str,
    device: DeviceInfoPayload,
    client: ClientContext,
    remember_me: bool = False,
) -> str:
    """
    Issue a short-lived JWT that proves the user passed password auth and
    carries enough context to build the session after they pass the TOTP step.

    Expire time comes from settings.TWO_FACTOR_CHALLENGE_EXPIRE_MINUTES
    (recommended: 3–5 minutes).
    """
    now = utc_now()
    expires_at = now + timedelta(minutes=settings.TWO_FACTOR_CHALLENGE_EXPIRE_MINUTES)

    payload: dict[str, Any] = {
        # standard claims
        "sub": user_id,
        "type": "two-factor",  # matches TokenType.twofactor
        "jti": str(uuid4()),
        "iat": now,
        "nbf": now,
        "exp": expires_at,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        # device context — needed to build CreateSessionPayload after verify
        "device_id": device.device_id,
        "device_name": device.device_name,
        "device_type": device.device_type,
        "os_name": device.os_name,
        "browser_name": device.browser_name,
        # client context
        "ip_address": client.ip_address,
        "user_agent": client.user_agent,
        # session preference
        "remember_me": remember_me,
    }

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def decode_two_factor_token(token: str) -> TwoFactorTokenPayload:
    """
    Decode and validate a two-factor challenge token.

    Raises ValueError with a human-readable message on any failure so the
    caller can surface it as a 401 without leaking internals.
    """
    try:
        raw: dict[str, Any] = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Two-factor challenge has expired. Please sign in again.")
    except jwt.InvalidAudienceError:
        raise ValueError("Invalid token audience.")
    except jwt.InvalidIssuerError:
        raise ValueError("Invalid token issuer.")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid two-factor token.")

    if raw.get("type") != "two-factor":
        raise ValueError("Invalid two-factor token.")

    return TwoFactorTokenPayload(
        sub=raw["sub"],
        device_id=raw.get("device_id"),
        device_name=raw.get("device_name"),
        device_type=raw.get("device_type"),
        os_name=raw.get("os_name"),
        browser_name=raw.get("browser_name"),
        ip_address=raw.get("ip_address"),
        user_agent=raw.get("user_agent"),
        remember_me=raw.get("remember_me", False),
    )
