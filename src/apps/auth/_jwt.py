from datetime import timedelta
from typing import Any
from enum import StrEnum
from uuid import uuid4

import jwt
from jwt import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenError,
)
from pydantic import BaseModel

from core.utils import utc_now
from core.config import settings
from apps.auth.schema import CreateSessionPayload


class TokenType(StrEnum):
    access = "access"
    refresh = "refresh"
    twofactor = "two-factor"
    googletoken = "google-token"


class AuthToken(BaseModel):
    sub: str
    session_id: str
    type: TokenType
    jti: str
    iat: int
    nbf: int
    exp: int
    iss: str
    aud: str


class GoogleTokenPayload(AuthToken):
    # Device info
    device_id: str | None = None
    device_name: str | None = None
    device_type: str | None = None
    os_name: str | None = None
    browser_name: str | None = None


def create_jwt_token(
    *,
    user_id: str,
    session_id: str,
    token_type: TokenType,
    expires_delta: timedelta,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    now = utc_now()
    expires_at = now + expires_delta

    payload = {
        "sub": user_id,
        "session_id": session_id,
        "type": token_type,
        "jti": str(uuid4()),
        "iat": now,
        "nbf": now,
        "exp": expires_at,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        **(extra_claims or {}),
    }

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_access_token(
    *, user_id: str, session_id: str, extra_claims: dict[str, Any] | None = None
) -> str:
    return create_jwt_token(
        user_id=user_id,
        session_id=session_id,
        token_type=TokenType.access,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        extra_claims=extra_claims,
    )


def create_refresh_token(
    *, user_id: str, session_id: str, extra_claims: dict[str, Any] | None = None
) -> str:
    return create_jwt_token(
        user_id=user_id,
        session_id=session_id,
        token_type=TokenType.refresh,
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        extra_claims=extra_claims,
    )


def create_google_token(*, user_id: str, session_payload: CreateSessionPayload) -> str:
    return create_jwt_token(
        user_id=user_id,
        session_id="",
        token_type=TokenType.googletoken,
        expires_delta=timedelta(minutes=settings.GOOGLE_TOKEN_EXPIRE_MINUTES),
        extra_claims={**session_payload.model_dump()},
    )


def decode_jwt_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
        )

        return payload

    except ExpiredSignatureError:
        raise ValueError("Token has expired")

    except InvalidAudienceError:
        raise ValueError("Invalid token audience")

    except InvalidIssuerError:
        raise ValueError("Invalid token issuer")

    except InvalidTokenError:
        raise ValueError("Invalid token")


def decode_access_token(token: str) -> dict[str, Any]:
    payload = decode_jwt_token(token)

    if payload.get("type") != "access":
        raise ValueError("Invalid access token")

    return payload


def decode_refresh_token(token: str) -> dict[str, Any]:
    payload = decode_jwt_token(token)

    if payload.get("type") != "refresh":
        raise ValueError("Invalid refresh token")

    return payload


def create_two_factor_token(
    *, user_id: str, session_payload: CreateSessionPayload
) -> str:
    now = utc_now()
    expires_at = now + timedelta(minutes=settings.TWO_FACTOR_CHALLENGE_EXPIRE_MINUTES)

    payload = {
        "sub": user_id,
        "type": "two_factor",
        "jti": str(uuid4()),
        "iat": now,
        "nbf": now,
        "exp": expires_at,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        **(session_payload.model_dump() or {}),
    }

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_two_factor_token(token: str) -> dict[str, Any]:
    payload = decode_jwt_token(token)

    if payload.get("type") != "two_factor":
        raise ValueError("Invalid two-factor token")

    return payload


def validate_token(token: str, type: TokenType):
    payload = decode_jwt_token(token=token)

    if payload.get("type") != type:
        raise ValueError(f"Invalid {type} token")
    return payload
