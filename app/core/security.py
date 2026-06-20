from datetime import timedelta
from enum import StrEnum
from typing import Any
from uuid import uuid4
import hashlib
import secrets

import jwt
from jwt import ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError, InvalidTokenError
from passlib.context import CryptContext

from app.config import settings
from app.core.utils import utc_now

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"
    TWO_FACTOR = "two-factor"
    GOOGLE = "google-token"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str | None) -> bool:
    if not hashed_password:
        return False
    return pwd_context.verify(plain_password, hashed_password)


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_jwt_token(
    *,
    user_id: str,
    token_type: TokenType,
    expires_delta: timedelta,
    session_id: str = "",
    extra_claims: dict[str, Any] | None = None,
) -> str:
    now = utc_now()
    expires_at = now + expires_delta

    payload = {
        "sub": user_id,
        "session_id": session_id,
        "type": token_type.value,
        "jti": str(uuid4()),
        "iat": now,
        "nbf": now,
        "exp": expires_at,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        **(extra_claims or {}),
    }

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_access_token(*, user_id: str, session_id: str, extra_claims: dict[str, Any] | None = None) -> str:
    return create_jwt_token(
        user_id=user_id,
        session_id=session_id,
        token_type=TokenType.ACCESS,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        extra_claims=extra_claims,
    )


def create_refresh_token(
    *,
    user_id: str,
    session_id: str,
    remember_me: bool = False,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    days = settings.REFRESH_TOKEN_EXPIRE_REMEMBER_ME_DAYS if remember_me else settings.REFRESH_TOKEN_EXPIRE_DAYS
    return create_jwt_token(
        user_id=user_id,
        session_id=session_id,
        token_type=TokenType.REFRESH,
        expires_delta=timedelta(days=days),
        extra_claims=extra_claims,
    )


def create_two_factor_token(*, user_id: str, extra_claims: dict[str, Any] | None = None) -> str:
    return create_jwt_token(
        user_id=user_id,
        token_type=TokenType.TWO_FACTOR,
        expires_delta=timedelta(minutes=settings.TWO_FACTOR_CHALLENGE_EXPIRE_MINUTES),
        extra_claims=extra_claims,
    )


def decode_jwt_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
        )
    except ExpiredSignatureError as exc:
        raise ValueError("Token has expired") from exc
    except InvalidAudienceError as exc:
        raise ValueError("Invalid token audience") from exc
    except InvalidIssuerError as exc:
        raise ValueError("Invalid token issuer") from exc
    except InvalidTokenError as exc:
        raise ValueError("Invalid token") from exc


def validate_token(token: str, token_type: TokenType) -> dict[str, Any]:
    payload = decode_jwt_token(token)
    if payload.get("type") != token_type.value:
        raise ValueError(f"Invalid {token_type.value} token")
    return payload
