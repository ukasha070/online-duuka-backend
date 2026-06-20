from __future__ import annotations

from datetime import timedelta
import base64
import hashlib
import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx
import urllib3
from fastapi import HTTPException, Request, status
from google.auth.transport import urllib3 as google_urllib3
from google.oauth2 import id_token
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.core import utils
from app.core.redis_client import get_redis_client
from app.core.security import TokenType, create_jwt_token, validate_token
from app.models.user import AuthType, User
from app.schemas.auth import DeviceInfoPayload, TokenResponse
from app.schemas.google_oauth import (
    GoogleCode,
    GoogleLoginPayload,
    GoogleOAuthCachedState,
    GoogleState,
    GoogleTokenResponse,
    GoogleUserInfoResponse,
)

GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
DEFAULT_NEXT_URL = "/"

_google_http = urllib3.PoolManager()


def generate_state() -> str:
    return secrets.token_urlsafe(32)


def generate_pkce_pair() -> tuple[str, str]:
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("utf-8")).digest())
        .decode("utf-8")
        .rstrip("=")
    )
    return code_verifier, code_challenge


def normalize_next_url(next_url: str | None) -> str:
    if not next_url:
        return DEFAULT_NEXT_URL

    next_url = next_url.strip()
    if not next_url or not next_url.startswith("/") or next_url.startswith("//"):
        return DEFAULT_NEXT_URL

    return next_url


def get_google_state_cache_key(state: str) -> str:
    return f"{settings.GOOGLE_OAUTH_STATE_PREFIX}:{state}"


def build_frontend_redirect_url(next_url: str | None) -> str:
    frontend_url = settings.FRONTEND_URL.strip().rstrip("/")
    return f"{frontend_url}{normalize_next_url(next_url)}"


def build_frontend_oauth_redirect_url(*, next_url: str | None, oauth_token: str) -> str:
    parsed_url = urlparse(build_frontend_redirect_url(next_url))
    fragment_params = dict(parse_qsl(parsed_url.fragment))
    fragment_params["oauth_token"] = oauth_token
    fragment_params["oauth_provider"] = "google"
    return urlunparse(parsed_url._replace(fragment=urlencode(fragment_params)))


def build_frontend_oauth_error_url(*, next_url: str | None, error: str) -> str:
    parsed_url = urlparse(build_frontend_redirect_url(next_url))
    fragment_params = dict(parse_qsl(parsed_url.fragment))
    fragment_params["oauth_provider"] = "google"
    fragment_params["oauth_error"] = error
    return urlunparse(parsed_url._replace(fragment=urlencode(fragment_params)))


async def save_google_oauth_state(*, state: str, code_verifier: str, payload: GoogleLoginPayload) -> None:
    client = await get_redis_client()
    cache_data = GoogleOAuthCachedState(code_verifier=code_verifier, payload=payload)
    await client.setex(
        get_google_state_cache_key(state),
        settings.GOOGLE_OAUTH_STATE_TTL_SECONDS,
        cache_data.model_dump_json(),
    )


async def consume_google_oauth_state(state: GoogleState) -> GoogleOAuthCachedState:
    client = await get_redis_client()
    cache_key = get_google_state_cache_key(state)

    cached_value = await client.get(cache_key)
    await client.delete(cache_key)

    if not cached_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state.",
        )

    try:
        return GoogleOAuthCachedState.model_validate_json(cached_value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OAuth state data.",
        ) from exc


def require_google_oauth_settings() -> None:
    missing = [
        name
        for name in ("GOOGLE_CLIENT_ID", "GOOGLE_SECRET_KEY", "GOOGLE_REDIRECT_URI")
        if not getattr(settings, name, None)
    ]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Google OAuth is not configured. Missing: {', '.join(missing)}",
        )


async def generate_google_auth_url(*, payload: GoogleLoginPayload) -> str:
    require_google_oauth_settings()

    payload.next_url = normalize_next_url(payload.next_url)
    state = generate_state()
    code_verifier, code_challenge = generate_pkce_pair()

    await save_google_oauth_state(
        state=state,
        code_verifier=code_verifier,
        payload=payload,
    )

    auth_params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "select_account",
    }

    return f"{GOOGLE_AUTHORIZATION_URL}?{urlencode(auth_params)}"


async def exchange_google_code_for_tokens(*, code: GoogleCode, code_verifier: str) -> GoogleTokenResponse:
    require_google_oauth_settings()

    token_data = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_SECRET_KEY,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": code_verifier,
    }

    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            GOOGLE_TOKEN_URL,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to exchange Google authorization code.",
        )

    return GoogleTokenResponse.model_validate(response.json())


async def verify_google_id_token(jwt_token: str, access_token: str) -> GoogleUserInfoResponse:
    if not jwt_token or not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google ID token and access token are required.",
        )

    try:
        google_user_info = id_token.verify_oauth2_token(
            jwt_token,
            google_urllib3.Request(_google_http),
            settings.GOOGLE_CLIENT_ID,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Google ID token.",
        ) from exc

    if google_user_info.get("iss") not in {
        "accounts.google.com",
        "https://accounts.google.com",
    }:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Google token issuer.",
        )

    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to fetch Google user info.",
        )

    user_info = {**google_user_info, **response.json()}
    return GoogleUserInfoResponse.model_validate(user_info)


async def verify_google_oauth_callback(
    *,
    state: GoogleState,
    code: GoogleCode,
) -> tuple[GoogleTokenResponse, GoogleLoginPayload]:
    cached_state = await consume_google_oauth_state(state)
    google_tokens = await exchange_google_code_for_tokens(
        code=code,
        code_verifier=cached_state.code_verifier,
    )
    return google_tokens, cached_state.payload


async def get_user_by_google_sub(db: AsyncSession, google_sub: str) -> User | None:
    result = await db.exec(select(User).where(User.google_sub == google_sub))
    return result.first()


async def get_or_create_google_user(
    db: AsyncSession,
    *,
    email: str,
    full_name: str | None,
    google_sub: str,
    image_url: str | None,
) -> tuple[User, bool]:
    normalized_email = email.lower().strip()

    existing_google_user = await get_user_by_google_sub(db, google_sub)
    if existing_google_user:
        if image_url and existing_google_user.image_url != image_url:
            existing_google_user.image_url = image_url
        if full_name and not existing_google_user.full_name:
            existing_google_user.full_name = full_name
        existing_google_user.is_verified = True
        existing_google_user.updated_at = utils.utc_now()
        db.add(existing_google_user)
        await db.commit()
        await db.refresh(existing_google_user)
        return existing_google_user, False

    result = await db.exec(select(User).where(User.email == normalized_email))
    existing_email_user = result.first()

    if existing_email_user:
        if existing_email_user.google_sub and existing_email_user.google_sub != google_sub:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This email is linked to a different Google account.",
            )

        existing_email_user.google_sub = google_sub
        existing_email_user.is_verified = True
        if image_url and not existing_email_user.image_url:
            existing_email_user.image_url = image_url
        if full_name and not existing_email_user.full_name:
            existing_email_user.full_name = full_name
        existing_email_user.updated_at = utils.utc_now()

        db.add(existing_email_user)
        await db.commit()
        await db.refresh(existing_email_user)
        return existing_email_user, False

    user = User(
        email=normalized_email,
        full_name=full_name or normalized_email,
        google_sub=google_sub,
        password=None,
        auth_type=AuthType.GOOGLE,
        is_verified=True,
        is_active=True,
        image_url=image_url,
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user, True


def create_google_exchange_token(*, user_id: str, payload: GoogleLoginPayload) -> str:
    return create_jwt_token(
        user_id=user_id,
        token_type=TokenType.GOOGLE,
        expires_delta=timedelta(minutes=settings.GOOGLE_TOKEN_EXPIRE_MINUTES),
        extra_claims=payload.model_dump(exclude_none=True),
    )


async def complete_google_oauth_callback(
    db: AsyncSession,
    *,
    state: GoogleState,
    code: GoogleCode,
) -> tuple[str, User, bool, str | None]:
    google_tokens, cached_payload = await verify_google_oauth_callback(
        state=state,
        code=code,
    )

    if not google_tokens.id_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google ID token is missing from the token response.",
        )

    user_info = await verify_google_id_token(
        google_tokens.id_token,
        google_tokens.access_token,
    )

    if not user_info.email or not user_info.sub:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google account information is incomplete.",
        )

    if not user_info.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google account email is not verified.",
        )

    user, created = await get_or_create_google_user(
        db,
        email=str(user_info.email),
        full_name=user_info.name or str(user_info.email),
        google_sub=user_info.sub,
        image_url=str(user_info.picture) if user_info.picture else None,
    )

    if not user.can_login():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account is disabled or not allowed to login.",
        )

    google_token = create_google_exchange_token(user_id=user.id, payload=cached_payload)
    redirect_url = build_frontend_oauth_redirect_url(
        next_url=cached_payload.next_url,
        oauth_token=google_token,
    )

    return google_token, user, created, redirect_url


async def create_google_login_session(
    db: AsyncSession,
    *,
    google_token: str,
    request: Request,
) -> TokenResponse:
    from app.services import auth_service

    try:
        token_payload = validate_token(google_token, TokenType.GOOGLE)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    user_id = token_payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Google session token.",
        )

    user = await auth_service.get_user_by_id(db, user_id)
    if user is None or not user.can_login():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is invalid or disabled.",
        )

    session_payload = DeviceInfoPayload.model_validate(
        {
            "device_id": token_payload.get("device_id"),
            "device_name": token_payload.get("device_name"),
            "device_type": token_payload.get("device_type"),
            "os_name": token_payload.get("os_name"),
            "browser_name": token_payload.get("browser_name"),
            "remember_me": bool(token_payload.get("remember_me", False)),
        }
    )

    return await auth_service.create_login_session(
        db,
        user=user,
        payload=session_payload,
        ip_address=auth_service.get_client_ip(request),
        user_agent=auth_service.get_user_agent(request),
    )
