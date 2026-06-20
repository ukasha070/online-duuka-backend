from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.core.security import TokenType, validate_token
from app.database import get_db
from app.schemas.auth import TokenResponse
from app.schemas.google_oauth import (
    GoogleAuthorizationResponse,
    GoogleCallbackResponse,
    GoogleLoginPayload,
    GoogleOAuthCallbackPayload,
    GoogleSessionExchangePayload,
)
from app.services import auth_service, google_oauth
from app.tasks.email_tasks import send_new_login_alert_email, send_welcome_email

router = APIRouter(tags=["google-auth"])


@router.get("/google", response_model=GoogleAuthorizationResponse)
async def google_oauth_url(next_url: str | None = None) -> GoogleAuthorizationResponse:
    """Compatibility endpoint for the project-stack route contract: GET /auth/google."""

    payload = GoogleLoginPayload(next_url=next_url)
    auth_url = await google_oauth.generate_google_auth_url(payload=payload)
    return GoogleAuthorizationResponse(URL=auth_url, url=auth_url)


@router.post("/google/login", response_model=GoogleAuthorizationResponse)
async def start_google_login(payload: GoogleLoginPayload) -> GoogleAuthorizationResponse:
    """Start Google OAuth with PKCE and return the Google authorization URL."""

    auth_url = await google_oauth.generate_google_auth_url(payload=payload)
    return GoogleAuthorizationResponse(URL=auth_url, url=auth_url)


async def _complete_google_callback(
    payload: GoogleOAuthCallbackPayload,
    db: AsyncSession,
) -> GoogleCallbackResponse:
    if payload.error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google OAuth failed: {payload.error}",
        )

    if not payload.code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google OAuth authorization code is required.",
        )

    google_token, user, created, redirect_url = await google_oauth.complete_google_oauth_callback(
        db,
        state=payload.state,
        code=payload.code,
    )

    if created:
        send_welcome_email.delay(user.email, user.full_name)

    return GoogleCallbackResponse(
        google_token=google_token,
        expires_in=settings.GOOGLE_TOKEN_EXPIRE_MINUTES * 60,
        redirect_url=redirect_url,
    )


@router.get("/google/callback", response_model=GoogleCallbackResponse)
async def google_oauth_callback(
    payload: Annotated[GoogleOAuthCallbackPayload, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> GoogleCallbackResponse:
    """Handle Google's redirect callback and return an internal google_token."""

    return await _complete_google_callback(payload, db)


@router.post("/google/callback", response_model=GoogleCallbackResponse)
async def google_oauth_callback_post(
    payload: GoogleOAuthCallbackPayload,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> GoogleCallbackResponse:
    """Body-based callback variant for clients that proxy the Google callback."""

    return await _complete_google_callback(payload, db)


@router.post("/google/session", response_model=TokenResponse)
async def create_google_session(
    payload: GoogleSessionExchangePayload,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    """Exchange a short-lived google_token for normal app access/refresh tokens."""

    token_response = await google_oauth.create_google_login_session(
        db,
        google_token=payload.google_token,
        request=request,
    )

    token_payload = validate_token(payload.google_token, TokenType.GOOGLE)
    user = await auth_service.get_user_by_id(db, token_payload["sub"])
    if user:
        send_new_login_alert_email.delay(
            user.email,
            user.full_name,
            auth_service.get_client_ip(request),
            auth_service.get_user_agent(request),
            None,
            None,
        )

    return token_response
