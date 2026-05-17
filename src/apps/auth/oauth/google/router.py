from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel.ext.asyncio.session import AsyncSession

from apps.auth.utils import get_client_context
from apps.auth.user import service_user as user_service
from apps.auth.session.schemas import LoginResponse
from apps.auth.authentication import create_login_session_response

from apps.auth._jwt import TokenType, create_google_token, validate_token
from apps.auth.schema import CreateSessionPayload
from apps.auth.validators import validate_user
from core.db import get_db

from apps.auth import tasks as _tasks

from .schemas import (
    GoogleLoginPayload,
    GoogleOAuthCallbackPayload,
    GoogleSessionExchangePayload,
)

from .oauth import (
    build_frontend_redirect_url,
    generate_google_auth_url,
    verify_google_id_token,
    verify_google_oauth_callback,
)

router = APIRouter(prefix="", tags=["google-auth"])


def build_frontend_oauth_error_url(*, next_url: str, error: str) -> str:
    redirect_url = build_frontend_redirect_url(next_url)
    parsed_url = urlparse(redirect_url)
    fragment_params = dict(parse_qsl(parsed_url.fragment))
    fragment_params["oauth_provider"] = "google"
    fragment_params["oauth_error"] = error

    return urlunparse(parsed_url._replace(fragment=urlencode(fragment_params)))


# -------------------------------------------------------------------
# Google OAuth endpoints
# -------------------------------------------------------------------


@router.post(
    "/login",
    status_code=status.HTTP_200_OK,
)
async def start_google_login(payload: GoogleLoginPayload):
    """
    Start the Google OAuth login flow.

    This endpoint generates the Google authorization URL that the frontend
    should redirect the user to.

    Flow:
    1. Frontend sends OAuth session payload.
    2. Backend creates a secure Google OAuth authorization URL.
    3. Backend returns the URL.
    4. Frontend redirects the user to that URL.
    """

    try:
        auth_url = await generate_google_auth_url(
            payload=payload,
        )

    except ValueError as exc:
        # Raised when the OAuth payload is invalid,
        # for example invalid redirect URL, invalid next URL,
        # missing config, or bad OAuth state data.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return {"URL": auth_url}


@router.get(
    "/callback",
    name="google_oauth_callback",
)
async def google_oauth_callback(
    request: Request,
    payload: GoogleOAuthCallbackPayload = Depends(),
    db: AsyncSession = Depends(get_db),
):
    # Google redirects back with an error when the user cancels
    # or when Google OAuth fails before sending us the code.
    if payload.error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google OAuth failed: {payload.error}",
        )

    # Verify the OAuth state, consume the cached PKCE code_verifier,
    # and exchange the Google authorization code for Google tokens.
    token_json, cached_login_payload = await verify_google_oauth_callback(
        state=payload.state,
        code=payload.code,
    )

    # The ID token contains the Google user's identity information.
    jwt_token = token_json.id_token

    if not jwt_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google ID token is missing from the token response.",
        )

    # Verify Google's ID token and extract the Google user info.
    user_info = verify_google_id_token(jwt_token)

    email = user_info.email
    google_sub = user_info.sub

    # Google account must have both an email and a stable Google user ID.
    if not email or not google_sub:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google account information is incomplete.",
        )

    # Do not allow login with an unverified Google email.
    if not user_info.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google account email is not verified.",
        )

    try:
        # Find an existing user by Google account/email,
        # or create a new user if this is the first Google login.
        user, created = await user_service.get_or_create_google_user(
            db=db,
            email=email,
            full_name=user_info.name or email,
            google_sub=google_sub,
        )
    except ValueError as exc:
        return {"detail": str(exc)}

    # Validate that the local user account is allowed to login.
    # For Google login, we do not require password auth type validation here.
    validated_user = validate_user(
        user=user,
        validate_auth_type=False,
        validate_verified=False,
        validate_is_active=True,
    )

    # Send welcome email only when a new account was created.
    if created:
        _tasks.send_welcome_email.delay(  # type: ignore
            to_email=validated_user.email,
            full_name=validated_user.full_name,
        )

    # Extract request-based client info, such as IP address and user-agent.
    client = get_client_context(request)

    # Merge request client info with the device info that was saved
    # during the first /google/login request.
    session_payload = CreateSessionPayload.model_validate(
        {
            **client.model_dump(),
            **cached_login_payload.model_dump(),
        }
    )

    # Create a short-lived internal Google token.
    # The frontend will exchange this token at /google/session
    # to receive the real app access_token and refresh_token.
    google_token = create_google_token(
        user_id=validated_user.id,
        session_payload=session_payload,
    )

    return {"google_token": google_token}


@router.post(
    "/session",
)
async def create_google_session(
    payload: GoogleSessionExchangePayload,
    db: AsyncSession = Depends(get_db),
):
    try:
        # Verify the short-lived internal Google token.
        # This token should only be used for exchanging Google login
        # into a real app session.
        token_payload = validate_token(
            payload.google_token,
            TokenType.googletoken,
        )

        # Rebuild the session payload from the token claims.
        session_payload = CreateSessionPayload.model_validate(token_payload)

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    # The subject claim should contain the local user ID.
    user_id = token_payload["sub"]

    # Create the real login session and issue app access/refresh tokens.
    response = await create_login_session_response(
        db=db,
        user_id=user_id,
        session_payload=session_payload,
    )

    return LoginResponse.model_validate(response)


# http://localhost:3000/auth/google/login/callback?
# state=oS3Y3kkKM3fkTleK6ZnwjgcoM_3KsFR1zIb15TJP0ak&iss=https%3A%2F%2Faccounts.google.com
# &
# code=4%2F0AeoWuM8H5Mtm41HHxFc9cf97_5JFKasUJUvKBsOLkOFCUwmfCzaUJlXAwHEUVCkjJoMA3g
# &scope=email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile&authuser=0&prompt=none


# Response body
# Download
# {
#   "google_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzBiTUFud2xBIiwic2Vzc2lvbl9pZCI6IiIsInR5cGUiOiJnb29nbGUtdG9rZW4iLCJqdGkiOiIxNGE0YjE5OC03YTUwLTRlZDgtYjRlMS1lYTRhOGM0MTA2NjkiLCJpYXQiOjE3Nzg5NTM4MzIsIm5iZiI6MTc3ODk1MzgzMiwiZXhwIjoxNzc5MTI2NjMyLCJpc3MiOiJPbmxpbmUgRHV1a2EiLCJhdWQiOiJ5b3VyLWFwcC1jbGllbnQiLCJkZXZpY2VfaWQiOm51bGwsImRldmljZV9uYW1lIjoiUGl4ZWwgOCIsImRldmljZV90eXBlIjoibW9iaWxlIiwib3NfbmFtZSI6IkFuZHJvaWQiLCJicm93c2VyX25hbWUiOm51bGx9.nQ3Ijh-UsEG9jvmivJwHF9RGIGJpR7Smuh-0YvQLn_o"
# }
