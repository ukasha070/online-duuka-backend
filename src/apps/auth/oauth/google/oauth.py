from __future__ import annotations

import httpx
import urllib3
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import HTTPException, status
from google.auth.transport import urllib3 as google_urllib3
from google.oauth2 import id_token

from core.cache import redis_client
from core.config import settings

from .security import generate_pkce_pair, generate_state
from .schemas import (
    GoogleCode,
    GoogleLoginPayload,
    GoogleOAuthCachedState,
    GoogleState,
    GoogleTokenResponse,
    GoogleUserInfoResponse,
)

GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
DEFAULT_NEXT_URL = "/"

_google_http = urllib3.PoolManager()


def get_google_state_cache_key(state: str) -> str:
    return f"{settings.GOOGLE_OAUTH_STATE_PREFIX}:{state}"


def build_frontend_redirect_url(next_url: str) -> str:
    frontend_url = settings.FRONTEND_URL.strip().rstrip("/")
    return f"{frontend_url}{next_url}"


def build_frontend_oauth_redirect_url(*, next_url: str, oauth_token: str) -> str:
    parsed_url = urlparse(build_frontend_redirect_url(next_url))
    fragment_params = dict(parse_qsl(parsed_url.fragment))

    fragment_params["oauth_token"] = oauth_token
    fragment_params["oauth_provider"] = "google"

    return urlunparse(parsed_url._replace(fragment=urlencode(fragment_params)))


async def save_google_oauth_state(
    *,
    state: str,
    code_verifier: str,
    payload: GoogleLoginPayload,
) -> None:
    cache_key = get_google_state_cache_key(state)

    cache_data = GoogleOAuthCachedState(
        code_verifier=code_verifier,
        payload=payload,
    )

    await redis_client.setex(
        cache_key,
        settings.GOOGLE_OAUTH_STATE_TTL_SECONDS,
        cache_data.model_dump_json(),
    )


async def consume_google_oauth_state(state: GoogleState) -> GoogleOAuthCachedState:
    cache_key = get_google_state_cache_key(state)

    pipeline = redis_client.pipeline(transaction=True)
    pipeline.get(cache_key)
    # TODO: uncomment before production — prevents state replay attacks
    # pipeline.delete(cache_key)

    (cached_value,) = await pipeline.execute()

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


async def generate_google_auth_url(
    *,
    payload: GoogleLoginPayload,
) -> str:
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


async def exchange_google_code_for_tokens(
    *,
    code: GoogleCode,
    code_verifier: str,
) -> GoogleTokenResponse:
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

        print("STATUS:", response.status_code)
        print("RESPONSE:", response.json())

    if response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to exchange Google authorization code.",
        )

    return GoogleTokenResponse.model_validate(response.json())


def verify_google_id_token(jwt_token: str) -> GoogleUserInfoResponse:
    if not jwt_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google ID token is missing.",
        )

    google_user_info = id_token.verify_oauth2_token(
        jwt_token,
        google_urllib3.Request(_google_http),
        settings.GOOGLE_CLIENT_ID,
    )

    if google_user_info.get("iss") not in {
        "accounts.google.com",
        "https://accounts.google.com",
    }:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Google token issuer.",
        )

    return GoogleUserInfoResponse.model_validate(google_user_info)


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


# {
#   "google_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzBiTUFud2xBIiwic2Vzc2lvbl9pZCI6IiIsInR5cGUiOiJnb29nbGUtdG9rZW4iLCJqdGkiOiIxNGE0YjE5OC03YTUwLTRlZDgtYjRlMS1lYTRhOGM0MTA2NjkiLCJpYXQiOjE3Nzg5NTM4MzIsIm5iZiI6MTc3ODk1MzgzMiwiZXhwIjoxNzc5MTI2NjMyLCJpc3MiOiJPbmxpbmUgRHV1a2EiLCJhdWQiOiJ5b3VyLWFwcC1jbGllbnQiLCJkZXZpY2VfaWQiOm51bGwsImRldmljZV9uYW1lIjoiUGl4ZWwgOCIsImRldmljZV90eXBlIjoibW9iaWxlIiwib3NfbmFtZSI6IkFuZHJvaWQiLCJicm93c2VyX25hbWUiOm51bGx9.nQ3Ijh-UsEG9jvmivJwHF9RGIGJpR7Smuh-0YvQLn_o"
# }
