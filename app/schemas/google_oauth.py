from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, EmailStr, Field, HttpUrl, PositiveInt

from app.schemas.auth import DeviceInfoPayload


GoogleCode = str
GoogleState = str
InternalGoogleToken = str
NextUrl = str


class GoogleTokenResponse(BaseModel):
    """Token response returned by Google's OAuth token endpoint."""

    access_token: str
    expires_in: PositiveInt
    token_type: str
    scope: str | None = None
    id_token: str
    refresh_token: str | None = None


class GoogleUserInfoResponse(BaseModel):
    """Normalized fields from Google's ID token/userinfo response."""

    sub: str
    email: EmailStr
    email_verified: bool
    name: str | None = None
    picture: HttpUrl | None = None
    given_name: str | None = None
    family_name: str | None = None


class GoogleLoginPayload(DeviceInfoPayload):
    """Payload sent when starting the Google OAuth flow."""

    next_url: NextUrl | None = Field(default="/", max_length=256)


class GoogleOAuthCallbackPayload(BaseModel):
    """Query/body payload sent by Google OAuth callback."""

    state: GoogleState = Field(min_length=16, max_length=512)
    code: GoogleCode | None = Field(default=None, min_length=1)
    error: str | None = None


class GoogleSessionExchangePayload(BaseModel):
    """Exchange the internal google_token for normal app tokens."""

    google_token: InternalGoogleToken = Field(min_length=20)


class GoogleOAuthCachedState(BaseModel):
    code_verifier: str = Field(min_length=32)
    payload: GoogleLoginPayload


class GoogleAuthorizationResponse(BaseModel):
    URL: str
    url: str


class GoogleCallbackResponse(BaseModel):
    google_token: str
    token_type: Literal["google-token"] = "google-token"
    expires_in: PositiveInt
    redirect_url: str | None = None
