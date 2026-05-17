from typing import Literal
from typing_extensions import Annotated

from pydantic import BaseModel, EmailStr, Field, HttpUrl, PositiveInt

from apps.auth.schema import DeviceInfoPayload

# -----------------------------
# Shared field types
# -----------------------------

GoogleCode = Annotated[str, Field(min_length=1)]
GoogleState = Annotated[str, Field(min_length=16, max_length=512)]
InternalGoogleToken = Annotated[str, Field(min_length=20)]
NextUrl = Annotated[str, Field(max_length=256)]


# -----------------------------
# 1. Data coming from Google
# -----------------------------


class GoogleTokenResponse(BaseModel):
    """
    Response returned by Google's token endpoint.
    This is NOT your app access token.
    """

    access_token: str
    expires_in: PositiveInt
    token_type: str
    scope: str
    id_token: str
    refresh_token: str | None = None


class GoogleUserInfoResponse(BaseModel):
    """
    Response returned by Google userinfo / ID token verification.
    Keep this close to Google's actual field names.
    """

    sub: str
    email: EmailStr
    email_verified: bool
    name: str | None = None
    picture: HttpUrl | None = None
    given_name: str | None = None
    family_name: str | None = None


# -----------------------------
# 2. Normalized Google user
# -----------------------------


class GoogleUserIdentity(BaseModel):
    """
    Clean internal user shape.
    This is what your app understands after reading Google data.
    """

    provider: Literal["google"] = "google"
    provider_user_id: str

    email: EmailStr
    email_verified: bool

    full_name: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    avatar_url: str | None = None

    @classmethod
    def from_google(cls, user: GoogleUserInfoResponse) -> "GoogleUserIdentity":
        return cls(
            provider_user_id=user.sub,
            email=user.email,
            email_verified=user.email_verified,
            full_name=user.name,
            first_name=user.given_name,
            last_name=user.family_name,
            avatar_url=str(user.picture) if user.picture else None,
        )


# -----------------------------
# 3. Data encoded inside your internal google_token
# -----------------------------


class GoogleSessionTokenClaims(BaseModel):
    """
    This is the payload you encode into your short-lived internal google_token.

    Flow:
    Google callback -> create google_token with these claims
    Session endpoint -> verify google_token -> create app access/refresh tokens
    """

    token_type: Literal["google_session"] = "google_session"

    user: GoogleUserIdentity

    # Optional, but useful if you want to keep the redirect target.
    next_url: NextUrl | None = None

    # JWT-style fields
    iat: int
    exp: int
    jti: str


# -----------------------------
# 4. Payloads received by your own API routes
# -----------------------------


class GoogleLoginPayload(DeviceInfoPayload):
    """
    Sent to /google/login.
    Used to generate the Google auth URL.
    """

    next_url: NextUrl | None = None


class GoogleOAuthCallbackPayload(BaseModel):
    """
    Sent to /google/callback.
    Usually Google gives you state/code/error.
    """

    state: GoogleState
    code: GoogleCode
    error: str | None = None


class GoogleSessionExchangePayload(BaseModel):
    """
    Sent to /google/session.

    This endpoint receives your internal google_token and returns
    your real app access_token + refresh_token.
    """

    google_token: InternalGoogleToken


# -----------------------------
# 5. Responses returned by your API
# -----------------------------


class GoogleCallbackResponse(BaseModel):
    """
    Returned by the callback route after Google auth succeeds.
    Frontend sends google_token to the session endpoint.
    """

    google_token: str
    token_type: Literal["google_session"] = "google_session"
    expires_in: PositiveInt


class AppSessionTokenResponse(BaseModel):
    """
    Returned by /google/session.
    These are your app tokens, not Google tokens.
    """

    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: PositiveInt


class GoogleOAuthCachedState(BaseModel):
    code_verifier: str = Field(min_length=32)
    payload: GoogleLoginPayload


class GoogleToken(BaseModel):
    pass
