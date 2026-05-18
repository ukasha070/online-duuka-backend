from datetime import datetime
from typing import Optional, Union

from fastapi import File
from pydantic import BaseModel, ConfigDict, Field

from .models import UserSession


class LoginSession(BaseModel):
    access_token: str
    refresh_token: str
    session: UserSession


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    two_factor_required: bool = Field(default=False)


class TwoFactorChallengeResponse(BaseModel):
    two_factor_required: bool = Field(default=True)
    two_factor_token: str


class RefreshSessionPayload(BaseModel):
    refresh_token: str = Field(min_length=5)
    ip_address: Optional[str] = Field(default=None)


class UserSessionResponse(BaseModel):
    """
    Safe public session response.

    Important:
    - Do NOT expose refresh_token_hash.
    - Do NOT expose internal revoke metadata unless the frontend needs it.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str

    device_id: str | None = None
    device_name: str | None = None
    device_type: str | None = None
    os_name: str | None = None
    browser_name: str | None = None

    ip_address: str | None = None
    last_ip_address: str | None = None
    user_agent: str | None = None

    is_active: bool
    is_current: bool = False

    created_at: datetime
    last_seen_at: datetime


class SessionListResponse(BaseModel):
    total: int
    sessions: list[UserSessionResponse]


class MeProfileResponse(BaseModel):
    avatar: str


SigninResponse = Union[LoginResponse, TwoFactorChallengeResponse]


class MeResponse(BaseModel):
    """
    Flat response — no nested profile object.
    avatar resolves: image_path (local upload) → image_url (Google OAuth) → None
    """

    full_name: str | None
    is_verified: bool
    created_at: datetime
    avatar: str | None

    model_config = ConfigDict(from_attributes=True)


class MePayload(BaseModel):
    """Both fields are optional so the user can update either or both."""

    full_name: str | None = None
