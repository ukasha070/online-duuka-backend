from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator


class DeviceInfoPayload(BaseModel):
    device_id: str | None = None
    device_name: str | None = None
    device_type: str | None = None
    os_name: str | None = None
    browser_name: str | None = None
    remember_me: bool = False


class RegisterPayload(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)
    turnstile_token: str | None = Field(default=None, min_length=5)

    @model_validator(mode="after")
    def passwords_match(self) -> "RegisterPayload":
        if self.password != self.confirm_password:
            raise ValueError("Passwords didn't match.")
        return self


class LoginPayload(DeviceInfoPayload):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    turnstile_token: str | None = Field(default=None, min_length=5)


class RefreshPayload(BaseModel):
    refresh_token: str = Field(min_length=5)


class LogoutPayload(BaseModel):
    refresh_token: str = Field(min_length=5)


class ChangePasswordPayload(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)
    confirm_new_password: str = Field(min_length=8, max_length=128)
    turnstile_token: str | None = Field(default=None, min_length=5)

    @model_validator(mode="after")
    def passwords_match(self) -> "ChangePasswordPayload":
        if self.new_password != self.confirm_new_password:
            raise ValueError("Passwords didn't match.")
        return self


class UpdateMePayload(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=100)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    two_factor_required: bool = False


class TwoFactorChallengeResponse(BaseModel):
    two_factor_required: bool = True
    two_factor_token: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    full_name: str | None = None
    avatar: str | None = None
    is_active: bool
    is_verified: bool
    is_admin: bool = False
    is_agent: bool = False
    created_at: datetime


class UserSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    device_id: str | None = None
    device_name: str | None = None
    device_type: str | None = None
    os_name: str | None = None
    browser_name: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    is_active: bool
    is_current: bool = False
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime


class SessionListResponse(BaseModel):
    total: int
    sessions: list[UserSessionResponse]


class TwoFactorEnableResponse(BaseModel):
    secret: str
    provisioning_uri: str


class TwoFactorVerifyPayload(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class TwoFactorValidatePayload(DeviceInfoPayload):
    two_factor_token: str = Field(min_length=5)
    code: str = Field(min_length=6, max_length=8)


class TwoFactorDisablePayload(BaseModel):
    password: str
    code: str = Field(min_length=6, max_length=8)


class PasswordResetRequestPayload(BaseModel):
    email: EmailStr
    turnstile_token: str | None = Field(default=None, min_length=5)


class PasswordResetConfirmPayload(BaseModel):
    token: str = Field(min_length=5)
    new_password: str = Field(min_length=8, max_length=128)
    confirm_new_password: str = Field(min_length=8, max_length=128)

    @model_validator(mode="after")
    def passwords_match(self) -> "PasswordResetConfirmPayload":
        if self.new_password != self.confirm_new_password:
            raise ValueError("Passwords didn't match.")
        return self


class GoogleCallbackPayload(DeviceInfoPayload):
    code: str = Field(min_length=5)
    state: str | None = None
