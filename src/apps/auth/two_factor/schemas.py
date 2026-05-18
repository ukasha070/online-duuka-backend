# app/schemas/two_factor.py

from typing import Optional
from pydantic import BaseModel, Field


class AuthenticatorSetupResponse(BaseModel):
    secret: str
    issuer: str
    account_name: str
    otpauth_uri: str
    qr_code_data_url: str


class AuthenticatorConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class AuthenticatorVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class RecoveryCodesResponse(BaseModel):
    recovery_codes: list[str]
    recovery_codes_remaining: int


class AuthenticatorConfirmResponse(RecoveryCodesResponse):
    is_enabled: bool


class AuthenticatorDisabledResponse(BaseModel):
    is_enabled: bool
    recovery_codes_remaining: int = 0


class AuthenticatorStatusResponse(BaseModel):
    is_enabled: bool
    recovery_codes_remaining: int = 0
    confirmed_at: Optional[str] = None
    last_used_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Schema — only used in this router, so defined inline
# ---------------------------------------------------------------------------


class TwoFactorVerifyPayload(BaseModel):
    """Body sent by the client after password auth when 2FA is required."""

    two_factor_token: str = Field(
        description="The JWT returned by /signin when two_factor_required is true."
    )
    code: str = Field(
        min_length=6,
        max_length=11,  # TOTP is 6 digits; recovery codes are 9 chars + 2 dashes
        description="6-digit TOTP code or XXX-XXX-XXX recovery code.",
    )


class TwoFactorChallengeResponse(BaseModel):
    two_factor_required: bool
    two_factor_token: str
    token_type: str = "bearer"
