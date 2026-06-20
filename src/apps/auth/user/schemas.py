# app/schemas/user_profile_schema.py

from typing import Optional
from fastapi import Depends
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from pydantic_core.core_schema import FieldValidationInfo

from apps.auth.validators import validate_password_strength
from apps.auth.schemas import DeviceInfoPayload
from apps.auth._jwt import validate_token, TokenType


class SignupPayload(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=4, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)
    turnstile_token:str = Field(min_length=5)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        """
        Field-level validation for new_password.

        Errors from this validator will appear under:
        body -> new_password
        """

        return validate_password_strength(value)

    @field_validator("confirm_password")
    @classmethod
    def validate_passwords_match(cls, v: str, info: FieldValidationInfo) -> str:
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords didn't match.")
        return v


class SigninPayload(DeviceInfoPayload):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    remember_me: bool = False
    turnstile_token:str = Field(min_length=5)


class SignOutPayload(BaseModel):
    refresh_token: str

    @model_validator(mode="after")
    def validate_refresh_token(self) -> "SignOutPayload":
        validate_token(self.refresh_token, TokenType.refresh)
        return self


class TwoFactorSigninPayload(BaseModel):
    two_factor_token: str
    code: str

    @model_validator(mode="after")
    def validate_(self) -> "TwoFactorSigninPayload":
        validate_token(self.two_factor_token, TokenType.twofactor)
        return self


class ChangePasswordPayload(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)
    new_confirm_password: str = Field(min_length=8, max_length=128)
    turnstile_token:str = Field(min_length=5)

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        """
        Field-level validation for new_password.

        Errors from this validator will appear under:
        body -> new_password
        """

        return validate_password_strength(value)

    @field_validator("new_confirm_password")
    @classmethod
    def validate_passwords_match(cls, v: str, info: FieldValidationInfo) -> str:
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords didn't match.")
        return v
