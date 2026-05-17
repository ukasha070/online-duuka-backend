# app/schemas/auth_schema.py
import re

from pydantic import BaseModel, Field, ValidationInfo, field_validator, EmailStr

from apps.auth.validators import validate_password_strength


class PasswordResetRequestPayload(BaseModel):
    email: EmailStr


class PasswordResetConfirmPayload(BaseModel):
    token: str

    new_password: str = Field(
        min_length=8,
        max_length=128,
    )

    new_password_confirm: str = Field(
        min_length=8,
        max_length=128,
    )

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        """
        Field-level validation for new_password.

        Errors from this validator will appear under:
        body -> new_password
        """

        return validate_password_strength(value)

    @field_validator("new_password_confirm")
    @classmethod
    def validate_passwords_match(
        cls,
        value: str,
        info: ValidationInfo,
    ) -> str:
        """
        Field-level validation for new_password_confirm.

        Errors from this validator will appear under:
        body -> new_password_confirm
        """

        new_password = info.data.get("new_password")

        # If new_password already failed validation, do not compare.
        if not new_password:
            return value

        if value != new_password:
            raise ValueError("Passwords didn't match.")

        return value
