import re
from fastapi import HTTPException, status

from apps.auth.user.models import AuthType, User


def validate_user(
    user: User | None,
    validate_auth_type: bool = True,
    validate_verified: bool = True,
    validate_is_active: bool = True,
) -> User:
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid credentials.",
        )

    if validate_auth_type and user.auth_type != AuthType.EMAIL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset is only available for email/password accounts",
        )

    if validate_verified and not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please verify your email before requesting a password reset",
        )

    if validate_is_active and not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Your account is inactive. Please contact support.",
        )

    return user


def validate_password_strength(password: str) -> str:
    """
    Validate password strength only.
    This should only check the password itself.
    """

    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")

    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter")

    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit")

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValueError("Password must contain at least one special character")

    return password
