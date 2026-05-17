from pydantic import HttpUrl
from sqlalchemy import (
    Column,
    DateTime,
    Enum as SAEnum,
    String,
    ForeignKey,
)

from datetime import datetime, timezone, timedelta

from enum import Enum
from typing import TYPE_CHECKING, Optional

from sqlmodel import Field, Relationship, SQLModel


from core import utils

if TYPE_CHECKING:
    from apps.auth.session.models import UserSession
    from apps.auth.two_factor.models import UserAuthenticatorApp

    # sdfd
    from apps.auth.password_reset.models import PasswordResetToken
    from apps.auth.verification.models import EmailVerificationToken


class AuthType(str, Enum):
    EMAIL = "email"
    GOOGLE = "google"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def token_expiry_time() -> datetime:
    return utc_now() + timedelta(minutes=15)


class User(SQLModel, table=True):
    __tablename__ = "users"  # type: ignore

    id: str = Field(
        default_factory=lambda: utils.generate_random_id("user"),
        sa_column=Column("_id", String, primary_key=True),
    )

    email: str = Field(sa_column=Column(String(255), unique=True, nullable=False))

    password: Optional[str] = Field(
        default=None,
        sa_column=Column("password", String(255)),
    )

    full_name: str = Field(
        default=None,
        sa_column=Column("full_name", String(255), nullable=True),
    )

    google_sub: Optional[str] = Field(
        default=None,
        sa_column=Column("google_sub", String(255), nullable=True),
    )

    profile: Optional["UserProfile"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={
            "uselist": False,
            "cascade": "all, delete-orphan",
            "single_parent": True,
        },
    )

    is_active: bool = Field(default=True)
    is_superuser: bool = Field(default=False)
    is_verified: bool = Field(default=False)

    auth_type: AuthType = Field(
        default=AuthType.EMAIL,
        sa_column=Column(
            SAEnum(AuthType),
            nullable=False,
            default=AuthType.EMAIL,
        ),
    )

    password_reset_token: Optional["PasswordResetToken"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={
            "uselist": False,
            "cascade": "all, delete-orphan",
            "single_parent": True,
        },
    )

    email_verification_token: Optional["EmailVerificationToken"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={
            "uselist": False,
            "cascade": "all, delete-orphan",
            "single_parent": True,
        },
    )

    sessions: list["UserSession"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )

    authenticator_app: Optional["UserAuthenticatorApp"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={
            "uselist": False,
            "cascade": "all, delete-orphan",
            "single_parent": True,
        },
    )

    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

    def is_google_user(self) -> bool:
        return self.auth_type == AuthType.GOOGLE

    def can_login_with_password(self) -> bool:
        return self.auth_type == AuthType.EMAIL and self.password is not None

    def mark_as_verified(self) -> None:
        self.is_verified = True

    def can_login(self) -> bool:
        return (
            self.is_active
            and (self.can_login_with_password() or self.is_google_user())
            and self.is_verified
        )

    def is_oauth_user(self) -> bool:
        return self.password is None and self.auth_type != AuthType.EMAIL


class UserProfile(SQLModel, table=True):
    __tablename__ = "user_profiles"  # type: ignore

    user_id: str = Field(
        sa_column=Column(
            String,
            ForeignKey("users._id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        )
    )

    # For users who upload profile images locally
    # Example: "uploads/profile_images/user_123.png"
    image_path: Optional[str] = Field(
        default=None,
        sa_column=Column(String(512), nullable=True),
    )

    # For Google OAuth users
    # Example: "https://lh3.googleusercontent.com/..."
    image_url: Optional[HttpUrl] = Field(
        default=None,
        sa_column=Column(String(2048), nullable=True),
    )

    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

    user: Optional["User"] = Relationship(
        back_populates="profile",
    )
