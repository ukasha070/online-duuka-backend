from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, Enum as SAEnum, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from app.config import settings
from app.core import utils
from app.core.utils import generate_random_id, utc_now


class AuthType(str, Enum):
    EMAIL = "email"
    GOOGLE = "google"


def password_reset_token_expiry_time() -> datetime:
    return utils.utc_now() + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES)


def email_verification_token_expiry_time() -> datetime:
    return utils.utc_now() + timedelta(minutes=settings.EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES)


class User(SQLModel, table=True):
    __tablename__ = "users"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: utils.generate_random_id("user"), sa_column=Column("_id", String, primary_key=True))
    email: str = Field(sa_column=Column(String(255), unique=True, nullable=False, index=True))
    password: Optional[str] = Field(default=None, sa_column=Column("password", String(255), nullable=True))
    full_name: Optional[str] = Field(default=None, sa_column=Column(String(255), nullable=True))
    google_sub: Optional[str] = Field(default=None, sa_column=Column(String(255), nullable=True, unique=True))
    image_path: Optional[str] = Field(default=None, sa_column=Column(String(512), nullable=True))
    image_url: Optional[str] = Field(default=None, sa_column=Column(String(2048), nullable=True))
    is_active: bool = Field(default=True)
    is_superuser: bool = Field(default=False)
    is_verified: bool = Field(default=False)
    is_disabled: bool = Field(default=False)
    is_admin: bool = Field(default=False)
    is_agent: bool = Field(default=False)
    auth_type: AuthType = Field(default=AuthType.EMAIL, sa_column=Column(SAEnum(AuthType), nullable=False, default=AuthType.EMAIL))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    failed_login_attempts: int = Field(default=0, nullable=False)
    login_locked_until: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    last_failed_login_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))

    password_reset_token: Optional["PasswordResetToken"] = Relationship(back_populates="user", sa_relationship_kwargs={"uselist": False, "cascade": "all, delete-orphan", "single_parent": True})
    email_verification_token: Optional["EmailVerificationToken"] = Relationship(back_populates="user", sa_relationship_kwargs={"uselist": False, "cascade": "all, delete-orphan", "single_parent": True})
    sessions: list["UserSession"] = Relationship(back_populates="user", sa_relationship_kwargs={"cascade": "all, delete-orphan"})
    authenticator_app: Optional["UserAuthenticatorApp"] = Relationship(back_populates="user", sa_relationship_kwargs={"uselist": False, "cascade": "all, delete-orphan", "single_parent": True})

    def is_google_user(self) -> bool:
        return self.auth_type == AuthType.GOOGLE

    def can_login_with_password(self) -> bool:
        return self.auth_type == AuthType.EMAIL and self.password is not None

    def can_login(self) -> bool:
        return self.is_active and self.is_verified and not self.is_disabled

    def lockdown_left_seconds(self) -> int:
        if self.login_locked_until is None:
            return 0
        now = utils.utc_now()
        if self.login_locked_until <= now:
            return 0
        return int((self.login_locked_until - now).total_seconds())


class UserSession(SQLModel, table=True):
    __tablename__ = "user_sessions"  # type: ignore[assignment]
    __table_args__ = (UniqueConstraint("user_id", "device_key_hash", name="uq_user_sessions_user_id_device_key_hash"), Index("ix_user_sessions_user_active_last_seen", "user_id", "is_active", "last_seen_at"))

    id: str = Field(default_factory=lambda: generate_random_id("session"), sa_column=Column("_id", String, primary_key=True))
    user_id: str = Field(sa_column=Column(String, ForeignKey("users._id", ondelete="CASCADE"), nullable=False, index=True))
    device_id: Optional[str] = Field(default=None, sa_column=Column(String(255), nullable=True))
    device_key_hash: str = Field(sa_column=Column(String(128), nullable=False, index=True))
    device_name: Optional[str] = Field(default=None, sa_column=Column(String(255), nullable=True))
    device_type: Optional[str] = Field(default=None, sa_column=Column(String(50), nullable=True))
    os_name: Optional[str] = Field(default=None, sa_column=Column(String(100), nullable=True))
    browser_name: Optional[str] = Field(default=None, sa_column=Column(String(100), nullable=True))
    user_agent: Optional[str] = Field(default=None, sa_column=Column(Text, nullable=True))
    ip_address: Optional[str] = Field(default=None, sa_column=Column(String(100), nullable=True))
    refresh_token_hash: str = Field(sa_column=Column(String(128), nullable=False, unique=True, index=True))
    is_active: bool = Field(default=True, sa_column=Column(Boolean, nullable=False, default=True, index=True))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    last_seen_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False, index=True))
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False, index=True))
    logged_out_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    revoked_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    revoked_reason: Optional[str] = Field(default=None, sa_column=Column(String(255), nullable=True))

    user: Optional[User] = Relationship(back_populates="sessions")


class UserAuthenticatorApp(SQLModel, table=True):
    __tablename__ = "user_authenticator_apps"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: generate_random_id("authapp"), sa_column=Column("_id", String, primary_key=True))
    user_id: str = Field(sa_column=Column(String, ForeignKey("users._id", ondelete="CASCADE"), nullable=False, unique=True, index=True))
    secret: str = Field(sa_column=Column(String(512), nullable=False))
    issuer: str = Field(sa_column=Column(String(255), nullable=False))
    is_enabled: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, default=False, index=True))
    last_used_counter: Optional[int] = Field(default=None, sa_column=Column(Integer, nullable=True))
    last_used_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    confirmed_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))

    user: Optional[User] = Relationship(back_populates="authenticator_app")


class UserTwoFactorRecoveryCode(SQLModel, table=True):
    __tablename__ = "user_two_factor_recovery_codes"  # type: ignore[assignment]
    __table_args__ = (Index("ix_user_two_factor_recovery_codes_user_unused", "user_id", "is_used"),)

    id: str = Field(default_factory=lambda: generate_random_id("2far"), sa_column=Column("_id", String, primary_key=True))
    user_id: str = Field(sa_column=Column(String, ForeignKey("users._id", ondelete="CASCADE"), nullable=False, index=True))
    code_hash: str = Field(sa_column=Column(String(128), nullable=False, unique=True, index=True))
    is_used: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, default=False, index=True))
    used_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))


class PasswordResetToken(SQLModel, table=True):
    __tablename__ = "password_reset_tokens"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: utils.generate_random_id("prt"), sa_column=Column("_id", String, primary_key=True))
    user_id: str = Field(sa_column=Column(String, ForeignKey("users._id", ondelete="CASCADE"), nullable=False, unique=True, index=True))
    token: str = Field(sa_column=Column(String, nullable=False, unique=True, index=True))
    is_used: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, default=False))
    request_count: int = Field(default=1, sa_column=Column(Integer, nullable=False, default=1))
    created_at: datetime = Field(default_factory=utils.utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    expires_at: datetime = Field(default_factory=password_reset_token_expiry_time, sa_column=Column(DateTime(timezone=True), nullable=False))
    cooldown_until: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    cooldown_reset_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))

    user: User = Relationship(back_populates="password_reset_token")


class EmailVerificationToken(SQLModel, table=True):
    __tablename__ = "email_verification_tokens"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: utils.generate_random_id("evt"), sa_column=Column("_id", String, primary_key=True))
    user_id: str = Field(sa_column=Column(String, ForeignKey("users._id", ondelete="CASCADE"), nullable=False, unique=True, index=True))
    token: str = Field(sa_column=Column(String, nullable=False, unique=True, index=True))
    is_used: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, default=False))
    created_at: datetime = Field(default_factory=utils.utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    expires_at: datetime = Field(default_factory=email_verification_token_expiry_time, sa_column=Column(DateTime(timezone=True), nullable=False))

    user: User = Relationship(back_populates="email_verification_token")
