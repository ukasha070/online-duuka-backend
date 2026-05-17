from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    String,
    ForeignKey,
)

from datetime import datetime

from typing import TYPE_CHECKING, Optional

from sqlmodel import Field, Relationship, SQLModel

from core.utils import generate_random_id, utc_now

if TYPE_CHECKING:
    from apps.auth.user.models import User


class UserAuthenticatorApp(SQLModel, table=True):
    __tablename__ = "user_authenticator_apps"  # type: ignore

    id: str = Field(
        default_factory=lambda: generate_random_id("authapp"),
        sa_column=Column("_id", String, primary_key=True),
    )

    user_id: str = Field(
        sa_column=Column(
            String,
            ForeignKey("users._id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
            index=True,
        )
    )

    secret: str = Field(
        sa_column=Column(String(512), nullable=False),
    )

    issuer: str = Field(
        sa_column=Column(String(255), nullable=False),
    )

    is_enabled: bool = Field(
        default=False,
        sa_column=Column(Boolean, nullable=False, default=False, index=True),
    )

    last_used_counter: Optional[int] = Field(
        default=None,
        sa_column=Column(Integer, nullable=True),
    )

    last_used_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )

    confirmed_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )

    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

    user: Optional["User"] = Relationship(back_populates="authenticator_app")


class UserTwoFactorRecoveryCode(SQLModel, table=True):
    __tablename__ = "user_two_factor_recovery_codes"  # type: ignore
    __table_args__ = (
        Index(
            "ix_user_two_factor_recovery_codes_user_unused",
            "user_id",
            "is_used",
        ),
    )

    id: str = Field(
        default_factory=lambda: generate_random_id("2far"),
        sa_column=Column("_id", String, primary_key=True),
    )

    user_id: str = Field(
        sa_column=Column(
            String,
            ForeignKey("users._id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        )
    )

    code_hash: str = Field(
        sa_column=Column(String(128), nullable=False, unique=True, index=True),
    )

    is_used: bool = Field(
        default=False,
        sa_column=Column(Boolean, nullable=False, default=False, index=True),
    )

    used_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )

    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
