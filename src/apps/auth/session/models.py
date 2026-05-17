from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    String,
    ForeignKey,
    Text,
    UniqueConstraint,
    Index,
)

from datetime import datetime

from typing import TYPE_CHECKING, Optional

from sqlmodel import Field, Relationship, SQLModel

from core.utils import generate_random_id, utc_now

if TYPE_CHECKING:
    from apps.auth.user.models import User


class UserSession(SQLModel, table=True):
    __tablename__ = "user_sessions"  # type: ignore

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "device_key_hash",
            name="uq_user_sessions_user_id_device_key_hash",
        ),
        Index(
            "ix_user_sessions_user_active_last_seen",
            "user_id",
            "is_active",
            "last_seen_at",
        ),
    )

    id: str = Field(
        default_factory=lambda: generate_random_id("session"),
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

    # Client-provided stable device ID.
    # Example: UUID stored in mobile SecureStore or web localStorage/cookie.
    device_id: Optional[str] = Field(
        default=None,
        sa_column=Column(String(255), nullable=True),
    )

    # Hash of device_id/user_agent. Used to detect same device without storing raw fingerprint.
    device_key_hash: str = Field(
        sa_column=Column(String(128), nullable=False, index=True),
    )

    # Human-friendly device info
    device_name: Optional[str] = Field(
        default=None,
        sa_column=Column(String(255), nullable=True),
    )

    device_type: Optional[str] = Field(
        default=None,
        sa_column=Column(String(50), nullable=True),
    )
    # examples: "mobile", "desktop", "tablet", "web"

    os_name: Optional[str] = Field(
        default=None,
        sa_column=Column(String(100), nullable=True),
    )

    browser_name: Optional[str] = Field(
        default=None,
        sa_column=Column(String(100), nullable=True),
    )

    user_agent: Optional[str] = Field(
        default=None,
        sa_column=Column(Text, nullable=True),
    )

    ip_address: Optional[str] = Field(
        default=None,
        sa_column=Column(String(100), nullable=True),
    )

    last_ip_address: Optional[str] = Field(
        default=None,
        sa_column=Column(String(100), nullable=True),
    )

    # Store only the hash, never the raw refresh token
    refresh_token_hash: str = Field(
        sa_column=Column(String(128), nullable=False, unique=True, index=True),
    )

    is_active: bool = Field(
        default=True,
        sa_column=Column(Boolean, nullable=False, default=True, index=True),
    )

    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

    last_seen_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False, index=True),
    )

    expires_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, index=True),
    )

    logged_out_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )

    revoked_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )

    revoked_reason: Optional[str] = Field(
        default=None,
        sa_column=Column(String(255), nullable=True),
    )

    user: Optional["User"] = Relationship(back_populates="sessions")
