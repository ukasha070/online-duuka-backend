from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    String,
    ForeignKey,
)

from datetime import datetime, timedelta


from sqlmodel import Field, Relationship, SQLModel

from apps.auth.user.models import User
from core import utils
from core.config import settings


def token_expiry_time() -> datetime:
    return utils.utc_now() + timedelta(
        minutes=settings.EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES
    )


class EmailVerificationToken(SQLModel, table=True):
    __tablename__ = "email_verification_tokens"  # type: ignore

    id: str = Field(
        default_factory=lambda: utils.generate_random_id("evt"),
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

    token: str = Field(
        sa_column=Column(String, nullable=False, unique=True, index=True)
    )

    is_used: bool = Field(
        default=False,
        sa_column=Column(Boolean, nullable=False, default=False),
    )

    created_at: datetime = Field(
        default_factory=utils.utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

    expires_at: datetime = Field(
        default_factory=token_expiry_time,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

    user: User = Relationship(back_populates="email_verification_token")

    def is_expired(self) -> bool:
        return utils.utc_now() > self.expires_at

    def can_be_used(self) -> bool:
        return not self.is_used and not self.is_expired()
