from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, Enum as SAEnum, ForeignKey, String, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from app.core.utils import generate_random_id, utc_now


class ParticipantType(str, Enum):
    USER = "user"
    SHOP = "shop"


class Conversation(SQLModel, table=True):
    __tablename__ = "conversations"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: generate_random_id("conversation"), sa_column=Column("_id", String, primary_key=True))
    product_id: Optional[str] = Field(default=None, sa_column=Column(String, ForeignKey("products._id"), nullable=True, index=True))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))


class ConversationParticipant(SQLModel, table=True):
    __tablename__ = "conversation_participants"  # type: ignore[assignment]
    __table_args__ = (UniqueConstraint("conversation_id", "participant_id", name="uq_conversation_participants_conversation_participant"),)

    id: str = Field(default_factory=lambda: generate_random_id("participant"), sa_column=Column("_id", String, primary_key=True))
    conversation_id: str = Field(sa_column=Column(String, ForeignKey("conversations._id"), nullable=False, index=True))
    participant_id: str = Field(sa_column=Column(String, ForeignKey("users._id"), nullable=False, index=True))
    participant_type: ParticipantType = Field(sa_column=Column(SAEnum(ParticipantType), nullable=False))


class Message(SQLModel, table=True):
    __tablename__ = "messages"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: generate_random_id("message"), sa_column=Column("_id", String, primary_key=True))
    conversation_id: str = Field(sa_column=Column(String, ForeignKey("conversations._id"), nullable=False, index=True))
    sender_id: str = Field(sa_column=Column(String, ForeignKey("users._id"), nullable=False, index=True))
    content: str = Field(sa_column=Column(Text, nullable=False))
    is_read: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, default=False))
    sent_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False, index=True))
