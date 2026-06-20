from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, String
from sqlmodel import Field, SQLModel

from app.core.utils import generate_random_id, utc_now


class Agent(SQLModel, table=True):
    __tablename__ = "agents"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: generate_random_id("agent"), sa_column=Column("_id", String, primary_key=True))
    user_id: str = Field(sa_column=Column(String, ForeignKey("users._id", ondelete="CASCADE"), unique=True, nullable=False, index=True))
    agent_code: str = Field(sa_column=Column(String(32), unique=True, nullable=False, index=True))
    full_name: str = Field(sa_column=Column(String(255), nullable=False))
    profile_pic_url: Optional[str] = Field(default=None, sa_column=Column(String(512), nullable=True))
    total_commission_ugx: int = Field(default=0, sa_column=Column(BigInteger, nullable=False, default=0))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))


class AgentCommission(SQLModel, table=True):
    __tablename__ = "agent_commissions"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: generate_random_id("fee"), sa_column=Column("_id", String, primary_key=True))
    agent_id: str = Field(sa_column=Column(String, ForeignKey("agents._id"), nullable=False, index=True))
    shop_id: str = Field(sa_column=Column(String, ForeignKey("shops._id"), nullable=False, index=True))
    subscription_id: str = Field(sa_column=Column(String, ForeignKey("subscriptions._id"), nullable=False, index=True))
    amount_ugx: int = Field(default=2000)
    paid_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
