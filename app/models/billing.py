from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import Column, DateTime, Enum as SAEnum, ForeignKey, Integer, String
from sqlmodel import Field, SQLModel

from app.core.utils import generate_random_id, utc_now


class SubscriptionPlan(str, Enum):
    SHOP = "shop"
    BUSINESS = "business"


class BillingCycle(str, Enum):
    MONTHLY = "monthly"
    YEARLY = "yearly"


class SubscriptionStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    LAPSED = "lapsed"
    CANCELLED = "cancelled"


class Subscription(SQLModel, table=True):
    __tablename__ = "subscriptions"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: generate_random_id("sub"), sa_column=Column("_id", String, primary_key=True))
    user_id: str = Field(sa_column=Column(String, ForeignKey("users._id"), nullable=False, index=True))
    plan: SubscriptionPlan = Field(sa_column=Column(SAEnum(SubscriptionPlan), nullable=False))
    billing_cycle: BillingCycle = Field(sa_column=Column(SAEnum(BillingCycle), nullable=False))
    status: SubscriptionStatus = Field(default=SubscriptionStatus.PENDING, sa_column=Column(SAEnum(SubscriptionStatus), nullable=False, default=SubscriptionStatus.PENDING, index=True))
    amount_ugx: int = Field(sa_column=Column(Integer, nullable=False))
    pesapal_order_id: Optional[str] = Field(default=None, sa_column=Column(String(255), nullable=True, index=True))
    pesapal_tracking_id: Optional[str] = Field(default=None, sa_column=Column(String(255), nullable=True, index=True))
    starts_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    ends_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
