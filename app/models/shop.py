from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from app.core.utils import generate_random_id, utc_now


class Location(SQLModel, table=True):
    __tablename__ = "locations"  # type: ignore[assignment]
    __table_args__ = (UniqueConstraint("area", "district", name="uq_locations_area_district"),)

    id: str = Field(default_factory=lambda: generate_random_id("loc"), sa_column=Column("_id", String, primary_key=True))
    area: str = Field(sa_column=Column(String(255), nullable=False, index=True))
    district: str = Field(sa_column=Column(String(255), nullable=False, index=True))
    is_verified: bool = Field(default=True, sa_column=Column(Boolean, nullable=False, default=True))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))


class Shop(SQLModel, table=True):
    __tablename__ = "shops"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: generate_random_id("shop"), sa_column=Column("_id", String, primary_key=True))
    owner_id: str = Field(sa_column=Column(String, ForeignKey("users._id"), nullable=False, index=True))
    subscription_id: str = Field(sa_column=Column(String, ForeignKey("subscriptions._id"), nullable=False, index=True))
    agent_id: Optional[str] = Field(default=None, sa_column=Column(String, ForeignKey("agents._id"), nullable=True, index=True))
    location_id: str = Field(sa_column=Column(String, ForeignKey("locations._id"), nullable=False, index=True))
    name: str = Field(sa_column=Column(String(255), nullable=False, index=True))
    slug: str = Field(sa_column=Column(String(255), unique=True, nullable=False, index=True))
    description: Optional[str] = Field(default=None, sa_column=Column(Text, nullable=True))
    logo_url: Optional[str] = Field(default=None, sa_column=Column(String(512), nullable=True))
    is_active: bool = Field(default=True, sa_column=Column(Boolean, nullable=False, default=True))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
    updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
