from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String
from sqlmodel import Field, SQLModel

from app.core.utils import generate_random_id, utc_now


class BoosterPack(SQLModel, table=True):
    __tablename__ = "booster_packs"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: generate_random_id("boost"), sa_column=Column("_id", String, primary_key=True))
    name: str = Field(sa_column=Column(String(64), unique=True, nullable=False, index=True))
    price_ugx: int = Field(sa_column=Column(Integer, nullable=False))
    score_weight: float = Field(sa_column=Column(Float, nullable=False))
    duration_days: int = Field(sa_column=Column(Integer, nullable=False))
    is_active: bool = Field(default=True, sa_column=Column(Boolean, nullable=False, default=True))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))


class ActiveBooster(SQLModel, table=True):
    __tablename__ = "active_boosters"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: generate_random_id("activeboost"), sa_column=Column("_id", String, primary_key=True))
    product_id: str = Field(sa_column=Column(String, nullable=False, index=True))
    booster_pack_id: str = Field(sa_column=Column(String, nullable=False, index=True))
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False, index=True))
    is_active: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, default=False, index=True))
