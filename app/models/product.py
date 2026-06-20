from datetime import datetime
from sqlalchemy import Column, DateTime, String
from sqlmodel import Field, SQLModel

from app.core.utils import generate_random_id, utc_now


class Product(SQLModel, table=True):
    __tablename__ = "products"  # type: ignore[assignment]

    id: str = Field(default_factory=lambda: generate_random_id("product"), sa_column=Column("_id", String, primary_key=True))
    shop_id: str = Field(sa_column=Column(String, nullable=False, index=True))
    name: str = Field(sa_column=Column(String(255), nullable=False, index=True))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False))
