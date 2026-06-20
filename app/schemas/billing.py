from __future__ import annotations

from typing import Any

from pydantic import BaseModel, EmailStr, Field

from app.models.billing import BillingCycle, SubscriptionPlan


class SubscribePayload(BaseModel):
    plan: SubscriptionPlan
    billing_cycle: BillingCycle
    amount_ugx: int = Field(gt=0)
    email: EmailStr
    phone_number: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    agent_code: str | None = None


class BoosterCheckoutPayload(BaseModel):
    product_id: str
    booster_pack_id: str
    amount_ugx: int = Field(gt=0)
    email: EmailStr
    phone_number: str | None = None
    first_name: str | None = None
    last_name: str | None = None


class PesaPalCheckoutResponse(BaseModel):
    order_tracking_id: str | None = None
    merchant_reference: str | None = None
    redirect_url: str | None = None
    raw: dict[str, Any]


class PesaPalIpnPayload(BaseModel):
    order_tracking_id: str | None = None
    order_merchant_reference: str | None = None
    order_notification_type: str | None = None


class PaymentStatusResponse(BaseModel):
    order_tracking_id: str
    raw: dict[str, Any]
