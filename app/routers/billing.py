from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.dependencies import get_current_user
from app.database import get_db
from app.models.billing import Subscription, SubscriptionStatus
from app.models.user import User
from app.schemas.billing import (
    PaymentStatusResponse,
    PesaPalCheckoutResponse,
    PesaPalIpnPayload,
    SubscribePayload,
)
from app.services.pesapal_service import pesapal_service

router = APIRouter(prefix="")


@router.post("/subscribe", response_model=PesaPalCheckoutResponse)
async def subscribe(
    payload: SubscribePayload,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> PesaPalCheckoutResponse:
    subscription = Subscription(
        user_id=current_user.id,
        plan=payload.plan,
        billing_cycle=payload.billing_cycle,
        status=SubscriptionStatus.PENDING,
        amount_ugx=payload.amount_ugx,
    )
    db.add(subscription)
    await db.commit()
    await db.refresh(subscription)

    checkout = await pesapal_service.submit_order(
        amount=payload.amount_ugx,
        description=f"{payload.plan.value.title()} {payload.billing_cycle.value} subscription",
        email=str(payload.email),
        phone_number=payload.phone_number,
        first_name=payload.first_name,
        last_name=payload.last_name,
        reference=subscription.id,
        metadata={
            "type": "subscription",
            "subscription_id": subscription.id,
            "user_id": current_user.id,
            "agent_code": payload.agent_code,
        },
    )

    subscription.pesapal_order_id = str(checkout.get("merchant_reference") or subscription.id)
    subscription.pesapal_tracking_id = checkout.get("order_tracking_id")
    db.add(subscription)
    await db.commit()

    return PesaPalCheckoutResponse(
        order_tracking_id=checkout.get("order_tracking_id"),
        merchant_reference=checkout.get("merchant_reference") or subscription.id,
        redirect_url=checkout.get("redirect_url"),
        raw=checkout,
    )


@router.post("/ipn")
async def pesapal_ipn(payload: PesaPalIpnPayload, request: Request) -> dict[str, Any]:
    # PesaPal may send either JSON body or query params depending on IPN configuration.
    order_tracking_id = (
        payload.order_tracking_id
        or request.query_params.get("OrderTrackingId")
        or request.query_params.get("orderTrackingId")
    )

    if not order_tracking_id:
        return {"detail": "IPN received without order tracking id.", "processed": False}

    status_payload = await pesapal_service.get_transaction_status(order_tracking_id=order_tracking_id)
    return {"detail": "IPN received.", "processed": True, "payment": status_payload}


@router.get("/status/{order_tracking_id}", response_model=PaymentStatusResponse)
async def payment_status(order_tracking_id: str) -> PaymentStatusResponse:
    status_payload = await pesapal_service.get_transaction_status(order_tracking_id=order_tracking_id)
    return PaymentStatusResponse(order_tracking_id=order_tracking_id, raw=status_payload)


@router.get("/me")
async def my_billing(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    # Subscription listing will be completed with the subscription repository layer.
    return {"detail": f"Billing profile for {current_user.id}"}
