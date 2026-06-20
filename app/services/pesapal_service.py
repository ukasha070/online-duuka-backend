from __future__ import annotations

from decimal import Decimal
from typing import Any
from uuid import uuid4

import httpx
from fastapi import HTTPException, status

from app.config import settings


class PesaPalService:
    """Small async client for PesaPal API 3.0 checkout, IPN and status flows."""

    def __init__(self) -> None:
        self.base_url = settings.PESAPAL_BASE_URL.rstrip("/")

    async def request_access_token(self) -> str:
        self._ensure_credentials()

        payload = {
            "consumer_key": settings.PESAPAL_CONSUMER_KEY,
            "consumer_secret": settings.PESAPAL_CONSUMER_SECRET,
        }

        data = await self._post("/api/Auth/RequestToken", json=payload, auth=False)
        token = data.get("token")
        if not token:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="PesaPal did not return an access token.",
            )
        return str(token)

    async def register_ipn_url(self, *, ipn_url: str | None = None, notification_type: str = "GET") -> dict[str, Any]:
        token = await self.request_access_token()
        payload = {
            "url": ipn_url or settings.PESAPAL_IPN_URL,
            "ipn_notification_type": notification_type,
        }
        return await self._post("/api/URLSetup/RegisterIPN", json=payload, token=token)

    async def submit_order(
        self,
        *,
        amount: int | Decimal,
        description: str,
        email: str,
        phone_number: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        reference: str | None = None,
        callback_url: str | None = None,
        notification_id: str | None = None,
        currency: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        token = await self.request_access_token()
        merchant_reference = reference or f"OD-{uuid4().hex}"

        payload: dict[str, Any] = {
            "id": merchant_reference,
            "currency": currency or settings.PESAPAL_CURRENCY,
            "amount": float(amount),
            "description": description,
            "callback_url": callback_url or settings.PESAPAL_CALLBACK_URL,
            "notification_id": notification_id or settings.PESAPAL_IPN_ID,
            "billing_address": {
                "email_address": email,
                "phone_number": phone_number,
                "first_name": first_name,
                "last_name": last_name,
            },
        }

        if metadata:
            payload["metadata"] = metadata

        return await self._post("/api/Transactions/SubmitOrderRequest", json=payload, token=token)

    async def get_transaction_status(self, *, order_tracking_id: str) -> dict[str, Any]:
        token = await self.request_access_token()
        return await self._get(
            "/api/Transactions/GetTransactionStatus",
            params={"orderTrackingId": order_tracking_id},
            token=token,
        )

    async def _get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        headers = self._headers(token)
        try:
            async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
                response = await client.get(f"{self.base_url}{path}", params=params, headers=headers)
                response.raise_for_status()
                data: Any = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="PesaPal request failed.",
            ) from exc
        return self._ensure_mapping(data)

    async def _post(
        self,
        path: str,
        *,
        json: dict[str, Any],
        token: str | None = None,
        auth: bool = True,
    ) -> dict[str, Any]:
        headers = self._headers(token if auth else None)
        try:
            async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
                response = await client.post(f"{self.base_url}{path}", json=json, headers=headers)
                response.raise_for_status()
                data: Any = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="PesaPal request failed.",
            ) from exc
        return self._ensure_mapping(data)

    @staticmethod
    def _headers(token: str | None = None) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    @staticmethod
    def _ensure_mapping(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="PesaPal returned an invalid response.",
            )
        return data

    @staticmethod
    def _ensure_credentials() -> None:
        if not settings.PESAPAL_CONSUMER_KEY or not settings.PESAPAL_CONSUMER_SECRET:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="PesaPal credentials are not configured.",
            )


pesapal_service = PesaPalService()
