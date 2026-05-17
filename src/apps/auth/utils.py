from fastapi import Request
from pydantic import BaseModel


class ClientContext(BaseModel):
    user_agent: str | None
    ip_address: str | None


def get_client_context(request: Request) -> ClientContext:
    return ClientContext(
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
