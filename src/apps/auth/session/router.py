from fastapi import APIRouter, Depends, HTTPException, Request, status

from sqlmodel.ext.asyncio.session import AsyncSession
from apps.auth.dependencies import get_current_user
from apps.auth.session.schemas import (
    RefreshSessionPayload,
    SessionListResponse,
    UserSessionResponse,
)
from apps.auth.user.models import User
from apps.auth.utils import get_client_context
from core.db import get_db

from . import services

router = APIRouter(prefix="", tags=["sessions"])


@router.get("", response_model=SessionListResponse)
async def list_my_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List active, non-expired sessions for the currently authenticated user.

    This is useful for a frontend screen like:
    - "Logged in devices"
    - "Active sessions"
    - "Where you're signed in"
    """
    sessions = await services.get_sessions_by_user_id(db=db, user_id=current_user.id)

    return SessionListResponse(
        total=len(sessions),
        sessions=[
            UserSessionResponse(
                id=session.id,
                device_id=session.device_id,
                device_name=session.device_name,
                device_type=session.device_type,
                os_name=session.os_name,
                browser_name=session.browser_name,
                ip_address=session.ip_address,
                last_ip_address=session.last_ip_address,
                user_agent=session.user_agent,
                is_active=session.is_active,
                is_current=False,
                created_at=session.created_at,
                last_seen_at=session.last_seen_at,
            )
            for session in sessions
        ],
    )


@router.delete("/revoke/{session_id}")
async def revoke_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Revoke/sign out one device session for the currently authenticated user.

    This is useful for frontend screens like:
    - Logged in devices
    - Active sessions
    - Where you're signed in
    """

    is_deleted = await services.delete_user_session_by_id(
        db=db,
        session_id=session_id,
        user_id=current_user.id,
    )

    if not is_deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or does not belong to the current user.",
        )

    return {"detail": "Successfully signed out of the device."}


@router.post("/refresh")
async def refresh_session(
    request: Request,
    payload: RefreshSessionPayload,
    db: AsyncSession = Depends(get_db),
):
    client = get_client_context(request)

    access_token = await services.refresh_user_session(
        db=db, refresh_token=payload.refresh_token, ip_address=client.ip_address
    )

    return {"access_token": access_token}
