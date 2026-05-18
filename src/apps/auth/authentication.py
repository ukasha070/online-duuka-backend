from sqlmodel.ext.asyncio.session import AsyncSession

from apps.auth.schemas import CreateSessionPayload
from apps.auth.session.services import create_login_session
from apps.auth.session.schemas import LoginResponse


async def create_login_session_response(
    db: AsyncSession,
    user_id: str,
    payload: CreateSessionPayload,
) -> LoginResponse:
    login_session = await create_login_session(
        db=db,
        user_id=user_id,
        # device
        os_name=payload.os_name,
        device_id=payload.device_id,
        device_name=payload.device_name,
        device_type=payload.device_type,
        browser_name=payload.browser_name,
        # client
        user_agent=payload.user_agent,
        ip_address=payload.ip_address,
        remember_me=payload.remember_me,
    )

    return LoginResponse(
        access_token=login_session.access_token,
        refresh_token=login_session.refresh_token,
        two_factor_required=False,
    )
