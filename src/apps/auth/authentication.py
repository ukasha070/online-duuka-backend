from sqlmodel.ext.asyncio.session import AsyncSession

from apps.auth.schema import CreateSessionPayload
from apps.auth.session.services import create_login_session


async def create_login_session_response(
    db: AsyncSession, user_id: str, session_payload: CreateSessionPayload
):
    login_session = await create_login_session(
        db=db,
        user_id=user_id,
        # device
        os_name=session_payload.os_name,
        device_id=session_payload.device_id,
        device_name=session_payload.device_name,
        device_type=session_payload.device_type,
        browser_name=session_payload.browser_name,
        # client
        user_agent=session_payload.user_agent,
        ip_address=session_payload.ip_address,
    )

    return {
        "access_token": login_session.access_token,
        "refresh_token": login_session.refresh_token,
    }
