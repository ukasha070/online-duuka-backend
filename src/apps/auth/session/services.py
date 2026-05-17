from datetime import datetime, timezone, timedelta
from typing import Optional
import hashlib

from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from .schemas import (
    LoginSession,
)

from apps.auth._jwt import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
)
from .models import UserSession

from core.config import settings
from core.utils import generate_random_id


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def make_device_key_hash(
    *,
    device_id: Optional[str],
    user_agent: Optional[str],
) -> str:
    if device_id:
        raw_value = f"device_id:{device_id.strip()}"
    else:
        raw_value = f"user_agent:{user_agent or 'unknown'}"

    return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()


async def delete_expired_sessions_for_user(
    *,
    db: AsyncSession,
    user_id: str,
) -> None:
    now = utc_now()

    statement = select(UserSession).where(
        UserSession.user_id == user_id,
        UserSession.expires_at <= now,
    )

    result = await db.exec(statement)
    expired_sessions = result.all()

    for session in expired_sessions:
        await db.delete(session)


async def enforce_max_sessions(
    *,
    db: AsyncSession,
    user_id: str,
) -> None:
    now = utc_now()

    statement = (
        select(UserSession)
        .where(
            UserSession.user_id == user_id,
            UserSession.is_active == True,  # noqa: E712
            UserSession.expires_at > now,
        )
        .order_by(col(UserSession.last_seen_at).desc())
    )

    result = await db.exec(statement)
    sessions = result.all()

    sessions_to_delete = sessions[settings.MAX_ACTIVE_SESSIONS_PER_USER :]

    for session in sessions_to_delete:
        await db.delete(session)


async def create_login_session(
    *,
    db: AsyncSession,
    user_id: str,
    device_id: Optional[str],
    device_name: Optional[str],
    device_type: Optional[str],
    os_name: Optional[str],
    browser_name: Optional[str],
    user_agent: Optional[str],
    ip_address: Optional[str],
) -> LoginSession:
    """
    Called after successful login.

    Returns:
    - access_token
    - refresh_token
    - session
    """
    await delete_expired_sessions_for_user(db=db, user_id=user_id)

    now = utc_now()
    expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    device_id = device_id if device_id else generate_random_id("device")

    device_key_hash = make_device_key_hash(
        device_id=device_id,
        user_agent=user_agent,
    )

    statement = select(UserSession).where(
        UserSession.user_id == user_id,
        UserSession.device_key_hash == device_key_hash,
    )

    result = await db.exec(statement)
    existing_session = result.first()

    if existing_session:
        session_id = existing_session.id

        refresh_token = create_refresh_token(
            user_id=user_id,
            session_id=session_id,
        )

        existing_session.device_id = device_id
        existing_session.device_name = device_name
        existing_session.device_type = device_type
        existing_session.os_name = os_name
        existing_session.browser_name = browser_name
        existing_session.user_agent = user_agent
        existing_session.last_ip_address = ip_address
        existing_session.refresh_token_hash = hash_token(refresh_token)
        existing_session.is_active = True
        existing_session.revoked_at = None
        existing_session.revoked_reason = None
        existing_session.logged_out_at = None
        existing_session.last_seen_at = now
        existing_session.expires_at = expires_at

        db.add(existing_session)
        await enforce_max_sessions(db=db, user_id=user_id)

        await db.commit()
        await db.refresh(existing_session)

        access_token = create_access_token(
            user_id=user_id,
            session_id=existing_session.id,
            extra_claims={"device_id": device_id},
        )

        return LoginSession(
            access_token=access_token,
            refresh_token=refresh_token,
            session=UserSession(**existing_session.model_dump()),
        )

    session_id = generate_random_id("session")

    refresh_token = create_refresh_token(
        user_id=user_id,
        session_id=session_id,
        extra_claims={"device_id": device_id},
    )

    new_session = UserSession(
        id=session_id,
        user_id=user_id,
        device_id=device_id,
        device_key_hash=device_key_hash,
        device_name=device_name,
        device_type=device_type,
        os_name=os_name,
        browser_name=browser_name,
        user_agent=user_agent,
        ip_address=ip_address,
        last_ip_address=ip_address,
        refresh_token_hash=hash_token(refresh_token),
        is_active=True,
        created_at=now,
        last_seen_at=now,
        expires_at=expires_at,
    )

    db.add(new_session)

    await enforce_max_sessions(db=db, user_id=user_id)

    await db.commit()
    await db.refresh(new_session)

    access_token = create_access_token(
        user_id=user_id,
        session_id=new_session.id,
        extra_claims={"device_id": device_id},
    )

    return LoginSession(
        access_token=access_token,
        refresh_token=refresh_token,
        session=UserSession(**new_session.model_dump()),
    )


async def refresh_user_session(
    *,
    db: AsyncSession,
    refresh_token: str,
    ip_address: Optional[str] = None,
) -> dict:
    """
    Refresh-token rotation:
    - old refresh token comes in
    - validate JWT
    - check hash against DB
    - create new access token
    - create new refresh token
    - replace DB hash with new refresh token hash
    """
    try:
        payload = decode_refresh_token(refresh_token)
    except ValueError:
        raise ValueError("Invalid or expired refresh token")

    user_id = payload.get("sub")
    session_id = payload.get("session_id")

    if not user_id or not session_id:
        raise ValueError("Invalid refresh token payload")

    refresh_token_hash = hash_token(refresh_token)
    now = utc_now()

    statement = select(UserSession).where(
        UserSession.id == session_id,
        UserSession.user_id == user_id,
        UserSession.refresh_token_hash == refresh_token_hash,
        UserSession.is_active == True,  # noqa: E712
        UserSession.expires_at > now,
    )

    result = await db.exec(statement)
    user_session = result.first()

    if not user_session:
        raise ValueError("Invalid or revoked session")

    new_access_token = create_access_token(
        user_id=user_id,
        session_id=session_id,
        extra_claims={"device_id": user_session.device_id},
    )

    new_refresh_token = create_refresh_token(
        user_id=user_id,
        session_id=session_id,
        extra_claims={"device_id": user_session.device_id},
    )

    user_session.refresh_token_hash = hash_token(new_refresh_token)
    user_session.last_seen_at = now

    if ip_address:
        user_session.last_ip_address = ip_address

    db.add(user_session)
    await db.commit()
    await db.refresh(user_session)

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "session": user_session,
    }


async def delete_session_by_refresh_token(
    *,
    db: AsyncSession,
    refresh_token: str,
) -> bool:
    try:
        payload = decode_refresh_token(refresh_token)
    except ValueError:
        return False

    session_id = payload.get("session_id")
    user_id = payload.get("sub")

    if not session_id or not user_id:
        return False

    statement = select(UserSession).where(
        UserSession.id == session_id,
        UserSession.user_id == user_id,
    )

    result = await db.exec(statement)
    user_session = result.first()

    if not user_session:
        return False

    await db.delete(user_session)
    await db.commit()

    return True


async def delete_all_user_sessions(
    *,
    db: AsyncSession,
    user_id: str,
) -> int:
    statement = select(UserSession).where(UserSession.user_id == user_id)

    result = await db.exec(statement)
    sessions = result.all()

    count = len(sessions)

    for session in sessions:
        await db.delete(session)

    await db.commit()

    return count
