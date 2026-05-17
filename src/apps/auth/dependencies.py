from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession


from ._jwt import decode_access_token

from core.db import get_db
from apps.auth.user.models import User
from apps.auth.session.models import UserSession

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/signin")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
):
    try:
        payload = decode_access_token(token)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    session_id = payload.get("session_id")

    if not user_id or not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    session_statement = select(UserSession).where(
        UserSession.id == session_id,
        UserSession.user_id == user_id,
        UserSession.is_active == True,  # noqa: E712
    )

    session_result = await db.exec(session_statement)
    user_session = session_result.first()

    if not user_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or was logged out",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_statement = select(User).where(User.id == user_id)
    user_result = await db.exec(user_statement)
    user = user_result.first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account not active contact support",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email Account not verified",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
