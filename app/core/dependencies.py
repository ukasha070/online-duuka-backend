from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.security import TokenType, validate_token
from app.database import get_db
from app.models.user import User, UserSession

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    try:
        payload = validate_token(token, TokenType.ACCESS)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    user_id = payload.get("sub")
    session_id = payload.get("session_id")

    if not user_id or not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token.")

    session_result = await db.exec(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
            UserSession.is_active == True,  # noqa: E712
        )
    )
    if session_result.first() is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has expired or was revoked.")

    user_result = await db.exec(select(User).where(User.id == user_id))
    user = user_result.first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")

    if not user.is_active or user.is_disabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account is disabled.")

    return user


async def require_admin(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    if not (current_user.is_admin or current_user.is_superuser):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required.")
    return current_user
