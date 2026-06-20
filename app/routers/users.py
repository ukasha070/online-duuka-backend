from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.dependencies import get_current_user
from app.models.user import User
from app.schemas.auth import UpdateMePayload, UserResponse
from app.services import auth_service
from app.database import get_db
from sqlmodel.ext.asyncio.session import AsyncSession

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def me(current_user: Annotated[User, Depends(get_current_user)]) -> UserResponse:
    return auth_service.public_user(current_user)


@router.patch("/me", response_model=UserResponse)
async def update_me(
    payload: UpdateMePayload,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserResponse:
    if payload.full_name is not None:
        current_user.full_name = payload.full_name
        db.add(current_user)
        await db.commit()
        await db.refresh(current_user)
    return auth_service.public_user(current_user)
