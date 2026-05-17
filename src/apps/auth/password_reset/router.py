from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession

from apps.auth.validators import validate_user
from core.db import get_db

from apps.auth.user import service_user as user_service
from apps.auth.session import services as session_service

from . import tasks
from . import service
from .schemas import PasswordResetConfirmPayload, PasswordResetRequestPayload

router = APIRouter(prefix="", tags=["auth"])


# passsowrd reset endpoints
@router.post("/request/")
async def request_password_reset(
    payload: PasswordResetRequestPayload, db: AsyncSession = Depends(get_db)
):

    user = await user_service.get_user_by_email(
        db=db,
        email=payload.email,
    )

    validated_user = validate_user(user)

    try:
        reset_token = await service.create_or_update_password_reset_token(
            db=db,
            user_id=validated_user.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            # headers={"Retry-After": str(settings.PASSWORD_RESET_REQUEST_COOLDOWN_SECONDS)},
        )

    tasks.send_password_reset_email.delay(  # type: ignore
        to_email=payload.email,
        full_name=validated_user.full_name,
        token=reset_token.token,
    )

    return {"detail": "A password reset email has been sent."}


@router.get("/confirm/token/{token}")
async def confirm_password_reset_token(token: str, db: AsyncSession = Depends(get_db)):
    reset_token = await service.get_valid_token(token=token, db=db)
    return {"detail": "Password reset token is valid", "reset_token": reset_token}


@router.post("/confirm/")
async def confirm_password_reset(
    payload: PasswordResetConfirmPayload, db: AsyncSession = Depends(get_db)
):
    reset_token = await service.get_valid_token(token=payload.token, db=db)

    user = await user_service.change_password(
        db=db,
        user_id=reset_token.user_id,
        new_password=payload.new_password,
    )
    # TODO add infor of the password changing device

    await service.mark_token_as_used(
        db=db,
        reset_token=reset_token,
    )

    await session_service.delete_all_user_sessions(user_id=user.id, db=db)

    tasks.send_password_changed_email.delay(  # type: ignore
        to_email=user.email, full_name=user.full_name
    )

    return {
        "detail": "Password has been reset successfully. Please log in with your new password."
    }
