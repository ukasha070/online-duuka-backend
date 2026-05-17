from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel.ext.asyncio.session import AsyncSession

from apps.auth.authentication import create_login_session_response
from apps.auth.schema import CreateSessionPayload
from apps.auth.session.schemas import LoginResponse
from apps.auth.validators import validate_user
from apps.auth._jwt import create_two_factor_token
from core.db import get_db
from apps.auth.utils import get_client_context

from apps.auth.dependencies import get_current_user

from apps.auth.verification import services as verification_service
from apps.auth.two_factor.service import authenticator_app_service
from apps.auth.user.models import User
from .schemas import (
    ChangePasswordPayLoad,
    SignOutPayload,
    SigninPayload,
    SignupPayload,
    UserProfileUpdatePayload,
)

from apps.auth import tasks
from apps.auth.session import services as session_service
from apps.auth.user import service_user as user_service, service_pro as profile_service

router = APIRouter(prefix="", tags=["auth"])


@router.post(
    "/signup",
    status_code=status.HTTP_201_CREATED,
)
async def sign_up_user(
    payload: SignupPayload,
    db: AsyncSession = Depends(get_db),
):
    normalized_email = payload.email.lower().strip()
    normalized_full_name = payload.full_name.strip()

    exiting_user = user_service.get_user_by_email(db=db, email=normalized_email)

    if exiting_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered",
        )

    new_user = await user_service.create_email_user(
        db=db,
        email=normalized_email,
        full_name=normalized_full_name,
        password=payload.password,
    )

    _ver_token = await verification_service.create_or_update_verification_token(
        db=db,
        user_id=new_user.id,
    )

    tasks.send_verification_email.delay(  # type: ignore
        to_email=payload.email,
        token=_ver_token.token,
        full_name=payload.full_name,
    )

    return {
        "detail": "Account created successfully. Please verify your email.",
    }


@router.post("/signin", response_model=LoginResponse)
async def sign_in_user(
    payload: SigninPayload,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    user = await user_service.authenticate_email_user(
        db=db,
        email=payload.email,
        password=payload.password,
    )
    validated_user = validate_user(user)
    client = get_client_context(request)

    # ── two-factor gating ──────────────────────────────────────────────────
    if await authenticator_app_service.is_enabled(db=db, user_id=validated_user.id):
        session_payload = CreateSessionPayload.model_validate(
            {
                **client.model_dump(),
                **payload.model_dump(),
                "remember_me": payload.remember_me,
            }
        )
        token = create_two_factor_token(
            user_id=validated_user.id, session_payload=session_payload
        )
        return {
            "two_factor_token": token,
        }

    # ── normal login ───────────────────────────────────────────────────────
    session_payload = CreateSessionPayload.model_validate(
        {**client.model_dump(), **payload.model_dump()}
    )
    response = await create_login_session_response(
        db=db,
        user_id=validated_user.id,
        session_payload=session_payload,
    )

    return response


@router.post("/signout", status_code=status.HTTP_200_OK)
async def signout_user(
    payload: SignOutPayload,
    db: AsyncSession = Depends(get_db),
):
    await session_service.delete_session_by_refresh_token(
        db=db,
        refresh_token=payload.refresh_token,
    )

    return {"detail": "Logged out successfully"}


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordPayLoad,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user = current_user

    await user_service.change_password(db, user.id, payload.confirm_password)

    await session_service.delete_all_user_sessions(user_id=user.id, db=db)

    tasks.send_password_changed_email.delay(  # type: ignore
        to_email=user.email, full_name=user.full_name
    )
    return {"detail": "Password changed successfully"}


@router.get("/me")
async def get_me(current_user=Depends(get_current_user)):
    return current_user


@router.patch("/me/image")
async def update_my_profile_image(
    payload: UserProfileUpdatePayload,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    profile = await profile_service.update_profile_image_path(
        session=session,
        user_id=current_user.id,
        image_path=payload.image_path,
    )

    return {"image": profile_service.get_display_image(profile)}
