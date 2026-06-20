from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from sqlmodel.ext.asyncio.session import AsyncSession

from apps.auth.authentication import create_login_session_response
from apps.auth.schemas import CreateSessionPayload
from apps.auth.session.schemas import (
    MePayload,
    MeResponse,
    SigninResponse,
    TwoFactorChallengeResponse,
)
from apps.auth.validators import validate_user
from apps.auth.two_factor.tokens import create_two_factor_token
from core.image.service import (
    ProcessConfig,
    process_upload,
)
from core.storage import file_storage
from core.db import get_db
from core import turnstile

from apps.auth.utils import get_client_context

from apps.auth.dependencies import get_current_user

from apps.auth.verification import services as verification_service
from apps.auth.two_factor.service import authenticator_app_service
from apps.auth.user.models import User, utc_now
from .schemas import (
    ChangePasswordPayload,
    SignOutPayload,
    SigninPayload,
    SignupPayload,
)

from apps.auth import tasks
from apps.auth.session import services as session_service
from apps.auth.user import service as user_service

router = APIRouter(prefix="", tags=["auth"])


@router.post(
    "/signup",
    status_code=status.HTTP_201_CREATED,
)
async def sign_up_user(
    payload: SignupPayload,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    client = get_client_context(request)

    await turnstile.validate_turnstile_token(
        turnstile_token=payload.turnstile_token,
        expected_action="signup",
        ip_address=client.ip_address
    )

    normalized_email = payload.email.lower().strip()
    normalized_full_name = payload.full_name.strip()

    existing_user = await user_service.get_user_by_email(
        db=db,
        email=normalized_email,
    )

    if existing_user:
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


@router.post("/signin", response_model=SigninResponse)
async def sign_in_user(
    payload: SigninPayload,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    
    client = get_client_context(request)

    await turnstile.validate_turnstile_token(
        turnstile_token=payload.turnstile_token,
        expected_action="signin",
        ip_address=client.ip_address
    )

    user = await user_service.authenticate_email_user(
        db=db,
        email=payload.email,
        password=payload.password,
    )

    validated_user = validate_user(user, message="Invalid Login Credentials.")
    
    client = get_client_context(request)

    # ── two-factor gating ──────────────────────────────────────────────────
    if await authenticator_app_service.is_enabled(db=db, user_id=validated_user.id):

        token = create_two_factor_token(
            client=client,
            user_id=validated_user.id,
            device=payload,
            remember_me=payload.remember_me,
        )

        return TwoFactorChallengeResponse(
            two_factor_token=token, two_factor_required=True
        )

    # ── normal login ───────────────────────────────────────────────────────
    session_payload = CreateSessionPayload(
        # device fields from payload
        device_id=payload.device_id,
        device_name=payload.device_name,
        device_type=payload.device_type,
        os_name=payload.os_name,
        browser_name=payload.browser_name,
        remember_me=payload.remember_me,
        # client fields from request
        ip_address=client.ip_address,
        user_agent=client.user_agent,
    )

    response = await create_login_session_response(
        db=db, user_id=validated_user.id, payload=session_payload
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
    payload: ChangePasswordPayload,
    request:Request,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    client = get_client_context(request)

    await turnstile.validate_turnstile_token(
        turnstile_token=payload.turnstile_token,
        expected_action="change_password",
        ip_address=client.ip_address
    )

    if not user_service.verify_password(payload.current_password, current_user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    await user_service.change_password(
        db=db,
        user_id=current_user.id,
        new_password=payload.new_password,
    )

    await session_service.delete_all_user_sessions(user_id=current_user.id, db=db)

    tasks.send_password_changed_email.delay(  # type: ignore
        to_email=current_user.email, full_name=current_user.full_name
    )
    return {"detail": "Password changed successfully"}


@router.get("/me", response_model=MeResponse)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> MeResponse:
    return user_service.build_me_response(current_user)


@router.patch("/me", response_model=MeResponse)
async def update_user(
    payload: MePayload,
    request:Request,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MeResponse:
    client = get_client_context(request)

    await turnstile.validate_turnstile_token(
        turnstile_token=payload.turnstile_token,
        expected_action="update_me",
        ip_address=client.ip_address
    )

    if payload.full_name is not None:
        current_user.full_name = payload.full_name
        current_user.updated_at = utc_now()

    await session.commit()
    await session.refresh(current_user)

    return user_service.build_me_response(current_user)


@router.patch("/me/avatar", response_model=MeResponse)
async def update_user_avatar(
    image: Annotated[UploadFile, File()],
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MeResponse:
    old_path = current_user.image_path

    data = await image.read()

    config = ProcessConfig(
        preset="avatar",
        height=100,
        width=100,
    )

    saved_path = user_service.update_user_avatar(
        config=config,
        content_type=image.content_type,
        data=data,
        user_id=current_user.id,
    )

    current_user.image_path = saved_path
    current_user.updated_at = utc_now()

    await session.commit()
    await session.refresh(current_user)

    if old_path:
        file_storage.delete(old_path)

    return user_service.build_me_response(current_user)
