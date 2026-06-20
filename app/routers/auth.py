from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.dependencies import get_current_user
from app.core.security import create_two_factor_token
from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    ChangePasswordPayload,
    GoogleCallbackPayload,
    LoginPayload,
    LogoutPayload,
    PasswordResetConfirmPayload,
    PasswordResetRequestPayload,
    RefreshPayload,
    RegisterPayload,
    SessionListResponse,
    TokenResponse,
    TwoFactorChallengeResponse,
    TwoFactorDisablePayload,
    TwoFactorEnableResponse,
    TwoFactorValidatePayload,
    TwoFactorVerifyPayload,
    UpdateMePayload,
    UserResponse,
    UserSessionResponse,
)
from app.services import auth_service

router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED)
@router.post("/signup", status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def register(payload: RegisterPayload, db: Annotated[AsyncSession, Depends(get_db)]) -> dict[str, str]:
    await auth_service.create_email_user(
        db,
        email=str(payload.email),
        full_name=payload.full_name,
        password=payload.password,
    )
    return {"detail": "Account created successfully. Please verify your email."}


@router.post("/login", response_model=TokenResponse | TwoFactorChallengeResponse)
@router.post("/signin", response_model=TokenResponse | TwoFactorChallengeResponse, include_in_schema=False)
async def login(
    payload: LoginPayload,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse | TwoFactorChallengeResponse:
    user = await auth_service.authenticate_email_user(
        db,
        email=str(payload.email),
        password=payload.password,
    )

    if await auth_service.is_two_factor_enabled(db, user_id=user.id):
        return TwoFactorChallengeResponse(two_factor_token=create_two_factor_token(user_id=user.id))

    return await auth_service.create_login_session(
        db,
        user=user,
        payload=payload,
        ip_address=auth_service.get_client_ip(request),
        user_agent=auth_service.get_user_agent(request),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshPayload,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    return await auth_service.refresh_login_session(db, refresh_token=payload.refresh_token, request=request)


@router.post("/logout")
@router.post("/signout", include_in_schema=False)
async def logout(payload: LogoutPayload, db: Annotated[AsyncSession, Depends(get_db)]) -> dict[str, str]:
    await auth_service.revoke_session_by_refresh_token(db, refresh_token=payload.refresh_token)
    return {"detail": "Logged out successfully."}


@router.post("/logout-all")
async def logout_all(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    await auth_service.revoke_user_sessions(db, user_id=current_user.id)
    return {"detail": "All sessions revoked successfully."}


@router.get("/sessions", response_model=SessionListResponse)
async def list_sessions(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SessionListResponse:
    sessions = await auth_service.list_user_sessions(db, user_id=current_user.id)
    session_responses = [UserSessionResponse.model_validate(session) for session in sessions]
    return SessionListResponse(total=len(session_responses), sessions=session_responses)


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    await auth_service.revoke_session_by_id(db, user_id=current_user.id, session_id=session_id)
    return {"detail": "Session revoked successfully."}


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


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordPayload,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    await auth_service.change_password(
        db,
        user=current_user,
        current_password=payload.current_password,
        new_password=payload.new_password,
    )
    return {"detail": "Password changed successfully. Please login again."}


@router.post("/2fa/enable", response_model=TwoFactorEnableResponse)
async def enable_two_factor(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TwoFactorEnableResponse:
    secret, provisioning_uri = await auth_service.enable_two_factor(db, user=current_user)
    return TwoFactorEnableResponse(secret=secret, provisioning_uri=provisioning_uri)


@router.post("/2fa/verify")
async def verify_two_factor_setup(
    payload: TwoFactorVerifyPayload,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    await auth_service.verify_two_factor_setup(db, user=current_user, code=payload.code)
    return {"detail": "2FA enabled successfully."}


@router.post("/2fa/validate", response_model=TokenResponse)
async def validate_two_factor_login(
    payload: TwoFactorValidatePayload,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    return await auth_service.validate_two_factor_login(
        db,
        two_factor_token=payload.two_factor_token,
        code=payload.code,
        payload=payload,
        request=request,
    )


@router.post("/2fa/disable")
async def disable_two_factor(
    payload: TwoFactorDisablePayload,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    await auth_service.disable_two_factor(db, user=current_user, password=payload.password, code=payload.code)
    return {"detail": "2FA disabled successfully."}


@router.post("/password-reset/request")
async def request_password_reset(
    payload: PasswordResetRequestPayload,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str | None]:
    token = await auth_service.create_password_reset_token(db, email=str(payload.email))
    # In production this token should be emailed via Celery, not returned. Returning it in local/dev keeps
    # the endpoint testable until the email task module is migrated into app/tasks.
    return {"detail": "If that email exists, a password reset link has been prepared.", "debug_token": token}


@router.post("/password-reset/confirm")
async def confirm_password_reset(
    payload: PasswordResetConfirmPayload,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    await auth_service.confirm_password_reset(db, token=payload.token, new_password=payload.new_password)
    return {"detail": "Password reset successfully."}


@router.get("/google")
async def google_oauth_url() -> dict[str, str]:
    # Full Google OAuth service migration is separate; this keeps the route contract stable.
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Google OAuth service has not been migrated yet.",
    )


@router.post("/google/callback")
async def google_callback(payload: GoogleCallbackPayload) -> dict[str, str]:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Google OAuth callback service has not been migrated yet.",
    )


@router.get("/health")
async def auth_health() -> dict[str, str]:
    return {"router": "auth", "status": "ok"}
