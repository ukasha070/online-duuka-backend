from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
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
)
from app.services import auth_service
from app.services.turnstile_service import validate_turnstile_token
from app.services.verification_service import create_email_verification_token
from app.tasks.email_tasks import (
    send_new_login_alert_email,
    send_password_changed_email,
    send_password_reset_email,
    send_two_factor_security_email,
    send_verification_email,
    send_welcome_email,
)

router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED)
@router.post("/signup", status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def register(
    payload: RegisterPayload,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    await validate_turnstile_token(
        payload.turnstile_token,
        remote_ip=auth_service.get_client_ip(request),
        expected_action="register",
    )

    user = await auth_service.create_email_user(
        db,
        email=str(payload.email),
        full_name=payload.full_name,
        password=payload.password,
    )

    send_welcome_email.delay(user.email, user.full_name)
    verification_token = await create_email_verification_token(db, user=user)
    send_verification_email.delay(user.email, verification_token, user.full_name)

    response = {"detail": "Account created successfully. Please verify your email."}
    if settings.ENV == "local":
        response["debug_verification_token"] = verification_token
    return response


@router.post("/login", response_model=TokenResponse | TwoFactorChallengeResponse)
@router.post("/signin", response_model=TokenResponse | TwoFactorChallengeResponse, include_in_schema=False)
async def login(
    payload: LoginPayload,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse | TwoFactorChallengeResponse:
    await validate_turnstile_token(
        payload.turnstile_token,
        remote_ip=auth_service.get_client_ip(request),
        expected_action="login",
    )

    user = await auth_service.authenticate_email_user(
        db,
        email=str(payload.email),
        password=payload.password,
    )

    if await auth_service.is_two_factor_enabled(db, user_id=user.id):
        return TwoFactorChallengeResponse(two_factor_token=create_two_factor_token(user_id=user.id))

    token_response = await auth_service.create_login_session(
        db,
        user=user,
        payload=payload,
        ip_address=auth_service.get_client_ip(request),
        user_agent=auth_service.get_user_agent(request),
    )

    send_new_login_alert_email.delay(
        user.email,
        user.full_name,
        auth_service.get_client_ip(request),
        auth_service.get_user_agent(request),
        None,
        None,
    )

    return token_response


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
    session_responses = [session_response(session) for session in sessions]
    return SessionListResponse(total=len(session_responses), sessions=session_responses)


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    await auth_service.revoke_session_by_id(db, user_id=current_user.id, session_id=session_id)
    return {"detail": "Session revoked successfully."}


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordPayload,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    await validate_turnstile_token(
        payload.turnstile_token,
        remote_ip=auth_service.get_client_ip(request),
        expected_action="change_password",
    )

    await auth_service.change_password(
        db,
        user=current_user,
        current_password=payload.current_password,
        new_password=payload.new_password,
    )

    send_password_changed_email.delay(current_user.email, current_user.full_name)
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
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    await auth_service.verify_two_factor_setup(db, user=current_user, code=payload.code)
    send_two_factor_security_email.delay(
        current_user.email,
        "enabled",
        current_user.full_name,
        auth_service.get_client_ip(request),
        auth_service.get_user_agent(request),
        None,
    )
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
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    await auth_service.disable_two_factor(db, user=current_user, password=payload.password, code=payload.code)
    send_two_factor_security_email.delay(
        current_user.email,
        "disabled",
        current_user.full_name,
        auth_service.get_client_ip(request),
        auth_service.get_user_agent(request),
        None,
    )
    return {"detail": "2FA disabled successfully."}


@router.post("/password-reset/request")
async def request_password_reset(
    payload: PasswordResetRequestPayload,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str | None]:
    await validate_turnstile_token(
        payload.turnstile_token,
        remote_ip=auth_service.get_client_ip(request),
        expected_action="password_reset",
    )

    token = await auth_service.create_password_reset_token(db, email=str(payload.email))
    if token:
        user = await auth_service.get_user_by_email(db, str(payload.email))
        send_password_reset_email.delay(str(payload.email), token, user.full_name if user else None)

    response: dict[str, str | None] = {
        "detail": "If that email exists, a password reset link has been sent.",
    }
    if settings.ENV == "local":
        response["debug_token"] = token
    return response


@router.post("/password-reset/confirm")
async def confirm_password_reset(
    payload: PasswordResetConfirmPayload,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    await auth_service.confirm_password_reset(db, token=payload.token, new_password=payload.new_password)
    return {"detail": "Password reset successfully."}


@router.get("/google")
async def google_oauth_url() -> dict[str, str]:
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


def session_response(session) -> object:
    from app.schemas.auth import UserSessionResponse

    return UserSessionResponse.model_validate(session)
