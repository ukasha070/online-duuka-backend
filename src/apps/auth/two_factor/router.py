# ===========================================================================
# 2.  apps/auth/two_factor/router.py   (full file)
# ===========================================================================

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from fastapi import APIRouter, Depends, HTTPException, Request, status

from apps.auth.user.service_user import get_user_by_id
from apps.auth.validators import validate_user
from core.db import get_db
from apps.auth import tasks
from apps.auth.user.models import User
from apps.auth.utils import get_client_context
from apps.auth.schema import CreateSessionPayload
from apps.auth.dependencies import get_current_user
from apps.auth.session.schemas import LoginResponse
from apps.auth.authentication import create_login_session_response
from apps.auth.two_factor.tokens import decode_two_factor_token

from .schemas import (
    AuthenticatorConfirmRequest,
    AuthenticatorConfirmResponse,
    AuthenticatorDisabledResponse,
    AuthenticatorSetupResponse,
    AuthenticatorVerifyRequest,
    AuthenticatorStatusResponse,
    RecoveryCodesResponse,
    TwoFactorVerifyPayload,
)
from .service import (
    AuthenticatorSetupData,
    authenticator_app_service,
    build_provisioning_uri,
)
from .qr import build_qr_code_data_url

router = APIRouter(prefix="", tags=["Two-factor authentication"])


# ---------------------------------------------------------------------------
# /verify  — completes the two-factor login flow
# ---------------------------------------------------------------------------


@router.post("/verify")
async def verify_two_factor_login(
    payload: TwoFactorVerifyPayload,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Called after /signin returns two_factor_required=true.

    Accepts:
      - a valid two-factor challenge JWT  (two_factor_token)
      - a 6-digit TOTP code  OR  an XXX-XXX-XXX recovery code  (code)

    On success returns the same LoginResponse as a normal /signin.
    On failure returns 401 (bad/expired token) or 400 (wrong code).
    """
    # ── 1. decode & validate the challenge token ───────────────────────────
    try:
        token_data = decode_two_factor_token(payload.two_factor_token)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        )

    user_id = token_data.sub

    # ── 2. fetch the user (must still be active) ───────────────────────────
    user = await get_user_by_id(db=db, user_id=user_id)

    validated_user = validate_user(user, validate_auth_type=False)

    # ── 3. verify the TOTP / recovery code ────────────────────────────────
    verified_method = (
        await authenticator_app_service.verify_login_code_or_recovery_code(
            db=db,
            user_id=user_id,
            code=payload.code,
        )
    )

    if verified_method is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authenticator code.",
        )

    # ── 4. send security email when a recovery code was consumed ──────────
    client = get_client_context(request)

    if verified_method == "recovery_code":
        tasks.send_two_factor_security_email.delay(  # type: ignore
            to_email=validated_user.email,
            full_name=validated_user.full_name,
            action="recovery_code_used",
            ip_address=client.ip_address,
            user_agent=client.user_agent,
        )

    # ── 5. build the session using context carried inside the JWT ──────────
    #      (device info + remember_me were baked in at signin time)
    session_payload = CreateSessionPayload.model_validate(
        {
            "device_id": token_data.device_id,
            "device_name": token_data.device_name,
            "device_type": token_data.device_type,
            "os_name": token_data.os_name,
            "browser_name": token_data.browser_name,
            "ip_address": token_data.ip_address,
            "user_agent": token_data.user_agent,
            "remember_me": token_data.remember_me,
        }
    )

    response = await create_login_session_response(
        db=db,
        user_id=user_id,
        session_payload=session_payload,
    )

    return LoginResponse.model_validate(response)


# ---------------------------------------------------------------------------
# /status
# ---------------------------------------------------------------------------


@router.get("/status", response_model=AuthenticatorStatusResponse)
async def get_authenticator_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    authenticator = await authenticator_app_service.get_for_user(
        db=db,
        user_id=current_user.id,
    )

    if not authenticator:
        return AuthenticatorStatusResponse(is_enabled=False)

    recovery_codes_remaining = (
        await authenticator_app_service.get_recovery_codes_remaining(
            db=db,
            user_id=current_user.id,
        )
    )

    return AuthenticatorStatusResponse(
        is_enabled=authenticator.is_enabled,
        recovery_codes_remaining=recovery_codes_remaining,
        confirmed_at=(
            authenticator.confirmed_at.isoformat()
            if authenticator.confirmed_at
            else None
        ),
        last_used_at=(
            authenticator.last_used_at.isoformat()
            if authenticator.last_used_at
            else None
        ),
    )


# ---------------------------------------------------------------------------
# /setup
# ---------------------------------------------------------------------------


@router.post("/setup", response_model=AuthenticatorSetupResponse)
async def start_authenticator_setup(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    try:
        setup_data: AuthenticatorSetupData = (
            await authenticator_app_service.start_setup(
                db=db,
                user=current_user,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    authenticator = setup_data.authenticator

    otpauth_uri = build_provisioning_uri(
        secret=setup_data.secret,
        issuer=authenticator.issuer,
        account_name=current_user.email,
    )
    qr_code_data_url = build_qr_code_data_url(otpauth_uri)

    return AuthenticatorSetupResponse(
        secret=setup_data.secret,
        issuer=authenticator.issuer,
        account_name=current_user.email,
        otpauth_uri=otpauth_uri,
        qr_code_data_url=qr_code_data_url,
    )


# ---------------------------------------------------------------------------
# /confirm
# ---------------------------------------------------------------------------


@router.post("/confirm", response_model=AuthenticatorConfirmResponse)
async def confirm_authenticator_setup(
    payload: AuthenticatorConfirmRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    recovery_codes: list[str] | None = await authenticator_app_service.confirm_setup(
        db=db,
        user_id=current_user.id,
        code=payload.code,
    )

    if recovery_codes is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authenticator code.",
        )

    client = get_client_context(request)
    tasks.send_two_factor_security_email.delay(  # type: ignore
        to_email=current_user.email,
        full_name=current_user.full_name,
        action="enabled",
        ip_address=client.ip_address,
        user_agent=client.user_agent,
    )

    return AuthenticatorConfirmResponse(
        is_enabled=True,
        recovery_codes=recovery_codes,
        recovery_codes_remaining=len(recovery_codes),
    )


# ---------------------------------------------------------------------------
# /recovery-codes/regenerate
# ---------------------------------------------------------------------------


@router.post("/recovery-codes/regenerate", response_model=RecoveryCodesResponse)
async def regenerate_recovery_codes(
    payload: AuthenticatorVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    recovery_codes = await authenticator_app_service.regenerate_recovery_codes(
        db=db,
        user_id=current_user.id,
        code=payload.code,
    )

    if not recovery_codes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authenticator code.",
        )

    client = get_client_context(request)
    tasks.send_two_factor_security_email.delay(  # type: ignore
        to_email=current_user.email,
        full_name=current_user.full_name,
        action="recovery_codes_regenerated",
        ip_address=client.ip_address,
        user_agent=client.user_agent,
    )

    return RecoveryCodesResponse(
        recovery_codes=recovery_codes,
        recovery_codes_remaining=len(recovery_codes),
    )


# ---------------------------------------------------------------------------
# /disable
# ---------------------------------------------------------------------------


@router.post("/disable", response_model=AuthenticatorDisabledResponse)
async def disable_authenticator_app(
    payload: AuthenticatorVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    disabled = await authenticator_app_service.disable(
        db=db,
        user_id=current_user.id,
        code=payload.code,
    )

    if not disabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authenticator code.",
        )

    client = get_client_context(request)
    tasks.send_two_factor_security_email.delay(  # type: ignore
        to_email=current_user.email,
        full_name=current_user.full_name,
        action="disabled",
        ip_address=client.ip_address,
        user_agent=client.user_agent,
    )

    return AuthenticatorDisabledResponse(is_enabled=False)
