from datetime import timedelta
import hashlib

import pyotp
from fastapi import HTTPException, Request, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.core import utils
from app.core.security import (
    TokenType,
    create_access_token,
    create_refresh_token,
    hash_password,
    hash_token,
    validate_token,
    verify_password,
)
from app.models.user import AuthType, PasswordResetToken, User, UserAuthenticatorApp, UserSession
from app.schemas.auth import DeviceInfoPayload, TokenResponse, UserResponse


def get_client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def get_user_agent(request: Request) -> str | None:
    return request.headers.get("user-agent")


def make_device_key_hash(payload: DeviceInfoPayload, user_agent: str | None) -> str:
    fingerprint = "|".join(
        [
            payload.device_id or "",
            payload.device_name or "",
            payload.device_type or "",
            payload.os_name or "",
            payload.browser_name or "",
            user_agent or "",
        ]
    )
    return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()


def public_user(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        avatar=user.image_path or user.image_url,
        is_active=user.is_active,
        is_verified=user.is_verified,
        is_admin=user.is_admin or user.is_superuser,
        is_agent=user.is_agent,
        created_at=user.created_at,
    )


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.exec(select(User).where(User.email == email.lower().strip()))
    return result.first()


async def get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    result = await db.exec(select(User).where(User.id == user_id))
    return result.first()


async def create_email_user(db: AsyncSession, *, email: str, full_name: str, password: str) -> User:
    existing_user = await get_user_by_email(db, email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered.")

    user = User(
        email=email.lower().strip(),
        full_name=full_name.strip(),
        password=hash_password(password),
        auth_type=AuthType.EMAIL,
        is_verified=False,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def authenticate_email_user(db: AsyncSession, *, email: str, password: str) -> User:
    user = await get_user_by_email(db, email)
    invalid_credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password.",
    )

    if user is None:
        raise invalid_credentials_error

    if user.auth_type != AuthType.EMAIL:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Please continue with {user.auth_type.value}.",
        )

    if user.lockdown_left_seconds() > 0:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={
                "seconds": user.lockdown_left_seconds(),
                "message": "Account is temporarily locked because of failed login attempts.",
            },
        )

    if not verify_password(password, user.password):
        user.failed_login_attempts += 1
        user.last_failed_login_at = utils.utc_now()
        lockout_duration = utils.get_lockout_duration(user.failed_login_attempts)
        if lockout_duration.total_seconds() > 0:
            user.login_locked_until = utils.utc_now() + lockout_duration
        db.add(user)
        await db.commit()
        raise invalid_credentials_error

    if not user.is_active or user.is_disabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account is disabled.")

    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Please verify your email before login.")

    user.failed_login_attempts = 0
    user.login_locked_until = None
    user.last_failed_login_at = None
    user.updated_at = utils.utc_now()
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def is_two_factor_enabled(db: AsyncSession, *, user_id: str) -> bool:
    result = await db.exec(
        select(UserAuthenticatorApp).where(
            UserAuthenticatorApp.user_id == user_id,
            UserAuthenticatorApp.is_enabled == True,  # noqa: E712
        )
    )
    return result.first() is not None


async def create_login_session(
    db: AsyncSession,
    *,
    user: User,
    payload: DeviceInfoPayload,
    ip_address: str | None,
    user_agent: str | None,
) -> TokenResponse:
    device_key_hash = make_device_key_hash(payload, user_agent)

    result = await db.exec(
        select(UserSession).where(
            UserSession.user_id == user.id,
            UserSession.device_key_hash == device_key_hash,
        )
    )
    session = result.first()

    now = utils.utc_now()
    days = settings.REFRESH_TOKEN_EXPIRE_REMEMBER_ME_DAYS if payload.remember_me else settings.REFRESH_TOKEN_EXPIRE_DAYS
    expires_at = now + timedelta(days=days)

    if session is None:
        session = UserSession(
            user_id=user.id,
            device_id=payload.device_id,
            device_key_hash=device_key_hash,
            device_name=payload.device_name,
            device_type=payload.device_type,
            os_name=payload.os_name,
            browser_name=payload.browser_name,
            user_agent=user_agent,
            ip_address=ip_address,
            refresh_token_hash="pending",
            expires_at=expires_at,
        )
    else:
        session.device_id = payload.device_id
        session.device_name = payload.device_name
        session.device_type = payload.device_type
        session.os_name = payload.os_name
        session.browser_name = payload.browser_name
        session.user_agent = user_agent
        session.ip_address = ip_address
        session.last_seen_at = now
        session.expires_at = expires_at
        session.is_active = True
        session.revoked_at = None
        session.revoked_reason = None
        session.logged_out_at = None

    db.add(session)
    await db.commit()
    await db.refresh(session)

    access_token = create_access_token(user_id=user.id, session_id=session.id)
    refresh_token = create_refresh_token(user_id=user.id, session_id=session.id, remember_me=payload.remember_me)
    session.refresh_token_hash = hash_token(refresh_token)

    db.add(session)
    await db.commit()
    await db.refresh(session)

    await enforce_session_limit(db, user_id=user.id, current_session_id=session.id)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


async def enforce_session_limit(db: AsyncSession, *, user_id: str, current_session_id: str) -> None:
    result = await db.exec(
        select(UserSession)
        .where(
            UserSession.user_id == user_id,
            UserSession.is_active == True,  # noqa: E712
        )
        .order_by(UserSession.last_seen_at.desc())
    )
    sessions = list(result.all())
    max_sessions = settings.MAX_ACTIVE_SESSIONS_PER_USER

    for session in sessions[max_sessions:]:
        if session.id == current_session_id:
            continue
        session.is_active = False
        session.revoked_at = utils.utc_now()
        session.revoked_reason = "max_active_sessions_exceeded"
        db.add(session)

    await db.commit()


async def refresh_login_session(db: AsyncSession, *, refresh_token: str, request: Request) -> TokenResponse:
    try:
        payload = validate_token(refresh_token, TokenType.REFRESH)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    session_id = payload.get("session_id")
    user_id = payload.get("sub")
    if not session_id or not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")

    result = await db.exec(select(UserSession).where(UserSession.id == session_id))
    session = result.first()
    if (
        session is None
        or not session.is_active
        or session.user_id != user_id
        or session.expires_at <= utils.utc_now()
        or session.refresh_token_hash != hash_token(refresh_token)
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session is invalid or expired.")

    user = await get_user_by_id(db, user_id)
    if user is None or not user.can_login():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is invalid or disabled.")

    session.last_seen_at = utils.utc_now()
    session.ip_address = get_client_ip(request)
    db.add(session)
    await db.commit()

    access_token = create_access_token(user_id=user.id, session_id=session.id)
    new_refresh_token = create_refresh_token(user_id=user.id, session_id=session.id)
    session.refresh_token_hash = hash_token(new_refresh_token)
    db.add(session)
    await db.commit()

    return TokenResponse(access_token=access_token, refresh_token=new_refresh_token)


async def revoke_session_by_refresh_token(db: AsyncSession, *, refresh_token: str) -> None:
    try:
        payload = validate_token(refresh_token, TokenType.REFRESH)
    except ValueError:
        return

    session_id = payload.get("session_id")
    if not session_id:
        return

    result = await db.exec(select(UserSession).where(UserSession.id == session_id))
    session = result.first()
    if session:
        session.is_active = False
        session.logged_out_at = utils.utc_now()
        session.revoked_at = utils.utc_now()
        session.revoked_reason = "logout"
        db.add(session)
        await db.commit()


async def revoke_user_sessions(db: AsyncSession, *, user_id: str, except_session_id: str | None = None) -> None:
    result = await db.exec(select(UserSession).where(UserSession.user_id == user_id, UserSession.is_active == True))  # noqa: E712
    for session in result.all():
        if except_session_id and session.id == except_session_id:
            continue
        session.is_active = False
        session.revoked_at = utils.utc_now()
        session.revoked_reason = "logout_all"
        db.add(session)
    await db.commit()


async def list_user_sessions(db: AsyncSession, *, user_id: str, current_session_id: str | None = None) -> list[UserSession]:
    result = await db.exec(
        select(UserSession)
        .where(UserSession.user_id == user_id)
        .order_by(UserSession.last_seen_at.desc())
    )
    return list(result.all())


async def revoke_session_by_id(db: AsyncSession, *, user_id: str, session_id: str) -> None:
    result = await db.exec(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
        )
    )
    session = result.first()
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    session.is_active = False
    session.revoked_at = utils.utc_now()
    session.revoked_reason = "manual_revoke"
    db.add(session)
    await db.commit()


async def change_password(db: AsyncSession, *, user: User, current_password: str, new_password: str) -> None:
    if not verify_password(current_password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect.")

    user.password = hash_password(new_password)
    user.updated_at = utils.utc_now()
    db.add(user)
    await db.commit()
    await revoke_user_sessions(db, user_id=user.id)


async def enable_two_factor(db: AsyncSession, *, user: User) -> tuple[str, str]:
    result = await db.exec(select(UserAuthenticatorApp).where(UserAuthenticatorApp.user_id == user.id))
    authenticator = result.first()
    secret = pyotp.random_base32()

    if authenticator is None:
        authenticator = UserAuthenticatorApp(
            user_id=user.id,
            secret=secret,
            issuer=settings.APP_NAME,
            is_enabled=False,
        )
    else:
        authenticator.secret = secret
        authenticator.issuer = settings.APP_NAME
        authenticator.is_enabled = False
        authenticator.confirmed_at = None
        authenticator.updated_at = utils.utc_now()

    db.add(authenticator)
    await db.commit()

    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=settings.APP_NAME)
    return secret, provisioning_uri


async def verify_two_factor_setup(db: AsyncSession, *, user: User, code: str) -> None:
    result = await db.exec(select(UserAuthenticatorApp).where(UserAuthenticatorApp.user_id == user.id))
    authenticator = result.first()
    if authenticator is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="2FA setup has not been started.")

    if not pyotp.TOTP(authenticator.secret).verify(code, valid_window=settings.TWO_FACTOR_TOTP_VALID_WINDOW):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 2FA code.")

    authenticator.is_enabled = True
    authenticator.confirmed_at = utils.utc_now()
    authenticator.updated_at = utils.utc_now()
    db.add(authenticator)
    await db.commit()


async def validate_two_factor_login(
    db: AsyncSession,
    *,
    two_factor_token: str,
    code: str,
    payload: DeviceInfoPayload,
    request: Request,
) -> TokenResponse:
    try:
        token_payload = validate_token(two_factor_token, TokenType.TWO_FACTOR)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    user_id = token_payload.get("sub")
    user = await get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA token.")

    result = await db.exec(
        select(UserAuthenticatorApp).where(
            UserAuthenticatorApp.user_id == user.id,
            UserAuthenticatorApp.is_enabled == True,  # noqa: E712
        )
    )
    authenticator = result.first()
    if authenticator is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is not enabled.")

    if not pyotp.TOTP(authenticator.secret).verify(code, valid_window=settings.TWO_FACTOR_TOTP_VALID_WINDOW):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 2FA code.")

    authenticator.last_used_at = utils.utc_now()
    db.add(authenticator)
    await db.commit()

    return await create_login_session(
        db,
        user=user,
        payload=payload,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
    )


async def disable_two_factor(db: AsyncSession, *, user: User, password: str, code: str) -> None:
    if not verify_password(password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid password.")

    result = await db.exec(select(UserAuthenticatorApp).where(UserAuthenticatorApp.user_id == user.id))
    authenticator = result.first()
    if authenticator is None or not authenticator.is_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is not enabled.")

    if not pyotp.TOTP(authenticator.secret).verify(code, valid_window=settings.TWO_FACTOR_TOTP_VALID_WINDOW):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 2FA code.")

    authenticator.is_enabled = False
    authenticator.updated_at = utils.utc_now()
    db.add(authenticator)
    await db.commit()


async def create_password_reset_token(db: AsyncSession, *, email: str) -> str | None:
    user = await get_user_by_email(db, email)
    if user is None:
        return None

    raw_token = utils.generate_random_id("reset", 32)
    result = await db.exec(select(PasswordResetToken).where(PasswordResetToken.user_id == user.id))
    reset_token = result.first()

    if reset_token is None:
        reset_token = PasswordResetToken(user_id=user.id, token=raw_token)
    else:
        reset_token.token = raw_token
        reset_token.is_used = False
        reset_token.created_at = utils.utc_now()
        reset_token.expires_at = utils.utc_now() + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES)
        reset_token.request_count += 1

    db.add(reset_token)
    await db.commit()
    return raw_token


async def confirm_password_reset(db: AsyncSession, *, token: str, new_password: str) -> None:
    result = await db.exec(select(PasswordResetToken).where(PasswordResetToken.token == token))
    reset_token = result.first()
    if reset_token is None or reset_token.is_used or reset_token.expires_at <= utils.utc_now():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token.")

    user = await get_user_by_id(db, reset_token.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid reset token.")

    user.password = hash_password(new_password)
    user.updated_at = utils.utc_now()
    reset_token.is_used = True

    db.add(user)
    db.add(reset_token)
    await db.commit()
    await revoke_user_sessions(db, user_id=user.id)
