from datetime import datetime, timezone, timedelta, time
from fastapi import HTTPException, status
from typing import Optional

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from apps.auth.security import generate_token, hash_password

from core import utils
from core.config import settings

from .models import PasswordResetToken, User

COOLDOWN_STEPS = settings.COOLDOWN_STEPS
MAX_PASSWORD_RESET_REQUESTS_PER_DAY = settings.PASSWORD_RESET_MAX_REQUESTS_PER_DAY
PASSWORD_RESET_TOKEN_EXPIRY_MINUTES = settings.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES


def next_utc_midnight() -> datetime:
    now = utils.utc_now()
    tomorrow = now.date() + timedelta(days=1)
    return datetime.combine(tomorrow, time.min, tzinfo=timezone.utc)


def get_cooldown_delay(request_count: int) -> timedelta:
    index = min(request_count - 1, len(COOLDOWN_STEPS) - 1)
    return COOLDOWN_STEPS[index]


async def get_token_for_user(
    db: AsyncSession,
    user_id: str,
) -> Optional[PasswordResetToken]:
    statement = select(PasswordResetToken).where(PasswordResetToken.user_id == user_id)

    result = await db.exec(statement)
    return result.first()


async def create_or_update_password_reset_token(
    db: AsyncSession,
    user_id: str,
) -> PasswordResetToken:
    now = utils.utc_now()

    reset_token = await get_token_for_user(
        db=db,
        user_id=user_id,
    )

    if reset_token:
        if reset_token.cooldown_until and reset_token.cooldown_until > now:
            cooldown_remaining = reset_token.cooldown_until - now
            cooldown_seconds = int(cooldown_remaining.total_seconds())

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": f"Please wait {cooldown_seconds} seconds before requesting another reset email.",
                    "cooldown": cooldown_seconds,
                },
            )

        if reset_token.cooldown_reset_at and reset_token.cooldown_reset_at > now:
            request_count = reset_token.request_count + 1
            cooldown_reset_at = reset_token.cooldown_reset_at
        else:
            request_count = 1
            cooldown_reset_at = next_utc_midnight()

        if request_count > MAX_PASSWORD_RESET_REQUESTS_PER_DAY:
            raise ValueError(
                f"Too many password reset requests. Try again after {cooldown_reset_at.isoformat()}."
            )

        cooldown_delay = get_cooldown_delay(request_count)

        reset_token.token = generate_token()
        reset_token.request_count = request_count
        reset_token.cooldown_until = now + cooldown_delay
        reset_token.cooldown_reset_at = cooldown_reset_at
        reset_token.created_at = now
        reset_token.expires_at = now + timedelta(
            minutes=PASSWORD_RESET_TOKEN_EXPIRY_MINUTES
        )
        reset_token.is_used = False

    else:
        request_count = 1
        cooldown_reset_at = next_utc_midnight()
        cooldown_delay = get_cooldown_delay(request_count)

        reset_token = PasswordResetToken(
            user_id=user_id,
            token=generate_token(),
            request_count=request_count,
            cooldown_until=now + cooldown_delay,
            cooldown_reset_at=cooldown_reset_at,
            created_at=now,
            expires_at=now + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRY_MINUTES),
            is_used=False,
        )

    db.add(reset_token)
    await db.commit()
    await db.refresh(reset_token)

    return reset_token


async def get_valid_token(
    db: AsyncSession,
    token: str,
) -> PasswordResetToken:
    statement = select(PasswordResetToken).where(PasswordResetToken.token == token)

    result = await db.exec(statement)
    reset_token = result.first()

    if not reset_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        )

    if reset_token.is_used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This password reset token has already been used",
        )

    if reset_token.is_expired():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Expired password reset token.",
        )

    if not reset_token.can_be_used():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        )

    return reset_token


async def mark_token_as_used(
    db: AsyncSession,
    reset_token: PasswordResetToken,
) -> PasswordResetToken:
    reset_token.is_used = True

    db.add(reset_token)
    await db.commit()
    await db.refresh(reset_token)

    return reset_token
