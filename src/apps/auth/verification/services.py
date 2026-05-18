from typing import Optional
from datetime import timedelta

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from apps.auth.security import generate_token
from apps.auth.user import service as user_service

from .models import EmailVerificationToken, User

from core import utils
from core.config import settings

EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES = (
    settings.EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES
)


async def get_verification_token(
    db: AsyncSession,
    user_id: str,
) -> Optional[EmailVerificationToken]:
    statement = select(EmailVerificationToken).where(
        EmailVerificationToken.user_id == user_id
    )

    result = await db.exec(statement)
    return result.first()


async def create_or_update_verification_token(
    db: AsyncSession,
    user_id: str,
) -> EmailVerificationToken:
    now = utils.utc_now()

    verification_token = await get_verification_token(
        db=db,
        user_id=user_id,
    )

    if verification_token:
        verification_token.token = generate_token()
        verification_token.created_at = now
        verification_token.expires_at = now + timedelta(
            minutes=EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES
        )
        verification_token.is_used = False

    else:
        verification_token = EmailVerificationToken(
            user_id=user_id,
            token=generate_token(),
            created_at=now,
            expires_at=now + timedelta(minutes=EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES),
            is_used=False,
        )

    db.add(verification_token)
    await db.commit()
    await db.refresh(verification_token)

    return verification_token


async def get_valid_verification_token(
    db: AsyncSession,
    token: str,
) -> Optional[EmailVerificationToken]:
    statement = select(EmailVerificationToken).where(
        EmailVerificationToken.token == token
    )

    result = await db.exec(statement)
    verification_token = result.first()

    if not verification_token:
        return None

    if not verification_token.can_be_used():
        return None

    return verification_token


async def confirm_verification_token(
    db: AsyncSession,
    token: str,
) -> Optional[User]:
    ver_token_instance = await get_valid_verification_token(
        db=db,
        token=token,
    )

    if not ver_token_instance:
        return None

    user = await user_service.verify_user(db=db, user_id=ver_token_instance.user_id)

    if not user:
        return None

    await db.delete(ver_token_instance)
    await db.commit()

    return user


async def mark_verification_token_as_used(
    db: AsyncSession,
    verification_token: EmailVerificationToken,
) -> EmailVerificationToken:
    verification_token.is_used = True

    db.add(verification_token)
    await db.commit()
    await db.refresh(verification_token)

    return verification_token
