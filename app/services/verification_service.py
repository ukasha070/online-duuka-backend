from __future__ import annotations

from datetime import timedelta

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import settings
from app.core import utils
from app.models.user import EmailVerificationToken, User


async def create_email_verification_token(db: AsyncSession, *, user: User) -> str:
    raw_token = utils.generate_random_id("verify", 32)

    result = await db.exec(select(EmailVerificationToken).where(EmailVerificationToken.user_id == user.id))
    verification_token = result.first()

    if verification_token is None:
        verification_token = EmailVerificationToken(user_id=user.id, token=raw_token)
    else:
        verification_token.token = raw_token
        verification_token.is_used = False
        verification_token.created_at = utils.utc_now()
        verification_token.expires_at = utils.utc_now() + timedelta(
            minutes=settings.EMAIL_VERIFICATION_TOKEN_EXPIRY_MINUTES
        )

    db.add(verification_token)
    await db.commit()
    return raw_token
