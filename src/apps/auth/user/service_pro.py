# app/services/user_profile_service.py

from typing import Optional

from pydantic import HttpUrl
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from core.utils import utc_now

from apps.auth.user.models import UserProfile


async def get_profile(
    session: AsyncSession,
    user_id: str,
) -> Optional[UserProfile]:
    statement = select(UserProfile).where(UserProfile.user_id == user_id)
    result = await session.exec(statement)
    return result.first()


async def get_or_create_profile(
    session: AsyncSession,
    user_id: str,
) -> UserProfile:
    profile = await get_profile(
        session=session,
        user_id=user_id,
    )

    if profile:
        return profile

    profile = UserProfile(
        user_id=user_id,
        image_path=None,
        image_url=None,
    )

    session.add(profile)
    await session.commit()
    await session.refresh(profile)

    return profile


def get_display_image(profile: UserProfile) -> Optional[HttpUrl]:
    # TODO
    # if profile.image_path:
    #     return profile.image_path

    if profile.image_url:
        return profile.image_url

    return None


async def update_profile_image_path(
    session: AsyncSession,
    user_id: str,
    image_path: Optional[str],
) -> UserProfile:
    profile = await get_or_create_profile(
        session=session,
        user_id=user_id,
    )

    profile.image_path = image_path
    profile.updated_at = utc_now()

    session.add(profile)
    await session.commit()
    await session.refresh(profile)

    return profile


async def update_google_profile_image_url(
    session: AsyncSession,
    user_id: str,
    image_url: Optional[HttpUrl],
) -> UserProfile:
    profile = await get_or_create_profile(
        session=session,
        user_id=user_id,
    )

    profile.image_url = image_url
    profile.updated_at = utc_now()

    session.add(profile)
    await session.commit()
    await session.refresh(profile)

    return profile
