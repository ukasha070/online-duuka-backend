from typing import Optional, Sequence, Any

from fastapi import HTTPException, status
from pydantic import HttpUrl
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from apps.auth.user.models import User, AuthType
from apps.auth.session.schemas import MeResponse
from apps.auth.security import hash_password, verify_password
from core.image.service import (
    ImageProcessingError,
    ProcessConfig,
    process_upload,
)
from core.storage import file_storage


async def get_user_by_id(db: AsyncSession, user_id: str) -> Optional[User]:
    statement = select(User).where(User.id == user_id)
    result = await db.exec(statement)
    return result.first()


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    statement = select(User).where(User.email == email.lower().strip())
    result = await db.exec(statement)
    return result.first()


async def get_user_by_google_sub(
    db: AsyncSession,
    google_sub: str,
) -> Optional[User]:
    statement = select(User).where(User.google_sub == google_sub)
    result = await db.exec(statement)
    return result.first()


async def get_users(
    db: AsyncSession,
    offset: int = 0,
    limit: int = 100,
) -> Sequence[User]:
    statement = select(User).offset(offset).limit(limit)
    result = await db.exec(statement)
    return result.all()


async def create_email_user(
    db: AsyncSession,
    email: str,
    password: str,
    full_name: str,
) -> User:
    normalized_email = email.lower().strip()
    existing_user = await get_user_by_email(db, normalized_email)

    if existing_user:
        raise ValueError("User with this email already exists")

    user = User(
        email=normalized_email,
        password=hash_password(password),
        full_name=full_name,
        auth_type=AuthType.EMAIL,
        is_verified=False,
        is_active=True,
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def get_or_create_google_user(
    db: AsyncSession, *, email: str, full_name: str, google_sub: str, image_url: HttpUrl
) -> tuple[User, bool]:  # (user, created)
    normalized_email = email.lower().strip()

    existing = await get_user_by_email(db, normalized_email)

    if existing:
        if existing.google_sub and existing.google_sub != google_sub:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This email is linked to a different Google account.",
            )

        if existing.google_sub is None:
            existing.google_sub = google_sub
            db.add(existing)
            await db.commit()
            await db.refresh(existing)
        return existing, False

    user = User(
        email=normalized_email,
        full_name=full_name,
        google_sub=google_sub,
        password=None,
        auth_type=AuthType.GOOGLE,
        is_verified=True,
        is_active=True,
        image_url=image_url,
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user, True


async def update_user(
    db: AsyncSession,
    user_id: str,
    update_data: dict[str, Any],
) -> Optional[User]:
    user = await get_user_by_id(db, user_id)

    if not user:
        return None

    allowed_fields = {
        "email",
        "full_name",
    }

    for key, value in update_data.items():
        if key in allowed_fields and value is not None:
            setattr(user, key, value)

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def change_password(
    db: AsyncSession,
    user_id: str,
    new_password: str,
) -> User:
    user = await get_user_by_id(db, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    user.password = hash_password(new_password)

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def check_password(
    db: AsyncSession,
    user_id: str,
    password: str,
) -> bool:
    user = await get_user_by_id(db, user_id)

    if not user or not user.password:
        return False

    return verify_password(password, user.password)


async def verify_user(
    db: AsyncSession,
    user_id: str,
) -> Optional[User]:
    user = await get_user_by_id(db, user_id)

    if not user:
        return None

    user.is_verified = True

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def deactivate_user(
    db: AsyncSession,
    user_id: str,
) -> Optional[User]:
    user = await get_user_by_id(db, user_id)

    if not user:
        return None

    user.is_active = False

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def delete_user(
    db: AsyncSession,
    user_id: str,
) -> bool:
    user = await get_user_by_id(db, user_id)

    if not user:
        return False

    await db.delete(user)
    await db.commit()

    return True


async def authenticate_email_user(
    db: AsyncSession,
    email: str,
    password: str,
) -> Optional[User]:
    user = await get_user_by_email(db, email)

    if not user:
        return None

    if user.auth_type != AuthType.EMAIL:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Please Continue with {user.auth_type}.",
        )

    if not user.password:
        return None

    if not verify_password(password, user.password):
        return None

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Contact support your account is inactive.",
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Please Verify account to login.",
        )

    return user


def get_display_avatar(user: User | None) -> str | None:
    """
    Local upload takes priority over the OAuth image URL.
    Returns a plain str so the response serialises cleanly.
    """
    if user is None:
        return None
    if user.image_path:
        return user.image_path
    if user.image_url:
        return str(user.image_url)  # HttpUrl → str
    return None


def build_me_response(user: User) -> MeResponse:
    """Single place that maps User → MeResponse, keeping endpoints thin."""
    return MeResponse(
        full_name=user.full_name,
        is_verified=user.is_verified,
        created_at=user.created_at,
        avatar=get_display_avatar(user),
    )


def update_user_avatar(
    data: bytes, content_type: str | None, config: ProcessConfig, user_id: str
) -> str:
    try:
        result = process_upload(data, content_type or "", config)
    except ImageProcessingError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    saved_path = file_storage.save(result, user_id)

    return saved_path
